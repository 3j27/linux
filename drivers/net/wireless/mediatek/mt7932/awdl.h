/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MT7932_AWDL_H
#define MT7932_AWDL_H

#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/unaligned.h>

/*
 * AWDL (Apple Wireless Direct Link), the link layer AirDrop and AirPlay run
 * over, is implemented in the IZUBA firmware's awdl_sync module; the firmware
 * log names its session controls AWDL_EN, 2GChNum, 5GChNum and awdlba. The
 * firmware runs discovery, the CWME availability schedule, election and its
 * peer table on its own schedule, hopping to the availability-window channels
 * around the station's infrastructure association.
 *
 * The AWDL session is the firmware's second BSS: CID 0x11 with BSS index 1
 * activates and deactivates it with its host MAC in bytes 4-9, the same body
 * the station BSS uses, and EID 0x11 reports its presence with the BSS index
 * in byte 0. For BSS 1 the presence event carries, after the absence and
 * quota bytes the station BSS uses, the WTBL entry the firmware assigned the
 * AWDL BSS as a little-endian 16-bit value in bytes 3-4; AWDL data frames
 * carry that entry in the receive descriptor.
 *
 * The firmware's AWDL session control family is the runtime command CID 0x7e,
 * whose body selects the operation in byte 0:
 *
 *   1 enable  {1, master 2 GHz channel, peer 5 GHz channel, slot density}
 *   2 disable {2}
 *   3 service record  {3, u16 length, bytes}  (advertised in MIFs)
 *   4 PSF template    {4, u16 length, bytes}  (sync-frame body)
 *   5 action frame    {5, u16 length, bytes}  (one transmission)
 *   6 peer add        {6, mac[6]}
 *   7 peer remove     {7, mac[6]}
 *   8 state GET       {8, selector} answered with EID 0x7e; selectors:
 *                     0 advertisers, 1 statistics, 2 opmode, 3 channel
 *                     sequence, 4 sync parameters
 *   9 election        {9, u32 metric, s8 rssi threshold}
 *
 * The firmware refuses 3-5 and 8 while the session is disabled; the driver
 * refuses them the same way rather than submitting commands the firmware
 * would answer with an error.
 */
#define MT7932_AWDL_BSS 1

/* Slot density of the firmware's availability schedule: idle windows,
 * active windows around the station's association, or the mirror map used
 * while a peer's windows must be matched. The firmware derives its
 * bandwidth-availability map (awdlba) from the selection.
 */
enum mt7932_awdl_density {
	MT7932_AWDL_DENSITY_IDLE,
	MT7932_AWDL_DENSITY_ACTIVE,
	MT7932_AWDL_DENSITY_MIRROR,
};

/* Longest body accepted for one length-prefixed session command
 * (service record, PSF template, action frame).
 */
#define MT7932_AWDL_BODY_MAX 512

/* The fixed BSSID every AWDL node uses, so a peer accepts the interface's
 * frames whatever its own session state.
 */
#define MT7932_AWDL_BSSID { 0x00, 0x25, 0x00, 0xff, 0x94, 0x73 }

/*
 * AWDL data frames on the air are 802.3 + LLC/SNAP (OUI 00:17:f2, protocol
 * 0x0800, then 03 04) + a 4-byte data header (the 2-byte header above, a
 * little-endian sequence and two zero bytes), then the real ethertype. The
 * kernel only speaks Ethernet II, so the driver translates at the awdl0
 * boundary in both directions; the firmware passes these frames without
 * EtherType translation in either direction.
 */
#define MT7932_AWDL_ENCAP_LEN		16
#define MT7932_AWDL_DATA_MIN_LEN	(ETH_HLEN + MT7932_AWDL_ENCAP_LEN)

static const u8 mt7932_awdl_snap[10] = { 0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2,
					 0x08, 0x00, 0x03, 0x04 };

/* Unwrap SNAP + AWDL data header into Ethernet II, in place. skb->data is the
 * 802.3 header. Frames that are not AWDL-encapsulated pass unchanged.
 */
static inline void mt7932_awdl_decap(struct sk_buff *skb)
{
	const struct ethhdr *eh = (const struct ethhdr *)skb->data;

	if (skb->len < MT7932_AWDL_DATA_MIN_LEN ||
	    ntohs(eh->h_proto) > ETH_DATA_LEN ||
	    memcmp(skb->data + ETH_HLEN, mt7932_awdl_snap, sizeof(mt7932_awdl_snap)))
		return;

	memmove(skb->data + MT7932_AWDL_ENCAP_LEN, skb->data, 2 * ETH_ALEN);
	skb_pull(skb, MT7932_AWDL_ENCAP_LEN);
}

/* Whether a received translated frame carries the AWDL data envelope. */
static inline bool mt7932_awdl_frame(const struct sk_buff *skb)
{
	const struct ethhdr *eh = (const struct ethhdr *)skb->data;

	return skb->len >= MT7932_AWDL_DATA_MIN_LEN &&
	       ntohs(eh->h_proto) <= ETH_DATA_LEN &&
	       !memcmp(skb->data + ETH_HLEN, mt7932_awdl_snap,
		       sizeof(mt7932_awdl_snap));
}

/* Wrap Ethernet II into 802.3 + SNAP + AWDL data header, in place. Frames
 * already carrying a length field (raw AF_PACKET senders that build the
 * encapsulation themselves) pass unchanged. Caller guarantees headroom.
 */
static inline int mt7932_awdl_encap(struct sk_buff *skb, u16 *seq)
{
	const struct ethhdr *eh = (const struct ethhdr *)skb->data;
	u8 *hdr;

	if (ntohs(eh->h_proto) < ETH_P_802_3_MIN)
		return 0;
	if (skb->len - ETH_HLEN + MT7932_AWDL_ENCAP_LEN > ETH_DATA_LEN)
		return -EMSGSIZE;

	hdr = skb_push(skb, MT7932_AWDL_ENCAP_LEN);
	memmove(hdr, hdr + MT7932_AWDL_ENCAP_LEN, 2 * ETH_ALEN);
	put_unaligned_be16(skb->len - ETH_HLEN, hdr + 2 * ETH_ALEN);
	memcpy(hdr + ETH_HLEN, mt7932_awdl_snap, sizeof(mt7932_awdl_snap));
	put_unaligned_le16((*seq)++, hdr + ETH_HLEN + sizeof(mt7932_awdl_snap));
	hdr[ETH_HLEN + sizeof(mt7932_awdl_snap) + 2] = 0;
	hdr[ETH_HLEN + sizeof(mt7932_awdl_snap) + 3] = 0;
	return 0;
}

#endif
