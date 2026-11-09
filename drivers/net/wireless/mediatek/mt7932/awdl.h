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
 * Session control is runtime CID 0xf7, which the firmware's command
 * registry maps to a handler at 0x918422. That handler is a multiplexer:
 * every 0xf7 body is a header and a list of elements,
 *
 *   { __le16 count, __le16 reserved, { __le32 type, __le32 len, u8 len }[] }
 *
 * and the element type picks the operation. The types and payload lengths
 * below are what the vendor driver sends, byte for byte; the firmware
 * answers each of these with an empty command reply (set, no response bit),
 * so the driver never waits for one:
 *
 *   0x00 bssid          { __le32 1, mac[6] }
 *   0x02 channel list   { __le32 1, u8 pref, u8 count, u8 ch[64], u8 class[64] }
 *   0x03 psf period     { 8 bytes }
 *   0x06 oob auto       { 0xc bytes }
 *   0x07 edge rssi      { 5 bytes }
 *   0x08 enable/disable { __le32 1, __le16 on }
 *   0x09 sync master    { 0x1e bytes }
 *   0x0a election params{ 0x15 bytes }
 *   0x0b election metric{ 8 bytes }
 *   0x0c af tx mode     { 8 bytes }
 *   0x0d min af rate    { 5 bytes }
 *   0x10 action frame   { 0x19 + length bytes }
 *
 * A payload layout is only claimed here once it was read out of the vendor
 * driver; the driver refuses an operation whose payload it has not.
 *
 * Bringing the session up is a fixed order, and none of these commands
 * reports failure, so the order and the BSS state each command leaves
 * behind are the contract:
 *
 *   1. CID 0x12 with BSS 1 inactive and the AWDL operation mode (7);
 *   2. CID 0x11 activates BSS 1 (net type 5, the interface address, the
 *      broadcast-WTBL entry the firmware assigns);
 *   3. CID 0x12 again with BSS 1 active;
 *   4. CID 0xf7 with the sync-frame payload elements, then type 8 with the
 *      on flag, then type 0 with the BSSID.
 *
 * EID 0x11 with BSS index 1 is the only thing that says the firmware
 * accepted the activation: it carries the absence byte, the transmit quota
 * and the WTBL entry the firmware assigned, and it is what the presence
 * path below waits for.
 */
#define MT7932_AWDL_BSS 1

/* Peer station records the driver may set up for the firmware's AWDL BSS.
 * Apple's allocator takes station IDs from 2 up for non-AIS station types
 * (`_cnmStaRecAllocSeq` starts at 2 unless the type is 0x41, the AIS link),
 * and a separate WTBL index, which the host chooses when it builds the
 * connect body. The infrastructure link owns IDs 0/1 and WTBL 2..5 here, so
 * AWDL peers start above those.
 */
#define MT_AWDL_PEERS 4
#define MT7932_AWDL_FIRST_STATION 2
#define MT7932_AWDL_LAST_STATION 14
/* `_secPrivacySeekForEntrySeq` scans the AIS side downward from 7 and the
 * non-AIS (peer) side upward from 8, bounded by the table capacity. The
 * infrastructure association's own entries come out of the firmware's
 * connect reply, so a peer record uses 8..13 and the BSS entry 1..7.
 */
#define MT7932_AWDL_FIRST_WTBL 8
#define MT7932_AWDL_LAST_WTBL 13
#define MT7932_AWDL_BSS_WTBL_MAX 7
#define MT7932_AWDL_STATION_TYPE 0x10
#define MT7932_AWDL_STATION_START 2
#define MT7932_AWDL_PEER_BODY_LEN 200

/* One peer station update, CID 0x13. The layout below was read from
 * `_cnmStaSendUpdateCmd` and confirmed by executing the DEXT's own x86_64
 * code for an AWDL peer allocation in an emulator: the resulting 200-byte
 * body carried the station ID, type 0x10, the peer MAC, BSS 1, the assigned
 * WTBL index, and the literals reproduced here. Bytes this function leaves
 * zero are the peer-capability fields Apple fills from the peer's sync
 * frame; no value for them has been established for this driver, so they
 * are not invented. Caller must not assume the firmware accepted the record.
 */
static inline void mt7932_awdl_peer_body(u8 body[MT7932_AWDL_PEER_BODY_LEN],
					 u8 station, const u8 mac[ETH_ALEN],
					 u8 bss, u8 wtbl)
{
	memset(body, 0, MT7932_AWDL_PEER_BODY_LEN);
	body[0x00] = station;
	body[0x01] = MT7932_AWDL_STATION_TYPE;
	memcpy(body + 0x02, mac, ETH_ALEN);
	body[0x0c] = bss;
	/* Apple's AWDL peer setup sets these host fields before the update:
	 * station+0x32c = 1, state = 2 (start), station+0x54 = 1,
	 * station+0x5a = 3, and the local aggregation policy it derives is 3.
	 */
	body[0x12] = 1;
	body[0x14] = MT7932_AWDL_STATION_START;
	body[0x17] = 1;
	put_unaligned_le32(1, body + 0x24);
	body[0x30] = 3;
	body[0x36] = wtbl;
	body[0x37] = 0xff;
	body[0x44] = 3;
	body[0x7d] = 1;
}

/* Runtime CID 0xf7 element types (see the table above). */
#define MT7932_AWDL_TLV_BSSID 0x00
#define MT7932_AWDL_TLV_CHANNELS 0x02
#define MT7932_AWDL_TLV_ENABLE 0x08

/* CID 0xf7 type 2: the channel sequence the availability windows hop over,
 * { __le32 1, u8 master preference, u8 count, u8 channel[64],
 *   u8 operating class[64] }. The classes are the driver's operating-class
 * table read out of the vendor driver's binary: 81 is 2 GHz at 20 MHz, 128
 * is 5 GHz at 80 MHz, and a channel's class is named by its bandwidth's
 * center channel (36-48 at 42, 149-161 at 155, and so on).
 */
#define MT7932_AWDL_CHANNELS_MAX 64
#define MT7932_AWDL_CHANNEL_BODY (4 + 2 + 2 * MT7932_AWDL_CHANNELS_MAX)
#define MT7932_AWDL_CLASS_2G 81
#define MT7932_AWDL_CLASS_5G 128

/* An 0xf7 body is a four-byte header plus type and length per element. */
#define MT7932_AWDL_TLV_HDR 8
#define MT7932_AWDL_TLV_OVERHEAD (4 + MT7932_AWDL_TLV_HDR)

/* The operation mode the firmware calls AWDL, in CID 0x12's third byte. */
#define MT7932_AWDL_OPMODE 7

/* CID 0x12's body: four bytes of BSS state, then the BSS description the
 * firmware keeps in the same order the host does.
 */
#define MT7932_AWDL_BSSINFO_LEN 0x74

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

/* A guessed AWDL entry must never name an infrastructure-owned WTBL slot.
 * Station-record IDs are a separate namespace and are not in this list.
 * Caller supplies a stable snapshot of the infrastructure WTBL resources.
 */
static inline bool mt7932_awdl_wtbl_conflicts(u16 wtbl, const u8 *infra_wtbl,
					    size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (wtbl == infra_wtbl[i])
			return true;
	return false;
}

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

/* Whether a received payload carries the AWDL data envelope. The skb form
 * below is what the receive path tests once the frame has been copied.
 */
static inline bool mt7932_awdl_payload(const void *data, size_t length)
{
	const u8 *p = data;

	return length >= MT7932_AWDL_DATA_MIN_LEN &&
	       get_unaligned_be16(p + 2 * ETH_ALEN) <= ETH_DATA_LEN &&
	       !memcmp(p + ETH_HLEN, mt7932_awdl_snap, sizeof(mt7932_awdl_snap));
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
