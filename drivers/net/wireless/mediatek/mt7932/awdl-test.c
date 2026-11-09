// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <kunit/test-bug.h>
#include <linux/skbuff.h>

#include "mt7932.h"
#include "awdl.h"

/* One plain Ethernet II frame: every test starts from these bytes. */
static const u8 mt_awdl_test_eth[60] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, /* dest */
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, /* source */
	0x08, 0x00,				  /* Ethernet II: IPv4 */
	0x45, 0x00, 0x00, 0x2e,
};

static struct sk_buff *mt_awdl_test_skb(struct kunit *test, const u8 *eth,
					size_t len, size_t eth_bytes)
{
	struct sk_buff *skb = alloc_skb(eth_bytes + MT7932_AWDL_ENCAP_LEN, GFP_KERNEL);

	if (!skb)
		kunit_fail_current_test("no memory for a test frame");
	else {
		skb_reserve(skb, MT7932_AWDL_ENCAP_LEN);
		skb_put_data(skb, eth, len);
	}
	return skb;
}

static void mt_awdl_encap_frame_test(struct kunit *test)
{
	struct sk_buff *skb = mt_awdl_test_skb(test, mt_awdl_test_eth,
					       sizeof(mt_awdl_test_eth),
					       sizeof(mt_awdl_test_eth));
	u16 seq = 0;
	int ret;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, skb);
	ret = mt7932_awdl_encap(skb, &seq);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* The envelope is the whole point: 16 bytes of it, then the frame. */
	KUNIT_EXPECT_EQ(test, skb->len, (unsigned int)(sizeof(mt_awdl_test_eth) + MT7932_AWDL_ENCAP_LEN));
	KUNIT_EXPECT_MEMEQ(test, skb->data, mt_awdl_test_eth, 2 * ETH_ALEN);
	KUNIT_EXPECT_EQ(test, get_unaligned_be16(skb->data + 2 * ETH_ALEN),
			(u16)(sizeof(mt_awdl_test_eth) - ETH_HLEN + MT7932_AWDL_ENCAP_LEN));
	KUNIT_EXPECT_MEMEQ(test, skb->data + ETH_HLEN, mt7932_awdl_snap,
			   sizeof(mt7932_awdl_snap));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(skb->data + ETH_HLEN +
						 sizeof(mt7932_awdl_snap)), (u16)0);
	KUNIT_EXPECT_EQ(test, skb->data[ETH_HLEN + sizeof(mt7932_awdl_snap) + 2], (u8)0);
	KUNIT_EXPECT_EQ(test, skb->data[ETH_HLEN + sizeof(mt7932_awdl_snap) + 3], (u8)0);
	KUNIT_EXPECT_EQ(test, get_unaligned_be16(skb->data + 28), (u16)0x0800);
	KUNIT_EXPECT_MEMEQ(test, skb->data + 30, mt_awdl_test_eth + 14,
			   sizeof(mt_awdl_test_eth) - 14);
	KUNIT_EXPECT_TRUE(test, mt7932_awdl_frame(skb));
	KUNIT_EXPECT_TRUE(test, mt7932_awdl_payload(skb->data, skb->len));
	kfree_skb(skb);
}

static void mt_awdl_encap_sequence_test(struct kunit *test)
{
	struct sk_buff *first = mt_awdl_test_skb(test, mt_awdl_test_eth,
						 sizeof(mt_awdl_test_eth),
						 sizeof(mt_awdl_test_eth));
	struct sk_buff *second = mt_awdl_test_skb(test, mt_awdl_test_eth,
						  sizeof(mt_awdl_test_eth),
						  sizeof(mt_awdl_test_eth));
	u16 seq = 0xffff;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, first);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, second);
	KUNIT_ASSERT_EQ(test, mt7932_awdl_encap(first, &seq), 0);
	KUNIT_ASSERT_EQ(test, mt7932_awdl_encap(second, &seq), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(first->data + ETH_HLEN +
						 sizeof(mt7932_awdl_snap)), (u16)0xffff);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(second->data + ETH_HLEN +
						 sizeof(mt7932_awdl_snap)), (u16)0);
	KUNIT_EXPECT_EQ(test, (int)seq, 1);
	kfree_skb(first);
	kfree_skb(second);
}

static void mt_awdl_encap_8023_test(struct kunit *test)
{
	static const u8 frame[60] = {
		0x33, 0x33, 0x00, 0x00, 0x00, 0x01,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x2e, /* 802.3 length: sender built the envelope */
	};
	struct sk_buff *skb = mt_awdl_test_skb(test, frame, sizeof(frame),
					       sizeof(frame));
	u16 seq = 7;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, skb);
	KUNIT_ASSERT_EQ(test, mt7932_awdl_encap(skb, &seq), 0);

	/* A frame that already carries a length field is sent as built. */
	KUNIT_EXPECT_EQ(test, skb->len, (unsigned int)sizeof(frame));
	KUNIT_EXPECT_EQ(test, (int)seq, 7);
	kfree_skb(skb);
}

static void mt_awdl_encap_oversize_test(struct kunit *test)
{
	/* Payload field 1485 bytes: plus the 16-byte envelope that is 1501,
	 * one over the largest 802.3 payload field.
	 */
	size_t length = ETH_HLEN + ETH_DATA_LEN - MT7932_AWDL_ENCAP_LEN + 1;
	struct sk_buff *skb;
	u8 *eth;
	u16 seq = 0;

	eth = kunit_kmalloc(test, length, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, eth);
	memset(eth, 0, length);
	eth[12] = 0x08;
	eth[13] = 0x00;
	skb = mt_awdl_test_skb(test, eth, length, length);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, skb);
	KUNIT_EXPECT_EQ(test, mt7932_awdl_encap(skb, &seq), -EMSGSIZE);
	KUNIT_EXPECT_EQ(test, (int)seq, 0);
	kfree_skb(skb);
}

static void mt_awdl_decap_frame_test(struct kunit *test)
{
	struct sk_buff *skb = mt_awdl_test_skb(test, mt_awdl_test_eth,
					       sizeof(mt_awdl_test_eth),
					       sizeof(mt_awdl_test_eth));
	u16 seq = 5;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, skb);
	KUNIT_ASSERT_EQ(test, mt7932_awdl_encap(skb, &seq), 0);
	mt7932_awdl_decap(skb);

	/* The envelope disappears; the frame is the original again. */
	KUNIT_EXPECT_EQ(test, skb->len, (unsigned int)sizeof(mt_awdl_test_eth));
	KUNIT_EXPECT_MEMEQ(test, skb->data, mt_awdl_test_eth, sizeof(mt_awdl_test_eth));
	kfree_skb(skb);
}

static void mt_awdl_decap_pass_test(struct kunit *test)
{
	struct sk_buff *skb = mt_awdl_test_skb(test, mt_awdl_test_eth,
					       sizeof(mt_awdl_test_eth),
					       sizeof(mt_awdl_test_eth));
	size_t before = sizeof(mt_awdl_test_eth);

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, skb);
	/* A plain Ethernet II frame with the real EtherType passes
	 * unchanged, as on brcmfmac.
	 */
	mt7932_awdl_decap(skb);
	KUNIT_EXPECT_EQ(test, skb->len, (unsigned int)before);
	KUNIT_EXPECT_FALSE(test, mt7932_awdl_frame(skb));
	kfree_skb(skb);
}

static void mt_awdl_decap_short_test(struct kunit *test)
{
	static const u8 short_frame[30] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x10, /* length: 16 bytes follow the 802.3 header */
	};
	struct sk_buff *skb = mt_awdl_test_skb(test, short_frame,
					       sizeof(short_frame),
					       sizeof(short_frame));

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, skb);
	/* Too short to carry the envelope: passed up, never pulled. */
	mt7932_awdl_decap(skb);
	KUNIT_EXPECT_EQ(test, skb->len, (unsigned int)sizeof(short_frame));
	KUNIT_EXPECT_FALSE(test, mt7932_awdl_frame(skb));
	kfree_skb(skb);
}

static void mt_awdl_payload_length_test(struct kunit *test)
{
	u8 frame[ETH_HLEN + ETH_DATA_LEN] = {};

	memcpy(frame + ETH_HLEN, mt7932_awdl_snap, sizeof(mt7932_awdl_snap));
	/* Both values expose an accidental second byte swap: 62 becomes
	 * 15872, while the non-length value 1536 becomes 6.
	 */
	put_unaligned_be16(62, frame + 2 * ETH_ALEN);
	KUNIT_EXPECT_TRUE(test, mt7932_awdl_payload(frame, ETH_HLEN + 62));
	put_unaligned_be16(ETH_DATA_LEN, frame + 2 * ETH_ALEN);
	KUNIT_EXPECT_TRUE(test, mt7932_awdl_payload(frame, sizeof(frame)));
	put_unaligned_be16(ETH_P_802_3_MIN, frame + 2 * ETH_ALEN);
	KUNIT_EXPECT_FALSE(test, mt7932_awdl_payload(frame, sizeof(frame)));
	KUNIT_EXPECT_FALSE(test, mt7932_awdl_payload(frame, ETH_HLEN - 1));
}

static void mt_awdl_wtbl_conflict_test(struct kunit *test)
{
	static const u8 infra_wtbl[] = {2, 3, 4, 5};
	u16 wtbl;

	for (wtbl = 2; wtbl <= 5; wtbl++)
		KUNIT_EXPECT_TRUE(test,
			mt7932_awdl_wtbl_conflicts(wtbl, infra_wtbl,
						 ARRAY_SIZE(infra_wtbl)));
	/* Station-record IDs 0/1 are not WTBL ownership claims. */
	KUNIT_EXPECT_FALSE(test, mt7932_awdl_wtbl_conflicts(0, infra_wtbl, 4));
	KUNIT_EXPECT_FALSE(test, mt7932_awdl_wtbl_conflicts(1, infra_wtbl, 4));
	KUNIT_EXPECT_FALSE(test, mt7932_awdl_wtbl_conflicts(6, infra_wtbl, 4));
	/* Compare the full WTBL index, never just its low byte. */
	KUNIT_EXPECT_FALSE(test, mt7932_awdl_wtbl_conflicts(258, infra_wtbl, 4));
	KUNIT_EXPECT_FALSE(test, mt7932_awdl_wtbl_conflicts(2, NULL, 0));
}

static void mt_awdl_peer_body_test(struct kunit *test)
{
	static const u8 mac[ETH_ALEN] = { 0xaa, 0xbe, 0xcb, 0x9c, 0xe5, 0x1f };
	u8 body[MT7932_AWDL_PEER_BODY_LEN];

	mt7932_awdl_peer_body(body, 2, mac, MT7932_AWDL_BSS, 7);

	/* Offsets confirmed by running the vendor driver's own allocator in an
	 * emulator; see AWDL-PEER-ABI.md. Everything else must stay zero.
	 */
	KUNIT_EXPECT_EQ(test, body[0x00], (u8)2);
	KUNIT_EXPECT_EQ(test, body[0x01], (u8)MT7932_AWDL_STATION_TYPE);
	KUNIT_EXPECT_MEMEQ(test, body + 0x02, mac, ETH_ALEN);
	KUNIT_EXPECT_EQ(test, body[0x0c], (u8)MT7932_AWDL_BSS);
	KUNIT_EXPECT_EQ(test, body[0x12], (u8)1);
	KUNIT_EXPECT_EQ(test, body[0x14], (u8)MT7932_AWDL_STATION_START);
	KUNIT_EXPECT_EQ(test, body[0x17], (u8)1);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(body + 0x24), (u32)1);
	KUNIT_EXPECT_EQ(test, body[0x30], (u8)3);
	KUNIT_EXPECT_EQ(test, body[0x36], (u8)7);
	KUNIT_EXPECT_EQ(test, body[0x37], (u8)0xff);
	KUNIT_EXPECT_EQ(test, body[0x44], (u8)3);
	KUNIT_EXPECT_EQ(test, body[0x7d], (u8)1);
	for (unsigned int i = 0; i < sizeof(body); i++) {
		bool known = i < 8 || i == 0x0c || i == 0x12 || i == 0x14 ||
			i == 0x17 || (i >= 0x24 && i < 0x28) || i == 0x30 ||
			i == 0x36 || i == 0x37 || i == 0x44 || i == 0x7d;
		if (!known)
			KUNIT_EXPECT_EQ(test, body[i], (u8)0);
	}
	/* A different station/WTBL must not leak the previous values. */
	mt7932_awdl_peer_body(body, 9, mac, MT7932_AWDL_BSS, 13);
	KUNIT_EXPECT_EQ(test, body[0x00], (u8)9);
	KUNIT_EXPECT_EQ(test, body[0x36], (u8)13);
}

static struct kunit_case mt_awdl_test_cases[] = {
	KUNIT_CASE(mt_awdl_peer_body_test),
	KUNIT_CASE(mt_awdl_wtbl_conflict_test),
	KUNIT_CASE(mt_awdl_payload_length_test),
	KUNIT_CASE(mt_awdl_encap_frame_test),
	KUNIT_CASE(mt_awdl_encap_sequence_test),
	KUNIT_CASE(mt_awdl_encap_8023_test),
	KUNIT_CASE(mt_awdl_encap_oversize_test),
	KUNIT_CASE(mt_awdl_decap_frame_test),
	KUNIT_CASE(mt_awdl_decap_pass_test),
	KUNIT_CASE(mt_awdl_decap_short_test),
	{}
};

static struct kunit_suite mt_awdl_test_suite = {
	.name = "mt7932-awdl",
	.test_cases = mt_awdl_test_cases,
};

kunit_test_suite(mt_awdl_test_suite);
