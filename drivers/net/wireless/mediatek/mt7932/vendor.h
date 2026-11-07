/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MT7932_VENDOR_H
#define MT7932_VENDOR_H

#include <linux/types.h>

/* MediaTek's OUI. */
#define MEDIATEK_OUI 0x000ce7

enum mt7932_vendor_cmds {
	MT7932_VNDR_CMDS_UNSPEC,
	/* struct mt7932_vndr_awdl_op (little-endian u32): create or destroy
	 * the AWDL interface. Asynchronous, like the AWDL interface_create
	 * on the Broadcom firmware: the netdev appears when the firmware
	 * reports the interface's BSS present.
	 */
	MT7932_VNDR_CMDS_AWDL,
	/* struct mt7932_vndr_awdl_cmd plus its operation-specific body:
	 * one runtime command of the firmware's AWDL session family.
	 */
	MT7932_VNDR_CMDS_AWDL_CMD,
	MT7932_VNDR_CMDS_LAST
};

/**
 * enum mt7932_vndr_awdl_op - operations for MT7932_VNDR_CMDS_AWDL
 *
 * @MT7932_VNDR_AWDL_OP_CREATE: create the AWDL interface
 * @MT7932_VNDR_AWDL_OP_DESTROY: remove the AWDL interface
 */
enum mt7932_vndr_awdl_op {
	MT7932_VNDR_AWDL_OP_CREATE,
	MT7932_VNDR_AWDL_OP_DESTROY,
};

/**
 * enum mt7932_vndr_awdl_cmd_op - operations for MT7932_VNDR_CMDS_AWDL_CMD,
 *				  mapping one-to-one onto the firmware's
 *				  CID 0x7e body selectors (see awdl.h)
 */
enum mt7932_vndr_awdl_cmd_op {
	MT7932_VNDR_AWDL_OP_ENABLE,
	MT7932_VNDR_AWDL_OP_DISABLE,
	MT7932_VNDR_AWDL_OP_SERVICE,
	MT7932_VNDR_AWDL_OP_TEMPLATE,
	MT7932_VNDR_AWDL_OP_ACTION_FRAME,
	MT7932_VNDR_AWDL_OP_PEER_ADD,
	MT7932_VNDR_AWDL_OP_PEER_REMOVE,
	MT7932_VNDR_AWDL_OP_STATE,
	MT7932_VNDR_AWDL_OP_ELECTION,
	MT7932_VNDR_AWDL_OP_LAST
};

/**
 * struct mt7932_vndr_awdl_cmd - one AWDL session command
 *
 * @op: one of enum mt7932_vndr_awdl_cmd_op (little-endian u32)
 * @body: the operation-specific CID 0x7e body, after its selector byte;
 *	  enable carries {channel, channel, density}, disable nothing,
 *	  service/template/action carry a little-endian u16 length then
 *	  that many bytes, peers carry the six MAC bytes, state carries one
 *	  selector byte and election a little-endian u32 metric and a
 *	  signed 8-bit RSSI threshold.
 */
struct mt7932_vndr_awdl_cmd {
	__le32 op;
	__u8 body[];
};

/**
 * enum mt7932_nlattrs - nl80211 message attributes
 *
 * @MT7932_NLATTR_LEN: reply body length
 * @MT7932_NLATTR_DATA: reply body
 */
enum mt7932_nlattrs {
	MT7932_NLATTR_UNSPEC,

	MT7932_NLATTR_LEN,
	MT7932_NLATTR_DATA,

	__MT7932_NLATTR_AFTER_LAST,
	MT7932_NLATTR_MAX = __MT7932_NLATTR_AFTER_LAST - 1
};

extern const struct wiphy_vendor_command mt7932_vendor_cmds[2];

#endif
