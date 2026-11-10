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
	/* struct mt7932_vndr_raw_cmd plus its body: one firmware command in
	 * either descriptor layout, answered with the firmware reply. This is
	 * how the AWDL bring-up probes reach command ids the rest of the
	 * driver does not use; it refuses nothing but the descriptor itself.
	 */
	MT7932_VNDR_CMDS_RAW,
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
 *				  one per element of the firmware's AWDL
 *				  session multiplexer (runtime CID 0xf7,
 *				  see awdl.h)
 *
 * The operations past @MT7932_VNDR_AWDL_OP_BSSID have no payload this
 * driver has read out of the vendor firmware's counterpart; they answer
 * -EOPNOTSUPP rather than send a body nobody has confirmed.
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
	MT7932_VNDR_AWDL_OP_BSSID,
	MT7932_VNDR_AWDL_OP_CHANNELS,
	/* Diagnostic: one MCU register (CID 0xc0) read or write. Body:
	 * {__le32 address, __le32 value, u8 write}. A read returns the
	 * firmware's eight-byte reply as {__le32 address, __le32 value}.
	 */
	MT7932_VNDR_AWDL_OP_MCR,
	MT7932_VNDR_AWDL_OP_LAST
};

/**
 * struct mt7932_vndr_awdl_cmd - one AWDL session command
 *
 * @op: one of enum mt7932_vndr_awdl_cmd_op (little-endian u32)
 * @body: the operation-specific payload, after the element header the
 *	  driver builds; enable, disable and channels carry nothing (the
 *	  channel list the driver builds from the wiphy's permitted
 *	  channels), the BSSID carries its six address bytes, and the
 *	  operations that are not implemented are refused whatever they
 *	  carry.
 */
struct mt7932_vndr_awdl_cmd {
	__le32 op;
	__u8 body[];
};

/**
 * struct mt7932_vndr_raw_cmd - one firmware command, for the bring-up probes
 *
 * @cid: command id (original layout: low byte only; unified: 16-bit id,
 *	 MCU command-class bits included)
 * @uni: 0 for the original descriptor, 1 for the unified one
 * @ext: extension command id, original descriptor only
 * @set: 1 for SET, 0 for QUERY (the option byte's SET bit)
 * @wait: 1 to wait for the firmware reply and return its body
 * @resp_eid: event id to match the reply against (0 to derive it from the
 *	  command id, as the rest of the driver does; the boot ROM's register
 *	  read answers with the access-register event, which has no
 *	  derivation)
 * @runtime: 1 to request the reply with the runtime command option (the
 *	   firmware's own runtime command table answers those, if it has one
 *	   for the id); 0 sends it like every driver command, which the
 *	   firmware answers with the command-reply event
 * @length: body length
 * @body: the command body
 */
struct mt7932_vndr_raw_cmd {
	__le16 cid;
	__u8 uni;
	__u8 ext;
	__u8 set;
	__u8 wait;
	__u8 resp_eid;
	__u8 runtime;
	__le16 length;
	__u8 body[];
} __packed;

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

extern const struct wiphy_vendor_command mt7932_vendor_cmds[3];

#endif
