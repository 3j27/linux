// SPDX-License-Identifier: GPL-2.0-only
/*
 * AWDL (Apple Wireless Direct Link) for the MT7932 on the MacBook Neo.
 *
 * The IZUBA firmware implements AWDL itself (awdl_sync): discovery, the CWME
 * availability schedule, election and the peer table. What the host owns is
 * the awdl0 interface, its data path and the userspace control channel.
 * There is no nl80211 interface type for AWDL, so this interface cannot go
 * through add_virtual_intf(); the driver creates it from a vendor command,
 * the way brcmfmac exposes the same firmware feature.
 *
 * The AWDL session is the firmware's second BSS (CID 0x11 with BSS index 1;
 * see awdl.h). Creating it activates that BSS; the firmware's presence event
 * is what lets the host register the netdev, so creation is asynchronous and
 * callers must wait for awdl0 rather than assume it exists. Destroying it
 * deactivates the BSS and tears the netdev down from the presence-absent
 * event.
 *
 * nl80211 calls vendor commands holding the wiphy mutex and NOT the RTNL, so
 * no vendor handler may register or unregister a netdev: doing so re-enters
 * the netdev notifier chain, which asserts the RTNL, and deadlocks the whole
 * netdev layer. Registration and teardown run from plain work items holding
 * no locks; the event path only updates state and queues them.
 *
 * Lock ownership (see mt7932.h): the data gates (awdl_absent, awdl_quota,
 * awdl_wtbl, awdl_present, awdl_registered) belong to data_lock, like the
 * station BSS's absence and quota; the netdev and wireless_dev pointers and
 * the lifecycle flags (awdl_pending, awdl_attaching, awdl_destroying,
 * awdl_active) belong to response_lock; awdl_enabled belongs to command_mutex
 * and is read with READ_ONCE() from the data path. Contexts that hold none
 * of the owning locks, like the RX demultiplexer under response_lock, read
 * the data gates with READ_ONCE(); a stale reading there costs at most one
 * frame or one wakeup pass, never a lost packet.
 */
#include <linux/etherdevice.h>
#include <linux/unaligned.h>
#include <linux/if_ether.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <net/cfg80211.h>
#include <net/netlink.h>

#include "mt7932.h"
#include "awdl.h"
#include "vendor.h"

/* AWDL interface creation through the vendor command is on by default.
 * awdl=0 at module load turns it off: neither vendor command is registered,
 * and nothing in the driver creates or drives an AWDL interface.
 */
static int mt7932_awdl_enable = 1;
module_param_named(awdl, mt7932_awdl_enable, int, 0444);
MODULE_PARM_DESC(awdl, "AWDL interface creation through the vendor command (default 1, 0 turns it off)");

/* Opt-in host buffer-release logging, not proof of over-air delivery.
 */
int mt7932_awdl_trace;
module_param_named(awdl_trace, mt7932_awdl_trace, int, 0644);
MODULE_PARM_DESC(awdl_trace, "Log AWDL TX buffer releases (delivery unverified)");

/* WTBL entry override for the AWDL BSS. Zero, the default, makes the driver
 * choose an entry that the infrastructure association's own reply did not
 * assign and that no peer record uses; a positive value pins it for
 * diagnostics. The transmit path still refuses an entry it can observe the
 * association owning. Peer unicast uses the entry its peer-add allocated.
 */
int mt7932_awdl_wtbl;
module_param_named(awdl_wtbl, mt7932_awdl_wtbl, int, 0644);
MODULE_PARM_DESC(awdl_wtbl, "WTBL entry of the AWDL BSS (0: choose a free one when the BSS is created)");

/* The own-MAC (OM) index the transmit descriptor names for AWDL frames. The
 * station BSS owns index 0; the AWDL BSS is a second BSS with its own address,
 * and the firmware attributes a frame, its keys and its address to a BSS by
 * this index. Naming the station's index transmits AWDL frames under the
 * station identity, which no AWDL peer accepts, and leaves frames addressed
 * to the AWDL interface unclaimed on receive. The firmware assigns the index
 * when the second BSS is activated; this is the value it uses for it.
 */
/* Diagnostic-only: force the WTBL entry named in every AWDL transmit
 * descriptor, including entries the conflict guard would otherwise refuse.
 * Used to tell "this BSS's TX binding is broken" from "TX0 never drains AWDL
 * frames at all" by transmitting with an entry the firmware demonstrably
 * services. Never for normal operation; 0 disables it.
 */
/* Diagnostic-only: override the queue/TID value written into AWDL transmit
 * descriptors. The vendor's `_awdlHardStartXmit` selects a queue explicitly
 * (`_wlanSelectMultiPeerQueue`: station+0x612[user_pri] for a peer,
 * bss+0x65f for BSS traffic) and stores it in the packet; this driver
 * derives the field from cfg80211_classify8021d() instead. -1 keeps the
 * classified value.
 */
int mt7932_awdl_force_ac = -1;
module_param_named(awdl_force_ac, mt7932_awdl_force_ac, int, 0644);
MODULE_PARM_DESC(awdl_force_ac, "Diagnostic: force this queue/TID value in AWDL TX descriptors (-1: classify)");

int mt7932_awdl_probe_wtbl;
module_param_named(awdl_probe_wtbl, mt7932_awdl_probe_wtbl, int, 0644);
MODULE_PARM_DESC(awdl_probe_wtbl, "Diagnostic: force this WTBL entry in AWDL TX descriptors (0: off)");

int mt7932_awdl_omac = 1;
module_param_named(awdl_omac, mt7932_awdl_omac, int, 0644);
MODULE_PARM_DESC(awdl_omac, "Own-MAC (OM) index of the AWDL BSS (station is 0)");

#define MT7932_AWDL_IFNAME "awdl0"
#define MT7932_AWDL_CREATE_TIMEOUT (5 * HZ)
#define MT7932_AWDL_DESTROY_TIMEOUT (10 * HZ)

/* The two BSS commands, defined with the session controls below and used by
 * the interface paths that come first.
 */
static int mt_awdl_bss_info(struct mt7932 *m, bool active, u8 wtbl);
static int mt_awdl_bss_activate(struct mt7932 *m, bool active, const u8 *mac,
				u8 wtbl);
static void mt_awdl_peer_reset(struct mt7932 *m);
static int mt_awdl_bss_queue(struct mt7932 *m);

static bool mt_awdl_rf_ready(const struct mt7932 *m)
{
	return READ_ONCE(m->rf_ready) && !READ_ONCE(m->stopping) &&
	       !READ_ONCE(m->link_failed) && !READ_ONCE(m->cal_state.error);
}

/* command_mutex held. The WTBL entry the AWDL BSS will name. The
 * infrastructure association receives its own entries from the firmware's
 * reply and the driver logs them; a module parameter overrides this for
 * diagnostics. Zero here means no entry is available, and the caller must
 * fail the BSS activation rather than publish a guessed index.
 */
static u16 mt_awdl_wtbl_select(struct mt7932 *m)
{
	unsigned long flags;
	u16 candidate;

	if (mt7932_awdl_wtbl > 0)
		return min_t(u16, mt7932_awdl_wtbl, 0x3ff);
	/* Entry 0 is this driver's "unknown" sentinel. The association's
	 * entries come out of the firmware's reply, so scan the AIS-side range
	 * downward the way the vendor driver does.
	 */
	for (candidate = MT7932_AWDL_BSS_WTBL_MAX; candidate >= 1; candidate--) {
		bool used = false;
		unsigned int i;

		spin_lock_irqsave(&m->response_lock, flags);
		if (m->peer_valid)
			used = mt7932_awdl_wtbl_conflicts(candidate,
						m->peer_ids.wtbl,
						ARRAY_SIZE(m->peer_ids.wtbl));
		used |= m->peer_valid && candidate == m->peer_wtbl;
		for (i = 0; i < MT_AWDL_PEERS; i++)
			used |= m->awdl_peer_wtbl[i] == candidate;
		spin_unlock_irqrestore(&m->response_lock, flags);
		if (!used)
			return candidate;
	}
	return 0;
}

/* data_lock held: AWDL TX admission mirrors the station BSS quota, with the
 * AWDL BSS's own presence state.
 */
bool mt_awdl_tx_allowed(const struct mt7932 *m)
{
	return !m->awdl_absent || m->awdl_quota;
}

/* Presence of the firmware's AWDL BSS (EID 0x11, BSS index 1). Called from
 * the event consumer with response_lock held; never waits. The first
 * present event lets the attach work register the netdev; an absent event
 * during a destroy queues the teardown work, which unregisters it where no
 * locks are held.
 */
void mt_awdl_presence(struct mt7932 *m, const struct mt7932_event *event)
{
	const u8 *body = event->packet + 36;
	bool attach, teardown;

	if (event->length < 41 || body[0] != MT7932_AWDL_BSS || !m->awdl_active)
		return;
	/* response_lock is held by the caller; data_lock nests inside it,
	 * as in mt_data_receive().
	 */
	spin_lock(&m->data_lock);
	m->awdl_absent = !!body[1];
	m->awdl_quota = body[2];
	m->awdl_wtbl = get_unaligned_le16(body + 3);
	m->awdl_present = !m->awdl_absent;
	if (m->awdl_registered) {
		if (m->awdl_present)
			netif_carrier_on(m->awdl_netdev);
		else
			netif_carrier_off(m->awdl_netdev);
		if (!mt_awdl_tx_allowed(m)) {
			netif_stop_queue(m->awdl_netdev);
			mt_data_kick_locked(m);
		} else {
			mt_data_clean_locked(m);
		}
	}
	attach = !m->awdl_registered && m->awdl_present && m->awdl_netdev;
	teardown = m->awdl_registered && m->awdl_absent;
	spin_unlock(&m->data_lock);
	dev_dbg_ratelimited(&m->pdev->dev, "AWDL_PRESENCE: absent=%u quota=%u wtbl=%u\n",
			    !!body[1], body[2], get_unaligned_le16(body + 3));
	if (attach && READ_ONCE(m->awdl_pending) && !READ_ONCE(m->awdl_attaching) &&
	    !READ_ONCE(m->awdl_destroying))
		queue_work(system_long_wq, &m->awdl_attach_work);
	if (teardown && READ_ONCE(m->awdl_destroying))
		queue_work(system_long_wq, &m->awdl_teardown_work);
}

/* Register the netdev the firmware just reported present. Plain work item:
 * register_netdev() takes the RTNL, which no vendor context holds here and
 * which the netdev notifier chain would assert against the wiphy mutex.
 */
void mt_awdl_attach_work(struct work_struct *work)
{
	struct mt7932 *m = container_of(work, struct mt7932, awdl_attach_work);
	struct net_device *netdev;
	struct wireless_dev *wdev;
	unsigned long flags;
	bool present;
	int ret;

	spin_lock_irqsave(&m->response_lock, flags);
	if (!READ_ONCE(m->awdl_pending) || READ_ONCE(m->awdl_attaching) ||
	    READ_ONCE(m->awdl_destroying) || READ_ONCE(m->awdl_registered) ||
	    !m->awdl_netdev) {
		spin_unlock_irqrestore(&m->response_lock, flags);
		return;
	}
	WRITE_ONCE(m->awdl_attaching, true);
	netdev = m->awdl_netdev;
	wdev = m->awdl_wdev;
	present = READ_ONCE(m->awdl_present);
	spin_unlock_irqrestore(&m->response_lock, flags);

	strscpy(netdev->name, m->awdl_ifname, sizeof(netdev->name));
	ret = register_netdev(netdev);

	spin_lock_irqsave(&m->response_lock, flags);
	WRITE_ONCE(m->awdl_attaching, false);
	WRITE_ONCE(m->awdl_pending, false);
	if (ret) {
		/* Nothing else publishes an unregistered netdev: the RX path
		 * only demultiplexes once awdl_registered, so this free is
		 * exclusive with every other AWDL context.
		 */
		m->awdl_netdev = NULL;
		m->awdl_wdev = NULL;
	}
	spin_unlock_irqrestore(&m->response_lock, flags);
	if (ret) {
		dev_err(&m->pdev->dev, "AWDL_REGISTER_FAILED: %d\n", ret);
		free_netdev(netdev);
		kfree(wdev);
		return;
	}
	spin_lock_irqsave(&m->data_lock, flags);
	m->awdl_registered = true;
	if (present)
		netif_carrier_on(netdev);
	spin_unlock_irqrestore(&m->data_lock, flags);
	dev_info(&m->pdev->dev, "AWDL_INTERFACE_READY: %s, session awaits the vendor command\n",
		 netdev->name);
}

void mt_awdl_teardown_work(struct work_struct *work)
{
	struct mt7932 *m = container_of(work, struct mt7932, awdl_teardown_work);
	struct net_device *netdev;
	struct wireless_dev *wdev;
	unsigned long flags;

	spin_lock_irqsave(&m->response_lock, flags);
	if (!READ_ONCE(m->awdl_destroying) || READ_ONCE(m->awdl_attaching) ||
	    !READ_ONCE(m->awdl_registered) || !m->awdl_netdev) {
		spin_unlock_irqrestore(&m->response_lock, flags);
		return;
	}
	netdev = m->awdl_netdev;
	wdev = m->awdl_wdev;
	m->awdl_netdev = NULL;
	m->awdl_wdev = NULL;
	WRITE_ONCE(m->awdl_destroying, false);
	WRITE_ONCE(m->awdl_active, false);
	WRITE_ONCE(m->awdl_enabled, false);
	spin_unlock_irqrestore(&m->response_lock, flags);

	spin_lock_irqsave(&m->data_lock, flags);
	m->awdl_registered = false;
	m->awdl_present = false;
	m->awdl_wtbl = 0;
	m->awdl_bss_wtbl = 0;
	spin_unlock_irqrestore(&m->data_lock, flags);
	mt_awdl_peer_reset(m);

	unregister_netdev(netdev);
	free_netdev(netdev);
	kfree(wdev);
	dev_info(&m->pdev->dev, "AWDL_INTERFACE_REMOVED\n");
}

/* One deadline covers both phases. A creation that never saw a present
 * event frees what the vendor command allocated, because its BSS activation
 * never produced a usable interface; a destroy whose absence event never
 * arrived removes the netdev anyway, because the destroy's command already
 * deactivated the BSS.
 */
void mt_awdl_timeout(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct mt7932 *m = container_of(dwork, struct mt7932, awdl_timeout);
	struct net_device *netdev;
	struct wireless_dev *wdev;
	unsigned long flags;
	bool destroying;

	spin_lock_irqsave(&m->response_lock, flags);
	destroying = READ_ONCE(m->awdl_destroying);
	if (destroying ? (READ_ONCE(m->awdl_attaching) || !READ_ONCE(m->awdl_registered)) :
			 (!READ_ONCE(m->awdl_pending) || READ_ONCE(m->awdl_attaching) ||
			  READ_ONCE(m->awdl_registered))) {
		spin_unlock_irqrestore(&m->response_lock, flags);
		return;
	}
	netdev = m->awdl_netdev;
	wdev = m->awdl_wdev;
	WRITE_ONCE(m->awdl_pending, false);
	if (!destroying) {
		m->awdl_netdev = NULL;
		m->awdl_wdev = NULL;
		WRITE_ONCE(m->awdl_active, false);
	}
	spin_unlock_irqrestore(&m->response_lock, flags);

	if (destroying) {
		/* The absence event was lost; the BSS is deactivated either
		 * way, so the teardown work may remove the interface.
		 */
		dev_warn(&m->pdev->dev, "AWDL destruction timed out; removing the interface anyway\n");
		queue_work(system_long_wq, &m->awdl_teardown_work);
		return;
	}
	dev_err(&m->pdev->dev, "AWDL creation timed out\n");
	free_netdev(netdev);
	kfree(wdev);
}

/* Vendor CREATE. Runs with the wiphy mutex held and never registers
 * anything: the state is published, then the firmware is asked, and the
 * netdev appears from the attach work on the first present event. An
 * activation whose response was lost is retired by the timeout work, the
 * way brcmfmac retires a creation whose interface event was lost.
 */
int mt_awdl_add_vif(struct wiphy *wiphy, const char *name)
{
	struct mt7932 *m = mt_from_wiphy(wiphy);
	struct net_device *netdev;
	struct wireless_dev *wdev;
	u16 wtbl;
	u8 mac[ETH_ALEN];
	unsigned long flags;
	int ret;

	if (!mt_awdl_rf_ready(m))
		return -ENODEV;

	/* The BSS and the netdev share one address: the station's with the
	 * local bit set, which is how a peer tells the AWDL interface from
	 * the infrastructure one.
	 */
	ether_addr_copy(mac, m->mac);
	mac[0] |= 0x02;

	wdev = kzalloc(sizeof(*wdev), GFP_KERNEL);
	netdev = wdev ? alloc_etherdev(sizeof(m)) : NULL;
	if (!netdev) {
		kfree(wdev);
		return -ENOMEM;
	}
	*(struct mt7932 **)netdev_priv(netdev) = m;
	wdev->wiphy = wiphy;
	/* cfg80211 needs some valid type for its bookkeeping; the firmware
	 * side is what decides the interface behaviour. ADHOC, not STATION:
	 * IWD and NetworkManager treat every STATION netdev as a candidate
	 * for autoconnect, adopt awdl0 the moment it appears, and disturb
	 * the station's association (observed as IWD listing awdl0 as its
	 * only station and wlan0 failing to come back up). Apple's AWDL is a
	 * peer link, and a supplicant has no business connecting it.
	 */
	wdev->iftype = NL80211_IFTYPE_ADHOC;
	wdev->netdev = netdev;
	netdev->ieee80211_ptr = wdev;
	netdev->netdev_ops = &mt_awdl_net_ops;
	netdev->needed_headroom = MT7932_AWDL_ENCAP_LEN;
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = ETH_DATA_LEN - MT7932_AWDL_ENCAP_LEN;
	SET_NETDEV_DEV(netdev, wiphy_dev(wiphy));
	eth_hw_addr_set(netdev, mac);
	strscpy(netdev->name, MT7932_AWDL_IFNAME, IFNAMSIZ);
	netif_carrier_off(netdev);

	mutex_lock(&m->command_mutex);
	spin_lock_irqsave(&m->response_lock, flags);
	if (m->awdl_netdev || READ_ONCE(m->awdl_pending) ||
	    READ_ONCE(m->awdl_attaching)) {
		spin_unlock_irqrestore(&m->response_lock, flags);
		mutex_unlock(&m->command_mutex);
		free_netdev(netdev);
		kfree(wdev);
		return -EEXIST;
	}
	m->awdl_netdev = netdev;
	m->awdl_wdev = wdev;
	ether_addr_copy(m->awdl_mac, mac);
	strscpy(m->awdl_ifname, name, sizeof(m->awdl_ifname));
	WRITE_ONCE(m->awdl_active, true);
	WRITE_ONCE(m->awdl_destroying, false);
	WRITE_ONCE(m->awdl_enabled, false);
	WRITE_ONCE(m->awdl_pending, true);
	spin_unlock_irqrestore(&m->response_lock, flags);
	spin_lock_irqsave(&m->data_lock, flags);
	m->awdl_registered = false;
	/* This firmware reports no BSS presence, associated or not: EID 0x11
	 * has never been seen on it. So the BSS is taken as present as soon
	 * as it has been activated and its WTBL entry as unknown, which the
	 * receive path reads as "whatever the station does not claim". A
	 * presence event, if one ever arrives, replaces both.
	 */
	m->awdl_present = true;
	m->awdl_absent = false;
	m->awdl_quota = 0;
	m->awdl_wtbl = 0;
	m->awdl_tx_seq = 0;
	memset(m->awdl_duplicates, 0, sizeof(m->awdl_duplicates));
	spin_unlock_irqrestore(&m->data_lock, flags);
	queue_delayed_work(system_long_wq, &m->awdl_timeout,
			   MT7932_AWDL_CREATE_TIMEOUT);

	/* The vendor driver's order: describe the BSS while it is still
	 * inactive, activate it, then describe it again as active. None of
	 * the three is answered; the presence event is the report.
	 */
	wtbl = mt_awdl_wtbl_select(m);
	if (!wtbl) {
		ret = -ENOSPC;
	} else {
		spin_lock_irqsave(&m->data_lock, flags);
		m->awdl_wtbl = wtbl;
		m->awdl_bss_wtbl = wtbl;
		spin_unlock_irqrestore(&m->data_lock, flags);
		ret = mt_awdl_bss_info(m, false, 0xff);
	}
	if (!ret)
		ret = mt_awdl_bss_activate(m, true, mac, wtbl);
	if (!ret)
		ret = mt_awdl_bss_queue(m);
	if (!ret)
		ret = mt_awdl_bss_info(m, true, wtbl);
	if (ret)
		dev_err(&m->pdev->dev, "AWDL_CREATE_WTBL: entry=%u ret=%d\n", wtbl, ret);
	mutex_unlock(&m->command_mutex);
	if (ret) {
		/* A present event may already be in flight; retire through
		 * the same path that created the state.
		 */
		dev_err(&m->pdev->dev, "AWDL_CREATE_FAILED: %d\n", ret);
		queue_delayed_work(system_long_wq, &m->awdl_timeout, 0);
	} else {
		/* Nothing waits for the firmware here: the BSS is activated,
		 * so publish the interface. The transmit completions the
		 * firmware gives for its frames are the only report this
		 * BSS ever gets, and they need the netdev to exist.
		 */
		queue_work(system_long_wq, &m->awdl_attach_work);
	}
	return ret;
}

/* Vendor DESTROY: ask the firmware to drop the AWDL BSS and return. The
 * presence-absent event lands in the event consumer, which queues the
 * teardown work; nothing here may reach unregister_netdev().
 */
int mt_awdl_del_vif(struct wiphy *wiphy, struct wireless_dev *wdev)
{
	struct mt7932 *m = mt_from_wiphy(wiphy);
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&m->response_lock, flags);
	if (wdev->wiphy != wiphy || wdev != m->awdl_wdev) {
		spin_unlock_irqrestore(&m->response_lock, flags);
		return -ENODEV;
	}
	if (READ_ONCE(m->awdl_registered) && READ_ONCE(m->awdl_enabled)) {
		/* The firmware refuses to remove a BSS whose AWDL session is
		 * running; the caller turns the session off first.
		 */
		spin_unlock_irqrestore(&m->response_lock, flags);
		return -EBUSY;
	}
	WRITE_ONCE(m->awdl_destroying, true);
	WRITE_ONCE(m->awdl_active, false);
	spin_unlock_irqrestore(&m->response_lock, flags);

	mutex_lock(&m->command_mutex);
	ret = mt_awdl_bss_activate(m, false, m->awdl_mac,
				  READ_ONCE(m->awdl_wtbl) ?: mt_awdl_wtbl_select(m));
	mutex_unlock(&m->command_mutex);
	if (ret) {
		spin_lock_irqsave(&m->response_lock, flags);
		WRITE_ONCE(m->awdl_destroying, false);
		WRITE_ONCE(m->awdl_active, true);
		spin_unlock_irqrestore(&m->response_lock, flags);
		return ret;
	}
	/* Nothing reports the absence either: take the interface away as
	 * soon as the BSS is deactivated, the same way creation publishes
	 * it as soon as the BSS is activated.
	 */
	queue_work(system_long_wq, &m->awdl_teardown_work);
	return 0;
}

/* --- awdl0 netdev ------------------------------------------------------- */

static int mt_awdl_net_open(struct net_device *netdev)
{
	struct mt7932 *m = *(struct mt7932 **)netdev_priv(netdev);

	if (READ_ONCE(m->awdl_present))
		netif_carrier_on(netdev);
	netif_start_queue(netdev);
	return 0;
}

static int mt_awdl_net_stop(struct net_device *netdev)
{
	struct mt7932 *m = *(struct mt7932 **)netdev_priv(netdev);

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);
	/* Closing the link with the session on would leave the firmware
	 * advertising to peers that can no longer receive an answer, so
	 * take the session down with the link.
	 */
	if (READ_ONCE(m->awdl_registered) && READ_ONCE(m->awdl_enabled)) {
		mutex_lock(&m->command_mutex);
		mt_awdl_session(m, false);
		mutex_unlock(&m->command_mutex);
	}
	return 0;
}

/* One AWDL data packet: envelope, then the shared TX0 publication. */
static netdev_tx_t mt_awdl_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct mt7932 *m = *(struct mt7932 **)netdev_priv(netdev);
	struct mt7932_ring *q = &m->tx[0];
	struct mt7932_desc *desc;
	unsigned int tid = cfg80211_classify8021d(skb, NULL);
	unsigned int own_mac = READ_ONCE(mt7932_awdl_omac);
	u16 wtbl = READ_ONCE(m->awdl_wtbl);
	u16 chosen = READ_ONCE(m->awdl_bss_wtbl);
	int probe = READ_ONCE(mt7932_awdl_probe_wtbl);
	u8 *payload, *header;
	dma_addr_t dma;
	unsigned long flags;
	unsigned int slot;
	bool wtbl_conflict;
	int ret;

	/* The entry comes from a presence event when the firmware reports
	 * one. It reports zero for this BSS, and a module parameter of zero
	 * means "chosen at creation", so fall back to that choice instead of
	 * dropping every frame.
	 */
	if (!wtbl)
		wtbl = chosen;
	if (!wtbl && mt7932_awdl_wtbl > 0 && mt7932_awdl_wtbl <= 0xff)
		wtbl = mt7932_awdl_wtbl;
	/* Explicit module parameter outranks the creation-time choice, and the
	 * diagnostic probe outranks both. Both are operator decisions.
	 */
	if (mt7932_awdl_wtbl > 0 && mt7932_awdl_wtbl <= 0x3ff)
		wtbl = mt7932_awdl_wtbl;
	if (probe > 0 && probe <= 0x3ff) {
		wtbl = probe;
		dev_warn_ratelimited(&m->pdev->dev,
				    "AWDL_TX_PROBE_WTBL: forcing entry %d for every AWDL frame\n",
				    probe);
	}
	if (!netif_running(netdev) || !netif_device_present(netdev) ||
	    !READ_ONCE(m->awdl_registered) || !READ_ONCE(m->awdl_present) ||
	    !READ_ONCE(m->awdl_enabled) || !mt_awdl_rf_ready(m) ||
	    !wtbl || !READ_ONCE(m->data_ready) || skb->len < ETH_HLEN ||
	    skb->len > ETH_FRAME_LEN + VLAN_HLEN) {
		u8 why = 0;

		if (!netif_running(netdev))
			why |= BIT(0);
		if (!netif_device_present(netdev))
			why |= BIT(1);
		if (!READ_ONCE(m->awdl_registered))
			why |= BIT(2);
		if (!READ_ONCE(m->awdl_present))
			why |= BIT(3);
		if (!READ_ONCE(m->awdl_enabled))
			why |= BIT(4);
		if (!mt_awdl_rf_ready(m))
			why |= BIT(5);
		if (!wtbl)
			why |= BIT(6);
		if (!READ_ONCE(m->data_ready))
			why |= BIT(7);
		if (skb->len < ETH_HLEN || skb->len > ETH_FRAME_LEN + VLAN_HLEN)
			why |= BIT(8);
		dev_warn_ratelimited(&m->pdev->dev,
				     "AWDL_TX_DROP: why=%02x wtbl=%u chosen=%u present=%d absent=%d quota=%u enabled=%d len=%u\n",
				     why, wtbl, chosen, READ_ONCE(m->awdl_present),
				     READ_ONCE(m->awdl_absent), READ_ONCE(m->awdl_quota),
				     READ_ONCE(m->awdl_enabled), skb->len);
		goto drop;
	}
	if (tid > 7)
		tid = 7;
	if (mt7932_awdl_force_ac >= 0 && mt7932_awdl_force_ac <= 7)
		tid = mt7932_awdl_force_ac;
	/* The old fallback (2) overlaps the station association's reserved
	 * WTBL resources. A released host token with that header says nothing
	 * about AWDL delivery. Refuse cross-BSS identity instead of publishing
	 * an observed conflicting index. peer_valid/peer_ids belong to response_lock;
	 * do this before taking data_lock to preserve the nesting order.
	 */
	spin_lock_irqsave(&m->response_lock, flags);
	wtbl_conflict = !probe && m->peer_valid &&
		mt7932_awdl_wtbl_conflicts(wtbl, m->peer_ids.wtbl,
					 ARRAY_SIZE(m->peer_ids.wtbl));
	/* Unicast to a peer with a station record uses that peer's WTBL entry;
	 * the BSS entry describes broadcast frames. Only the peer identity the
	 * vendor command installed is matched, never a guessed index.
	 */
	if (!wtbl_conflict) {
		unsigned int peer;

		for (peer = 0; peer < ARRAY_SIZE(m->awdl_peer_mac); peer++) {
			if (!m->awdl_peer_wtbl[peer] ||
			    !ether_addr_equal(skb->data, m->awdl_peer_mac[peer]))
				continue;
			wtbl = m->awdl_peer_wtbl[peer];
			break;
		}
	}
	spin_unlock_irqrestore(&m->response_lock, flags);
	if (wtbl_conflict) {
		dev_warn_ratelimited(&m->pdev->dev,
				    "AWDL_TX_WTBL_CONFLICT: entry=%u belongs to infrastructure; refusing TX\n",
				    wtbl);
		goto drop;
	}
	if (skb_headroom(skb) < MT7932_AWDL_ENCAP_LEN || skb_header_cloned(skb)) {
		ret = pskb_expand_head(skb,
			ALIGN(MT7932_AWDL_ENCAP_LEN - skb_headroom(skb), NET_SKB_PAD),
			0, GFP_ATOMIC);
		if (ret)
			goto drop;
	}
	spin_lock_irqsave(&m->data_lock, flags);
	/* The presence path closes admission under data_lock; recheck here
	 * with the queue lock held, as the station path rechecks its
	 * connection the same way.
	 */
	if (!m->awdl_registered || !m->awdl_present || !mt_awdl_tx_allowed(m)) {
		netif_stop_queue(netdev);
		mt_data_kick_locked(m);
		spin_unlock_irqrestore(&m->data_lock, flags);
		return NETDEV_TX_BUSY;
	}
	mt_data_clean_locked(m);
	slot = q->head;
	if (m->data_live[slot] || q->queued >= q->count - 1) {
		netif_stop_queue(netdev);
		mt_data_kick_locked(m);
		spin_unlock_irqrestore(&m->data_lock, flags);
		return NETDEV_TX_BUSY;
	}
	ret = mt7932_awdl_encap(skb, &m->awdl_tx_seq);
	if (ret) {
		spin_unlock_irqrestore(&m->data_lock, flags);
		goto drop;
	}
	payload = m->data_payloads + 4096 * slot;
	header = m->data_headers + 64 * slot;
	ret = skb_copy_bits(skb, 0, payload, skb->len);
	if (!ret)
		ret = mt7932_data_header(header, payload, skb->len,
					 m->data_payloads_dma + 4096 * slot,
					 slot, wtbl, own_mac, tid, false);
	if (ret) {
		spin_unlock_irqrestore(&m->data_lock, flags);
		goto drop;
	}
	dma = m->data_headers_dma + 64 * slot;
	desc = &q->desc[slot];
	desc->address = cpu_to_le32(lower_32_bits(dma));
	desc->second = 0;
	desc->info = cpu_to_le32(upper_32_bits(dma));
	m->data_live[slot] = m->data_token[slot] = true;
	m->data_retired[slot] = false;
	__set_bit(slot, m->data_awdl);
	dma_wmb();
	desc->control = cpu_to_le32((64 << 16) | BIT(30));
	q->head = (slot + 1) % q->count;
	q->queued++;
	dma_wmb();
	m->data_unkicked++;
	if (m->awdl_absent)
		m->awdl_quota--;
	m->awdl_tx_packets++;
	m->awdl_tx_bytes += skb->len;
	if (!mt_awdl_tx_allowed(m) || m->data_live[q->head] ||
	    q->queued >= q->count - 1)
		netif_stop_queue(netdev);
	if (!netdev_xmit_more() || netif_queue_stopped(netdev) ||
	    m->data_unkicked >= MT7932_TX_BATCH)
		mt_data_kick_locked(m);
	spin_unlock_irqrestore(&m->data_lock, flags);
	netdev->stats.tx_packets++;
	netdev->stats.tx_bytes += skb->len;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
drop:
	if (!netdev_xmit_more() && READ_ONCE(m->data_ready)) {
		spin_lock_irqsave(&m->data_lock, flags);
		mt_data_kick_locked(m);
		spin_unlock_irqrestore(&m->data_lock, flags);
	}
	netdev->stats.tx_dropped++;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

/* The AWDL BSS identity is the netdev's address. NetworkManager and the
 * omdrop helpers take the link down before changing it, and the firmware
 * reprograms the BSS identity while the session is off.
 */
static int mt_awdl_set_mac_address(struct net_device *netdev, void *address)
{
	struct sockaddr *sa = address;
	struct mt7932 *m = *(struct mt7932 **)netdev_priv(netdev);
	unsigned long flags;
	int ret;

	if (!is_valid_ether_addr(sa->sa_data))
		return -EADDRNOTAVAIL;
	if (netif_running(netdev))
		return -EBUSY;
	mutex_lock(&m->command_mutex);
	spin_lock_irqsave(&m->response_lock, flags);
	if (!m->awdl_registered || READ_ONCE(m->awdl_enabled)) {
		spin_unlock_irqrestore(&m->response_lock, flags);
		mutex_unlock(&m->command_mutex);
		return m->awdl_registered ? -EBUSY : -ENODEV;
	}
	WRITE_ONCE(m->awdl_active, false);
	spin_unlock_irqrestore(&m->response_lock, flags);
	spin_lock_irqsave(&m->data_lock, flags);
	m->awdl_present = false;
	spin_unlock_irqrestore(&m->data_lock, flags);
	mt_awdl_peer_reset(m);

	ret = eth_mac_addr(netdev, address);
	if (!ret) {
		/* Reprogram the AWDL BSS identity: deactivate it, then
		 * reactivate with the new address, and tell the session the
		 * BSSID moved with it. The absence and presence events that
		 * answer re-derive the WTBL entry.
		 */
		u16 wtbl;
		u8 mac[ETH_ALEN];

		ether_addr_copy(mac, sa->sa_data);
		ether_addr_copy(m->awdl_mac, mac);
		wtbl = READ_ONCE(m->awdl_wtbl) ?: mt_awdl_wtbl_select(m);
		ret = mt_awdl_bss_activate(m, false, mac, wtbl);
		if (!ret) {
			spin_lock_irqsave(&m->response_lock, flags);
			WRITE_ONCE(m->awdl_active, true);
			spin_unlock_irqrestore(&m->response_lock, flags);
			ret = mt_awdl_bss_activate(m, true, mac, wtbl);
			if (!ret)
				ret = mt_awdl_bss_queue(m);
			if (!ret)
				ret = mt_awdl_bss_info(m, true, wtbl);
			if (!ret)
				ret = mt_awdl_set_bssid(m, mac);
			if (!ret) {
				/* The re-activation above is the only evidence
				 * this firmware ever gives that the BSS is
				 * back: it reports no presence event, so the
				 * gate cleared at the top of this function
				 * must be restored here. Leaving it clear makes
				 * the interface accept frames and drop every
				 * one of them.
				 */
				spin_lock_irqsave(&m->data_lock, flags);
				m->awdl_present = true;
				m->awdl_absent = false;
				spin_unlock_irqrestore(&m->data_lock, flags);
			}
			if (ret) {
				spin_lock_irqsave(&m->response_lock, flags);
				WRITE_ONCE(m->awdl_active, false);
				spin_unlock_irqrestore(&m->response_lock, flags);
			}
		}
		if (ret)
			dev_err(&m->pdev->dev, "AWDL_IDENTITY_FAILED: %d\n", ret);
	}
	mutex_unlock(&m->command_mutex);
	return ret;
}

const struct net_device_ops mt_awdl_net_ops = {
	.ndo_open = mt_awdl_net_open,
	.ndo_stop = mt_awdl_net_stop,
	.ndo_start_xmit = mt_awdl_xmit,
	.ndo_set_mac_address = mt_awdl_set_mac_address,
	.ndo_validate_addr = eth_validate_addr,
};

/* Deliver one AWDL data frame. The envelope is unwrapped in place before
 * the stack classifies the frame; frames without the envelope pass through
 * unchanged, as on brcmfmac. response_lock held.
 */
void mt_awdl_receive(struct mt7932 *m, const struct mt7932_rx_frame *frame)
{
	struct net_device *netdev = m->awdl_netdev;
	struct sk_buff *skb;

	if (!netdev) {
		m->rx_wrong_peer++;
		return;
	}
	netdev->stats.rx_packets++;
	netdev->stats.rx_bytes += frame->length;
	if (!netif_running(netdev)) {
		netdev->stats.rx_dropped++;
		return;
	}
	if (mt7932_rx_duplicate(m->awdl_duplicates, frame)) {
		m->rx_duplicate++;
		netdev->stats.rx_dropped++;
		return;
	}
	skb = netdev_alloc_skb_ip_align(netdev, frame->length + MT7932_AWDL_ENCAP_LEN);
	if (!skb) {
		m->rx_no_memory++;
		netdev->stats.rx_dropped++;
		return;
	}
	skb_put_data(skb, frame->data, frame->length);
	skb->protocol = eth_type_trans(skb, netdev);
	skb->ip_summed = CHECKSUM_NONE;
	mt7932_awdl_decap(skb);
	m->rx_ethernet++;
	netif_rx(skb);
	dev_dbg_ratelimited(&m->pdev->dev, "AWDL_ETHERNET_RX: bytes=%zu wtbl=%u\n",
			    frame->length, frame->wtbl);
}

/* --- firmware session control ------------------------------------------ */

/* command_mutex held. One element of the firmware's AWDL multiplexer,
 * runtime CID 0xf7: a four-byte header, then a little-endian type, a
 * little-endian length and that many bytes. Every AWDL set goes out the way
 * the vendor driver sends it, with the response bit clear, so this returns
 * once the command is on the ring; the firmware's answer is the empty
 * command reply, which carries nothing to check.
 */
static int mt_awdl_tlv_cmd(struct mt7932 *m, u32 type, const void *payload,
			   size_t length)
{
	size_t total = MT7932_AWDL_TLV_OVERHEAD + length;
	u8 *body;
	int ret;

	if (!mt_awdl_rf_ready(m))
		return -ENODEV;
	if (length > MT7932_AWDL_BODY_MAX - MT7932_AWDL_TLV_OVERHEAD)
		return -EINVAL;

	body = kvmalloc(total, GFP_KERNEL);
	if (!body)
		return -ENOMEM;
	/* The firmware's dispatcher validates this word against the element
	 * payload length: sending 1 here made every session command but the
	 * one whose payload happens to be one byte fail with "Body length
	 * mismatch (expected N, got 1)". The enable only ever took effect
	 * when the length was sent explicitly.
	 */
	put_unaligned_le16(length, body);
	put_unaligned_le16(0, body + 2);
	put_unaligned_le32(type, body + 4);
	put_unaligned_le32(length, body + 8);
	/* Past the four-byte prefix and the eight-byte element header. Copying
	 * at MT7932_AWDL_TLV_HDR (8) wrote the payload over the length field
	 * itself, so the firmware saw a length of 1 (the first payload byte)
	 * and rejected the command: "expected 6, got 1".
	 */
	memcpy(body + MT7932_AWDL_TLV_OVERHEAD, payload, length);
	/* Original command table, not the runtime one: with runtime set the
	 * firmware's dispatcher reads a different body layout and answers
	 * "Body length mismatch (expected N, got 1)" for every element. The
	 * raw probe path uses the original table and dispatches correctly.
	 */
	ret = mt_request(m, 0xf7, false, true, false, body, total);
	kvfree(body);
	return ret;
}

/* command_mutex held. CID 0x12, the description the firmware keeps for one
 * BSS. The firmware takes the BSS index, the active byte, the operation mode
 * and the service-set length from the first four bytes and the channel from
 * offset 0xa, and keeps the rest as the BSS's own description. The bytes
 * below are what the vendor driver's AWDL BSS carries, including the fields
 * it overwrites after the copy: the type-5 marker, the rate set, the WTBL
 * entry (still -1 until the firmware assigns one, which is how the first of
 * the two updates differs from the second) and the two availability maps.
 */
static int mt_awdl_bss_info(struct mt7932 *m, bool active, u8 wtbl)
{
	u8 body[MT7932_AWDL_BSSINFO_LEN] = {};

	(void)wtbl;
	body[0] = MT7932_AWDL_BSS;
	body[1] = active;
	body[2] = MT7932_AWDL_OPMODE;
	/* The vendor driver copies the current infrastructure primary channel
	 * into the AWDL BSS description.  Leaving this zero creates the BSS but
	 * gives the firmware no home channel from which to schedule its
	 * availability windows, so it neither hears nor emits AWDL action frames.
	 */
	body[0x0a] = m->connect_channel;
	/* Field offsets decoded from _nicUpdateBss (the 0x70-byte BSS blob is
	 * copied from host bss+0x24 into body+4) and from the values _awdlDevInit
	 * stores: the interface address lands at blob+0x26 (body+0x4a), the
	 * type-5 marker, rate set and the constant 4 at body+0x5a.  The old
	 * 0x3a write was overwritten by the firmware's rate-set selection, not
	 * a WTBL entry.
	 */
	body[0x2a] = 1;
	body[0x30] = 0xfe;
	body[0x32] = 0x4b;
	/* body[0x3a] is the bandwidth selector the firmware logs as BM
	 * (bss+0x78). The station negotiates 80 MHz, so use CMD_CBW_80MHZ=2;
	 * a stale WTBL value used to land here by accident.
	 */
	body[0x3a] = 2;
	memcpy(body + 0x4a, m->awdl_mac, ETH_ALEN);
	body[0x5a] = 4;

	return mt_request(m, 0x12, true, true, false, body, sizeof(body));
}

/* command_mutex held. CID 0x11 activates a BSS: its index, the active byte,
 * the net type (5 is AWDL), the BSS's reuse index, its address, the WTBL
 * entry its broadcast frames use, and a byte the vendor driver always sends
 * as 1. Deactivation is the same length with the active byte clear. Neither
 * waits: the presence event is the only report either one gets.
 */
static int mt_awdl_bss_activate(struct mt7932 *m, bool active, const u8 *mac,
				u8 wtbl)
{
	u8 body[12] = { MT7932_AWDL_BSS, 1, 5, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

	/* body[3] is the BSS's own index in the vendor driver: _nicActivateNetwork
	 * copies bss+0x50, which _cnmGetBssInfoAndInit fills with the BSS slot,
	 * into the activation. Sending 0 there binds the second BSS to the
	 * first BSS's own-MAC index, which is what the transmit descriptors
	 * then contradict.
	 */
	body[3] = mt7932_awdl_omac;

	body[1] = active;
	body[10] = wtbl;
	memcpy(body + 4, mac, ETH_ALEN);

	return mt_request(m, 0x11, true, true, false, body, sizeof(body));
}

/* command_mutex held. Allocate the AWDL BSS's own TX queues. The vendor
 * driver's `_awdlDevInit`/BSS activation path allocates a BSS queue set
 * (`_nicTxQAllocForBss`), which for a BSS with no queue index sets the token
 * base to 1 and the bitmap to 0xf, and sends CID 0x6b with the BSS update
 * selector. The station BSS gets the same command when it associates; a
 * second BSS without it has no queue for the firmware to drain TX0 into,
 * which is consistent with frames being accepted by the driver and never
 * appearing on air.
 */
static int mt_awdl_bss_queue(struct mt7932 *m)
{
	u8 queue[32] = {};

	put_unaligned_le16(15, queue);		/* BSS queue bitmap */
	queue[2] = 1;				/* BSS update */
	queue[3] = MT7932_AWDL_BSS;		/* BSS index */
	queue[14] = 1;				/* token base when bss+0x1b is 0 */
	return mt_request(m, 0x6b, true, true, false, queue, sizeof(queue));
}

/* command_mutex held. Turn the firmware's AWDL session on or off: element
 * type 8, a word that is always 1 and the on/off flag. Channel selection is
 * a different element and the driver does not build it yet, so this brings
 * the session up on whatever availability map the firmware last held.
 */
int mt_awdl_session(struct mt7932 *m, bool enable)
{
	u8 payload[6];
	int ret;

	put_unaligned_le32(1, payload);
	put_unaligned_le16(enable ? 1 : 0, payload + 4);
	ret = mt_awdl_tlv_cmd(m, MT7932_AWDL_TLV_ENABLE, payload,
			      sizeof(payload));
	if (ret)
		return ret;

	WRITE_ONCE(m->awdl_enabled, enable);
	dev_info(&m->pdev->dev, "AWDL session %s\n",
		 enable ? "enabled" : "disabled");
	return 0;
}

/* command_mutex held. The AWDL BSSID, element type 0: a word that is always
 * 1 and the six address bytes. Every AWDL node advertises the same one, so a
 * peer takes the interface's frames whatever its own session state.
 */
int mt_awdl_set_bssid(struct mt7932 *m, const u8 *mac)
{
	u8 payload[4 + ETH_ALEN];

	put_unaligned_le32(1, payload);
	memcpy(payload + 4, mac, ETH_ALEN);

	return mt_awdl_tlv_cmd(m, MT7932_AWDL_TLV_BSSID, payload,
			       sizeof(payload));
}

/* command_mutex held. The channel list, CID 0xf7 element type 2. The
 * firmware does not take a set of channels here: it takes the 16-slot
 * availability sequence the AWDL real-time group runs, in order, with each
 * slot's channel number and operating class. macOS's own trace on this
 * network shows the sequence
 *
 *   153 153 149 153 153 153 153 153 153 153 149 153 153 153 153 153
 *
 * i.e. the infrastructure channel in every slot except two windows on the
 * next 80 MHz sibling, which is what the RTG widens bandwidth with. A list
 * of distinct channels is rejected by the firmware's channel-sequence
 * handler ("PM or CS error"); this 16-slot form is accepted and makes the
 * scheduler leave the empty state.
 */
int mt_awdl_channel_list(struct mt7932 *m)
{
	u8 body[MT7932_AWDL_CHANNEL_BODY] = {};
	unsigned int home = m->connect_channel;
	unsigned int secondary = 0;
	unsigned int count = 16;
	unsigned int i;
	int ret;

	if (!mt_awdl_rf_ready(m))
		return -ENODEV;
	if (!home)
		return -EINVAL;
	if (home >= 36 && home >= 4 + 36)
		secondary = home - 4;

	for (i = 0; i < count; i++) {
		unsigned int ch = (secondary && (i == 2 || i == 10)) ?
				  secondary : home;

		body[6 + i] = ch;
		body[6 + MT7932_AWDL_CHANNELS_MAX + i] =
			ch >= 36 ? MT7932_AWDL_CLASS_5G : MT7932_AWDL_CLASS_2G;
	}

	put_unaligned_le32(1, body);
	body[4] = 4;
	body[5] = count;
	ret = mt_awdl_tlv_cmd(m, MT7932_AWDL_TLV_CHANNELS, body, sizeof(body));
	if (!ret)
		dev_info(&m->pdev->dev,
			 "AWDL channel sequence: %u slots, home %u, secondary %u\n",
			 count, home, secondary);
	return ret;
}

/* command_mutex held. The session operations that are left have no payload
 * this driver has read: the vendor driver's channel list (type 2, 0x86
 * bytes), sync master (9), PSF period (3), election parameters (0xa) and
 * metric (0xb), action-frame mode (0xc) and minimum rate (0xd), edge RSSI
 * (7) and out-of-band request (6) are all elements whose body was never
 * reconstructed. A guessed body is what made the first probe loop
 * uninformative, so these refuse instead, and name the id they need.
 */
int mt_awdl_data_cmd(struct mt7932 *m, u8 selector, const void *data, size_t length)
{
	return -EOPNOTSUPP;
}

/* Peer records describe this firmware BSS, so they die with it. Caller holds
 * (or is about to publish) the gate that stops the transmit path.
 */
static void mt_awdl_peer_reset(struct mt7932 *m)
{
	unsigned long flags;

	spin_lock_irqsave(&m->response_lock, flags);
	memset(m->awdl_peer_mac, 0, sizeof(m->awdl_peer_mac));
	memset(m->awdl_peer_station, 0, sizeof(m->awdl_peer_station));
	memset(m->awdl_peer_wtbl, 0, sizeof(m->awdl_peer_wtbl));
	m->awdl_peer_count = 0;
	spin_unlock_irqrestore(&m->response_lock, flags);
}

/* command_mutex held. Install one peer station record for the AWDL BSS.
 *
 * Apple's driver allocates a station ID and a WTBL entry, fills a 200-byte
 * station description, and sends it as CID 0x13 SET. It then starts data
 * only after the firmware reports the peer through its station-record event.
 * This driver has no verified remove command and no verified source for the
 * peer-capability fields, so a removal is refused rather than faked, and a
 * record is only added when the caller names the peer explicitly.
 */
int mt_awdl_peer_op(struct mt7932 *m, bool add, const u8 mac[ETH_ALEN])
{
	u8 body[MT7932_AWDL_PEER_BODY_LEN];
	u8 queue[32];
	unsigned long flags;
	unsigned int slot, peer;
	u8 station = 0, wtbl = 0;
	bool exists = false;
	int ret;

	if (!is_valid_ether_addr(mac))
		return -EINVAL;

	spin_lock_irqsave(&m->response_lock, flags);
	for (peer = 0; peer < MT_AWDL_PEERS; peer++)
		if (m->awdl_peer_wtbl[peer] &&
		    ether_addr_equal(mac, m->awdl_peer_mac[peer])) {
			exists = true;
			break;
		}
	spin_unlock_irqrestore(&m->response_lock, flags);

	if (!add) {
		/* No verified firmware removal exists. Reporting success would
		 * leave a live peer record the host no longer tracks.
		 */
		return -EOPNOTSUPP;
	}
	if (exists)
		return 0;
	if (!READ_ONCE(m->awdl_active))
		return -ENODEV;

	/* Station IDs 2..14 are Apple's non-AIS range; WTBL 2..5 already belong
	 * to the infrastructure link, and the AWDL BSS entry is excluded too.
	 */
	for (station = MT7932_AWDL_FIRST_STATION;
	     station <= MT7932_AWDL_LAST_STATION; station++) {
		bool used = false;

		spin_lock_irqsave(&m->response_lock, flags);
		for (peer = 0; peer < MT_AWDL_PEERS; peer++)
			used |= m->awdl_peer_station[peer] == station;
		for (peer = 0; peer < ARRAY_SIZE(m->peer_ids.station); peer++)
			used |= m->peer_valid && m->peer_ids.station[peer] == station;
		spin_unlock_irqrestore(&m->response_lock, flags);
		if (!used)
			break;
	}
	if (station > MT7932_AWDL_LAST_STATION)
		return -ENOSPC;

	for (wtbl = MT7932_AWDL_FIRST_WTBL; wtbl <= MT7932_AWDL_LAST_WTBL; wtbl++) {
		bool used = wtbl == READ_ONCE(m->awdl_wtbl);

		spin_lock_irqsave(&m->response_lock, flags);
		for (peer = 0; peer < MT_AWDL_PEERS; peer++)
			used |= m->awdl_peer_wtbl[peer] == wtbl;
		used |= m->peer_valid &&
			mt7932_awdl_wtbl_conflicts(wtbl, m->peer_ids.wtbl,
						ARRAY_SIZE(m->peer_ids.wtbl));
		spin_unlock_irqrestore(&m->response_lock, flags);
		if (!used)
			break;
	}
	if (wtbl > MT7932_AWDL_LAST_WTBL)
		return -ENOSPC;

	mt7932_awdl_peer_body(body, station, mac, MT7932_AWDL_BSS, wtbl);
	ret = mt_request(m, 0x13, true, true, false, body, sizeof(body));
	if (ret)
		return ret;

	/* The vendor driver allocates the peer's TX queues immediately after
	 * the station update (`_cnmStaRecAllocSeq` calls `_nicTxQAlloc`, which
	 * binds the station to the BSS queues with CID 0x6b). Without it the
	 * firmware accepts the record and then flushes every data frame for
	 * the peer's WTBL entry. The station path uses the same helper.
	 */
	memset(queue, 0, sizeof(queue));
	mt7932_peer_queue(queue, station, true);
	ret = mt_request(m, 0x6b, true, true, false, queue, sizeof(queue));
	if (ret)
		return ret;

	spin_lock_irqsave(&m->response_lock, flags);
	for (slot = 0; slot < MT_AWDL_PEERS; slot++)
		if (!m->awdl_peer_wtbl[slot])
			break;
	if (slot < MT_AWDL_PEERS) {
		m->awdl_peer_station[slot] = station;
		m->awdl_peer_wtbl[slot] = wtbl;
		memcpy(m->awdl_peer_mac[slot], mac, ETH_ALEN);
		m->awdl_peer_count++;
	}
	spin_unlock_irqrestore(&m->response_lock, flags);
	if (slot == MT_AWDL_PEERS)
		return -ENOSPC;

	dev_info(&m->pdev->dev,
		 "AWDL_PEER_ADDED: mac=%pM station=%u wtbl=%u (acceptance unconfirmed)\n",
		 mac, station, wtbl);
	return 0;
}

int mt_awdl_state(struct mt7932 *m, u8 selector, void **reply, size_t *length)
{
	return -EOPNOTSUPP;
}

int mt_awdl_election(struct mt7932 *m, u32 metric, s8 rssi_threshold)
{
	return -EOPNOTSUPP;
}

/* --- vendor commands ---------------------------------------------------- */

static int mt_vendor_awdl_handler(struct wiphy *wiphy, struct wireless_dev *wdev,
				  const void *data, int len)
{
	struct net_device *ndev;
	struct wireless_dev *awdl_wdev;
	u32 op;
	int err;

	if (len < sizeof(op))
		return -EINVAL;
	op = get_unaligned_le32(data);

	switch (op) {
	case MT7932_VNDR_AWDL_OP_CREATE:
		ndev = dev_get_by_name(wiphy_net(wiphy), MT7932_AWDL_IFNAME);
		if (ndev) {
			dev_put(ndev);
			return -EEXIST;
		}
		/* Asynchronous: returns as soon as firmware has been asked.
		 * The netdev appears once the present event is processed, so
		 * userspace must wait for awdl0 rather than assume it exists.
		 */
		return mt_awdl_add_vif(wiphy, MT7932_AWDL_IFNAME);
	case MT7932_VNDR_AWDL_OP_DESTROY:
		ndev = dev_get_by_name(wiphy_net(wiphy), MT7932_AWDL_IFNAME);
		if (!ndev)
			return -ENODEV;
		awdl_wdev = ndev->ieee80211_ptr;
		if (!awdl_wdev || awdl_wdev->wiphy != wiphy) {
			dev_put(ndev);
			return -ENODEV;
		}
		err = mt_awdl_del_vif(wiphy, awdl_wdev);
		dev_put(ndev);
		return err;
	default:
		return -EINVAL;
	}
}

/* One state GET: the driver copies the firmware event body into the
 * reply while it still owns it, before releasing the command mutex.
 */
static int mt_vendor_awdl_state_reply(struct wiphy *wiphy, const void *reply,
				      size_t reply_len)
{
	struct sk_buff *skb;
	__be16 len = cpu_to_be16(reply_len);
	int ret;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
			nla_total_size(sizeof(u16)) + reply_len +
			nla_total_size(reply_len));
	if (!skb)
		return -ENOMEM;
	if (nla_put_be16(skb, MT7932_NLATTR_LEN, len) ||
	    nla_put(skb, MT7932_NLATTR_DATA, reply_len, reply)) {
		kfree_skb(skb);
		return -ENOBUFS;
	}
	ret = cfg80211_vendor_cmd_reply(skb);
	return ret;
}

static int mt_vendor_awdl_cmd_handler(struct wiphy *wiphy, struct wireless_dev *wdev,
				      const void *data, int len)
{
	struct mt7932 *m = mt_from_wiphy(wiphy);
	const struct mt7932_vndr_awdl_cmd *cmd = data;
	unsigned int op;
	int err;

	if (len < (int)sizeof(*cmd))
		return -EINVAL;
	op = get_unaligned_le32(&cmd->op);
	if (op >= MT7932_VNDR_AWDL_OP_LAST)
		return -EINVAL;

	mutex_lock(&m->command_mutex);
	switch (op) {
	case MT7932_VNDR_AWDL_OP_ENABLE:
		if (len != (int)sizeof(*cmd))
			err = -EINVAL;
		else
			err = mt_awdl_session(m, true);
		break;
	case MT7932_VNDR_AWDL_OP_BSSID:
		if (len != (int)sizeof(*cmd) + ETH_ALEN)
			err = -EINVAL;
		else
			err = mt_awdl_set_bssid(m, cmd->body);
		break;
	case MT7932_VNDR_AWDL_OP_DISABLE:
		err = mt_awdl_session(m, false);
		break;
	case MT7932_VNDR_AWDL_OP_CHANNELS:
		if (len != (int)sizeof(*cmd))
			err = -EINVAL;
		else
			err = mt_awdl_channel_list(m);
		break;
	case MT7932_VNDR_AWDL_OP_SERVICE:
	case MT7932_VNDR_AWDL_OP_TEMPLATE:
	case MT7932_VNDR_AWDL_OP_ACTION_FRAME: {
		u8 selector = op == MT7932_VNDR_AWDL_OP_SERVICE ? 3 :
			op == MT7932_VNDR_AWDL_OP_TEMPLATE ? 4 : 5;
		u16 body_len;

		if (len < (int)sizeof(*cmd) + 2) {
			err = -EINVAL;
			break;
		}
		body_len = get_unaligned_le16(cmd->body);
		if (body_len != len - sizeof(*cmd) - 2) {
			err = -EINVAL;
			break;
		}
		err = mt_awdl_data_cmd(m, selector, cmd->body + 2, body_len);
		break;
	}
	case MT7932_VNDR_AWDL_OP_PEER_ADD:
	case MT7932_VNDR_AWDL_OP_PEER_REMOVE:
		if (len != (int)sizeof(*cmd) + 6) {
			err = -EINVAL;
			break;
		}
		err = mt_awdl_peer_op(m, op == MT7932_VNDR_AWDL_OP_PEER_ADD,
				      cmd->body);
		break;
	case MT7932_VNDR_AWDL_OP_STATE: {
		void *reply = NULL;
		size_t reply_len = 0;

		if (len != (int)sizeof(*cmd) + 1) {
			err = -EINVAL;
			break;
		}
		err = mt_awdl_state(m, cmd->body[0], &reply, &reply_len);
		if (!err)
			err = mt_vendor_awdl_state_reply(wiphy, reply, reply_len);
		break;
	}
	case MT7932_VNDR_AWDL_OP_ELECTION:
		if (len != (int)sizeof(*cmd) + 5) {
			err = -EINVAL;
			break;
		}
		err = mt_awdl_election(m, get_unaligned_le32(cmd->body),
				       (s8)cmd->body[4]);
		break;
	default:
		err = -EINVAL;
	}
	mutex_unlock(&m->command_mutex);
	return err;
}

/* One firmware command, either descriptor, answered with the raw reply body.
 * This exists so the AWDL bring-up can talk to command ids the driver has no
 * typed path for; it is not used by the interface or by ordinary operation.
 */
static int mt_vendor_raw_handler(struct wiphy *wiphy, struct wireless_dev *wdev,
				 const void *data, int len)
{
	struct mt7932 *m = mt_from_wiphy(wiphy);
	const struct mt7932_vndr_raw_cmd *cmd = data;
	unsigned int body_len;
	int err;

	if (len < (int)sizeof(*cmd))
		return -EINVAL;
	body_len = get_unaligned_le16(&cmd->length);
	if (body_len != (unsigned int)(len - sizeof(*cmd)) ||
	    body_len > MT7932_AWDL_BODY_MAX)
		return -EINVAL;
	mutex_lock(&m->command_mutex);
	err = mt_request_mcu(m, get_unaligned_le16(&cmd->cid), cmd->ext, cmd->uni,
			     cmd->runtime, cmd->set, cmd->wait, cmd->body, body_len,
			     cmd->resp_eid ? (int)cmd->resp_eid : -1);
	if (!err && cmd->wait && m->reply_length > 36)
		err = mt_vendor_awdl_state_reply(wiphy, m->reply + 36,
						 m->reply_length - 36);
	mutex_unlock(&m->command_mutex);
	return err;
}

const struct wiphy_vendor_command mt7932_vendor_cmds[] = {
	{
		{
			.vendor_id = MEDIATEK_OUI,
			.subcmd = MT7932_VNDR_CMDS_AWDL
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.policy = VENDOR_CMD_RAW_DATA,
		.doit = mt_vendor_awdl_handler
	},
	{
		{
			.vendor_id = MEDIATEK_OUI,
			.subcmd = MT7932_VNDR_CMDS_AWDL_CMD
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.policy = VENDOR_CMD_RAW_DATA,
		.doit = mt_vendor_awdl_cmd_handler
	},
	{
		{
			.vendor_id = MEDIATEK_OUI,
			.subcmd = MT7932_VNDR_CMDS_RAW
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.policy = VENDOR_CMD_RAW_DATA,
		.doit = mt_vendor_raw_handler
	},
};

bool mt7932_awdl_enabled(void)
{
	return !!mt7932_awdl_enable;
}

/* --- received action-frame capture -------------------------------------- */

/* The firmware runs the AWDL peer table itself: it consumes PSFs, MIFs and
 * AWSFs, and nothing in this driver ever saw a received action frame. Apple's
 * driver does see them, keeps a peer cache, and hands that cache back to the
 * firmware when it seeds a peer with runtime element 0x10 (Unicast AWSF).
 * That is the step this driver is missing, and its absence is why the TX
 * manager refuses AWDL data frames even though sync (PSF) reaches peers.
 *
 * This ring captures the frames so the peer information can be obtained from
 * what the peer actually sent instead of guessed. It is a debug aid: off by
 * default, bounded, and read only through debugfs.
 */
int mt7932_awdl_capture;
module_param_named(awdl_capture, mt7932_awdl_capture, int, 0644);
MODULE_PARM_DESC(awdl_capture, "Capture received AWDL action frames for debugfs");

void mt_awdl_capture_action(struct mt7932 *m, const struct mt7932_rx_frame *frame)
{
	unsigned long flags;
	unsigned int slot;
	u16 subtype = frame->frame_control & 0x00f0;

	/* Action and action-no-ack only; beacons and probe responses are the
	 * same management type and carry nothing the peer work needs.
	 */
	if (subtype != IEEE80211_STYPE_ACTION && subtype != 0x00e0)
		return;
	if (frame->length < 24 || frame->length > MT_AWDL_CAPTURE_BYTES)
		return;
	spin_lock_irqsave(&m->response_lock, flags);
	slot = m->awdl_capture_next;
	m->awdl_capture_len[slot] = frame->length;
	m->awdl_capture_fc[slot] = frame->frame_control;
	m->awdl_capture_wtbl[slot] = frame->wtbl;
	m->awdl_capture_signal[slot] = mt7932_rx_signal(frame, m->antenna_mask);
	m->awdl_capture_channel[slot] = frame->channel;
	memcpy(m->awdl_capture_data[slot], frame->data, frame->length);
	m->awdl_capture_next = (slot + 1) % MT_AWDL_CAPTURE_SLOTS;
	m->awdl_capture_total++;
	spin_unlock_irqrestore(&m->response_lock, flags);
}

static int mt_awdl_actions_show(struct seq_file *s, void *unused)
{
	struct mt7932 *m = s->private;
	u16 len[MT_AWDL_CAPTURE_SLOTS], fc[MT_AWDL_CAPTURE_SLOTS];
	u16 wtbl[MT_AWDL_CAPTURE_SLOTS];
	s8 signal[MT_AWDL_CAPTURE_SLOTS];
	u8 channel[MT_AWDL_CAPTURE_SLOTS], next;
	unsigned long flags;
	unsigned int i, slot, offset;
	u32 total;
	u8 *data;

	data = kmalloc(sizeof(m->awdl_capture_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	spin_lock_irqsave(&m->response_lock, flags);
	memcpy(data, m->awdl_capture_data, sizeof(m->awdl_capture_data));
	memcpy(len, m->awdl_capture_len, sizeof(len));
	memcpy(fc, m->awdl_capture_fc, sizeof(fc));
	memcpy(wtbl, m->awdl_capture_wtbl, sizeof(wtbl));
	memcpy(signal, m->awdl_capture_signal, sizeof(signal));
	memcpy(channel, m->awdl_capture_channel, sizeof(channel));
	next = m->awdl_capture_next;
	total = m->awdl_capture_total;
	spin_unlock_irqrestore(&m->response_lock, flags);

	seq_printf(s, "captures: %u\n", total);
	for (i = 0; i < MT_AWDL_CAPTURE_SLOTS; i++) {
		slot = (next + i) % MT_AWDL_CAPTURE_SLOTS;
		if (!len[slot])
			continue;
		seq_printf(s, "frame len %u fc 0x%04x wtbl %u channel %u signal %d\n",
			   len[slot], fc[slot], wtbl[slot], channel[slot],
			   signal[slot]);
		/* %*ph stops at 64 bytes, and a PSF is longer than that; print it
		 * in chunks so nothing is lost to the format's limit.
		 */
		for (offset = 0; offset < len[slot]; offset += 64) {
			unsigned int chunk = min_t(unsigned int, len[slot] - offset, 64);
			seq_printf(s, "  %*ph\n", chunk,
				   data + (size_t)slot * MT_AWDL_CAPTURE_BYTES + offset);
		}
	}
	kfree(data);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(mt_awdl_actions);

void mt_awdl_debugfs_init(struct mt7932 *m)
{
	debugfs_create_file("mt7932_awdl_actions", 0400, m->wiphy->debugfsdir,
			    m, &mt_awdl_actions_fops);
}
