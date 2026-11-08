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

/* AWDL tx completions are logged per frame. Userspace counts them to tell a
 * radio that is transmitting from one whose firmware has parked the AWDL
 * data path, and turns this on only while it checks.
 */
int mt7932_awdl_trace;
module_param_named(awdl_trace, mt7932_awdl_trace, int, 0644);
MODULE_PARM_DESC(awdl_trace, "Log AWDL tx completions");

/* The WTBL entry of the AWDL BSS: sent in the activation and the BSS
 * description, written into the header of every frame the interface
 * transmits, and matched against received frames. The vendor driver asks
 * its security layer for a broadcast entry and passes what it gets; this
 * firmware reports no presence event, so the entry is never learned and
 * this is the only thing that can say it. The station's association takes
 * the station, broadcast and peer entries (seen as 1, 3 and 4), and the
 * AWDL BSS has an entry of its own in between: 2. Zero means unknown, and
 * with it the interface refuses to transmit rather than describe frames
 * with an entry the firmware may hand to another BSS.
 */
int mt7932_awdl_wtbl = 2;
module_param_named(awdl_wtbl, mt7932_awdl_wtbl, int, 0644);
MODULE_PARM_DESC(awdl_wtbl, "WTBL entry of the AWDL BSS (0: unknown, refuse to transmit)");

/* The own-MAC (OM) index the transmit descriptor names for AWDL frames. The
 * station BSS owns index 0; the AWDL BSS is a second BSS with its own address,
 * and the firmware attributes a frame, its keys and its address to a BSS by
 * this index. Naming the station's index transmits AWDL frames under the
 * station identity, which no AWDL peer accepts, and leaves frames addressed
 * to the AWDL interface unclaimed on receive. The firmware assigns the index
 * when the second BSS is activated; this is the value it uses for it.
 */
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

static bool mt_awdl_rf_ready(const struct mt7932 *m)
{
	return READ_ONCE(m->rf_ready) && !READ_ONCE(m->stopping) &&
	       !READ_ONCE(m->link_failed) && !READ_ONCE(m->cal_state.error);
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
	spin_unlock_irqrestore(&m->data_lock, flags);

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
	 * side is what decides the interface behaviour.
	 */
	wdev->iftype = NL80211_IFTYPE_STATION;
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
	ret = mt_awdl_bss_info(m, false, 0xff);
	if (!ret)
		ret = mt_awdl_bss_activate(m, true, mac, mt7932_awdl_wtbl);
	if (!ret)
		ret = mt_awdl_bss_info(m, true, mt7932_awdl_wtbl);
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
	ret = mt_awdl_bss_activate(m, false, m->awdl_mac, mt7932_awdl_wtbl);
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
	u8 *payload, *header;
	dma_addr_t dma;
	unsigned long flags;
	unsigned int slot;
	int ret;

	/* The entry comes from a presence event when the firmware ever
	 * reports one; until then it is what the module parameter says.
	 */
	if (!wtbl && mt7932_awdl_wtbl > 0 && mt7932_awdl_wtbl <= 0xff)
		wtbl = mt7932_awdl_wtbl;
	if (!netif_running(netdev) || !netif_device_present(netdev) ||
	    !READ_ONCE(m->awdl_registered) || !READ_ONCE(m->awdl_present) ||
	    !READ_ONCE(m->awdl_enabled) || !mt_awdl_rf_ready(m) ||
	    !wtbl || !READ_ONCE(m->data_ready) || skb->len < ETH_HLEN ||
	    skb->len > ETH_FRAME_LEN + VLAN_HLEN)
		goto drop;
	if (tid > 7)
		tid = 7;
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

	ret = eth_mac_addr(netdev, address);
	if (!ret) {
		/* Reprogram the AWDL BSS identity: deactivate it, then
		 * reactivate with the new address, and tell the session the
		 * BSSID moved with it. The absence and presence events that
		 * answer re-derive the WTBL entry.
		 */
		u8 mac[ETH_ALEN];

		ether_addr_copy(mac, sa->sa_data);
		ether_addr_copy(m->awdl_mac, mac);
		ret = mt_awdl_bss_activate(m, false, mac, mt7932_awdl_wtbl);
		if (!ret) {
			spin_lock_irqsave(&m->response_lock, flags);
			WRITE_ONCE(m->awdl_active, true);
			spin_unlock_irqrestore(&m->response_lock, flags);
			ret = mt_awdl_bss_activate(m, true, mac,
						  mt7932_awdl_wtbl);
			if (!ret)
				ret = mt_awdl_bss_info(m, true,
						       mt7932_awdl_wtbl);
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
	put_unaligned_le16(1, body);
	put_unaligned_le16(0, body + 2);
	put_unaligned_le32(type, body + 4);
	put_unaligned_le32(length, body + 8);
	memcpy(body + MT7932_AWDL_TLV_HDR, payload, length);
	ret = mt_request(m, 0xf7, true, true, false, body, total);
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

	body[0] = MT7932_AWDL_BSS;
	body[1] = active;
	body[2] = MT7932_AWDL_OPMODE;
	/* The vendor driver copies the current infrastructure primary channel
	 * into the AWDL BSS description.  Leaving this zero creates the BSS but
	 * gives the firmware no home channel from which to schedule its
	 * availability windows, so it neither hears nor emits AWDL action frames.
	 */
	body[0x0a] = m->connect_channel;
	body[0x2a] = 1;
	body[0x30] = 0xfe;
	body[0x32] = 0x4b;
	body[0x3a] = wtbl;
	body[0x5a] = 4;
	body[0x60] = 0xf0;
	body[0x61] = 0x3f;

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

	body[1] = active;
	body[10] = wtbl;
	memcpy(body + 4, mac, ETH_ALEN);

	return mt_request(m, 0x11, true, true, false, body, sizeof(body));
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
 * firmware hops the availability windows over this list: without it the
 * session is enabled but never goes on air, and discovery never starts.
 * The vendor driver sends the word that is always 1, the master preference
 * its BSS holds (4 by default), the count, then the channel numbers and,
 * in the same order, each channel's operating class. The classes come from
 * the driver's operating-class table: 81 covers a 2 GHz channel at 20 MHz,
 * 128 a 5 GHz channel at its 80 MHz bandwidth whatever the primary channel
 * inside the block.
 */
int mt_awdl_channel_list(struct mt7932 *m)
{
	static const struct {
		u8 first, last;
	} blocks5g[] = {
		{ 36, 48 }, { 52, 64 }, { 100, 112 }, { 116, 128 },
		{ 132, 144 }, { 149, 161 }, { 165, 177 },
	};
	u8 body[MT7932_AWDL_CHANNEL_BODY] = {};
	unsigned int count = 0;
	unsigned int i, j;
	int ret;

	if (!mt_awdl_rf_ready(m))
		return -ENODEV;

	for (i = 0; i < NUM_NL80211_BANDS && count < MT7932_AWDL_CHANNELS_MAX; i++) {
		struct ieee80211_supported_band *sband = m->wiphy->bands[i];

		if (!sband || (i != NL80211_BAND_2GHZ && i != NL80211_BAND_5GHZ))
			continue;
		for (j = 0; j < sband->n_channels && count < MT7932_AWDL_CHANNELS_MAX; j++) {
			struct ieee80211_channel *ch = &sband->channels[j];
			u8 class = 0;
			unsigned int k;

			if (ch->flags & IEEE80211_CHAN_DISABLED)
				continue;
			if (i == NL80211_BAND_2GHZ) {
				class = MT7932_AWDL_CLASS_2G;
			} else {
				for (k = 0; k < ARRAY_SIZE(blocks5g); k++)
					if (ch->hw_value >= blocks5g[k].first &&
					    ch->hw_value <= blocks5g[k].last) {
						class = MT7932_AWDL_CLASS_5G;
						break;
					}
			}
			if (!class)
				continue;
			body[6 + count] = ch->hw_value;
			body[6 + MT7932_AWDL_CHANNELS_MAX + count] = class;
			count++;
		}
	}
	if (!count)
		return -EINVAL;

	put_unaligned_le32(1, body);
	body[4] = 4;
	body[5] = count;
	ret = mt_awdl_tlv_cmd(m, MT7932_AWDL_TLV_CHANNELS, body, sizeof(body));
	if (!ret)
		dev_info(&m->pdev->dev, "AWDL channel list: %u channels\n", count);
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

int mt_awdl_peer_op(struct mt7932 *m, bool add, const u8 mac[ETH_ALEN])
{
	return -EOPNOTSUPP;
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
