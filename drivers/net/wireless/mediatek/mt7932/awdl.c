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

#define MT7932_AWDL_IFNAME "awdl0"
#define MT7932_AWDL_CREATE_TIMEOUT (5 * HZ)
#define MT7932_AWDL_DESTROY_TIMEOUT (10 * HZ)

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
	u8 body[12] = { MT7932_AWDL_BSS, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 1 };
	unsigned long flags;
	int ret;

	if (!mt_awdl_rf_ready(m))
		return -ENODEV;

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
	eth_hw_addr_set(netdev, m->mac);
	strscpy(netdev->name, MT7932_AWDL_IFNAME, IFNAMSIZ);
	netif_carrier_off(netdev);
	memcpy(body + 4, m->mac, ETH_ALEN);

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
	strscpy(m->awdl_ifname, name, sizeof(m->awdl_ifname));
	WRITE_ONCE(m->awdl_active, true);
	WRITE_ONCE(m->awdl_destroying, false);
	WRITE_ONCE(m->awdl_enabled, false);
	WRITE_ONCE(m->awdl_pending, true);
	spin_unlock_irqrestore(&m->response_lock, flags);
	spin_lock_irqsave(&m->data_lock, flags);
	m->awdl_registered = false;
	m->awdl_present = false;
	m->awdl_absent = true;
	m->awdl_quota = 0;
	m->awdl_wtbl = 0;
	m->awdl_tx_seq = 0;
	memset(m->awdl_duplicates, 0, sizeof(m->awdl_duplicates));
	spin_unlock_irqrestore(&m->data_lock, flags);
	queue_delayed_work(system_long_wq, &m->awdl_timeout,
			   MT7932_AWDL_CREATE_TIMEOUT);

	ret = mt_request(m, 0x11, true, true, false, body, sizeof(body));
	mutex_unlock(&m->command_mutex);
	if (ret) {
		/* A present event may already be in flight; retire through
		 * the same path that created the state.
		 */
		dev_err(&m->pdev->dev, "AWDL_CREATE_FAILED: %d\n", ret);
		queue_delayed_work(system_long_wq, &m->awdl_timeout, 0);
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
	u8 body[12] = { MT7932_AWDL_BSS, 0 };
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
	ret = mt_request(m, 0x11, true, true, false, body, sizeof(body));
	mutex_unlock(&m->command_mutex);
	if (ret) {
		spin_lock_irqsave(&m->response_lock, flags);
		WRITE_ONCE(m->awdl_destroying, false);
		WRITE_ONCE(m->awdl_active, true);
		spin_unlock_irqrestore(&m->response_lock, flags);
		return ret;
	}
	queue_delayed_work(system_long_wq, &m->awdl_timeout,
			   MT7932_AWDL_DESTROY_TIMEOUT);
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
		mt_awdl_session(m, false, 0, 0, 0);
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
	u16 wtbl = READ_ONCE(m->awdl_wtbl);
	u8 *payload, *header;
	dma_addr_t dma;
	unsigned long flags;
	unsigned int slot;
	int ret;

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
					 slot, m->awdl_wtbl, 0, tid, false);
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
		 * reactivate with the new address. The absence and presence
		 * events that answer re-derive the WTBL entry.
		 */
		u8 off[12] = { MT7932_AWDL_BSS, 0 };
		u8 on[12] = { MT7932_AWDL_BSS, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 1 };

		memcpy(on + 4, sa->sa_data, ETH_ALEN);
		ret = mt_request(m, 0x11, true, true, false, off, sizeof(off));
		if (!ret) {
			spin_lock_irqsave(&m->response_lock, flags);
			WRITE_ONCE(m->awdl_active, true);
			spin_unlock_irqrestore(&m->response_lock, flags);
			ret = mt_request(m, 0x11, true, true, false, on, sizeof(on));
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

/* command_mutex held. Enable or disable the firmware's AWDL session. The
 * master availability window is a 2 GHz channel and the peer window a 5 GHz
 * one, both country-permitted; the firmware derives its slot density from
 * the bandwidth-availability map for the selected density.
 */
int mt_awdl_session(struct mt7932 *m, bool enable, u8 master_chan, u8 peer_chan,
		    u8 density)
{
	u8 body[4] = { enable ? 1 : 2, master_chan, peer_chan, density };
	struct ieee80211_channel *ch;
	int ret;

	if (!mt_awdl_rf_ready(m))
		return -ENODEV;
	if (enable) {
		if (!mt7932_channel_band(NL80211_BAND_2GHZ, master_chan) ||
		    !mt7932_channel_band(NL80211_BAND_5GHZ, peer_chan) ||
		    density > MT7932_AWDL_DENSITY_MIRROR)
			return -EINVAL;
		ch = ieee80211_get_channel(m->wiphy,
			ieee80211_channel_to_frequency(master_chan, NL80211_BAND_2GHZ));
		if (!ch || (ch->flags & IEEE80211_CHAN_DISABLED))
			return -EINVAL;
		ch = ieee80211_get_channel(m->wiphy,
			ieee80211_channel_to_frequency(peer_chan, NL80211_BAND_5GHZ));
		if (!ch || (ch->flags & IEEE80211_CHAN_DISABLED))
			return -EINVAL;
	}
	ret = mt_request(m, 0x7e, true, true, true, body, sizeof(body));
	if (ret)
		return ret;
	WRITE_ONCE(m->awdl_enabled, enable);
	dev_info(&m->pdev->dev, "AWDL session %s: master=%u peer=%u density=%u\n",
		 enable ? "enabled" : "disabled", master_chan, peer_chan, density);
	return 0;
}

/* command_mutex held. The length-prefixed SETs (service record, PSF
 * template, action frame) share one body layout: selector, u16 length,
 * then that many bytes. The firmware refuses these while the session is
 * disabled; the driver refuses them the same way rather than submitting
 * commands the firmware would answer with an error.
 */
int mt_awdl_data_cmd(struct mt7932 *m, u8 selector, const void *data, size_t length)
{
	size_t offset = 3;
	u8 *body;
	int ret;

	if (!mt_awdl_rf_ready(m) || !READ_ONCE(m->awdl_enabled))
		return -EROFS;
	if (selector != 3 && selector != 4 && selector != 5)
		return -EINVAL;
	if (!length || length > MT7932_AWDL_BODY_MAX - offset)
		return -EINVAL;
	body = kvmalloc(offset + length, GFP_KERNEL);
	if (!body)
		return -ENOMEM;
	body[0] = selector;
	put_unaligned_le16(length, body + 1);
	memcpy(body + offset, data, length);
	ret = mt_request(m, 0x7e, true, true, true, body, offset + length);
	kvfree(body);
	return ret;
}

/* command_mutex held. One peer table entry, added or removed. The firmware
 * tracks at most eight peers; a peer without an entry silently loses every
 * frame sent to it, which is why the window supervisor evicts and re-adds.
 */
int mt_awdl_peer_op(struct mt7932 *m, bool add, const u8 mac[ETH_ALEN])
{
	u8 body[7] = { add ? 6 : 7 };

	if (!mt_awdl_rf_ready(m) || !READ_ONCE(m->awdl_enabled))
		return -EROFS;
	if (mac[0] & 1)
		return -EINVAL; /* a group address names no peer */
	memcpy(body + 1, mac, ETH_ALEN);
	return mt_request(m, 0x7e, true, true, true, body, sizeof(body));
}

/* command_mutex held. One firmware state readback; the reply is the event
 * body. Selectors: 0 advertisers, 1 statistics, 2 opmode, 3 channel
 * sequence, 4 sync parameters.
 */
int mt_awdl_state(struct mt7932 *m, u8 selector, void **reply, size_t *length)
{
	u8 body[2] = { 8, selector };
	int ret;

	if (!mt_awdl_rf_ready(m) || !READ_ONCE(m->awdl_enabled))
		return -EROFS;
	if (selector > 4)
		return -EINVAL;
	ret = mt_request(m, 0x7e, true, true, true, body, sizeof(body));
	if (ret)
		return ret;
	if (m->reply_length < 37)
		return -EPROTO;
	*reply = m->reply + 36;
	*length = m->reply_length - 36;
	return 0;
}

/* command_mutex held. Election configuration: the metric this machine
 * advertises and the RSSI floor for adopting a peer as root.
 */
int mt_awdl_election(struct mt7932 *m, u32 metric, s8 rssi_threshold)
{
	u8 body[6] = { 9 };

	if (!mt_awdl_rf_ready(m))
		return -ENODEV;
	put_unaligned_le32(metric, body + 1);
	body[5] = rssi_threshold;
	return mt_request(m, 0x7e, true, true, true, body, sizeof(body));
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
	if (!op || op >= MT7932_VNDR_AWDL_OP_LAST)
		return -EINVAL;

	mutex_lock(&m->command_mutex);
	switch (op) {
	case MT7932_VNDR_AWDL_OP_ENABLE:
		if (len != (int)sizeof(*cmd) + 3)
			err = -EINVAL;
		else
			err = mt_awdl_session(m, true, cmd->body[0], cmd->body[1],
					      cmd->body[2]);
		break;
	case MT7932_VNDR_AWDL_OP_DISABLE:
		err = mt_awdl_session(m, false, 0, 0, 0);
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
			     cmd->set, cmd->wait, cmd->body, body_len);
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
