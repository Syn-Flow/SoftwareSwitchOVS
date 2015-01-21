/*
 * Copyright (c) 2007-2012 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef DATAPATH_H
#define DATAPATH_H 1

#include <asm/page.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/u64_stats_sync.h>

#include "compat.h"
#include "flow.h"
#include "flow_table.h"
#include "vlan.h"
#include "vport.h"

#define DP_MAX_PORTS		USHRT_MAX
#define DP_VPORT_HASH_BUCKETS	1024

#define SAMPLE_ACTION_DEPTH 3

/**
 * struct dp_stats_percpu - per-cpu packet processing statistics for a given
 * datapath.
 * @n_hit: Number of received packets for which a matching flow was found in
 * the flow table.
 * @n_miss: Number of received packets that had no matching flow in the flow
 * table.  The sum of @n_hit and @n_miss is the number of packets that have
 * been received by the datapath.
 * @n_lost: Number of received packets that had no matching flow in the flow
 * table that could not be sent to userspace (normally due to an overflow in
 * one of the datapath's queues).
 * @n_mask_hit: Number of masks looked up for flow match.
 *   @n_mask_hit / (@n_hit + @n_missed)  will be the average masks looked
 *   up per packet.
 */
struct dp_stats_percpu {
	u64 n_hit;
	u64 n_missed;
	u64 n_lost;
	u64 n_mask_hit;
	struct u64_stats_sync sync;
};

/**
 * struct datapath - datapath for flow-based packet switching
 * @rcu: RCU callback head for deferred destruction.
 * @list_node: Element in global 'dps' list.
 * @table: flow table.
 * @ports: Hash table for ports.  %OVSP_LOCAL port always exists.  Protected by
 * ovs_mutex and RCU.
 * @stats_percpu: Per-CPU datapath statistics.
 * @net: Reference to net namespace.
 *
 * Context: See the comment on locking at the top of datapath.c for additional
 * locking information.
 */
struct datapath {
	struct rcu_head rcu;
	struct list_head list_node;

	/* Flow table. */
	struct flow_table table;

//*************F3_Modify_Part_Begin***************************
	struct flow_table f3_table;
//**************F3_Modify_Part_End****************************
	/* Switch ports. */
	struct hlist_head *ports;

	/* Stats. */
	struct dp_stats_percpu __percpu *stats_percpu;

#ifdef CONFIG_NET_NS
	/* Network namespace ref. */
	struct net *net;
#endif

	u32 user_features;
};

/**
 * struct ovs_skb_cb - OVS data in skb CB
 * @flow: The flow associated with this packet.  May be %NULL if no flow.
 * @pkt_key: The flow information extracted from the packet.  Must be nonnull.
 * @tun_key: Key for the tunnel that encapsulated this packet. NULL if the
 * packet is not being tunneled.
 */
struct ovs_skb_cb {
	struct sw_flow		*flow;
	struct sw_flow_key	*pkt_key;
	struct ovs_key_ipv4_tunnel  *tun_key;

	//*************F3_Modify_Part_Begin***************************
	struct vport *vport; /* For flood action */
	//**************F3_Modify_Part_End****************************
};
#define OVS_CB(skb) ((struct ovs_skb_cb *)(skb)->cb)

/**
 * struct dp_upcall - metadata to include with a packet to send to userspace
 * @cmd: One of %OVS_PACKET_CMD_*.
 * @key: Becomes %OVS_PACKET_ATTR_KEY.  Must be nonnull.
 * @userdata: If nonnull, its variable-length value is passed to userspace as
 * %OVS_PACKET_ATTR_USERDATA.
 * @portid: Netlink PID to which packet should be sent.  If @portid is 0 then no
 * packet is sent and the packet is accounted in the datapath's @n_lost
 * counter.
 */
struct dp_upcall_info {
	u8 cmd;
	const struct sw_flow_key *key;
	const struct nlattr *userdata;
	u32 portid;
};

/**
 * struct ovs_net - Per net-namespace data for ovs.
 * @dps: List of datapaths to enable dumping them all out.
 * Protected by genl_mutex.
 * @vport_net: Per network namespace data for vport.
 */
struct ovs_net {
	struct list_head dps;
	struct vport_net vport_net;
	struct work_struct dp_notify_work;
};

extern int ovs_net_id;
void ovs_lock(void);
void ovs_unlock(void);

#ifdef CONFIG_LOCKDEP
int lockdep_ovsl_is_held(void);
#else
#define lockdep_ovsl_is_held()	1
#endif

#define ASSERT_OVSL()		WARN_ON(unlikely(!lockdep_ovsl_is_held()))
#define ovsl_dereference(p)					\
	rcu_dereference_protected(p, lockdep_ovsl_is_held())
#define rcu_dereference_ovsl(p)					\
	rcu_dereference_check(p, lockdep_ovsl_is_held())

static inline struct net *ovs_dp_get_net(struct datapath *dp)
{
	return read_pnet(&dp->net);
}

static inline void ovs_dp_set_net(struct datapath *dp, struct net *net)
{
	write_pnet(&dp->net, net);
}

struct vport *ovs_lookup_vport(const struct datapath *dp, u16 port_no);

static inline struct vport *ovs_vport_rcu(const struct datapath *dp, int port_no)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return ovs_lookup_vport(dp, port_no);
}

static inline struct vport *ovs_vport_ovsl_rcu(const struct datapath *dp, int port_no)
{
	WARN_ON_ONCE(!rcu_read_lock_held() && !lockdep_ovsl_is_held());
	return ovs_lookup_vport(dp, port_no);
}

static inline struct vport *ovs_vport_ovsl(const struct datapath *dp, int port_no)
{
	ASSERT_OVSL();
	return ovs_lookup_vport(dp, port_no);
}

extern struct notifier_block ovs_dp_device_notifier;
extern struct genl_multicast_group ovs_dp_vport_multicast_group;

void ovs_dp_process_received_packet(struct vport *, struct sk_buff *);
void ovs_dp_detach_port(struct vport *);
int ovs_dp_upcall(struct datapath *, struct sk_buff *,
		  const struct dp_upcall_info *);

const char *ovs_dp_name(const struct datapath *dp);
struct sk_buff *ovs_vport_cmd_build_info(struct vport *, u32 portid, u32 seq,
					 u8 cmd);

int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb);
void ovs_dp_notify_wq(struct work_struct *work);




int f3_find_netdev_upcall_port(struct datapath *dp);
int f3_push_skb_header(struct sk_buff *skb, u8 ttl, u8 ap_len, actionptr *ap_list);
int f3_extract_f3_header(struct sk_buff * skb, u8* ttl, u8* ptrs, actionptr *ap_list);
int f3_set_skb_ptrs(struct sk_buff *skb, u8 ptrs);
int f3_set_skb_ttl(struct sk_buff *skb, u8 ttl);
u8 f3_get_skb_ptrs(struct sk_buff *skb);
u8 f3_get_skb_ttl(struct sk_buff *skb);
int f3_skb_push(struct sk_buff *skb, int size);
int f3_is_f3_packet(struct sk_buff *skb) ;
int f3_queue_userspace_upcall(struct datapath *dp, struct sk_buff *skb);
int ovs_f3_execute_actions(struct datapath *dp, struct sk_buff *skb);
int f3_pop_ap(u8 *ap_len, actionptr *ap_list);
actionptr f3_pop_skb_ap(struct sk_buff *skb);
int f3_push_header(struct sk_buff *skb, const struct nlattr *attr, u8* ttl, u8* ap_len, actionptr *ap_list);
int f3_push_skb_ap(struct sk_buff *skb, actionptr ap);
int f3_push_ap(u8 *ap_len, actionptr *ap, const struct nlattr *attr);
int f3_flood(struct sk_buff *skb, struct datapath *dp, struct vport *origin_vport, u8 ttl, u8 ap_len, actionptr *ap_list, bool pop_f3_header);
int f3_jump(actionptr *jump_ap, const struct nlattr *attr);
int f3_dec_ttl(u8 *ttl);
int f3_set_ttl(u8 *ttl, const struct nlattr* attr);
int f3_output_userspace(struct datapath *dp, struct sk_buff *skb,
			    const struct nlattr *attr, u8 ttl, u8 ap_len, actionptr *ap, bool pop_f3_header);

int especially_judge(struct sk_buff *skb);







#define OVS_NLERR(fmt, ...) \
	pr_info_once("netlink: " fmt, ##__VA_ARGS__)

#endif /* datapath.h */