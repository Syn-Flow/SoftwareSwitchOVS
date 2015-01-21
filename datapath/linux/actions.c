/*
 * Copyright (c) 2007-2013 Nicira, Inc.
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/openvswitch.h>
#include <linux/sctp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/sctp/checksum.h>

#include "datapath.h"
#include "vlan.h"
#include "vport.h"
#define NET_IP_ALIGN__ 2
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			      const struct nlattr *attr, int len, bool keep_skb);

static int make_writable(struct sk_buff *skb, int write_len)
{
	if (!skb_cloned(skb) || skb_clone_writable(skb, write_len))
		return 0;

	return pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
}

/* remove VLAN header from packet and update csum accordingly. */
static int __pop_vlan_tci(struct sk_buff *skb, __be16 *current_tci)
{
	struct vlan_hdr *vhdr;
	int err;

	err = make_writable(skb, VLAN_ETH_HLEN);
	if (unlikely(err))
		return err;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = csum_sub(skb->csum, csum_partial(skb->data
					+ (2 * ETH_ALEN), VLAN_HLEN, 0));

	vhdr = (struct vlan_hdr *)(skb->data + ETH_HLEN);
	*current_tci = vhdr->h_vlan_TCI;

	memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);
	__skb_pull(skb, VLAN_HLEN);

	vlan_set_encap_proto(skb, vhdr);
	skb->mac_header += VLAN_HLEN;
	skb_reset_mac_len(skb);

	return 0;
}

static int pop_vlan(struct sk_buff *skb)
{
	__be16 tci;
	int err;

	if (likely(vlan_tx_tag_present(skb))) {
		vlan_set_tci(skb, 0);
	} else {
		if (unlikely(skb->protocol != htons(ETH_P_8021Q) ||
			     skb->len < VLAN_ETH_HLEN))
			return 0;

		err = __pop_vlan_tci(skb, &tci);
		if (err)
			return err;
	}
	/* move next vlan tag to hw accel tag */
	if (likely(skb->protocol != htons(ETH_P_8021Q) ||
		   skb->len < VLAN_ETH_HLEN))
		return 0;

	err = __pop_vlan_tci(skb, &tci);
	if (unlikely(err))
		return err;

	__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), ntohs(tci));
	return 0;
}

static int push_vlan(struct sk_buff *skb, const struct ovs_action_push_vlan *vlan)
{
	if (unlikely(vlan_tx_tag_present(skb))) {
		u16 current_tag;

		/* push down current VLAN tag */
		current_tag = vlan_tx_tag_get(skb);

		if (!__vlan_put_tag(skb, skb->vlan_proto, current_tag))
			return -ENOMEM;

		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->csum = csum_add(skb->csum, csum_partial(skb->data
					+ (2 * ETH_ALEN), VLAN_HLEN, 0));

	}
	__vlan_hwaccel_put_tag(skb, vlan->vlan_tpid, ntohs(vlan->vlan_tci) & ~VLAN_TAG_PRESENT);
	return 0;
}

static bool f3_check_all_zero(char *ch, int len) {
	for (; len --; ch ++)
		if (*ch != 0)
			return 0;
	return 1;
}

static int set_eth_addr(struct sk_buff *skb,
			const struct ovs_key_ethernet *eth_key)
{
	int err;
	err = make_writable(skb, ETH_HLEN);
	if (unlikely(err))
		return err;

	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_ALEN * 2);
	
	if (!f3_check_all_zero(eth_key->eth_src, ETH_ALEN))
		memcpy(eth_hdr(skb)->h_source, eth_key->eth_src, ETH_ALEN);
	if (!f3_check_all_zero(eth_key->eth_dst, ETH_ALEN))
		memcpy(eth_hdr(skb)->h_dest, eth_key->eth_dst, ETH_ALEN);

	ovs_skb_postpush_rcsum(skb, eth_hdr(skb), ETH_ALEN * 2);

	return 0;
}

static void set_ip_addr(struct sk_buff *skb, struct iphdr *nh,
				__be32 *addr, __be32 new_addr)
{
	int transport_len = skb->len - skb_transport_offset(skb);

	if (nh->protocol == IPPROTO_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			inet_proto_csum_replace4(&tcp_hdr(skb)->check, skb,
						 *addr, new_addr, 1);
	} else if (nh->protocol == IPPROTO_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
				inet_proto_csum_replace4(&uh->check, skb,
							 *addr, new_addr, 1);
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	}

	csum_replace4(&nh->check, *addr, new_addr);
	skb_clear_rxhash(skb);
	*addr = new_addr;
}

static void update_ipv6_checksum(struct sk_buff *skb, u8 l4_proto,
				 __be32 addr[4], const __be32 new_addr[4])
{
	int transport_len = skb->len - skb_transport_offset(skb);

	if (l4_proto == IPPROTO_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			inet_proto_csum_replace16(&tcp_hdr(skb)->check, skb,
						  addr, new_addr, 1);
	} else if (l4_proto == IPPROTO_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
				inet_proto_csum_replace16(&uh->check, skb,
							  addr, new_addr, 1);
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	}
}

static void set_ipv6_addr(struct sk_buff *skb, u8 l4_proto,
			  __be32 addr[4], const __be32 new_addr[4],
			  bool recalculate_csum)
{
	if (recalculate_csum)
		update_ipv6_checksum(skb, l4_proto, addr, new_addr);

	skb_clear_rxhash(skb);
	memcpy(addr, new_addr, sizeof(__be32[4]));
}

static void set_ipv6_tc(struct ipv6hdr *nh, u8 tc)
{
	nh->priority = tc >> 4;
	nh->flow_lbl[0] = (nh->flow_lbl[0] & 0x0F) | ((tc & 0x0F) << 4);
}

static void set_ipv6_fl(struct ipv6hdr *nh, u32 fl)
{
	nh->flow_lbl[0] = (nh->flow_lbl[0] & 0xF0) | (fl & 0x000F0000) >> 16;
	nh->flow_lbl[1] = (fl & 0x0000FF00) >> 8;
	nh->flow_lbl[2] = fl & 0x000000FF;
}

static void set_ip_ttl(struct sk_buff *skb, struct iphdr *nh, u8 new_ttl)
{
	csum_replace2(&nh->check, htons(nh->ttl << 8), htons(new_ttl << 8));
	nh->ttl = new_ttl;
}

static int set_ipv4(struct sk_buff *skb, const struct ovs_key_ipv4 *ipv4_key)
{
	struct iphdr *nh;
	int err;

	err = make_writable(skb, skb_network_offset(skb) +
				 sizeof(struct iphdr));
	if (unlikely(err))
		return err;

	nh = ip_hdr(skb);

	if (ipv4_key->ipv4_src != nh->saddr && !f3_check_all_zero(&(ipv4_key->ipv4_src), 4) )
		set_ip_addr(skb, nh, &nh->saddr, ipv4_key->ipv4_src);

	if (ipv4_key->ipv4_dst != nh->daddr && !f3_check_all_zero(&(ipv4_key->ipv4_dst), 4))
		set_ip_addr(skb, nh, &nh->daddr, ipv4_key->ipv4_dst);

	if (ipv4_key->ipv4_tos != nh->tos && !f3_check_all_zero(&(ipv4_key->ipv4_tos), 1))
		ipv4_change_dsfield(nh, 0, ipv4_key->ipv4_tos);

	if (ipv4_key->ipv4_ttl != nh->ttl  && !f3_check_all_zero(&(ipv4_key->ipv4_ttl), 1))
		set_ip_ttl(skb, nh, ipv4_key->ipv4_ttl);

	return 0;
}

static int set_ipv6(struct sk_buff *skb, const struct ovs_key_ipv6 *ipv6_key)
{
	struct ipv6hdr *nh;
	int err;
	__be32 *saddr;
	__be32 *daddr;

	err = make_writable(skb, skb_network_offset(skb) +
			    sizeof(struct ipv6hdr));
	if (unlikely(err))
		return err;

	nh = ipv6_hdr(skb);
	saddr = (__be32 *)&nh->saddr;
	daddr = (__be32 *)&nh->daddr;

	if (memcmp(ipv6_key->ipv6_src, saddr, sizeof(ipv6_key->ipv6_src)))
		set_ipv6_addr(skb, ipv6_key->ipv6_proto, saddr,
			      ipv6_key->ipv6_src, true);

	if (memcmp(ipv6_key->ipv6_dst, daddr, sizeof(ipv6_key->ipv6_dst))) {
		unsigned int offset = 0;
		int flags = OVS_IP6T_FH_F_SKIP_RH;
		bool recalc_csum = true;

		if (ipv6_ext_hdr(nh->nexthdr))
			recalc_csum = ipv6_find_hdr(skb, &offset,
						    NEXTHDR_ROUTING, NULL,
						    &flags) != NEXTHDR_ROUTING;

		set_ipv6_addr(skb, ipv6_key->ipv6_proto, daddr,
			      ipv6_key->ipv6_dst, recalc_csum);
	}

	set_ipv6_tc(nh, ipv6_key->ipv6_tclass);
	set_ipv6_fl(nh, ntohl(ipv6_key->ipv6_label));
	nh->hop_limit = ipv6_key->ipv6_hlimit;

	return 0;
}

/* Must follow make_writable() since that can move the skb data. */
static void set_tp_port(struct sk_buff *skb, __be16 *port,
			 __be16 new_port, __sum16 *check)
{
	inet_proto_csum_replace2(check, skb, *port, new_port, 0);
	*port = new_port;
	skb_clear_rxhash(skb);
}

static void set_udp_port(struct sk_buff *skb, __be16 *port, __be16 new_port)
{
	struct udphdr *uh = udp_hdr(skb);

	if (uh->check && skb->ip_summed != CHECKSUM_PARTIAL) {
		set_tp_port(skb, port, new_port, &uh->check);

		if (!uh->check)
			uh->check = CSUM_MANGLED_0;
	} else {
		*port = new_port;
		skb_clear_rxhash(skb);
	}
}

static int set_udp(struct sk_buff *skb, const struct ovs_key_udp *udp_port_key)
{
	struct udphdr *uh;
	int err;

	err = make_writable(skb, skb_transport_offset(skb) +
				 sizeof(struct udphdr));
	if (unlikely(err))
		return err;

	uh = udp_hdr(skb);
	if (udp_port_key->udp_src != uh->source  && 
         !f3_check_all_zero(&udp_port_key->udp_src, 2) )
		set_udp_port(skb, &uh->source, udp_port_key->udp_src);

	if (udp_port_key->udp_dst != uh->dest &&
 !f3_check_all_zero(&udp_port_key->udp_dst, 2))
		set_udp_port(skb, &uh->dest, udp_port_key->udp_dst);

	return 0;
}

static int set_tcp(struct sk_buff *skb, const struct ovs_key_tcp *tcp_port_key)
{
	struct tcphdr *th;
	int err;

	err = make_writable(skb, skb_transport_offset(skb) +
				 sizeof(struct tcphdr));
	if (unlikely(err))
		return err;

	th = tcp_hdr(skb);
	if (tcp_port_key->tcp_src != th->source && 
	!f3_check_all_zero(&(tcp_port_key->tcp_src), 2) )
		set_tp_port(skb, &th->source, tcp_port_key->tcp_src, &th->check);

	if (tcp_port_key->tcp_dst != th->dest  && 
	!f3_check_all_zero(&(tcp_port_key->tcp_dst), 2) )
		set_tp_port(skb, &th->dest, tcp_port_key->tcp_dst, &th->check);

	return 0;
}

static int set_sctp(struct sk_buff *skb,
		     const struct ovs_key_sctp *sctp_port_key)
{
	struct sctphdr *sh;
	int err;
	unsigned int sctphoff = skb_transport_offset(skb);

	err = make_writable(skb, sctphoff + sizeof(struct sctphdr));
	if (unlikely(err))
		return err;

	sh = sctp_hdr(skb);
	if (sctp_port_key->sctp_src != sh->source ||
	    sctp_port_key->sctp_dst != sh->dest) {
		__le32 old_correct_csum, new_csum, old_csum;

		old_csum = sh->checksum;
		old_correct_csum = sctp_compute_cksum(skb, sctphoff);

		sh->source = sctp_port_key->sctp_src;
		sh->dest = sctp_port_key->sctp_dst;

		new_csum = sctp_compute_cksum(skb, sctphoff);

		/* Carry any checksum errors through. */
		sh->checksum = old_csum ^ old_correct_csum ^ new_csum;

		skb_clear_rxhash(skb);
	}

	return 0;
}

static int do_output(struct datapath *dp, struct sk_buff *skb, int out_port)
{
	struct vport *vport;

	if (unlikely(!skb))
		return -ENOMEM;

	vport = ovs_vport_rcu(dp, out_port);
	if (unlikely(!vport)) {
		kfree_skb(skb);
		return -ENODEV;
	}

	ovs_vport_send(vport, skb);
	return 0;
}

static int output_userspace(struct datapath *dp, struct sk_buff *skb,
			    const struct nlattr *attr)
{
	struct dp_upcall_info upcall;
	const struct nlattr *a;
	int rem;

	BUG_ON(!OVS_CB(skb)->pkt_key);

	upcall.cmd = OVS_PACKET_CMD_ACTION;
	upcall.key = OVS_CB(skb)->pkt_key;
	upcall.userdata = NULL;
	upcall.portid = 0;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_USERSPACE_ATTR_USERDATA:
			upcall.userdata = a;
			break;

		case OVS_USERSPACE_ATTR_PID:
			upcall.portid = nla_get_u32(a);
			break;
		}
	}

	return ovs_dp_upcall(dp, skb, &upcall);
}

int f3_output_userspace(struct datapath *dp, struct sk_buff *skb,
			    const struct nlattr *attr, u8 ttl, u8 ap_len, actionptr *ap_list, bool pop_f3_header)
{
	#ifdef OVS_DEBUG
	printk("enter f3_output_userspace\n");
	#endif
	struct dp_upcall_info upcall;
	struct sw_flow_key key;
	const struct nlattr *a;
	int rem;

	upcall.cmd = OVS_F3_PACKET_CMD_ACTION;
	#ifdef OVS_DEBUG
	printk("f3_in_port = %d\n", OVS_CB(skb)->vport->port_no);
	#endif
	ovs_flow_extract(skb, OVS_CB(skb)->vport->port_no, &key);
	upcall.key = &key;
	upcall.userdata = NULL;
	upcall.portid = OVS_CB(skb)->vport->upcall_portid;
	if (!pop_f3_header)
		f3_push_skb_header(skb, ttl, ap_len, ap_list);
	return ovs_dp_upcall(dp, skb, &upcall);
}



static int sample(struct datapath *dp, struct sk_buff *skb,
		  const struct nlattr *attr)
{
	const struct nlattr *acts_list = NULL;
	const struct nlattr *a;
	int rem;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_SAMPLE_ATTR_PROBABILITY:
			if (net_random() >= nla_get_u32(a))
				return 0;
			break;

		case OVS_SAMPLE_ATTR_ACTIONS:
			acts_list = a;
			break;
		}
	}

	return do_execute_actions(dp, skb, nla_data(acts_list),
				  nla_len(acts_list), true);
}

static int execute_set_action(struct sk_buff *skb,
				 const struct nlattr *nested_attr)
{
	int err = 0;

	switch (nla_type(nested_attr)) {
	case OVS_KEY_ATTR_PRIORITY:
		skb->priority = nla_get_u32(nested_attr);
		break;

	case OVS_KEY_ATTR_SKB_MARK:
		skb->mark = nla_get_u32(nested_attr);
		break;

	case OVS_KEY_ATTR_IPV4_TUNNEL:
		OVS_CB(skb)->tun_key = nla_data(nested_attr);
		break;

	case OVS_KEY_ATTR_ETHERNET:
		err = set_eth_addr(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_IPV4:
		err = set_ipv4(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_IPV6:
		err = set_ipv6(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_TCP:
		err = set_tcp(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_UDP:
		err = set_udp(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_SCTP:
		err = set_sctp(skb, nla_data(nested_attr));
		break;
	}

	return err;
}

static int f3_header_length(u8 ap_len) {
	return sizeof(actionptr) * ap_len + 2;
}

/* Execute a list of actions against 'skb'. */
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			const struct nlattr *attr, int len, bool keep_skb)
{
	/* Every output action needs a separate clone of 'skb', but the common
	 * case is just a single output action, so that doing a clone and
	 * then freeing the original skbuff is wasteful.  So the following code
	 * is slightly obscure just to avoid that. */
	#ifdef OVS_DEBUG
	printk("do_execute_actions\n");
	#endif
	int prev_port = -1;
	const struct nlattr *a;
	int rem, err;
	/* 
		No Jump
		No F3OutputUserspace
	*/
	u8 f3_ttl = 0;
	u8 ap_len = 0;
	bool pop_f3_header = false;
	/* 
		If in this flow table, there isn't a action that is 
		"Push_F3_Header", the function will use the origin 
		function e.g. do_output(). Else it will do f3_do_output().
	*/
	bool push_f3_header = false;
	actionptr *ap_list = kmalloc(MAX_AP_NUMBER, GFP_ATOMIC);
	
	for (a = attr, rem = len; rem > 0;
	     a = nla_next(a, &rem)) {
		int err = 0;
		if (prev_port != -1) {
			if (push_f3_header) {
				f3_push_skb_header(skb, f3_ttl, ap_len, ap_list);
				do_output(dp, skb_copy(skb, GFP_ATOMIC), prev_port);
				skb_pull(skb, f3_header_length(ap_len));
			} else {
				do_output(dp, skb_copy(skb, GFP_ATOMIC), prev_port);
			}
			prev_port = -1;
		}
	#ifdef OVS_DEBUG
		printk("nla_type(a) = %d\n", nla_type(a));
	#endif

		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_OUTPUT:
			prev_port = nla_get_u32(a);
			break;

		case OVS_ACTION_ATTR_USERSPACE:
			output_userspace(dp, skb, a);
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			err = push_vlan(skb, nla_data(a));
			if (unlikely(err)) /* skb already freed. */
				return err;
			break;

		case OVS_ACTION_ATTR_POP_VLAN:
			err = pop_vlan(skb);
			break;

		case OVS_ACTION_ATTR_SET:
			err = execute_set_action(skb, nla_data(a));
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = sample(dp, skb, a);
			break;
		
		case OVS_ACTION_ATTR_F3_JUMP:
			err = -22;
			break;

		case OVS_ACTION_ATTR_PUSH_F3_HEADER:
			err = f3_push_header(skb, a, &f3_ttl, &ap_len, ap_list);
			push_f3_header = true;
	#ifdef OVS_DEBUG
			printk("push header %d %d %d\n", f3_ttl, ap_len, ap_list[0]);
	#endif
			
			break;
		

		case OVS_ACTION_ATTR_POP_F3_HEADER:
			pop_f3_header = true;
			break;
		

		case OVS_ACTION_ATTR_PUSH_F3_AP:
			err = f3_push_ap(&ap_len, ap_list, a);
			break;
		

		case OVS_ACTION_ATTR_POP_F3_AP:
			err = f3_pop_ap(&ap_len, ap_list);
			break;
		

		case OVS_ACTION_ATTR_SET_F3_TTL:
			err = f3_set_ttl(&f3_ttl, a);
			break;
		

		case OVS_ACTION_ATTR_DEC_F3_TTL:
			err = f3_dec_ttl(&f3_ttl);
			break;

		case OVS_ACTION_ATTR_F3_FLOOD:
			err = f3_flood(skb_copy(skb, GFP_ATOMIC), dp, OVS_CB(skb)->vport, f3_ttl, ap_len, ap_list, pop_f3_header);
			break;

		}
		if (unlikely(err)) {
			kfree_skb(skb);
			return err;
		}
	}

	if (prev_port != -1) {
		if (keep_skb)
			skb = skb_copy(skb, GFP_ATOMIC);
		if (push_f3_header) {
			f3_push_skb_header(skb, f3_ttl, ap_len, ap_list);
			do_output(dp, skb, prev_port);
		} else {
			do_output(dp, skb_copy(skb, GFP_ATOMIC), prev_port);
		}
	} else if (!keep_skb)
		consume_skb(skb);

	return 0;
}

/* We limit the number of times that we pass into execute_actions()
 * to avoid blowing out the stack in the event that we have a loop. */
#define MAX_LOOPS 4

struct loop_counter {
	u8 count;		/* Count. */
	bool looping;		/* Loop detected? */
};

static DEFINE_PER_CPU(struct loop_counter, loop_counters);

static int loop_suppress(struct datapath *dp, struct sw_flow_actions *actions)
{
	if (net_ratelimit())
		pr_warn("%s: flow looped %d times, dropping\n",
				ovs_dp_name(dp), MAX_LOOPS);
	actions->actions_len = 0;
	return -ELOOP;
}

/* Execute a list of actions against 'skb'. */
int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb)
{
	struct sw_flow_actions *acts = rcu_dereference(OVS_CB(skb)->flow->sf_acts);
	struct loop_counter *loop;
	int error;

	/* Check whether we've looped too much. */
	loop = &__get_cpu_var(loop_counters);
	if (unlikely(++loop->count > MAX_LOOPS))
		loop->looping = true;
	if (unlikely(loop->looping)) {
		error = loop_suppress(dp, acts);
		kfree_skb(skb);
		goto out_loop;
	}

	OVS_CB(skb)->tun_key = NULL;
	error = do_execute_actions(dp, skb, acts->actions,
					 acts->actions_len, false);

	/* Check whether sub-actions looped too much. */
	if (unlikely(loop->looping))
		error = loop_suppress(dp, acts);

out_loop:
	/* Decrement loop counter. */
	if (!--loop->count)
		loop->looping = false;

	return error;
}


int f3_find_netdev_upcall_port(struct datapath *dp) {
	if (dp == NULL) {
		return 0;
	}
	rcu_read_lock();
	int port_id = 0, i;
	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
		struct vport *vport;
		struct hlist_node *n;
		if (port_id != 0)
			break;
		hlist_for_each_entry_safe(vport, n, &dp->ports[i], dp_hash_node) {
			if ((vport->port_type == OVS_VPORT_TYPE_NETDEV))
				port_id = vport->upcall_portid;
	#ifdef OVS_DEBUG
			else
				printk("<3>""f3_find_netdev_upcall_port except internal port %d %d\n", vport->port_information, vport->port_no);
	#endif
		}
	}
	#ifdef OVS_DEBUG2
	printk("<3>""f3_find_netdev_upcall_port %d\n", port_id);
	#endif
	rcu_read_unlock();
	return port_id;
}


int f3_push_skb_header(struct sk_buff *skb, u8 ttl, u8 ap_len, actionptr *ap) {
	int i;
	actionptr *ap_ptr, *skb_ptr;
	int temp_ap;

	if (f3_skb_push(skb, f3_header_length(ap_len))) {
		printk("<3>""f3_push_skb_header no memory create new skb\n");	
		return -12;
	}
	f3_set_skb_ttl(skb, ttl);
	f3_set_skb_ptrs(skb, ap_len);
	ap_ptr = &ap[ap_len - 1];
	skb_ptr = (actionptr *)(skb->data + 2);
	
	for (i = ap_len - 1; i >= 0; --i, --ap_ptr, ++skb_ptr) {
		if (sizeof(actionptr) == 2)
			temp_ap = htons(*ap_ptr);
		else
		if (sizeof(actionptr) == 4)
			temp_ap = htonl(*ap_ptr);
		memcpy(skb_ptr, &temp_ap, sizeof(actionptr));
	}
	#ifdef OVS_DEBUG2
		printk("push_skb_header %d\n", *((actionptr *)(skb->data+2)));
	#endif
	return 0;
}

int f3_extract_f3_header(struct sk_buff *skb, u8 *ttl, u8 *ptrs, actionptr *ap_list) {
	int j, k;
	*ttl = f3_get_skb_ttl(skb);
	*ptrs = f3_get_skb_ptrs(skb);
	if (*ptrs >= 40) {
		return -1;
	}
	#ifdef OVS_DEBUG
	printk("<3>""f3_extract_f3_header ttl = %d, ptrs = %d\n", *ttl, *ptrs);
	#endif
	for (j = 0, k = *ptrs - 1; j < *ptrs; j ++, k --) {
		memcpy(&ap_list[j], (void *)(skb->data + 2 + k * sizeof(actionptr)), sizeof(actionptr));
		if (sizeof(actionptr) == 2)
			ap_list[j] = ntohs(ap_list[j]);
		else 
		if (sizeof(actionptr) == 4)
			ap_list[j] = ntohl(ap_list[j]);
	}
	skb_pull(skb, f3_header_length(*ptrs));
	return 0;
}


u8 f3_get_skb_ttl(struct sk_buff *skb) {
	return *((u8 *)(skb->data)) >> 2;
}
u8 f3_get_skb_ptrs(struct sk_buff *skb) {
	return *((u8 *)(skb->data + 1));
}

int f3_set_skb_ttl(struct sk_buff *skb, u8 ttl) {
	*((u8 *)(skb->data)) = ((ttl << 2) | 2);
	return 0;
}

int f3_set_skb_ptrs(struct sk_buff *skb, u8 ptrs) {
	*((u8 *)(skb->data + 1)) = ptrs;
	return 0;
}

int f3_skb_push(struct sk_buff *skb, int size) {
	if (skb_headroom(skb) - NET_IP_ALIGN__ > size) {
		skb_push(skb, size);
		return 0;
	} else {
		if (skb_headroom(skb) + skb_tailroom(skb) - NET_IP_ALIGN__ > size) {
			unsigned char *data_start = skb->data;
			int data_len = skb->len, i;
			skb_put(skb, size - skb_headroom(skb) + NET_IP_ALIGN__);
			skb_push(skb, skb_headroom(skb) - NET_IP_ALIGN__);

			unsigned char *buffer = kmalloc(data_len, GFP_ATOMIC);
			memcpy(buffer, data_start, data_len);
			memcpy(skb->data + size, buffer, data_len);
			kfree(buffer);
			return 0;
		} else 
		return -11;
	}
}
int especially_judge(struct sk_buff *skb) {
	if (
		skb->data == 6 &&
		skb->data + 1 == 1 &&
		skb->data + 2 == 6 &&
		skb->data + 3 == 0 &&
		skb->data + 4 == 0 &&
		skb->data + 5 == 0)
	return 1;
	return 0;
}
int f3_is_f3_packet(struct sk_buff *skb) {
	int i;
	u8 *ttl = skb->data;
	u8 ptrs = f3_get_skb_ptrs(skb);
	#ifdef OVS_DEBUG2
		printk("f3_is_f3_packet len = %d\n", skb->len); 
		for (i = 0; i < 12; i ++)
			printk("%d ", *(skb->data + i));
		printk("\n");
	#endif
	if ((*ttl & 3) == 2 && ptrs < MAX_AP_NUMBER)
		return 1;
	return 0;
}

actionptr f3_pop_skb_ap(struct sk_buff *skb) {
	u8 ttl = f3_get_skb_ttl(skb);
	u8 ptrs = f3_get_skb_ptrs(skb);
	actionptr ap;
	if (sizeof(actionptr) == 4)
		ap = ntohl(*((actionptr *)(skb->data + 2)));
	else
	if (sizeof(actionptr) == 2)
		ap = ntohs(*((actionptr *)(skb->data + 2)));
	skb_pull(skb, sizeof(actionptr));
	ptrs --;
	f3_set_skb_ttl(skb, ttl);
	f3_set_skb_ptrs(skb, ptrs);
	return ap;
}

int f3_pop_ap(u8 *ap_len, actionptr *ap_list) {
	ap_list[-- (*ap_len)] = 0;
	return 0;
}

int f3_push_header(struct sk_buff *skb, const struct nlattr *attr, u8* ttl, u8* ap_len, actionptr *ap_list) {
	struct nlattr *a;
	int rem;	
	int i, ptrs;
	actionptr *data;
	*ttl = 0;
	ptrs = 0;
	nla_for_each_nested(a, attr, rem) {
		switch (nla_type(a)) {
		case OVS_HEADER_ATTR_TTL:
			*ttl = nla_get_u8(a);
			break;
		case OVS_HEADER_ATTR_NUMBER:
			ptrs = nla_get_u8(a);
			break;
		case OVS_HEADER_ATTR_AP:
			data = nla_data(a);
			*ap_len = nla_len(a) / sizeof(actionptr);
	#ifdef OVS_DEBUG
			printk("push f3 header ap_len = %d\n", *ap_len);
	#endif
			for (i = *ap_len - 1; i >= 0; i --, data ++) {
				memcpy(ap_list + i, (void *)data, sizeof(actionptr));
			}
	#ifdef OVS_DEBUG2
			printk("ap list = %d %d %d\n", ap_list[0], ap_list[1], ap_list[2]);
	#endif
			break;
		}
	}
	return 0;
}


/*
	Push AP into the temp list.
*/

int f3_push_ap(u8 *ap_len, actionptr *ap, const struct nlattr *attr) {
	actionptr *attr_ap = nla_data(attr);
	memcpy(&ap[(*ap_len) ++], (void *)attr_ap, sizeof(actionptr));
	return 0;
}
/*
	Push AP into skb's data.
*/

int f3_push_skb_ap(struct sk_buff *skb, actionptr ap) {
	u8 ttl = f3_get_skb_ttl(skb);
	u8 ptrs = f3_get_skb_ptrs(skb);

	if (f3_skb_push(skb, sizeof(actionptr))) {
		return -12;
	}
	f3_set_skb_ttl(skb, ttl);
	f3_set_skb_ptrs(skb, ptrs + 1);
	if (sizeof(actionptr) == 4)
		ap = htonl(ap);
	else
	if (sizeof(actionptr) == 2)
		ap = htons(ap);
	memcpy(skb->data + 2, (void *) &ap, sizeof(actionptr));
	return 0;
}

int f3_flood(struct sk_buff *skb, struct datapath *dp, struct vport *origin_vport, u8 ttl, u8 ap_len, actionptr *ap_list, bool pop_f3_header) {
	int i;
	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
		struct vport *vport;
		struct hlist_node *n;
		hlist_for_each_entry_safe(vport, n, &dp->ports[i], dp_hash_node)
			if (origin_vport == NULL || vport->port_no != origin_vport->port_no)
				do_output(dp, skb_copy(skb, GFP_ATOMIC), vport->port_no);
	/* error */
	}
	kfree_skb(skb);
	return 0;
}

int f3_jump(actionptr *jump_ap, const struct nlattr *attr) {
	if (sizeof(actionptr) == 4)
		*jump_ap = nla_get_u32(attr);
	else
	if (sizeof(actionptr) == 2)
		*jump_ap = nla_get_u16(attr);
	return 0;
}

int f3_set_ttl(u8 *ttl, const struct nlattr* attr) {
	*ttl = nla_get_u8(attr);
	return 0;
}

int f3_dec_ttl(u8 *ttl) {
	if (unlikely(*ttl) == 0)
		return -22;
	*ttl -= 1;
	return 0;
}

static int do_f3_execute_ap(struct datapath *dp, struct sw_flow *flow, struct sk_buff *skb, bool keep_skb, actionptr *jump_ap, bool *has_jump_ap) {
	int prev_port = -1, i;
	const struct nlattr *a;
	int rem;
	#ifdef OVS_DEBUG
	printk("<3>""do_f3_execute_ap start init\n");
	#endif
	u8 f3_ttl;
	u8 ap_len;
	bool pop_f3_header = false;
	struct sw_flow_actions *acts = flow->sf_acts;
	int len = acts->actions_len;
	actionptr *ap_list = kmalloc(MAX_AP_SIZE/* Max ap */, GFP_ATOMIC);
	#ifdef OVS_DEBUG
	printk("<3>""do_f3_execute_ap start\n");
	#endif
	f3_extract_f3_header(skb, &f3_ttl, &ap_len, ap_list);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	/*
		for ipv4
	*/
	if (*(skb->data + 12) == 8 && *(skb->data + 13) == 0) {
		#ifdef OVS_DEBUG
		printk("set transport ipv4 %d\n", ETH_HLEN + (*(skb->data + 14) & 31) * 4);
		#endif
		skb_set_transport_header(skb, ETH_HLEN + (*(skb->data + 14) & 31) * 4);
	}


	#ifdef OVS_DEBUG
	for (i = 0; i < ap_len; i ++)
		printk("<3>""do_f3_execute_ap ap_list[%d] = %d\n", i, ap_list[i]);
	
	#endif

	
	for (a = acts->actions, rem = len; rem > 0;
	     a = nla_next(a, &rem)) {
		int err = 0, j;
	#ifdef OVS_DEBUG
		unsigned char *ch;
		printk("do_f3_execute_ap nla_type = %d\n", nla_type(a));
		printk("do_f3_execute_ap nla_date start ");
		ch = nla_data(a);
		for (j = 0; j < nla_len(a); j ++, ++ ch)
			printk("%d ", *ch);
		printk("\n");
	#endif
		
		if (prev_port != -1) {
	#ifdef OVS_DEBUG
			printk("prev_port first enter\n");
	#endif

			if (!pop_f3_header) {

				f3_push_skb_header(skb, f3_ttl, ap_len, ap_list);
				do_output(dp, skb_copy(skb, GFP_ATOMIC), prev_port);
				skb_pull(skb, f3_header_length(ap_len));
			} else {
				do_output(dp, skb_copy(skb, GFP_ATOMIC), prev_port);
			}
			prev_port = -1;
		}
		
		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_OUTPUT:
			prev_port = nla_get_u32(a);
	#ifdef OVS_DEBUG
			printk("prev_port = %d\n", prev_port);
	#endif
			break;

		case OVS_ACTION_ATTR_USERSPACE:
			f3_output_userspace(dp, skb, a, f3_ttl, ap_len, ap_list, pop_f3_header);
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			err = push_vlan(skb, nla_data(a));
			if (unlikely(err)) /* skb already freed. */
				return err;
			break;

		case OVS_ACTION_ATTR_POP_VLAN:
			err = pop_vlan(skb);
			break;

		case OVS_ACTION_ATTR_SET:
			err = execute_set_action(skb, nla_data(a));
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = sample(dp, skb, a);
			break;
		

		case OVS_ACTION_ATTR_PUSH_F3_HEADER:
			err = f3_push_header(skb, a, &f3_ttl, &ap_len, ap_list);
			break;
		

		case OVS_ACTION_ATTR_POP_F3_HEADER:
			pop_f3_header = true;
			break;
		

		case OVS_ACTION_ATTR_PUSH_F3_AP:
			err = f3_push_ap(&ap_len, ap_list, a);
			break;
		

		case OVS_ACTION_ATTR_POP_F3_AP:
			err = f3_pop_ap(&ap_len, ap_list);
			break;
		

		case OVS_ACTION_ATTR_SET_F3_TTL:
			err = f3_set_ttl(&f3_ttl, a);
			break;
		

		case OVS_ACTION_ATTR_DEC_F3_TTL:
			err = f3_dec_ttl(&f3_ttl);
			break;
		

		case OVS_ACTION_ATTR_F3_JUMP:
			err = f3_jump(jump_ap, a);
			*has_jump_ap = true;
			break;

		case OVS_ACTION_ATTR_F3_FLOOD:
			err = f3_flood(skb_copy(skb, GFP_ATOMIC), dp, OVS_CB(skb)->vport, f3_ttl, ap_len, ap_list, pop_f3_header);
			break;

		}
		if (unlikely(err)) {
			kfree_skb(skb);
			kfree(ap_list);
			return err;
		}

	}
	
	if (prev_port != -1) {
	
			struct sk_buff *new_skb = skb_copy(skb, GFP_ATOMIC);

			if (!pop_f3_header)
				f3_push_skb_header(new_skb, f3_ttl, ap_len, ap_list);
			do_output(dp, new_skb, prev_port);	
	}
	if (!pop_f3_header)
		f3_push_skb_header(skb, f3_ttl, ap_len, ap_list);
	kfree(ap_list);
	return 0;
}
/*
	Do the logic of the F3 table.
	Contains the F3 header of the skb.
*/
static int do_f3_execute_loop_actions(struct datapath *dp, struct sk_buff *skb, actionptr ap, bool keep_skb) {
	bool has_jump_ap = true;
	int i;
	u8 f3_ttl = f3_get_skb_ttl(skb);
	#ifdef OVS_DEBUG
	printk("<3>""do_f3_execute_loop_actions ttl = %d\n", f3_ttl);
	#endif
	if (f3_ttl == 0) {
		consume_skb(skb);
		return 0;
	} else {
		f3_ttl --;
		f3_set_skb_ttl(skb, f3_ttl);
	}
	while (has_jump_ap) {
		struct sw_flow *flow = ovs_f3_flow_lookup(&dp->f3_table, ap);
		has_jump_ap = false;
		/* upcall to f3_miss_upcall */
		if (flow == NULL) {
	#ifdef OVS_DEBUG2
			printk("<3>""kernel cant find f3 flow_entry %d\n", ap);
	#endif
			f3_push_skb_ap(skb, ap);
			f3_queue_userspace_upcall(dp, skb);
			if (!keep_skb)
				consume_skb(skb);
			return 0;
		}
	#ifdef OVS_DEBUG
		printk("<3>""do_f3_execute_loop_actions find flow ap = %d\n", ap);
	#endif
		do_f3_execute_ap(dp, flow, skb, keep_skb, &ap, &has_jump_ap);
	}
	return 0;
}

static int do_f3_execute_actions(struct datapath *dp, struct sk_buff *skb, bool keep_skb) {
	actionptr ap = f3_pop_skb_ap(skb);
	#ifdef OVS_DEBUG
	printk("<3>""do_f3_execute_actions pop ap = %d\n", ap);
	#endif
	do_f3_execute_loop_actions(dp, skb, ap, keep_skb);
	return 0;
}

int ovs_f3_execute_actions(struct datapath *dp, struct sk_buff *skb) {
	struct loop_counter *loop;
	int error;

	/* Check whether we've looped too much. */
	loop = &__get_cpu_var(loop_counters);
	if (unlikely(++loop->count > MAX_LOOPS))
		loop->looping = true;
	if (unlikely(loop->looping)) {
		kfree_skb(skb);
		goto out_loop;
	}

	OVS_CB(skb)->tun_key = NULL;

	error = do_f3_execute_actions(dp, skb, true);
	/* free skb because the origin flow is not multi flow */
	kfree_skb(skb);

	/* Check whether sub-actions looped too much. */

out_loop:
	/* Decrement loop counter. */
	if (!--loop->count)
		loop->looping = false;

	return error;
}

void f3_debug_print_ap(struct sk_buff *skb) {
}
