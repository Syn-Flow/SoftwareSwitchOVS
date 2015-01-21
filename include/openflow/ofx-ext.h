#ifndef OPENFLOW_OFX_EXT_H
#define OPENFLOW_OFX_EXT_H 1

#include "openflow/openflow.h" 
#include "openvswitch/types.h"

struct ofx_header {
    struct ofp_header header;
};

struct ofx_flow_mod {
    ovs_be64 cookie;             /* Opaque controller-issued identifier. */
    ovs_be64 cookie_mask;        /* Mask used to restrict the cookie bits
                                    that must match when the command is
                                    OFPFC_MODIFY* or OFPFC_DELETE*. A value
                                    of 0 indicates no restriction. */
    /* Flow actions. */
    uint8_t table_id;            /* ID of the table to put the flow in */
    uint8_t command;             /* One of OFPFC_*. */
    ovs_be16 idle_timeout;       /* Idle time before discarding (seconds). */
    ovs_be16 hard_timeout;       /* Max time before discarding (seconds). */
    ovs_be16 priority;           /* Priority level of flow entry. */
    ovs_be32 buffer_id;          /* Buffered packet to apply to (or -1).
                                    Not meaningful for OFPFC_DELETE*. */
    ovs_be32 out_port;           /* For OFPFC_DELETE* commands, require
                                    matching entries to include this as an
                                    output port. A value of OFPP_ANY
                                    indicates no restriction. */
    ovs_be32 out_group;          /* For OFPFC_DELETE* commands, require
                                    matching entries to include this as an
                                    output group. A value of OFPG11_ANY
                                    indicates no restriction. */
    ovs_be16 flags;              /* One of OFPFF_*. */
    uint8_t pad[2];
    /* Followed by an ofp11_match structure. */
    /* Followed by an instruction set. */
};
OFP_ASSERT(sizeof(struct ofx_flow_mod) == 40);

// User-defined controller message structure 
struct ofx_flow_mod_reply {
    struct ofp_header oh;
    ap_controller action_pointer; /* Installation position of this entry*/
    uint8_t error;
    uint8_t padding[5];
};

struct ofx_port_mod_reply {
    struct ofp_header oh;
    ovs_be64 dpif_id;
    ovs_be32 port_no;
    ovs_be32 config;
    uint8_t error;
    uint8_t pad[7];
};

struct ofx_kernel_port_mod_reply {
	uint16_t port_no;
    uint8_t config;
	uint8_t error;
};
// User-defined netlink message structure
/* Message Type */
enum F3_nl_msg_type {
    OFX_PORT_CONFIG,
    OFX_FLOW_MOD,
};

/* Port configuration */
struct port_classifier {
	int dp_ifindex;
	uint32_t upcall_pid;
	odp_port_t port_no;
    uint32_t port_information;
};

// User-defined action structure
/* Action structure for OFPAT11_OFX_PUSH_HEADER. */
struct ofp11_action_ofx_push_header {
    ovs_be16 type;                 /* OFPAT11_OFX_PUSH_HEADER. */
    ovs_be16 len;                  /* Length is variable. */
    uint8_t ttl;                   /* TTL in shim. */     
    uint8_t action_pointer_number; /* number of pushed action_pointer. */
    uint8_t pad[2];                /* padding */
};
OFP_ASSERT(sizeof(struct ofp11_action_ofx_push_header) == 8);

/* Action structure for OFPAT11_OFX_PUSH_AP. */
struct ofp11_action_ofx_push_ap {
    ovs_be16 type;                /* OFPAT11_OFX_PUSH_AP. */
    ovs_be16 len;                 /* Length is 8. */
    ap_controller action_pointer;      /* Action Pointer. */
    uint8_t pad[2];
};
OFP_ASSERT(sizeof(struct ofp11_action_ofx_push_ap) == 8);

/* Action structure for OFPAT11_OFX_SET_TTL. */
struct ofp11_action_ofx_set_ttl {
    ovs_be16 type;                /* OFPAT11_OFX_SET_TTL. */
    ovs_be16 len;                 /* Length is 8. */
    uint8_t ttl;                  /* TTL in shim. */
    uint8_t pad[3];               
};
OFP_ASSERT(sizeof(struct ofp11_action_ofx_set_ttl) == 8);

/* Action structure for OFPAT11_OFX_JUMP. */
struct ofp11_action_ofx_jump {
    ovs_be16 type;                /* OFPAT11_OFX_JUMP. */
    ovs_be16 len;                 /* Length is 8. */
    ap_controller action_pointer;      /* Action Pointer. */
    uint8_t pad[2];
};
OFP_ASSERT(sizeof(struct ofp11_action_ofx_jump) == 8);

// User-defined netlink messages
struct nl_key_ap {
    ap_kernel action_pointer;
};
OFP_ASSERT(sizeof(struct nl_key_ap) == 2);
#endif
