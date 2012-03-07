/* packet-batadv.c
 * Routines for B.A.T.M.A.N. Advanced dissection
 * Copyright 2008-2010  Sven Eckelmann <sven@narfation.org>
 *
 * $Id: packet-batadv.c 35960 2011-02-16 03:05:13Z morriss $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/addr_resolv.h>

/* Start content from packet-batadv.h */
#define ETH_P_BATMAN  0x4305

#define BATADV_PACKET    0x01
#define BATADV_ICMP      0x02
#define BATADV_UNICAST   0x03
#define BATADV_BCAST     0x04
#define BATADV_VIS       0x05

#define ECHO_REPLY 0
#define DESTINATION_UNREACHABLE 3
#define ECHO_REQUEST 8
#define TTL_EXCEEDED 11

#define BAT_RR_LEN 16

struct batman_packet_v5 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
	guint8  ttl;
	guint8  gwflags;  /* flags related to gateway functions: gateway class */
	guint8  tq;
	guint16 seqno;
	address orig;
	address prev_sender;
	guint8  num_hna;
	guint8  pad;
};
#define BATMAN_PACKET_V5_SIZE 22

struct batman_packet_v7 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
	guint8  tq;
	guint16 seqno;
	address orig;
	address prev_sender;
	guint8  ttl;
	guint8  num_hna;
};
#define BATMAN_PACKET_V7_SIZE 20

struct batman_packet_v9 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
	guint8  tq;
	guint16 seqno;
	address orig;
	address prev_sender;
	guint8  ttl;
	guint8  num_hna;
	guint8  gwflags;
	guint8  pad;
};
#define BATMAN_PACKET_V9_SIZE 22

struct batman_packet_v10 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
	guint8  tq;
	guint32 seqno;
	address orig;
	address prev_sender;
	guint8  ttl;
	guint8  num_hna;
	guint8  gwflags;
	guint8  pad;
};
#define BATMAN_PACKET_V10_SIZE 24

struct batman_packet_v11 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
	guint8  tq;
	guint32 seqno;
	address orig;
	address prev_sender;
	guint8  ttl;
	guint8  num_hna;
};
#define BATMAN_PACKET_V11_SIZE 22

struct icmp_packet_v6 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  msg_type;   /* 0 = ECHO REPLY, 3 = DESTINATION_UNREACHABLE, 8 = ECHO_REQUEST, 11 = TTL exceeded */
	address dst;
	address orig;
	guint8  ttl;
	guint8  uid;
	guint16 seqno;
};
#define ICMP_PACKET_V6_SIZE 19

struct icmp_packet_v7 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  msg_type;   /* 0 = ECHO REPLY, 3 = DESTINATION_UNREACHABLE, 8 = ECHO_REQUEST, 11 = TTL exceeded */
	guint8  ttl;
	address dst;
	address orig;
	guint16 seqno;
	guint8  uid;
};
#define ICMP_PACKET_V7_SIZE 19

struct unicast_packet_v6 {
	guint8  packet_type;
	guint8  version;
	address dest;
	guint8  ttl;
};
#define UNICAST_PACKET_V6_SIZE 9

struct bcast_packet_v6 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	address orig;
	guint16 seqno;
};
#define BCAST_PACKET_V6_SIZE 10

struct bcast_packet_v10 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	address orig;
	guint8  ttl;
	guint32 seqno;
};
#define BCAST_PACKET_V10_SIZE 13

struct vis_packet_v6 {
	guint8  packet_type;
	guint8  version;      /* batman version field */
	guint8  vis_type;     /* which type of vis-participant sent this? */
	guint8  seqno;        /* sequence number */
	guint8  entries;      /* number of entries behind this struct */
	guint8  ttl;          /* TTL */
	address vis_orig;     /* originator that informs about its neighbours */
	address target_orig;  /* who should receive this packet */
	address sender_orig;  /* who sent or rebroadcasted this packet */
};
#define VIS_PACKET_V6_SIZE 24

struct vis_packet_v10 {
	guint8  packet_type;
	guint8  version;      /* batman version field */
	guint8  vis_type;     /* which type of vis-participant sent this? */
	guint8  entries;      /* number of entries behind this struct */
	guint32 seqno;        /* sequence number */
	guint8  ttl;          /* TTL */
	address vis_orig;     /* originator that informs about its neighbours */
	address target_orig;  /* who should receive this packet */
	address sender_orig;  /* who sent or rebroadcasted this packet */
};
#define VIS_PACKET_V10_SIZE 27

#define VIS_ENTRY_V6_SIZE 7
#define VIS_ENTRY_V8_SIZE 13

#define VIS_TYPE_SERVER_SYNC  0
#define VIS_TYPE_CLIENT_UPDATE  1
/* End content from packet-batadv.h */

/* trees */
static gint ett_batadv_batman = -1;
static gint ett_batadv_batman_flags = -1;
static gint ett_batadv_batman_gwflags = -1;
static gint ett_batadv_batman_hna = -1;
static gint ett_batadv_bcast = -1;
static gint ett_batadv_icmp = -1;
static gint ett_batadv_icmp_rr = -1;
static gint ett_batadv_unicast = -1;
static gint ett_batadv_vis = -1;
static gint ett_batadv_vis_entry = -1;

/* hfs */
static int hf_batadv_packet_type = -1;

static int hf_batadv_batman_version = -1;
static int hf_batadv_batman_flags = -1;
static int hf_batadv_batman_ttl = -1;
static int hf_batadv_batman_gwflags = -1;
static int hf_batadv_batman_tq = -1;
static int hf_batadv_batman_seqno = -1;
static int hf_batadv_batman_seqno32 = -1;
static int hf_batadv_batman_orig = -1;
static int hf_batadv_batman_prev_sender = -1;
static int hf_batadv_batman_num_hna = -1;
static int hf_batadv_batman_pad = -1;
static int hf_batadv_batman_hna = -1;

static int hf_batadv_bcast_version = -1;
static int hf_batadv_bcast_pad = -1;
static int hf_batadv_bcast_orig = -1;
static int hf_batadv_bcast_seqno = -1;
static int hf_batadv_bcast_seqno32 = -1;
static int hf_batadv_bcast_ttl = -1;

static int hf_batadv_icmp_version = -1;
static int hf_batadv_icmp_msg_type = -1;
static int hf_batadv_icmp_dst = -1;
static int hf_batadv_icmp_orig = -1;
static int hf_batadv_icmp_ttl = -1;
static int hf_batadv_icmp_uid = -1;
static int hf_batadv_icmp_seqno = -1;

static int hf_batadv_unicast_version = -1;
static int hf_batadv_unicast_dst = -1;
static int hf_batadv_unicast_ttl = -1;

static int hf_batadv_vis_version = -1;
static int hf_batadv_vis_type = -1;
static int hf_batadv_vis_seqno = -1;
static int hf_batadv_vis_seqno32 = -1;
static int hf_batadv_vis_entries = -1;
static int hf_batadv_vis_ttl = -1;
static int hf_batadv_vis_vis_orig = -1;
static int hf_batadv_vis_target_orig = -1;
static int hf_batadv_vis_sender_orig = -1;
static int hf_batadv_vis_entry_src = -1;
static int hf_batadv_vis_entry_dst = -1;
static int hf_batadv_vis_entry_quality = -1;

/* flags */
static int hf_batadv_batman_flags_directlink = -1;
static int hf_batadv_batman_flags_vis_server = -1;
static int hf_batadv_batman_flags_primaries_first_hop = -1;

static const value_string icmp_packettypenames[] = {
	{ ECHO_REPLY, "ECHO_REPLY" },
	{ DESTINATION_UNREACHABLE, "DESTINATION UNREACHABLE" },
	{ ECHO_REQUEST, "ECHO_REQUEST" },
	{ TTL_EXCEEDED, "TTL exceeded" },
	{ 0, NULL }
};

static const value_string vis_packettypenames[] = {
	{ VIS_TYPE_SERVER_SYNC, "SERVER_SYNC" },
	{ VIS_TYPE_CLIENT_UPDATE, "CLIENT_UPDATE" },
	{ 0, NULL }
};


/* forward declaration */
void proto_reg_handoff_batadv(void);

static dissector_handle_t batman_handle;

/* supported packet dissectors */
static void dissect_batadv_batman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v7(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v9(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v10(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v11(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_bcast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_bcast_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_bcast_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_icmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_icmp_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_icmp_v7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_unicast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_unicast_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_vis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_vis_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_vis_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_hna(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_vis_entry_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_vis_entry_v8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* other dissectors */
static dissector_handle_t data_handle;
static dissector_handle_t eth_handle;

static int proto_batadv_plugin = -1;

/* tap */
static int batadv_tap = -1;
static int batadv_follow_tap = -1;

static unsigned int batadv_ethertype = ETH_P_BATMAN;

static void dissect_batman_plugin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 type;

	col_clear(pinfo->cinfo, COL_INFO);

	type = tvb_get_guint8(tvb, 0);

	switch (type) {
	case BATADV_PACKET:
		dissect_batadv_batman(tvb, pinfo, tree);
		break;
	case BATADV_ICMP:
		dissect_batadv_icmp(tvb, pinfo, tree);
		break;
	case BATADV_UNICAST:
		dissect_batadv_unicast(tvb, pinfo, tree);
		break;
	case BATADV_BCAST:
		dissect_batadv_bcast(tvb, pinfo, tree);
		break;
	case BATADV_VIS:
		dissect_batadv_vis(tvb, pinfo, tree);
		break;
	default:
		/* dunno */
	{
		tvbuff_t *next_tvb;
		guint length_remaining;

		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_???");

		length_remaining = tvb_length_remaining(tvb, 1);
		next_tvb = tvb_new_subset(tvb, 0, length_remaining, -1);
		call_dissector(data_handle, next_tvb, pinfo, tree);
		break;
	}
	}
}

static void dissect_batadv_batman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;
	int offset = 0;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_BATMAN");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 5:
	case 6:
		while (offset != -1 && tvb_length_remaining(tvb, offset) >= BATMAN_PACKET_V5_SIZE) {
			offset = dissect_batadv_batman_v5(tvb, offset, pinfo, tree);
		}
		break;
	case 7:
	case 8:
		while (offset != -1 && tvb_length_remaining(tvb, offset) >= BATMAN_PACKET_V7_SIZE) {
			offset = dissect_batadv_batman_v7(tvb, offset, pinfo, tree);
		}
		break;
	case 9:
		while (offset != -1 && tvb_length_remaining(tvb, offset) >= BATMAN_PACKET_V9_SIZE) {
			offset = dissect_batadv_batman_v9(tvb, offset, pinfo, tree);
		}
		break;
	case 10:
		while (offset != -1 && tvb_length_remaining(tvb, offset) >= BATMAN_PACKET_V10_SIZE) {
			offset = dissect_batadv_batman_v10(tvb, offset, pinfo, tree);
		}
		break;
	case 11:
		while (offset != -1 && tvb_length_remaining(tvb, offset) >= BATMAN_PACKET_V11_SIZE) {
			offset = dissect_batadv_batman_v11(tvb, offset, pinfo, tree);
		}
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_gwflags(tvbuff_t *tvb, guint8 gwflags, int offset, proto_item *tgw)
{
	proto_tree *gwflags_tree;
	guint8 s = (gwflags & 0x80) >> 7;
	guint8 downbits = (gwflags & 0x78) >> 3;
	guint8 upbits = (gwflags & 0x07);
	guint down, up;

	if (gwflags == 0) {
		down = 0;
		up = 0;
	} else {
		down = 32 * (s + 2) * (1 << downbits);
		up = ((upbits + 1) * down) / 8;
	}

	gwflags_tree =  proto_item_add_subtree(tgw, ett_batadv_batman_gwflags);
	proto_tree_add_text(gwflags_tree, tvb, offset, 1, "Download Speed: %dkbit", down);
	proto_tree_add_text(gwflags_tree, tvb, offset, 1, "Upload Speed: %dkbit", up);

}

static int dissect_batadv_batman_v5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf, *tgw;
	proto_tree *batadv_batman_tree = NULL, *flag_tree;
	guint8 type;
	struct batman_packet_v5 *batman_packeth;
	const guint8  *prev_sender_addr, *orig_addr;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v5));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+3);
	batman_packeth->gwflags = tvb_get_guint8(tvb, offset+4);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+5);
	batman_packeth->seqno = tvb_get_ntohs(tvb, offset+6);
	orig_addr = tvb_get_ptr(tvb, offset+8, 6);
	SET_ADDRESS(&batman_packeth->orig, AT_ETHER, 6, orig_addr);
	prev_sender_addr = tvb_get_ptr(tvb, offset+14, 6);
	SET_ADDRESS(&batman_packeth->prev_sender, AT_ETHER, 6, prev_sender_addr);
	batman_packeth->num_hna = tvb_get_guint8(tvb, offset+20);
	batman_packeth->pad = tvb_get_guint8(tvb, offset+21);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V5_SIZE,
			                                    "B.A.T.M.A.N., Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V5_SIZE, FALSE);
		}
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, FALSE);
	offset += 1;

	tf = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_flags, tvb, offset, 1, FALSE);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_vis_server, tvb, offset, 1, batman_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, FALSE);
	offset += 1;

	tgw = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_gwflags, tvb, offset, 1, FALSE);
	dissect_batadv_gwflags(tvb, batman_packeth->gwflags, offset, tgw);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, prev_sender_addr);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_hna, tvb, offset, 1, FALSE);
	offset += 1;

	/* Hidden: proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_pad, tvb, offset, 1, FALSE); */
	offset += 1;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_hna; i++) {
		next_tvb = tvb_new_subset(tvb, offset, 6, 6);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_batadv_hna(next_tvb, pinfo, batadv_batman_tree);
		offset += 6;
	}

	return offset;
}

static int dissect_batadv_batman_v7(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf;
	proto_tree *batadv_batman_tree = NULL, *flag_tree;
	guint8 type;
	struct batman_packet_v7 *batman_packeth;
	const guint8  *prev_sender_addr, *orig_addr;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v7));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohs(tvb, offset+4);
	orig_addr = tvb_get_ptr(tvb, offset+6, 6);
	SET_ADDRESS(&batman_packeth->orig, AT_ETHER, 6, orig_addr);
	prev_sender_addr = tvb_get_ptr(tvb, offset+12, 6);
	SET_ADDRESS(&batman_packeth->prev_sender, AT_ETHER, 6, prev_sender_addr);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+18);
	batman_packeth->num_hna = tvb_get_guint8(tvb, offset+19);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V7_SIZE,
			                                    "B.A.T.M.A.N., Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V7_SIZE, FALSE);
		}
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, FALSE);
	offset += 1;

	tf = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_flags, tvb, offset, 1, FALSE);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_vis_server, tvb, offset, 1, batman_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, prev_sender_addr);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_hna, tvb, offset, 1, FALSE);
	offset += 1;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_hna; i++) {
		next_tvb = tvb_new_subset(tvb, offset, 6, 6);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_batadv_hna(next_tvb, pinfo, batadv_batman_tree);
		offset += 6;
	}

	return offset;
}

static int dissect_batadv_batman_v9(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf, *tgw;
	proto_tree *batadv_batman_tree = NULL, *flag_tree;
	guint8 type;
	struct batman_packet_v9 *batman_packeth;
	const guint8  *prev_sender_addr, *orig_addr;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v9));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohs(tvb, offset+4);
	orig_addr = tvb_get_ptr(tvb, offset+6, 6);
	SET_ADDRESS(&batman_packeth->orig, AT_ETHER, 6, orig_addr);
	prev_sender_addr = tvb_get_ptr(tvb, offset+12, 6);
	SET_ADDRESS(&batman_packeth->prev_sender, AT_ETHER, 6, prev_sender_addr);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+18);
	batman_packeth->num_hna = tvb_get_guint8(tvb, offset+19);
	batman_packeth->gwflags = tvb_get_guint8(tvb, offset+20);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V9_SIZE,
			                                    "B.A.T.M.A.N., Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V9_SIZE, FALSE);
		}
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, FALSE);
	offset += 1;

	tf = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_flags, tvb, offset, 1, FALSE);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_vis_server, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_primaries_first_hop, tvb, offset, 1, batman_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, prev_sender_addr);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_hna, tvb, offset, 1, FALSE);
	offset += 1;

	tgw = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_gwflags, tvb, offset, 1, FALSE);
	dissect_batadv_gwflags(tvb, batman_packeth->gwflags, offset, tgw);
	offset += 1;

	/* Hidden: proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_pad, tvb, offset, 1, FALSE); */
	offset += 1;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_hna; i++) {
		next_tvb = tvb_new_subset(tvb, offset, 6, 6);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_batadv_hna(next_tvb, pinfo, batadv_batman_tree);
		offset += 6;
	}

	return offset;
}

static int dissect_batadv_batman_v10(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf, *tgw;
	proto_tree *batadv_batman_tree = NULL, *flag_tree;
	guint8 type;
	struct batman_packet_v10 *batman_packeth;
	const guint8  *prev_sender_addr, *orig_addr;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v10));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohl(tvb, offset+4);
	orig_addr = tvb_get_ptr(tvb, offset+8, 6);
	SET_ADDRESS(&batman_packeth->orig, AT_ETHER, 6, orig_addr);
	prev_sender_addr = tvb_get_ptr(tvb, offset+14, 6);
	SET_ADDRESS(&batman_packeth->prev_sender, AT_ETHER, 6, prev_sender_addr);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+20);
	batman_packeth->num_hna = tvb_get_guint8(tvb, offset+21);
	batman_packeth->gwflags = tvb_get_guint8(tvb, offset+22);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V10_SIZE,
			                                    "B.A.T.M.A.N., Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V10_SIZE, FALSE);
		}
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, FALSE);
	offset += 1;

	tf = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_flags, tvb, offset, 1, FALSE);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_vis_server, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_primaries_first_hop, tvb, offset, 1, batman_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno32, tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, prev_sender_addr);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_hna, tvb, offset, 1, FALSE);
	offset += 1;

	tgw = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_gwflags, tvb, offset, 1, FALSE);
	dissect_batadv_gwflags(tvb, batman_packeth->gwflags, offset, tgw);
	offset += 1;

	/* Hidden: proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_pad, tvb, offset, 1, FALSE); */
	offset += 1;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_hna; i++) {
		next_tvb = tvb_new_subset(tvb, offset, 6, 6);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_batadv_hna(next_tvb, pinfo, batadv_batman_tree);
		offset += 6;
	}

	return offset;
}

static int dissect_batadv_batman_v11(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf;
	proto_tree *batadv_batman_tree = NULL, *flag_tree;
	guint8 type;
	struct batman_packet_v11 *batman_packeth;
	const guint8  *prev_sender_addr, *orig_addr;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v11));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohl(tvb, offset+4);
	orig_addr = tvb_get_ptr(tvb, offset+8, 6);
	SET_ADDRESS(&batman_packeth->orig, AT_ETHER, 6, orig_addr);
	prev_sender_addr = tvb_get_ptr(tvb, offset+14, 6);
	SET_ADDRESS(&batman_packeth->prev_sender, AT_ETHER, 6, prev_sender_addr);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+20);
	batman_packeth->num_hna = tvb_get_guint8(tvb, offset+21);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V11_SIZE,
			                                    "B.A.T.M.A.N., Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V11_SIZE, FALSE);
		}
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, FALSE);
	offset += 1;

	tf = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_flags, tvb, offset, 1, FALSE);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_vis_server, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_primaries_first_hop, tvb, offset, 1, batman_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno32, tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, prev_sender_addr);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_hna, tvb, offset, 1, FALSE);
	offset += 1;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_hna; i++) {
		next_tvb = tvb_new_subset(tvb, offset, 6, 6);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_batadv_hna(next_tvb, pinfo, batadv_batman_tree);
		offset += 6;
	}

	return offset;
}

static void dissect_batadv_hna(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	const guint8  *hna;

	hna = tvb_get_ptr(tvb, 0, 6);

	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *batadv_batman_hna_tree;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, 6,
			                                    "B.A.T.M.A.N. HNA: %s (%s)",
			                                    get_ether_name(hna), ether_to_str(hna));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, 6, FALSE);
		}
		batadv_batman_hna_tree = proto_item_add_subtree(ti, ett_batadv_batman_hna);

		proto_tree_add_ether(batadv_batman_hna_tree, hf_batadv_batman_hna, tvb, 0, 6, hna);
	}
}

static void dissect_batadv_bcast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_BCAST");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 6:
	case 7:
	case 8:
	case 9:
		dissect_batadv_bcast_v6(tvb, pinfo, tree);
		break;
	case 10:
	case 11:
		dissect_batadv_bcast_v10(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_bcast_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct bcast_packet_v6 *bcast_packeth;
	const guint8  *orig_addr;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;

	bcast_packeth = ep_alloc(sizeof(struct bcast_packet_v6));

	bcast_packeth->version = tvb_get_guint8(tvb, 1);
	orig_addr = tvb_get_ptr(tvb, 2, 6);
	SET_ADDRESS(&bcast_packeth->orig, AT_ETHER, 6, orig_addr);
	bcast_packeth->seqno = tvb_get_ntohs(tvb, 8);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", bcast_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *batadv_bcast_tree;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V6_SIZE,
			                                    "B.A.T.M.A.N. Bcast, Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V6_SIZE, FALSE);
		}
		batadv_bcast_tree = proto_item_add_subtree(ti, ett_batadv_bcast);

		/* items */
		proto_tree_add_uint_format(batadv_bcast_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_BCAST,
		                           "Packet Type: %s (%u)", "BATADV_BCAST", BATADV_BCAST);
		offset += 1;

		proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_version, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_ether(batadv_bcast_tree, hf_batadv_bcast_orig, tvb, offset, 6, orig_addr);
		offset += 6;

		proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_seqno, tvb, offset, 2, FALSE);
		offset += 2;
	}

	/* Calculate offset even when we got no tree */
	offset = BCAST_PACKET_V6_SIZE;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, bcast_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(eth_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_bcast_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct bcast_packet_v10 *bcast_packeth;
	const guint8  *orig_addr;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;

	bcast_packeth = ep_alloc(sizeof(struct bcast_packet_v10));

	bcast_packeth->version = tvb_get_guint8(tvb, 1);
	orig_addr = tvb_get_ptr(tvb, 2, 6);
	SET_ADDRESS(&bcast_packeth->orig, AT_ETHER, 6, orig_addr);
	bcast_packeth->ttl = tvb_get_guint8(tvb, 8);
	bcast_packeth->seqno = tvb_get_ntohl(tvb, 9);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", bcast_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *batadv_bcast_tree;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V10_SIZE,
			                                    "B.A.T.M.A.N. Bcast, Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V10_SIZE, FALSE);
		}
		batadv_bcast_tree = proto_item_add_subtree(ti, ett_batadv_bcast);

		/* items */
		proto_tree_add_uint_format(batadv_bcast_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_BCAST,
		                           "Packet Type: %s (%u)", "BATADV_BCAST", BATADV_BCAST);
		offset += 1;

		proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_version, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_ether(batadv_bcast_tree, hf_batadv_bcast_orig, tvb, offset, 6, orig_addr);
		offset += 6;

		proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_ttl, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_seqno32, tvb, offset, 4, FALSE);
		offset += 4;
	}

	/* Calculate offset even when we got no tree */
	offset = BCAST_PACKET_V10_SIZE;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, bcast_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(eth_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_icmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_ICMP");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 6:
		dissect_batadv_icmp_v6(tvb, pinfo, tree);
		break;
	case 7:
	case 8:
	case 9:
	case 10:
	case 11:
		dissect_batadv_icmp_v7(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_icmp_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct icmp_packet_v6 *icmp_packeth;
	const guint8  *dst_addr, *orig_addr;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;

	icmp_packeth = ep_alloc(sizeof(struct icmp_packet_v6));

	icmp_packeth->version = tvb_get_guint8(tvb, 1);
	icmp_packeth->msg_type = tvb_get_guint8(tvb, 2);
	dst_addr = tvb_get_ptr(tvb, 3, 6);
	SET_ADDRESS(&icmp_packeth->dst, AT_ETHER, 6, dst_addr);
	orig_addr = tvb_get_ptr(tvb, 9, 6);
	SET_ADDRESS(&icmp_packeth->orig, AT_ETHER, 6, orig_addr);
	icmp_packeth->ttl = tvb_get_guint8(tvb, 15);
	icmp_packeth->uid = tvb_get_guint8(tvb, 16);
	icmp_packeth->seqno = tvb_get_ntohs(tvb, 17);

	/* Set info column */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
			     val_to_str(icmp_packeth->msg_type, icmp_packettypenames, "Unknown (0x%02x)"),
			     icmp_packeth->seqno);
	}
	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *batadv_icmp_tree;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V6_SIZE,
			                                    "B.A.T.M.A.N. ICMP, Orig: %s (%s), Dst: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr), get_ether_name(dst_addr), ether_to_str(dst_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V6_SIZE, FALSE);
		}
		batadv_icmp_tree = proto_item_add_subtree(ti, ett_batadv_icmp);

		/* items */
		proto_tree_add_uint_format(batadv_icmp_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_ICMP,
		                           "Packet Type: %s (%u)", "BATADV_ICMP", BATADV_ICMP);
		offset += 1;

		proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_version, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_msg_type, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_ether(batadv_icmp_tree, hf_batadv_icmp_dst, tvb, offset, 6, dst_addr);
		offset += 6;

		proto_tree_add_ether(batadv_icmp_tree, hf_batadv_icmp_orig, tvb, offset, 6, orig_addr);
		offset += 6;

		proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_ttl, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_uid, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_seqno, tvb, offset, 2, FALSE);
		offset += 2;
	}

	/* Calculate offset even when we got no tree */
	offset = ICMP_PACKET_V6_SIZE;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, icmp_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void
dissect_batadv_icmp_rr(proto_tree *batadv_icmp_tree, tvbuff_t *tvb, int offset)
{
	proto_tree *field_tree = NULL;
	proto_item *tf;
	int ptr, i;

	ptr = tvb_get_guint8(tvb, offset);
	if (ptr < 1 || ptr > BAT_RR_LEN)
		return;

	tf = proto_tree_add_text(batadv_icmp_tree, tvb, offset, 1+ 6 * BAT_RR_LEN, "ICMP RR");
	field_tree = proto_item_add_subtree(tf, ett_batadv_icmp_rr);
	proto_tree_add_text(field_tree, tvb, offset, 1, "Pointer: %d", ptr);

	ptr--;
	offset++;
	for (i = 0; i < BAT_RR_LEN; i++) {
		proto_tree_add_text(field_tree, tvb, offset, 6, "%s%s",
				    (i > ptr) ? "-" : tvb_ether_to_str(tvb, offset),
				    (i == ptr) ? " <- (current)" : "");

		offset += 6;
	}
}

static void dissect_batadv_icmp_v7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct icmp_packet_v7 *icmp_packeth;
	const guint8  *dst_addr, *orig_addr;
	proto_item *ti;
	proto_tree *batadv_icmp_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;

	icmp_packeth = ep_alloc(sizeof(struct icmp_packet_v7));

	icmp_packeth->version = tvb_get_guint8(tvb, 1);
	icmp_packeth->msg_type = tvb_get_guint8(tvb, 2);
	icmp_packeth->ttl = tvb_get_guint8(tvb, 3);
	dst_addr = tvb_get_ptr(tvb, 4, 6);
	SET_ADDRESS(&icmp_packeth->dst, AT_ETHER, 6, dst_addr);
	orig_addr = tvb_get_ptr(tvb, 10, 6);
	SET_ADDRESS(&icmp_packeth->orig, AT_ETHER, 6, orig_addr);
	icmp_packeth->seqno = tvb_get_ntohs(tvb, 16);
	icmp_packeth->uid = tvb_get_guint8(tvb, 17);

	/* Set info column */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
			     val_to_str(icmp_packeth->msg_type, icmp_packettypenames, "Unknown (0x%02x)"),
			     icmp_packeth->seqno);
	}

	/* Set tree info */
	if (tree) {
		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V7_SIZE,
								"B.A.T.M.A.N. ICMP, Orig: %s (%s), Dst: %s (%s)",
								get_ether_name(orig_addr), ether_to_str(orig_addr), get_ether_name(dst_addr), ether_to_str(dst_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V7_SIZE, FALSE);
		}
		batadv_icmp_tree = proto_item_add_subtree(ti, ett_batadv_icmp);
	}

	/* items */
	proto_tree_add_uint_format(batadv_icmp_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_ICMP,
					"Packet Type: %s (%u)", "BATADV_ICMP", BATADV_ICMP);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_version, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_msg_type, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_ttl, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_ether(batadv_icmp_tree, hf_batadv_icmp_dst, tvb, offset, 6, dst_addr);
	offset += 6;

	proto_tree_add_ether(batadv_icmp_tree, hf_batadv_icmp_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_seqno, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_uid, tvb, offset, 1, FALSE);
	offset += 1;

	/* rr data available? */
	length_remaining = tvb_length_remaining(tvb, offset);
	if (length_remaining >= 1 + BAT_RR_LEN * 6) {
		dissect_batadv_icmp_rr(batadv_icmp_tree, tvb, offset);
		offset += 1 + BAT_RR_LEN * 6;
	}

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, icmp_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_unicast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_UNICAST");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 6:
	case 7:
	case 8:
	case 9:
	case 10:
	case 11:
		dissect_batadv_unicast_v6(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_unicast_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct unicast_packet_v6 *unicast_packeth;
	const guint8  *dest_addr;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;

	unicast_packeth = ep_alloc(sizeof(struct unicast_packet_v6));

	unicast_packeth->version = tvb_get_guint8(tvb, 1);
	dest_addr = tvb_get_ptr(tvb, 2, 6);
	SET_ADDRESS(&unicast_packeth->dest, AT_ETHER, 6, dest_addr);
	unicast_packeth->ttl = tvb_get_guint8(tvb, 8);

	/* Set info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *batadv_unicast_tree;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, UNICAST_PACKET_V6_SIZE,
			                                    "B.A.T.M.A.N. Unicast, Dst: %s (%s)",
			                                    get_ether_name(dest_addr), ether_to_str(dest_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, UNICAST_PACKET_V6_SIZE, FALSE);
		}
		batadv_unicast_tree = proto_item_add_subtree(ti, ett_batadv_unicast);

		/* items */
		proto_tree_add_uint_format(batadv_unicast_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_UNICAST,
		                           "Packet Type: %s (%u)", "BATADV_UNICAST", BATADV_UNICAST);
		offset += 1;

		proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_version, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_ether(batadv_unicast_tree, hf_batadv_unicast_dst, tvb, offset, 6, dest_addr);
		offset += 6;

		proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_ttl, tvb, offset, 1, FALSE);
		offset += 1;
	}

	/* Calculate offset even when we got no tree */
	offset = UNICAST_PACKET_V6_SIZE;

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dest_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dest_addr);

	tap_queue_packet(batadv_tap, pinfo, unicast_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(eth_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_vis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_VIS");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 6:
	case 7:
	case 8:
	case 9:
		dissect_batadv_vis_v6(tvb, pinfo, tree);
		break;
	case 10:
	case 11:
		dissect_batadv_vis_v10(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_vis_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v6 *vis_packeth;
	const guint8  *vis_orig_addr, *target_orig_addr, *sender_orig_addr;
	proto_tree *batadv_vis_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining, entry_size;
	int offset = 0, i;

	vis_packeth = ep_alloc(sizeof(struct vis_packet_v6));

	vis_packeth->version = tvb_get_guint8(tvb, 1);
	vis_packeth->vis_type = tvb_get_guint8(tvb, 2);
	vis_packeth->seqno = tvb_get_guint8(tvb, 3);
	vis_packeth->entries = tvb_get_guint8(tvb, 4);
	vis_packeth->ttl = tvb_get_guint8(tvb, 5);

	vis_orig_addr = tvb_get_ptr(tvb, 6, 6);
	SET_ADDRESS(&vis_packeth->vis_orig, AT_ETHER, 6, vis_orig_addr);
	target_orig_addr = tvb_get_ptr(tvb, 12, 6);
	SET_ADDRESS(&vis_packeth->target_orig, AT_ETHER, 6, target_orig_addr);
	sender_orig_addr = tvb_get_ptr(tvb, 18, 6);
	SET_ADDRESS(&vis_packeth->sender_orig, AT_ETHER, 6, sender_orig_addr);

	/* Set info column */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
			     val_to_str(vis_packeth->vis_type, vis_packettypenames, "Unknown (0x%02x)"),
			     vis_packeth->seqno);
	}
	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V6_SIZE,
			                                    "B.A.T.M.A.N. Vis, Orig: %s (%s)",
			                                    get_ether_name(vis_orig_addr), ether_to_str(vis_orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V6_SIZE, FALSE);
		}
		batadv_vis_tree = proto_item_add_subtree(ti, ett_batadv_vis);

		/* items */
		proto_tree_add_uint_format(batadv_vis_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_VIS,
		                           "Packet Type: %s (%u)", "BATADV_VIS", BATADV_VIS);
		offset += 1;

		proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_version, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_type, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_seqno, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_entries, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_ttl, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_vis_orig, tvb, offset, 6, vis_orig_addr);
		offset += 6;

		proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_target_orig, tvb, offset, 6, target_orig_addr);
		offset += 6;

		proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_sender_orig, tvb, offset, 6, sender_orig_addr);
		offset += 6;
	}

	/* Calculate offset even when we got no tree */
	offset = VIS_PACKET_V6_SIZE;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, sender_orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, vis_orig_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, target_orig_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, target_orig_addr);

	tap_queue_packet(batadv_tap, pinfo, vis_packeth);

	switch (vis_packeth->version) {
	case 6:
	case 7:
		entry_size = VIS_ENTRY_V6_SIZE;
		break;
	default:
	case 8:
	case 9:
		entry_size = VIS_ENTRY_V8_SIZE;
		break;
	}

	for (i = 0; i < vis_packeth->entries; i++) {
		next_tvb = tvb_new_subset(tvb, offset, entry_size, entry_size);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		if (batadv_vis_tree != NULL) {
			switch (vis_packeth->version) {
			case 6:
			case 7:
				dissect_vis_entry_v6(next_tvb, pinfo, batadv_vis_tree);
				break;
			default:
			case 8:
			case 9:
				dissect_vis_entry_v8(next_tvb, pinfo, batadv_vis_tree);
				break;
			}
		}

		offset += entry_size;
	}

	length_remaining = tvb_length_remaining(tvb, offset);
	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_vis_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v10 *vis_packeth;
	const guint8  *vis_orig_addr, *target_orig_addr, *sender_orig_addr;
	proto_tree *batadv_vis_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0, i;

	vis_packeth = ep_alloc(sizeof(struct vis_packet_v10));

	vis_packeth->version = tvb_get_guint8(tvb, 1);
	vis_packeth->vis_type = tvb_get_guint8(tvb, 2);
	vis_packeth->entries = tvb_get_guint8(tvb, 3);
	vis_packeth->seqno = tvb_get_ntohl(tvb, 4);
	vis_packeth->ttl = tvb_get_guint8(tvb, 8);

	vis_orig_addr = tvb_get_ptr(tvb, 9, 6);
	SET_ADDRESS(&vis_packeth->vis_orig, AT_ETHER, 6, vis_orig_addr);
	target_orig_addr = tvb_get_ptr(tvb, 15, 6);
	SET_ADDRESS(&vis_packeth->target_orig, AT_ETHER, 6, target_orig_addr);
	sender_orig_addr = tvb_get_ptr(tvb, 21, 6);
	SET_ADDRESS(&vis_packeth->sender_orig, AT_ETHER, 6, sender_orig_addr);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(vis_packeth->vis_type, vis_packettypenames, "Unknown (0x%02x)"),
		     vis_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V10_SIZE,
			                                    "B.A.T.M.A.N. Vis, Orig: %s (%s)",
			                                    get_ether_name(vis_orig_addr), ether_to_str(vis_orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V10_SIZE, FALSE);
		}
		batadv_vis_tree = proto_item_add_subtree(ti, ett_batadv_vis);

		/* items */
		proto_tree_add_uint_format(batadv_vis_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_VIS,
		                           "Packet Type: %s (%u)", "BATADV_VIS", BATADV_VIS);
		offset += 1;

		proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_version, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_type, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_entries, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_seqno32, tvb, offset, 4, FALSE);
		offset += 4;

		proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_ttl, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_vis_orig, tvb, offset, 6, vis_orig_addr);
		offset += 6;

		proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_target_orig, tvb, offset, 6, target_orig_addr);
		offset += 6;

		proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_sender_orig, tvb, offset, 6, sender_orig_addr);
		offset += 6;
	}

	/* Calculate offset even when we got no tree */
	offset = VIS_PACKET_V10_SIZE;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, sender_orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, vis_orig_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, target_orig_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, target_orig_addr);

	tap_queue_packet(batadv_tap, pinfo, vis_packeth);

	for (i = 0; i < vis_packeth->entries; i++) {
		next_tvb = tvb_new_subset(tvb, offset, VIS_ENTRY_V8_SIZE, VIS_ENTRY_V8_SIZE);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_vis_entry_v8(next_tvb, pinfo, batadv_vis_tree);
		offset += VIS_ENTRY_V8_SIZE;
	}

	length_remaining = tvb_length_remaining(tvb, offset);
	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_vis_entry_v6(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* Set tree info */
	if (tree) {
		const guint8  *dst;
		proto_item    *ti;
		proto_tree    *batadv_vis_entry_tree;

		dst = tvb_get_ptr(tvb, 0, 6);

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_ENTRY_V6_SIZE,
			                                    "VIS Entry: %s (%s)",
			                                    get_ether_name(dst), ether_to_str(dst));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, VIS_ENTRY_V6_SIZE, FALSE);
		}
		batadv_vis_entry_tree = proto_item_add_subtree(ti, ett_batadv_vis_entry);

		proto_tree_add_ether(batadv_vis_entry_tree, hf_batadv_vis_entry_dst, tvb, 0, 6, dst);
		proto_tree_add_item(batadv_vis_entry_tree, hf_batadv_vis_entry_quality, tvb, 6, 1, FALSE);
	}
}

static void dissect_vis_entry_v8(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* Set tree info */
	if (tree) {
		const guint8  *dst, *src;
		proto_item *ti;
		proto_tree *batadv_vis_entry_tree;

		src = tvb_get_ptr(tvb, 0, 6);
		dst = tvb_get_ptr(tvb, 6, 6);

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_ENTRY_V8_SIZE,
			                                    "VIS Entry: %s (%s)",
			                                    get_ether_name(dst), ether_to_str(dst));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, VIS_ENTRY_V8_SIZE, FALSE);
		}
		batadv_vis_entry_tree = proto_item_add_subtree(ti, ett_batadv_vis_entry);

		proto_tree_add_ether(batadv_vis_entry_tree, hf_batadv_vis_entry_src, tvb, 0, 6, src);
		proto_tree_add_ether(batadv_vis_entry_tree, hf_batadv_vis_entry_dst, tvb, 6, 6, dst);
		proto_tree_add_item(batadv_vis_entry_tree, hf_batadv_vis_entry_quality, tvb, 12, 1, FALSE);
	}
}

void proto_register_batadv(void)
{
	module_t *batadv_module;

	static hf_register_info hf[] = {
		{ &hf_batadv_packet_type,
		  { "Packet Type", "batadv.batman.packet_type",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_version,
		  { "Version", "batadv.batman.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_flags,
		  { "Flags", "batadv.batman.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_ttl,
		  { "Time to Live", "batadv.batman.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_gwflags,
		  { "Gateway Flags", "batadv.batman.gwflags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_tq,
		  { "Transmission Quality", "batadv.batman.tq",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_seqno,
		  { "Sequence number", "batadv.batman.seq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_seqno32,
		  { "Sequence number", "batadv.batman.seq",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_orig,
		  { "Originator", "batadv.batman.orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_prev_sender,
		  { "Received from", "batadv.batman.prev_sender",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_num_hna,
		  { "Number of HNAs", "batadv.batman.num_hna",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_pad,
		  { "Padding", "batadv.batman.pad",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_flags_directlink,
		  { "DirectLink", "batadv.batman.flags.directlink",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_flags_vis_server,
		  { "VIS_SERVER", "batadv.batman.flags.vis_server",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_flags_primaries_first_hop,
		  { "PRIMARIES_FIRST_HOP", "batadv.batman.flags.primaries_first_hop",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_hna,
		  { "Host Network Announcement", "batadv.batman.hna",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_bcast_version,
		  { "Version", "batadv.bcast.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_bcast_pad,
		  { "Padding", "batadv.bcast.pad",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_bcast_orig,
		  { "Originator", "batadv.bcast.orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_bcast_seqno,
		  { "Sequence number", "batadv.bcast.seq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_bcast_seqno32,
		  { "Sequence number", "batadv.bcast.seq",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_bcast_ttl,
		  { "Time to Live", "batadv.bcast.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_icmp_version,
		  { "Version", "batadv.icmp.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_icmp_msg_type,
		  { "Message Type", "batadv.icmp.msg_type",
		    FT_UINT8, BASE_DEC, VALS(icmp_packettypenames), 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_icmp_dst,
		  { "Destination", "batadv.icmp.dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_icmp_orig,
		  { "Originator", "batadv.icmp.orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_icmp_ttl,
		  { "Time to Live", "batadv.icmp.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_icmp_uid,
		  { "UID", "batadv.icmp.uid",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_icmp_seqno,
		  { "Sequence number", "batadv.icmp.seq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_unicast_version,
		  { "Version", "batadv.unicast.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_dst,
		  { "Destination", "batadv.unicast.dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_ttl,
		  { "Time to Live", "batadv.unicast.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_version,
		  { "Version", "batadv.vis.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_type,
		  { "Type", "batadv.vis.type",
		    FT_UINT8, BASE_DEC, VALS(vis_packettypenames), 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_seqno,
		  { "Sequence number", "batadv.vis.seq",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_vis_seqno32,
		  { "Sequence number", "batadv.vis.seq",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_vis_entries,
		  { "Entries", "batadv.vis.entries",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of entries", HFILL}
		},
		{ &hf_batadv_vis_ttl,
		  { "Time to Live", "batadv.vis.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_vis_vis_orig,
		  { "Originator", "batadv.vis.vis_orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_target_orig,
		  { "Target Originator", "batadv.vis.target_orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_sender_orig,
		  { "Forwarding Originator", "batadv.vis.sender_orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_entry_src,
		  { "Source", "batadv.vis.src",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_entry_dst,
		  { "Destination", "batadv.vis.dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_entry_quality,
		  { "Quality", "batadv.vis.quality",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_batadv_batman,
		&ett_batadv_batman_flags,
		&ett_batadv_batman_hna,
		&ett_batadv_batman_gwflags,
		&ett_batadv_bcast,
		&ett_batadv_icmp,
		&ett_batadv_icmp_rr,
		&ett_batadv_unicast,
		&ett_batadv_vis,
		&ett_batadv_vis_entry
	};

	proto_batadv_plugin = proto_register_protocol(
	                              "B.A.T.M.A.N. Advanced Protocol",
	                              "BATADV",          /* short name */
	                              "batadv"           /* abbrev */
	                      );

	batadv_module = prefs_register_protocol(proto_batadv_plugin,
						proto_reg_handoff_batadv);

	prefs_register_uint_preference(batadv_module, "batmanadv.ethertype",
	                               "Ethertype",
	                               "Ethertype used to indicate B.A.T.M.A.N. packet.",
	                               16, &batadv_ethertype);

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_batadv_plugin, hf, array_length(hf));
}

void proto_reg_handoff_batadv(void)
{
	static gboolean inited = FALSE;
	static unsigned int old_batadv_ethertype;

	if (!inited) {
		batman_handle = create_dissector_handle(dissect_batman_plugin, proto_batadv_plugin);

		data_handle = find_dissector("data");
		eth_handle = find_dissector("eth");

		batadv_tap = register_tap("batman");
		batadv_follow_tap = register_tap("batman_follow");

		inited = TRUE;
	} else {
		dissector_delete_uint("ethertype", old_batadv_ethertype, batman_handle);
	}

	old_batadv_ethertype = batadv_ethertype;
	dissector_add_uint("ethertype", batadv_ethertype, batman_handle);
}
