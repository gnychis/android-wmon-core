/* packet-turnchannel.c
 * Routines for TURN channel dissection (TURN negociation is handled
 * in the STUN2 dissector
 * Copyright 2008, 8x8 Inc. <petithug@8x8.com>
 *
 * $Id: packet-turnchannel.c 32410 2010-04-06 21:14:01Z wmeier $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Please refer to the following specs for protocol detail:
 * - draft-ietf-behave-rfc3489bis-15
 * - draft-ietf-mmusic-ice-19
 * - draft-ietf-behave-nat-behavior-discovery-03
 * - draft-ietf-behave-turn-07
 * - draft-ietf-behave-turn-ipv6-03
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <packet-tcp.h>

/* heuristic subdissectors */
static heur_dissector_list_t heur_subdissector_list;

/* data dissector handle */
static dissector_handle_t data_handle;

/* Initialize the protocol and registered fields */
static int proto_turnchannel = -1;

static int hf_turnchannel_id = -1;
static int hf_turnchannel_len = -1;

#define TURNCHANNEL_HDR_LEN	((guint)4)	


/* Initialize the subtree pointers */
static gint ett_turnchannel = -1;

static int
dissect_turnchannel_message(tvbuff_t *tvb, packet_info *pinfo, 
			    proto_tree *tree)
{
  	guint   len;
	guint16 channel_id;
	guint16 data_len;
	proto_item *ti;
	proto_tree *turnchannel_tree;

	len = tvb_length(tvb);
	/* First, make sure we have enough data to do the check. */
	if (len < TURNCHANNEL_HDR_LEN) {
		  return 0;
	}

	channel_id = tvb_get_ntohs(tvb, 0);
	data_len = tvb_get_ntohs(tvb, 2);

	if ((channel_id < 0x4000) || (channel_id > 0xFFFE)) {
	  return 0;
	}

	if (len != TURNCHANNEL_HDR_LEN + data_len) {
	  return 0;
	}

	/* Seems to be a decent TURN channel message */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TURN CHANNEL");

	if (check_col(pinfo->cinfo, COL_INFO))
	  col_add_fstr(pinfo->cinfo, COL_INFO, "Channel Id 0x%x", channel_id);

	ti = proto_tree_add_item(tree, proto_turnchannel, tvb, 0, -1, FALSE);

	turnchannel_tree = proto_item_add_subtree(ti, ett_turnchannel);

	proto_tree_add_uint(turnchannel_tree, hf_turnchannel_id, tvb, 0, 2, channel_id);
	proto_tree_add_uint(turnchannel_tree, hf_turnchannel_len, tvb, 2, 2, data_len);

	
	if (len > TURNCHANNEL_HDR_LEN) {
	  tvbuff_t *next_tvb;
	  guint reported_len, new_len;

	  new_len = tvb_length_remaining(tvb, TURNCHANNEL_HDR_LEN);
	  reported_len = tvb_reported_length_remaining(tvb, 
						       TURNCHANNEL_HDR_LEN);
	  if (data_len < reported_len) {
	    reported_len = data_len;
	  }
	  next_tvb = tvb_new_subset(tvb, TURNCHANNEL_HDR_LEN, new_len, 
				    reported_len);


	  if (!dissector_try_heuristic(heur_subdissector_list, 
				       next_tvb, pinfo, tree)) {
	    call_dissector(data_handle,next_tvb, pinfo, tree);
	  }
	}

	return tvb_length(tvb);
}


static void
dissect_turnchannel_message_no_return(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_turnchannel_message(tvb, pinfo, tree);
}


static guint
get_turnchannel_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	return (guint)tvb_get_ntohs(tvb, offset+2) + TURNCHANNEL_HDR_LEN;
}

static void
dissect_turnchannel_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, TURNCHANNEL_HDR_LEN,
			get_turnchannel_message_len, dissect_turnchannel_message_no_return);
}


static gboolean
dissect_turnchannel_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  	guint   len;
	guint16 channel_id;
	guint16 data_len;

  	len = tvb_length(tvb);
	/* First, make sure we have enough data to do the check. */
	if (len < TURNCHANNEL_HDR_LEN) {
		  return FALSE;
	}

	channel_id = tvb_get_ntohs(tvb, 0);
	data_len = tvb_get_ntohs(tvb, 2);

	if ((channel_id < 0x4000) || (channel_id > 0xFFFE)) {
	  return FALSE;
	}

	if (len != TURNCHANNEL_HDR_LEN + data_len) {
	  return FALSE;
	}

	return dissect_turnchannel_message(tvb, pinfo, tree);
}

void
proto_register_turnchannel(void)
{
	static hf_register_info hf[] = {
		{ &hf_turnchannel_id,
			{ "TURN Channel ID",	"turnchannel.id",	FT_UINT16,
			BASE_HEX,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &hf_turnchannel_len,
			{ "Data Length",  "turnchannel.length",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	NULL,	HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_turnchannel,
	};

/* Register the protocol name and description */
	proto_turnchannel = proto_register_protocol("TURN Channel",
	    "TURNCHANNEL", "turnchannel");

	new_register_dissector("turnchannel", dissect_turnchannel_message,
			   proto_turnchannel);

/* subdissectors */
	register_heur_dissector_list("turnchannel", &heur_subdissector_list);

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_turnchannel, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_turnchannel(void)
{
	dissector_handle_t turnchannel_tcp_handle;
	dissector_handle_t turnchannel_udp_handle;

	turnchannel_tcp_handle = create_dissector_handle(dissect_turnchannel_tcp, proto_turnchannel);
	turnchannel_udp_handle = find_dissector("turnchannel");

	dissector_add_handle("tcp.port", turnchannel_tcp_handle);   /* for decode-as */
	dissector_add_handle("udp.port", turnchannel_udp_handle);   /* ...           */

	heur_dissector_add("udp", dissect_turnchannel_heur, proto_turnchannel);
	heur_dissector_add("tcp", dissect_turnchannel_heur, proto_turnchannel);

	data_handle = find_dissector("data");
}
