/* packet-erspan.c
 * Routines for the disassembly of Cisco's ERSPAN protocol
 *
 * $Id: packet-cisco-erspan.c 35224 2010-12-20 05:35:29Z guy $
 *
 * Copyright 2005 Joerg Mayer (see AUTHORS file)
 * Updates for newer versions by Jason Masker <jason at masker.net>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * TODO:
 *	Find out the Unknown values
 *
 * Specs:
 *	No real specs exist. Some general description can be found at:
 *	http://www.cisco.com/en/US/products/hw/routers/ps368/products_configuration_guide_chapter09186a008069952a.html
 *
 *	Some information on ERSPAN type III can be found at:
 *	http://www.cisco.com/en/US/docs/switches/datacenter/nexus1000/sw/4_0_4_s_v_1_3/system_management/configuration/guide/n1000v_system_9span.html
 *
 *	For ERSPAN packets, the "protocol type" field value in the GRE header
 *	is 0x88BE (version 1) or 0x22EB (version 2).
 *
 *	ERSPAN type II is version 1
 *	ERSPAN type III is version 2
 *
 * 0000000: d4c3 b2a1 0200 0400 0000 0000 0000 0000 <-- pcap header
 * 0000010: ffff 0000
 * 0000010:           7100 0000 <-- 0x71 (DLT_TYPE) = linux_cooked_capture (of course not)
 * 0000010:                     7507 f845 11d1 0500 <-- pcap record header
 * 0000020: 7a00 0000 7a00 0000
 * 0000020:                     0000 030a 0000 0000 <-- unknown
 * 0000030: 0000 0000
 * 0000030:           0000 88be <-- GRE header (version 1)
 * 0000030:                     1002 0001 0000 0380 <-- ERSPAN header (01: erspan-id)
 * 0000040: 00d0 b7a7 7480 0015 c721 75c0 0800 4500 <-- Ethernet packet
 * ...
 * 
 *
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/greproto.h>

static int proto_erspan = -1;

static gint ett_erspan = -1;

static int hf_erspan_version = -1;
static int hf_erspan_vlan = -1;
static int hf_erspan_priority = -1;
static int hf_erspan_unknown2 = -1;
static int hf_erspan_direction = -1;
static int hf_erspan_unknown3 = -1;
static int hf_erspan_truncated = -1;
static int hf_erspan_spanid = -1;
static int hf_erspan_timestamp = -1;
static int hf_erspan_unknown4 = -1;
static int hf_erspan_direction2 = -1;
static int hf_erspan_unknown5 = -1;
static int hf_erspan_unknown6 = -1;
static int hf_erspan_unknown7 = -1;

#define PROTO_SHORT_NAME "ERSPAN"
#define PROTO_LONG_NAME "Encapsulated Remote Switch Packet ANalysis"

#define ERSPAN_DIRECTION_INCOMING 0
#define ERSPAN_DIRECTION_OUTGOING 1
static const value_string erspan_direction_vals[] = {
	{ERSPAN_DIRECTION_INCOMING, "Incoming"},
	{ERSPAN_DIRECTION_OUTGOING, "Outgoing"},
	{0, NULL},
};

static const value_string erspan_truncated_vals[] = {
	{0, "Not truncated"},
	{1, "Trunkated"},
	{0, NULL},
};

static const value_string erspan_version_vals[] = {
	{1, "Type II"},
	{2, "Type III"},
	{0, NULL},
};

static dissector_handle_t ethnofcs_handle;

static void
erspan_fmt_timestamp(gchar *result, guint32 timeval)
{
	g_snprintf(result, ITEM_LABEL_LENGTH, "%.4f", (((gfloat)timeval)/10000));
}

static void
dissect_erspan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_item *unknown_version;
	proto_tree *erspan_tree = NULL;
	tvbuff_t *eth_tvb;
	guint32 offset = 0;
	guint16 version = 0;

        col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
        col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME ":");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_erspan, tvb, offset, -1,
		    FALSE);
		erspan_tree = proto_item_add_subtree(ti, ett_erspan);

		version = tvb_get_ntohs(tvb, offset) >> 12;
		proto_tree_add_item(erspan_tree, hf_erspan_version, tvb, offset, 2,
			FALSE);
		if ((version != 1) && (version != 2 )) {
			unknown_version = proto_tree_add_text(erspan_tree, tvb, 0, 0,
				"Unknown version, please report");
			PROTO_ITEM_SET_GENERATED(unknown_version);
                	return;
		}
		proto_tree_add_item(erspan_tree, hf_erspan_vlan, tvb, offset, 2,
			FALSE);
		offset += 2;

		proto_tree_add_item(erspan_tree, hf_erspan_priority, tvb, offset, 2,
			FALSE);
		proto_tree_add_item(erspan_tree, hf_erspan_unknown2, tvb, offset, 2,
			FALSE);
		if (version == 1)
			proto_tree_add_item(erspan_tree, hf_erspan_direction, tvb,
				offset, 2, FALSE);
		else /* version = 2 */
			proto_tree_add_item(erspan_tree, hf_erspan_unknown3, tvb,
				offset, 2, FALSE);
		proto_tree_add_item(erspan_tree, hf_erspan_truncated, tvb, offset, 2,
			FALSE);
		proto_tree_add_item(erspan_tree, hf_erspan_spanid, tvb, offset, 2,
			FALSE);
		offset += 2;

		if (version == 2) {
			proto_tree_add_item(erspan_tree, hf_erspan_timestamp, tvb,
				offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(erspan_tree, hf_erspan_unknown4, tvb,
				offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(erspan_tree, hf_erspan_direction2, tvb,
				offset, 2, FALSE);
			proto_tree_add_item(erspan_tree, hf_erspan_unknown5, tvb,
				offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(erspan_tree, hf_erspan_unknown6, tvb,
				offset, 4, FALSE);
			offset += 4;
		}
		proto_tree_add_item(erspan_tree, hf_erspan_unknown7, tvb, offset, 4,
			FALSE);
		offset += 4;
	}
	else {
		offset += 8;
		if (version == 2)
			offset += 12;
	}

        eth_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(ethnofcs_handle, eth_tvb, pinfo, tree);
}

void
proto_register_erspan(void)
{
	static hf_register_info hf[] = {

		{ &hf_erspan_version,
		{ "Version",	"erspan.version", FT_UINT16, BASE_DEC, VALS(erspan_version_vals),
			0xf000, NULL, HFILL }},

		{ &hf_erspan_vlan,
		{ "Vlan",	"erspan.vlan", FT_UINT16, BASE_DEC, NULL,
			0x0fff, NULL, HFILL }},

		{ &hf_erspan_priority,
		{ "Priority",	"erspan.priority", FT_UINT16, BASE_DEC, NULL,
			0xe000, NULL, HFILL }},

		{ &hf_erspan_unknown2,
		{ "Unknown2",	"erspan.unknown2", FT_UINT16, BASE_DEC, NULL,
			0x1000, NULL, HFILL }},

		{ &hf_erspan_direction,
		{ "Direction",	"erspan.direction", FT_UINT16, BASE_DEC, VALS(erspan_direction_vals),
			0x0800, NULL, HFILL }},

		{ &hf_erspan_unknown3,
		{ "Unknown3",	"erspan.unknown3", FT_UINT16, BASE_DEC, NULL,
			0x0800, NULL, HFILL }},

		{ &hf_erspan_truncated,
		{ "Truncated",	"erspan.truncated", FT_UINT16, BASE_DEC, VALS(erspan_truncated_vals),
			0x0400, "ERSPAN packet exceeded the MTU size", HFILL }},

		{ &hf_erspan_spanid,
		{ "SpanID",	"erspan.spanid", FT_UINT16, BASE_DEC, NULL,
			0x03ff, NULL, HFILL }},

		{ &hf_erspan_timestamp,
		{ "Timestamp",	"erspan.timestamp", FT_UINT32, BASE_CUSTOM, erspan_fmt_timestamp,
			0, NULL, HFILL }},

		{ &hf_erspan_unknown4,
		{ "Unknown4",	"erspan.unknown4", FT_BYTES, BASE_NONE, NULL,
			0, NULL, HFILL }},

		{ &hf_erspan_direction2,
		{ "Direction2",	"erspan.direction2", FT_UINT16, BASE_DEC, VALS(erspan_direction_vals),
			0x0008, NULL, HFILL }},

		{ &hf_erspan_unknown5,
		{ "Unknown5",	"erspan.unknown5", FT_UINT16, BASE_HEX, NULL,
			0xfff7, NULL, HFILL }},

		{ &hf_erspan_unknown6,
		{ "Unknown6",	"erspan.unknown6", FT_BYTES, BASE_NONE, NULL,
			0, NULL, HFILL }},

		{ &hf_erspan_unknown7,
		{ "Unknown7",	"erspan.unknown7", FT_BYTES, BASE_NONE, NULL,
			0, NULL, HFILL }},

        };
	static gint *ett[] = {
		&ett_erspan,
	};

        proto_erspan = proto_register_protocol(PROTO_LONG_NAME,
	    PROTO_SHORT_NAME, "erspan");
        proto_register_field_array(proto_erspan, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_erspan(void)
{
	dissector_handle_t erspan_handle;

        ethnofcs_handle = find_dissector("eth_withoutfcs");

	erspan_handle = create_dissector_handle(dissect_erspan, proto_erspan);
        dissector_add_uint("gre.proto", GRE_ERSPAN_88BE, erspan_handle);
        dissector_add_uint("gre.proto", GRE_ERSPAN_22EB, erspan_handle);

}

