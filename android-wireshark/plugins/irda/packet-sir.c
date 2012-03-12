/** Decode IrDA Serial Infrared (SIR) wrapped packets.
 * @author Shaun Jackman <sjackman@debian.org>
 * @copyright Copyright 2004 Shaun Jackman
 * @license GPL
 *
 * $Id: packet-sir.c 35224 2010-12-20 05:35:29Z guy $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/crc16.h>

/** Serial infrared port. */
#define TCP_PORT_SIR 6417


/** Beginning of frame. */
#define SIR_BOF 0xc0

/** End of frame. */
#define SIR_EOF 0xc1

/** Control escape. */
#define SIR_CE 0x7d

/** Escapes this character. */
#define SIR_ESCAPE(x) ((x)^0x20)


/** Protocol handles. */
static dissector_handle_t data_handle;
static dissector_handle_t irda_handle;

/** Protocol fields. */
static int proto_sir = -1;
static int ett_sir = -1;
static int hf_sir_bof = -1;
static int hf_sir_ce = -1;
static int hf_sir_eof = -1;
static int hf_sir_fcs = -1;
static int hf_sir_fcs_bad = -1;
static int hf_sir_length = -1;
static int hf_sir_preamble = -1;


/** Unescapes the data. */
static tvbuff_t *
unescape_data(tvbuff_t *tvb, packet_info *pinfo)
{
	if (tvb_find_guint8(tvb, 0, -1, SIR_CE) == -1) {
		return tvb;
	} else {
		guint length = tvb_length(tvb);
		guint offset;
		guint8 *data = g_malloc(length);
		guint8 *dst = data;
		tvbuff_t *next_tvb;

		for (offset = 0; offset < length; )
		{
			guint8 c = tvb_get_guint8(tvb, offset++);
			if ((c == SIR_CE) && (offset < length))
				c = SIR_ESCAPE(tvb_get_guint8(tvb, offset++));
			*dst++ = c;
		}

		next_tvb = tvb_new_child_real_data(tvb, data, (guint) (dst-data), (guint) (dst-data));
		tvb_set_free_cb(next_tvb, g_free);
		add_new_data_source(pinfo, next_tvb, "Unescaped SIR");
		return next_tvb;
	}
}


/** Checksums the data. */
static tvbuff_t *
checksum_data(tvbuff_t *tvb, proto_tree *tree)
{
	proto_item *hidden_item;
	int len = tvb_length(tvb) - 2;
	if (len < 0)
		return tvb;
	if (tree) {
		guint16 actual_fcs = tvb_get_letohs(tvb, len);
		guint16 calculated_fcs = crc16_ccitt_tvb(tvb, len);
		if (calculated_fcs == actual_fcs) {
			proto_tree_add_uint_format(tree, hf_sir_fcs,
					tvb, len, 2, actual_fcs,
					"Frame check sequence: 0x%04x (correct)",
					actual_fcs);
		} else {
			hidden_item = proto_tree_add_boolean(tree,
					hf_sir_fcs_bad, tvb, len, 2, TRUE);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			proto_tree_add_uint_format(tree, hf_sir_fcs,
					tvb, len, 2, actual_fcs,
					"Frame check sequence: 0x%04x "
					"(incorrect, should be 0x%04x)",
					actual_fcs, calculated_fcs);
		}
	}
	return tvb_new_subset(tvb, 0, len, len);
}


/** Dissects an SIR packet. */
static void
dissect_sir(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root)
{
	gint offset = 0;
	gint bof_offset;
	gint eof_offset;

	while (tvb_length_remaining(tvb, offset) > 0) {
		bof_offset = tvb_find_guint8(tvb, offset, -1, SIR_BOF);
		eof_offset = (bof_offset == -1) ? -1 :
			tvb_find_guint8(tvb, bof_offset, -1, SIR_EOF);

		if (bof_offset == -1 || eof_offset == -1) {
			if (pinfo->can_desegment) {
				pinfo->desegment_offset = offset;
				pinfo->desegment_len = 1;
			}
			return;
		} else {
			guint preamble_len = bof_offset - offset;
			gint data_offset = bof_offset + 1;
			tvbuff_t* next_tvb = tvb_new_subset(tvb,
				data_offset, eof_offset - data_offset, -1);
			next_tvb = unescape_data(next_tvb, pinfo);
			if (root) {
				unsigned data_len = tvb_length(next_tvb) < 2 ? 0 :
					tvb_length(next_tvb) - 2;
				proto_tree* ti = proto_tree_add_protocol_format(root,
						proto_sir, tvb, offset, eof_offset - offset + 1,
						"Serial Infrared, Len: %d", data_len);
				proto_tree* tree = proto_item_add_subtree(ti, ett_sir);
				if (preamble_len > 0)
					proto_tree_add_item(tree, hf_sir_preamble, tvb,
							offset, preamble_len, FALSE);
				proto_tree_add_item(tree, hf_sir_bof, tvb,
						bof_offset, 1, FALSE);
				proto_tree_add_uint(tree, hf_sir_length,
						next_tvb, 0, data_len, data_len);
				next_tvb = checksum_data(next_tvb, tree);
				proto_tree_add_item(tree, hf_sir_eof, tvb,
						eof_offset, 1, FALSE);
			} else {
				next_tvb = checksum_data(next_tvb, NULL);
			}
			call_dissector(irda_handle, next_tvb, pinfo, root);
		}
		offset = eof_offset + 1;
	}
}


/** Registers this dissector with the parent dissector. */
void
proto_reg_handoff_irsir(void)
{
	dissector_add_uint("tcp.port", TCP_PORT_SIR, find_dissector("sir"));

	data_handle = find_dissector("data");
	irda_handle = find_dissector("irda");
	if (irda_handle == NULL)
		irda_handle = data_handle;
}


/** Initializes this protocol. */
void
proto_register_irsir(void)
{
	static gint* ett[] = { &ett_sir };

	static hf_register_info hf_sir[] = {
		{ &hf_sir_bof,
			{ "Beginning of frame", "sir.bof",
				FT_UINT8, BASE_HEX, NULL, 0,
				NULL, HFILL }},
		{ &hf_sir_ce,
			{ "Command escape", "sir.ce",
				FT_UINT8, BASE_HEX, NULL, 0,
				NULL, HFILL }},
		{ &hf_sir_eof,
			{ "End of frame", "sir.eof",
				FT_UINT8, BASE_HEX, NULL, 0,
				NULL, HFILL }},
		{ &hf_sir_fcs,
			{ "Frame check sequence", "sir.fcs",
				FT_UINT16, BASE_HEX, NULL, 0,
				NULL, HFILL }},
		{ &hf_sir_fcs_bad,
			{ "Bad frame check sequence", "sir.fcs_bad",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},
		{ &hf_sir_length,
			{ "Length", "sir.length",
				FT_UINT16, BASE_DEC, NULL, 0,
				NULL, HFILL }},
		{ &hf_sir_preamble,
			{ "Preamble", "sir.preamble",
				FT_BYTES, BASE_NONE, NULL, 0,
				NULL, HFILL }}
	};

	proto_sir = proto_register_protocol(
			"Serial Infrared", "SIR", "sir");
	register_dissector("sir", dissect_sir, proto_sir);
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(
			proto_sir, hf_sir, array_length(hf_sir));
}
