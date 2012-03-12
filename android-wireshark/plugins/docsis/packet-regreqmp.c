/* packet-regreqmp.c
 * $Id: packet-regreqmp.c 35224 2010-12-20 05:35:29Z guy $
 * Routines for REG-REQ-MP Message dissection
 * Copyright 2007, Bruno Verstuyft  <bruno.verstuyft@excentis.com>
 *
 * Based on packet-regreq.c (by Anand V. Narwani <anand[AT]narwani.org>)
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>


/* Initialize the protocol and registered fields */
static int proto_docsis_regreqmp = -1;

static int hf_docsis_regreqmp_sid = -1;

static int hf_docsis_regreqmp_number_of_fragments = -1;
static int hf_docsis_regreqmp_fragment_sequence_number = -1;

static dissector_handle_t docsis_tlv_handle;



/* Initialize the subtree pointers */
static gint ett_docsis_regreqmp = -1;

static void
dissect_regreqmp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	
	proto_item *it;
	proto_tree *regreqmp_tree = NULL;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_INFO, "REG-REQ-MP Message:");

		if (tree)
		{
			it = proto_tree_add_protocol_format (tree, proto_docsis_regreqmp, tvb, 0, -1,"REG-REQ-MP Message");
			regreqmp_tree = proto_item_add_subtree (it, ett_docsis_regreqmp);
			
			proto_tree_add_item (regreqmp_tree, hf_docsis_regreqmp_sid, tvb, 0, 2, FALSE);
			proto_tree_add_item (regreqmp_tree, hf_docsis_regreqmp_number_of_fragments, tvb, 2, 1, FALSE);
			proto_tree_add_item (regreqmp_tree, hf_docsis_regreqmp_fragment_sequence_number, tvb, 3, 1, FALSE);

		}
		/* Call Dissector for Appendix C TLV's */
		next_tvb = tvb_new_subset_remaining (tvb, 4);
		call_dissector (docsis_tlv_handle, next_tvb, pinfo, regreqmp_tree);
	}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_regreqmp (void)
{
	/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{&hf_docsis_regreqmp_sid,
		{"Sid", "docsis_regreqmp.sid",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"Reg-Req-Mp Sid", HFILL}
		},
		{&hf_docsis_regreqmp_number_of_fragments,
		{"Number of Fragments", "docsis_regreqmp.number_of_fragments",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Reg-Req-Mp Number of Fragments", HFILL}
		},
		{&hf_docsis_regreqmp_fragment_sequence_number,
		{"Fragment Sequence Number", "docsis_regreqmp.fragment_sequence_number",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Reg-Req-Mp Fragment Sequence Number", HFILL}
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_docsis_regreqmp,
	};

	/* Register the protocol name and description */
	proto_docsis_regreqmp =
		proto_register_protocol ("DOCSIS Registration Request Multipart",
					"DOCSIS Reg-Req-Mp", "docsis_regreqmp");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array (proto_docsis_regreqmp, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));

	register_dissector ("docsis_regreqmp", dissect_regreqmp, proto_docsis_regreqmp);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_regreqmp (void)
{
	dissector_handle_t docsis_regreqmp_handle;

	docsis_tlv_handle = find_dissector ("docsis_tlv");
	docsis_regreqmp_handle = find_dissector ("docsis_regreqmp");
	dissector_add_uint ("docsis_mgmt", 44, docsis_regreqmp_handle);
}
