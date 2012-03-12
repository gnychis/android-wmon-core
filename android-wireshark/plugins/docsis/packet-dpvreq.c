/* packet-dpvreq.c
 * Routines for DOCSIS 3.0 DOCSIS Path Verify Response Message dissection.
 * Copyright 2010, Guido Reismueller <g.reismueller[AT]avm.de>
 *
 * $Id: packet-dpvreq.c 35224 2010-12-20 05:35:29Z guy $
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
#include "config.h"
#endif

#include <epan/packet.h>

/* Initialize the protocol and registered fields */
static int proto_docsis_dpvreq = -1;
static int hf_docsis_dpvreq_tranid = -1;
static int hf_docsis_dpvreq_dschan = -1;
static int hf_docsis_dpvreq_flags = -1;
static int hf_docsis_dpvreq_us_sf = -1;
static int hf_docsis_dpvreq_n = -1;
static int hf_docsis_dpvreq_start = -1;
static int hf_docsis_dpvreq_end = -1;
static int hf_docsis_dpvreq_ts_start = -1;
static int hf_docsis_dpvreq_ts_end = -1;

/* Initialize the subtree pointers */
static gint ett_docsis_dpvreq = -1;

/* Code to actually dissect the packets */
static void
dissect_dpvreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *it;
  proto_tree *dpvreq_tree = NULL;
  guint16 transid;
  guint8 dschan;

  transid = tvb_get_ntohs (tvb, 0);
  dschan = tvb_get_guint8 (tvb, 2);

  col_clear (pinfo->cinfo, COL_INFO);
  col_add_fstr (pinfo->cinfo, COL_INFO,
	    "DOCSIS Path Verify Request: Transaction-Id = %u DS-Ch %d", 
		transid, dschan);

  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_dpvreq, tvb, 0, -1,
					"DPV Request");
      dpvreq_tree = proto_item_add_subtree (it, ett_docsis_dpvreq);
      proto_tree_add_item (dpvreq_tree, hf_docsis_dpvreq_tranid, tvb, 
			  0, 2, FALSE);
      proto_tree_add_item (dpvreq_tree, hf_docsis_dpvreq_dschan, tvb, 
			  2, 1, FALSE);
      proto_tree_add_item (dpvreq_tree, hf_docsis_dpvreq_flags, tvb, 
			  3, 1, FALSE);
      proto_tree_add_item (dpvreq_tree, hf_docsis_dpvreq_us_sf, tvb, 
			  4, 4, FALSE);
      proto_tree_add_item (dpvreq_tree, hf_docsis_dpvreq_n, tvb, 
			  8, 2, FALSE);
      proto_tree_add_item (dpvreq_tree, hf_docsis_dpvreq_start, tvb, 
			  10, 1, FALSE);
      proto_tree_add_item (dpvreq_tree, hf_docsis_dpvreq_end, tvb, 
			  11, 1, FALSE);
      proto_tree_add_item (dpvreq_tree, hf_docsis_dpvreq_ts_start, tvb, 
			  12, 4, FALSE);
      proto_tree_add_item (dpvreq_tree, hf_docsis_dpvreq_ts_end, tvb, 
			  16, 4, FALSE);
    }
}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_docsis_dpvreq (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_dpvreq_tranid,
     {"Transaction Id", "docsis_dpvreq.tranid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvreq_dschan,
     {"Downstream Channel ID", "docsis_dpvreq.dschan",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvreq_flags,
     {"Flags", "docsis_dpvreq.flags",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvreq_us_sf,
     {"Upstream Service Flow ID", "docsis_dpvreq.us_sf",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvreq_n,
     {"N (Measurement avaraging factor)", "docsis_dpvreq.n",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvreq_start,
     {"Start Reference Point", "docsis_dpvreq.start",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvreq_end,
     {"End Reference Point", "docsis_dpvreq.end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvreq_ts_start,
     {"Timestamp Start", "docsis_dpvreq.ts_start",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvreq_ts_end,
     {"Timestamp End", "docsis_dpvreq.ts_end",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_dpvreq,
  };

/* Register the protocol name and description */
  proto_docsis_dpvreq =
    proto_register_protocol ("DOCSIS Path Verify Request",
			     "DOCSIS DPV-REQ", "docsis_dpvreq");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_dpvreq, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_dpvreq", dissect_dpvreq, proto_docsis_dpvreq);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_dpvreq (void)
{
  dissector_handle_t docsis_dpvreq_handle;

  docsis_dpvreq_handle = find_dissector ("docsis_dpvreq");
  dissector_add_uint ("docsis_mgmt", 0x27, docsis_dpvreq_handle);
}
