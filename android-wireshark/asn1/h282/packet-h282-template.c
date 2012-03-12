/* packet-h282.c
 * Routines for H.282 packet dissection
 * 2007  Tomas Kukosa
 *
 * $Id: packet-h282-template.c 32417 2010-04-07 16:54:29Z wmeier $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-per.h"

#define PNAME  "H.282 Remote Device Control"
#define PSNAME "RDC"
#define PFNAME "rdc"

/* Initialize the protocol and registered fields */
static int proto_h282 = -1;
#include "packet-h282-hf.c"

/* Initialize the subtree pointers */
static int ett_h282 = -1;
#include "packet-h282-ett.c"

/* Dissectors */

/* Subdissectors */

#include "packet-h282-fn.c"

static int
dissect_h282(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item  *ti = NULL;
  proto_tree  *h282_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  ti = proto_tree_add_item(tree, proto_h282, tvb, 0, -1, FALSE);
  h282_tree = proto_item_add_subtree(ti, ett_h282);

  return dissect_RDCPDU_PDU(tvb, pinfo, h282_tree);
}

/*--- proto_register_h282 ----------------------------------------------*/
void proto_register_h282(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-h282-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_h282,
#include "packet-h282-ettarr.c"
  };

  /* Register protocol */
  proto_h282 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h282, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  new_register_dissector(PFNAME, dissect_h282, proto_h282);
  new_register_dissector(PFNAME".device_list", dissect_NonCollapsingCapabilities_PDU, proto_h282);

}

/*--- proto_reg_handoff_h282 -------------------------------------------*/
void proto_reg_handoff_h282(void) 
{

}

