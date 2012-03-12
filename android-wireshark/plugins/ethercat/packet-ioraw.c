/* packet-ioraw.c
 * Routines for ethercat packet disassembly
 *
 * $Id: packet-ioraw.c 35224 2010-12-20 05:35:29Z guy $
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

#include "packet-ioraw.h"

/* Define the ioraw proto */
int proto_ioraw  = -1;

static int ett_ioraw = -1;

static int hf_ioraw_summary = -1;
static int hf_ioraw_header = -1;
static int hf_ioraw_data = -1;

/*ioraw*/
static void IoRawSummaryFormater( char *szText, int nMax)
{
   g_snprintf ( szText, nMax, "Raw IO Data" );
}

static void dissect_ioraw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *ioraw_tree;
   gint offset = 0;
   char szText[200];
   int nMax = sizeof(szText)-1;

   guint ioraw_length = tvb_reported_length(tvb);
   
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "IO-RAW");

   col_clear(pinfo->cinfo, COL_INFO);

      
   IoRawSummaryFormater(szText, nMax);
   col_append_str(pinfo->cinfo, COL_INFO, szText);

   if (tree) 
   {      
      ti = proto_tree_add_item(tree, proto_ioraw, tvb, 0, -1, TRUE);
      ioraw_tree = proto_item_add_subtree(ti, ett_ioraw);

      proto_item_append_text(ti,": %s",szText);
      proto_tree_add_item(ioraw_tree, hf_ioraw_header, tvb, offset, IoRawParserHDR_Len, TRUE);
      offset+=IoRawParserHDR_Len;

      proto_tree_add_item(ioraw_tree, hf_ioraw_data, tvb, offset, ioraw_length - offset, TRUE);
   }   
}

void proto_register_ioraw(void)
{
   static hf_register_info hf[] =
   {
      { &hf_ioraw_summary,
      { "Summary of the IoRaw Packet", "ioraw.summary",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ioraw_header, { "Header", "ioraw.header",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ioraw_data, { "VarData", "ioraw.data",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      }
   };

   static gint *ett[] =
   {
      &ett_ioraw
   };

   proto_ioraw = proto_register_protocol("TwinCAT IO-RAW",
      "IO-RAW","ioraw");
   proto_register_field_array(proto_ioraw,hf,array_length(hf));
   proto_register_subtree_array(ett,array_length(ett));
}

void proto_reg_handoff_ioraw(void)
{
   dissector_handle_t ioraw_handle;

   ioraw_handle = create_dissector_handle(dissect_ioraw, proto_ioraw);
   dissector_add_uint("ecatf.type", 3, ioraw_handle);
}
