/* packet-echo.c
 * Routines for ECHO packet disassembly (RFC862)
 *
 * Only useful to mark the packets as ECHO in the summary and in the
 * protocol hierarchy statistics (since not so many fields to decode ;-)
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * $Id: packet-echo.c 35546 2011-01-16 03:35:29Z morriss $
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

#define ECHO_PORT	7

static int proto_echo = -1;

static int hf_echo_data = -1;
static int hf_echo_request = -1;
static int hf_echo_response = -1;

static gint ett_echo = -1;

static void dissect_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

  proto_tree   *echo_tree = NULL;
  proto_item   *ti, *hidden_item;
  int           offset = 0;
  gboolean      request = FALSE;

  if (pinfo->destport == ECHO_PORT) {
    request = TRUE;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ECHO");

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_set_str(pinfo->cinfo, COL_INFO,
		 (request) ? "Request" : "Response");
  }

  if (tree) {

    ti = proto_tree_add_item(tree, proto_echo, tvb, offset, -1, FALSE);
    echo_tree = proto_item_add_subtree(ti, ett_echo);

    if (request) {
      hidden_item = proto_tree_add_boolean(echo_tree, hf_echo_request, tvb, 0, 0, 1);
    } else {
      hidden_item = proto_tree_add_boolean(echo_tree, hf_echo_response, tvb, 0, 0, 1);
    }
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    proto_tree_add_item(echo_tree, hf_echo_data, tvb, offset, -1, ENC_NA);

  }

} /* dissect_echo */

void proto_register_echo(void)
{

  static hf_register_info hf[] = {
    { &hf_echo_data,
      { "Echo data",	"echo.data",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	NULL, HFILL }},
    { &hf_echo_request,
      { "Echo request",	"echo.request",
	FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
      	"Echo data", HFILL }},
    { &hf_echo_response,
      { "Echo response","echo.response",
	FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
      	"Echo data", HFILL }}
  };

  static gint *ett[] = {
    &ett_echo
  };

  proto_echo = proto_register_protocol("Echo", "ECHO", "echo");
  proto_register_field_array(proto_echo, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

void proto_reg_handoff_echo(void)
{

  dissector_handle_t echo_handle;

  echo_handle = create_dissector_handle(dissect_echo, proto_echo);

  dissector_add_uint("udp.port", ECHO_PORT, echo_handle);
  dissector_add_uint("tcp.port", ECHO_PORT, echo_handle);

}

