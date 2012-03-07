/* packet-time.c
 * Routines for Time Protocol (RFC 868) packet dissection
 *
 * Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-time.c 35224 2010-12-20 05:35:29Z guy $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#include <epan/packet.h>

static int proto_time = -1;
static int hf_time_time = -1;

static gint ett_time = -1;

/* This dissector works for TCP and UDP time packets */
#define TIME_PORT 37

static void
dissect_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree	*time_tree;
  proto_item	*ti;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TIME");

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "TIME %s",
		 pinfo->srcport == pinfo->match_uint ? "Response":"Request");
  }

  if (tree) {

    ti = proto_tree_add_item(tree, proto_time, tvb, 0, -1, FALSE);
    time_tree = proto_item_add_subtree(ti, ett_time);

    proto_tree_add_text(time_tree, tvb, 0, 0,
			pinfo->srcport==TIME_PORT ? "Type: Response":"Type: Request");
    if (pinfo->srcport == TIME_PORT) {
      /* seconds since 1900-01-01 00:00:00 GMT, *not* 1970 */
      guint32 delta_seconds = tvb_get_ntohl(tvb, 0);
      proto_tree_add_uint_format(time_tree, hf_time_time, tvb, 0, 4,
				 delta_seconds, "%s",
				 abs_time_secs_to_str(delta_seconds-2208988800U, ABSOLUTE_TIME_LOCAL, TRUE));
    }
  }
}

void
proto_register_time(void)
{

  static hf_register_info hf[] = {
    { &hf_time_time,
      { "Time", "time.time",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Seconds since 00:00 (midnight) 1 January 1900 GMT", HFILL }}
  };
  static gint *ett[] = {
    &ett_time,
  };

  proto_time = proto_register_protocol("Time Protocol", "TIME", "time");
  proto_register_field_array(proto_time, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_time(void)
{
  dissector_handle_t time_handle;

  time_handle = create_dissector_handle(dissect_time, proto_time);
  dissector_add_uint("udp.port", TIME_PORT, time_handle);
  dissector_add_uint("tcp.port", TIME_PORT, time_handle);
}
