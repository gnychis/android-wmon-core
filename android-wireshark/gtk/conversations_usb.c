/* conversations_usb.c 2007 Jon Smirl
 * modified from conversations_eth.c   2003 Ronnie Sahlberg
 *
 * $Id: conversations_usb.c 34017 2010-08-30 16:10:01Z morriss $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>

#include "../stat_menu.h"

#include "gtk/gui_stat_menu.h"
#include "gtk/conversations_table.h"


static int
usb_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip _U_)
{
	add_conversation_table_data((conversations_table *)pct, &pinfo->src, &pinfo->dst, 0, 0, 1, pinfo->fd->pkt_len, &pinfo->fd->rel_ts, SAT_NONE, PT_NONE);

	return 1;
}



static void
usb_conversation_init(const char *optarg, void* userdata _U_)
{
	const char *filter=NULL;

	if (!strncmp(optarg, "conv,usb,", 9)) {
		filter = optarg + 9;
	} else {
		filter = NULL;
	}

	init_conversation_table(TRUE, "USB", "usb", filter, usb_conversation_packet);

}


static void
usb_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	usb_conversation_init("conv,usb", NULL);
}


void
register_tap_listener_usb_conversation(void)
{
	register_stat_cmd_arg("conv,usb", usb_conversation_init, NULL);

	register_stat_menu_item("USB", REGISTER_STAT_GROUP_CONVERSATION_LIST,
	    usb_endpoints_cb, NULL, NULL, NULL);

	register_conversation_table(TRUE, "USB", "usb", NULL /*filter*/, usb_conversation_packet);
}
