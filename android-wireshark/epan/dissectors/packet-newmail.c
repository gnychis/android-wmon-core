/* packet-newmail.c
 * Routines for Exchange New Mail Notification dissection
 * Copyright 2006, Stephen Fisher (see AUTHORS file)
 *
 * $Id: packet-newmail.c 35224 2010-12-20 05:35:29Z guy $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
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

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

/* Forward declaration we need below */
void proto_reg_handoff_newmail(void);

/* Variables for preferences */
static guint preference_default_port = 0;

/* Initialize the protocol and registered fields */
static int proto_newmail = -1;
static int hf_newmail_payload = -1;

/* Initialize the subtree pointers */
static gint ett_newmail = -1;

/* Code to actually dissect the packets */
static void
dissect_newmail(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *newmail_tree;

	/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NEWMAIL");

	col_set_str(pinfo->cinfo, COL_INFO, "Microsoft Exchange new mail notification");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_newmail, tvb, 0, -1, FALSE);

		newmail_tree = proto_item_add_subtree(ti, ett_newmail);

		proto_tree_add_item(newmail_tree, hf_newmail_payload, tvb, 0, 8, FALSE);
	}
}


/* Register the protocol with Wireshark */
void
proto_register_newmail(void)
{                 

	/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_newmail_payload,
		  { "Notification payload", "newmail.notification_payload",
		    FT_BYTES, BASE_NONE, NULL, 0x0,          
		    "Payload requested by client in the MAPI register push notification packet", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_newmail,
	};

	module_t *newmail_module;

	/* Register the protocol name and description */
	proto_newmail = proto_register_protocol("Microsoft Exchange New Mail Notification",
						"NEWMAIL", "newmail");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_newmail, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register the dissector without a port yet */
	register_dissector("newmail", dissect_newmail, proto_newmail);
        
	/* Register preferences module */
	newmail_module = prefs_register_protocol(proto_newmail,
						 proto_reg_handoff_newmail);

	prefs_register_uint_preference(newmail_module,
				       "default_port",
				       "Default UDP port (optional)",
				       "Always dissect this port's traffic as newmail notifications.  Additional ports will be dynamically registered as they are seen in MAPI register push notification packets.",
				       10, &preference_default_port);
	
}

void
proto_reg_handoff_newmail(void)
{
	static gboolean inited = FALSE;
	static dissector_handle_t newmail_handle;
        static guint preference_default_port_last;

	if(!inited) {
		newmail_handle = find_dissector("newmail");
		dissector_add_handle("udp.port", newmail_handle); /* for 'decode-as' */
		inited = TRUE;
	} else {
                if (preference_default_port_last != 0) {
                        dissector_delete_uint("udp.port", preference_default_port_last, newmail_handle);
                }
        }	

	if(preference_default_port != 0) {	
		dissector_add_uint("udp.port", preference_default_port, newmail_handle);
	}
        preference_default_port_last = preference_default_port;
}
