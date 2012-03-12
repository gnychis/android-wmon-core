/* packet-aim-invitation.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Invitation
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id: packet-aim-invitation.c 34412 2010-10-07 21:23:36Z wmeier $
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

#include <stdlib.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"

#define FAMILY_INVITATION 0x0006

/* Initialize the protocol and registered fields */
static int proto_aim_invitation = -1;

static int ett_aim_invitation = -1;

static int dissect_aim_invitation_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *invite_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, invite_tree, aim_onlinebuddy_tlvs);
}

static const aim_subtype aim_fnac_family_invitation[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Invite a friend to join AIM", dissect_aim_invitation_req },
	{ 0x0003, "Invitation Ack", NULL },
	{ 0, NULL, NULL }
};



/* Register the protocol with Wireshark */
void
proto_register_aim_invitation(void)
{

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_aim_invitation,
	};

/* Register the protocol name and description */
	proto_aim_invitation = proto_register_protocol("AIM Invitation Service", "AIM Invitation", "aim_invitation");

/* Required function calls to register the header fields and subtrees used */
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_invitation(void)
{
	aim_init_family(proto_aim_invitation, ett_aim_invitation, FAMILY_INVITATION, aim_fnac_family_invitation);
}
