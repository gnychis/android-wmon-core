/* msg_dsx_rvd.c
 * WiMax MAC Management DSX-RVD Message decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * $Id: msg_dsx_rvd.c 29296 2009-08-04 19:01:34Z wmeier $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
#include "wimax_mac.h"

static gint proto_mac_mgmt_msg_dsx_rvd_decoder = -1;
static gint ett_mac_mgmt_msg_dsx_rvd_decoder = -1;

/* fix fields */
static gint hf_dsx_rvd_message_type = -1;
static gint hf_dsx_rvd_transaction_id = -1;
static gint hf_dsx_rvd_confirmation_code = -1;


/* Decode DSX-RVD messages. */
void dissect_mac_mgmt_msg_dsx_rvd_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, payload_type;
	proto_item *dsx_rvd_item = NULL;
	proto_tree *dsx_rvd_tree = NULL;

	if(tree)
	{	/* we are being asked for details */
		/* get the message type */
		payload_type = tvb_get_guint8(tvb, offset);
		/* ensure the message type is DSX-RVD */
		if(payload_type != MAC_MGMT_MSG_DSX_RVD)
			return;
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC message type */
		dsx_rvd_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_dsx_rvd_decoder, tvb, offset, tvb_len, "DSx Received (DSX-RVD) (%u bytes)",  tvb_len);
		/* add MAC DSx subtree */
		dsx_rvd_tree = proto_item_add_subtree(dsx_rvd_item, ett_mac_mgmt_msg_dsx_rvd_decoder);
		/* display the Message Type */
		proto_tree_add_item(dsx_rvd_tree, hf_dsx_rvd_message_type, tvb, offset, 1, FALSE);
		/* move to next field */
		offset++;
		/* display the Transaction ID */
		proto_tree_add_item(dsx_rvd_tree, hf_dsx_rvd_transaction_id, tvb, offset, 2, FALSE);
		/* move to next field */
		offset += 2;
		/* display the Confirmation Code */
		proto_tree_add_item(dsx_rvd_tree, hf_dsx_rvd_confirmation_code, tvb, offset, 1, FALSE);
	}
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_dsx_rvd(void)
{
	/* DSX_RVD display */
	static hf_register_info hf_dsx_rvd[] =
	{
		{
			&hf_dsx_rvd_message_type,
			{"MAC Management Message Type", "wmx.macmgtmsgtype.dsx_rvd", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_dsx_rvd_confirmation_code,
			{ "Confirmation code", "wmx.dsx_rvd.confirmation_code", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_dsx_rvd_transaction_id,
			{ "Transaction ID", "wmx.dsx_rvd.transaction_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_dsx_rvd_decoder,
		};

	proto_mac_mgmt_msg_dsx_rvd_decoder = proto_register_protocol (
		"WiMax DSX-RVD Message", /* name       */
		"WiMax DSX-RVD (dsx)",   /* short name */
		"wmx.dsx"                /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_dsx_rvd_decoder, hf_dsx_rvd, array_length(hf_dsx_rvd));
	proto_register_subtree_array(ett, array_length(ett));
}
