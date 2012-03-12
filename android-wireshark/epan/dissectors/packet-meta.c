/* Routines for 'Metadata' disassembly
 *
 * $Id: packet-meta.c 35558 2011-01-16 20:51:21Z morriss $
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
#include "config.h"
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-meta.h"
#include "packet-sscop.h"
#include "wiretap/erf.h"

static int proto_meta = -1;
extern int proto_sscop;
extern int proto_malformed;

/* fields */
static int hf_meta_schema = -1;
static int hf_meta_hdrlen = -1;
static int hf_meta_proto = -1;
static int hf_meta_reserved = -1;
static int hf_meta_item = -1;
static int hf_meta_item_id = -1;
static int hf_meta_item_type = -1;
static int hf_meta_item_len = -1;
static int hf_meta_item_data = -1;
/* specific fields */
static int hf_meta_item_direction = -1;
static int hf_meta_item_ts = -1;
static int hf_meta_item_phylinkid = -1;
static int hf_meta_item_nsapi = -1;
static int hf_meta_item_imsi = -1;
static int hf_meta_item_imei = -1;
static int hf_meta_item_signaling = -1;
static int hf_meta_item_incomplete = -1;
static int hf_meta_item_deciphered = -1;
static int hf_meta_item_apn = -1;
static int hf_meta_item_rat = -1;
static int hf_meta_item_aal5proto = -1;
static int hf_meta_item_cell = -1;
static int hf_meta_item_localdevid = -1;
static int hf_meta_item_remotedevid = -1;
static int hf_meta_item_tapgroupid = -1;
static int hf_meta_item_tlli = -1;
static int hf_meta_item_calling = -1;
static int hf_meta_item_called = -1;

/* subtrees */
static gint ett_meta = -1;
static gint ett_meta_item = -1;

/* default handle */
static dissector_handle_t data_handle;
static dissector_handle_t atm_untrunc_handle;
static dissector_handle_t sscf_nni_handle;
static dissector_handle_t alcap_handle;
static dissector_handle_t nbap_handle;
static dissector_handle_t ethwithfcs_handle;
static dissector_handle_t ethwithoutfcs_handle;
static dissector_handle_t fphint_handle;
static dissector_handle_t erf_handle;

static const value_string meta_schema_vals[] = {
	{ META_SCHEMA_PCAP,		"PCAP" },
	{ META_SCHEMA_DXT,		"DXT" },
	{ 0, NULL }
};

static const value_string meta_proto_vals[] = {
	{ META_PROTO_DXT_ETHERNET,		"Ethernet without FCS" },
	{ META_PROTO_DXT_ETHERNET_CRC,	"Ethernet with FCS" },
	{ META_PROTO_DXT_FP_HINT,		"FP Hint" },
	{ META_PROTO_DXT_ERF_AAL5,		"ERF AAL5" },
	{ META_PROTO_DXT_ATM_AAL2,		"ATM AAL2" },
	{ META_PROTO_DXT_ATM,			"ATM" },
	{ 0, NULL }
};

static const value_string meta_type_vals[] = {
	{ META_TYPE_NONE,		"NONE" },
	{ META_TYPE_BOOLEAN,	"BOOLEAN" },
	{ META_TYPE_UINT8,		"UINT8" },
	{ META_TYPE_UINT16,		"UINT16" },
	{ META_TYPE_UINT32,		"UINT32" },
	{ META_TYPE_UINT64,		"UINT64" },
	{ META_TYPE_STRING,		"STRING" },
	{ 0, NULL }
};

/* TODO: this must be on a per-schema basis! */
static const value_string meta_id_vals[] = {
	{ META_ID_NULL,			"NULL" },
	{ META_ID_DIRECTION,	"Direction" },
	{ META_ID_SIGNALING,	"Signaling" },
	{ META_ID_INCOMPLETE,	"Incomplete" },
	{ META_ID_DECIPHERED,	"Deciphered" },
	{ META_ID_PAYLOADCUT,	"Payload cutted" },
	{ META_ID_TIMESTAMP64,	"Timestamp" },
	{ META_ID_AAL5PROTO,	"AAL5 Protocol Type" },
	{ META_ID_PHYLINKID,	"Physical Link ID" },
	{ META_ID_LOCALDEVID,	"Local Device ID" },
	{ META_ID_REMOTEDEVID,	"Remote Device ID" },
	{ META_ID_TAPGROUPID,	"Tap Group ID" },
	{ META_ID_IMSI,			"IMSI" },
	{ META_ID_IMEI,			"IMEI" },
	{ META_ID_CELL,			"Cell" },
	{ META_ID_TLLI,			"TLLI" },
	{ META_ID_NSAPI,		"NSAPI" },
	{ META_ID_APN,			"APN" },
	{ META_ID_RAT,			"RAT" },
	{ META_ID_CALLING,		"Calling Station ID" },
	{ META_ID_CALLED,		"Called Station ID" },
	{ 0, NULL }
};

#define META_AAL5PROTO_MTP3		2
#define META_AAL5PROTO_ALCAP	5
#define META_AAL5PROTO_NBAP		6
static const value_string meta_aal5proto_vals[] = {
	{ META_AAL5PROTO_MTP3,	"SSCOP MTP3" },
	{ META_AAL5PROTO_ALCAP,	"SSCOP ALCAP" },
	{ META_AAL5PROTO_NBAP,	"SSCOP NBAP" },
	{ 0, NULL }
};

static const value_string meta_direction_vals[] = {
	{ 0,	"Up" },
	{ 1,	"Down" },
	{ 0,	NULL }
};

static guint16 skip_item(proto_tree *meta_tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint16 offs)
{
	guint16 id;
	guint8 type, len, aligned_len, total_len;
	proto_tree *item_tree;
	proto_item *subti;

	id = tvb_get_letohs(tvb, offs); offs += 2;
	type = tvb_get_guint8(tvb, offs); offs++;
	len = tvb_get_guint8(tvb, offs); offs++;
	aligned_len = (len + 3) & 0xfffc;
	total_len = aligned_len + 4; /* 4: id, type, len fields */

	subti = proto_tree_add_item(meta_tree, hf_meta_item, tvb, offs - 4,
		aligned_len + 4, FALSE);
	item_tree = proto_item_add_subtree(subti, ett_meta_item);
	proto_tree_add_uint(item_tree, hf_meta_item_id, tvb, offs - 4, 2, id);
	proto_tree_add_uint(item_tree, hf_meta_item_type, tvb, offs - 2, 1, type);
	proto_tree_add_uint(item_tree, hf_meta_item_len,
		tvb, offs - 1, 1, len);
	if (len > 0)
		proto_tree_add_item(item_tree, hf_meta_item_data,
			tvb, offs, len, ENC_NA);

	return total_len;
}

/*
* offs: current offset in tvb
*/
static guint16 evaluate_meta_item_pcap(proto_tree *meta_tree, tvbuff_t *tvb, packet_info *pinfo, guint16 offs)
{
	guint16 id;
	guint8 type, len, aligned_len, total_len;
	proto_tree *item_tree;
	proto_item *subti;
	/* field values */
	guint8 dir;
	guint64 ts;

	id = tvb_get_letohs(tvb, offs); offs += 2;
	type = tvb_get_guint8(tvb, offs); offs++;
	len = tvb_get_guint8(tvb, offs); offs++;
	aligned_len = (len + 3) & 0xfffc;
	total_len = aligned_len + 4; /* 4: id, type, len fields */

	switch (id) {
		case META_ID_DIRECTION:
			dir = tvb_get_guint8(tvb, offs);
			pinfo->p2p_dir = dir == META_DIR_UP ? P2P_DIR_RECV : P2P_DIR_SENT;
			proto_tree_add_uint(meta_tree, hf_meta_item_direction, tvb, offs, 1, dir);
			break;
		case META_ID_TIMESTAMP64:
			ts = tvb_get_letoh64(tvb, offs);
			proto_tree_add_uint64(meta_tree, hf_meta_item_ts, tvb, offs, 8, ts);
			break;
		case META_ID_SIGNALING:
			proto_tree_add_boolean(meta_tree, hf_meta_item_signaling, tvb,
				offs, 0, 1);
			break;
		case META_ID_INCOMPLETE:
			proto_tree_add_boolean(meta_tree, hf_meta_item_incomplete, tvb,
				offs, 0, 1);
			break;
		default:
			subti = proto_tree_add_item(meta_tree, hf_meta_item, tvb, offs - 4,
				aligned_len + 4, FALSE);
			item_tree = proto_item_add_subtree(subti, ett_meta_item);
			proto_tree_add_uint(item_tree, hf_meta_item_id, tvb, offs - 4, 2, id);
			proto_tree_add_uint(item_tree, hf_meta_item_type, tvb, offs - 2, 1, type);
			proto_tree_add_uint(item_tree, hf_meta_item_len,
				tvb, offs - 1, 1, len);
			if (len > 0)
				proto_tree_add_item(item_tree, hf_meta_item_data,
					tvb, offs, len, ENC_NA);
	}
	return total_len;
}

/*
* offs: current offset in tvb
*/
static guint16 evaluate_meta_item_dxt(proto_tree *meta_tree, tvbuff_t *tvb, packet_info *pinfo, guint16 offs)
{
	guint16 id;
	guint8 type, len, aligned_len, total_len;
	proto_tree *item_tree;
	proto_item *subti;
	/* field values */
	guint8 dir, nsapi, rat, aal5proto, *apn, *calling, *called;
	guint16 phylinkid, localdevid, remotedevid, tapgroupid;
	guint32 tlli;
	guint64 ts, imsi, imei, cell;
	sscop_payload_info *p_sscop_info;

	id = tvb_get_letohs(tvb, offs); offs += 2;
	type = tvb_get_guint8(tvb, offs); offs++;
	len = tvb_get_guint8(tvb, offs); offs++;
	aligned_len = (len + 3) & 0xfffc;
	total_len = aligned_len + 4; /* 4: id, type, len fields */

	switch (id) {
		case META_ID_DIRECTION:
			dir = tvb_get_guint8(tvb, offs);
			pinfo->p2p_dir = dir == META_DIR_UP ? P2P_DIR_RECV : P2P_DIR_SENT;
			proto_tree_add_uint(meta_tree, hf_meta_item_direction, tvb, offs, 1, dir);
			break;
		case META_ID_TIMESTAMP64:
			ts = tvb_get_letoh64(tvb, offs);
			proto_tree_add_uint64(meta_tree, hf_meta_item_ts, tvb, offs, 8, ts);
			break;
		case META_ID_PHYLINKID:
			phylinkid = tvb_get_letohs(tvb, offs);
			pinfo->link_number = phylinkid;
			proto_tree_add_uint(meta_tree, hf_meta_item_phylinkid, tvb,
				offs, 2, phylinkid);
			break;
		case META_ID_NSAPI:
			nsapi = tvb_get_guint8(tvb, offs);
			proto_tree_add_uint(meta_tree, hf_meta_item_nsapi, tvb,
				offs, 1, nsapi);
			break;
		case META_ID_IMSI:
			imsi = tvb_get_letoh64(tvb, offs);
			proto_tree_add_uint64(meta_tree, hf_meta_item_imsi, tvb,
				offs, 8, imsi);
			break;
		case META_ID_IMEI:
			imei = tvb_get_letoh64(tvb, offs);
			proto_tree_add_uint64(meta_tree, hf_meta_item_imei, tvb,
				offs, 8, imei);
			break;
		case META_ID_APN:
			apn = tvb_get_string(tvb, offs, len);
			proto_tree_add_string(meta_tree, hf_meta_item_apn, tvb,
				offs, len, apn);
			break;
		case META_ID_RAT:
			rat = tvb_get_guint8(tvb, offs);
			proto_tree_add_uint(meta_tree, hf_meta_item_rat, tvb,
				offs, 1, rat);
			break;
		case META_ID_CELL:
			cell = tvb_get_ntoh64(tvb, offs);
			proto_tree_add_uint64(meta_tree, hf_meta_item_cell, tvb,
				offs, 8, cell);
			break;
		case META_ID_SIGNALING:
			proto_tree_add_boolean(meta_tree, hf_meta_item_signaling, tvb,
				offs, 0, 1);
			break;
		case META_ID_INCOMPLETE:
			proto_tree_add_boolean(meta_tree, hf_meta_item_incomplete, tvb,
				offs, 0, 1);
			break;
		case META_ID_DECIPHERED:
			proto_tree_add_boolean(meta_tree, hf_meta_item_deciphered, tvb,
				offs, 0, 1);
			break;
		case META_ID_AAL5PROTO:
			aal5proto = tvb_get_guint8(tvb, offs);
			p_sscop_info = p_get_proto_data(pinfo->fd, proto_sscop);
			if (!p_sscop_info) {
				p_sscop_info = se_alloc0(sizeof(sscop_payload_info));
				p_add_proto_data(pinfo->fd, proto_sscop, p_sscop_info);
			}
			switch (aal5proto) {
				case META_AAL5PROTO_MTP3:
					p_sscop_info->subdissector = sscf_nni_handle;
					break;
				case META_AAL5PROTO_ALCAP:
					p_sscop_info->subdissector = alcap_handle;
					break;
				case META_AAL5PROTO_NBAP:
					p_sscop_info->subdissector = nbap_handle;
					break;
				/* TODO: check for additional protos on Iu 802 LLC/SNAP ... */
				default:
					/* TODO: add warning */
					p_remove_proto_data(pinfo->fd, proto_sscop);
			}
			proto_tree_add_uint(meta_tree, hf_meta_item_aal5proto, tvb,
				offs, 1, aal5proto);
			break;
		case META_ID_LOCALDEVID:
			localdevid = tvb_get_letohs(tvb, offs);
			proto_tree_add_uint(meta_tree, hf_meta_item_localdevid, tvb,
				offs, 2, localdevid);
			break;
		case META_ID_REMOTEDEVID:
			remotedevid = tvb_get_letohs(tvb, offs);
			proto_tree_add_uint(meta_tree, hf_meta_item_remotedevid, tvb,
				offs, 2, remotedevid);
			break;
		case META_ID_TAPGROUPID:
			tapgroupid = tvb_get_letohs(tvb, offs);
			proto_tree_add_uint(meta_tree, hf_meta_item_tapgroupid, tvb,
				offs, 2, tapgroupid);
			break;
		case META_ID_TLLI:
			tlli = tvb_get_letohs(tvb, offs);
			proto_tree_add_uint(meta_tree, hf_meta_item_tlli, tvb,
				offs, 4, tlli);
			break;
		case META_ID_CALLING:
			calling = tvb_get_string(tvb, offs, len);
			proto_tree_add_string(meta_tree, hf_meta_item_calling, tvb,
				offs, len, calling);
			break;
		case META_ID_CALLED:
			called = tvb_get_string(tvb, offs, len);
			proto_tree_add_string(meta_tree, hf_meta_item_called, tvb,
				offs, len, called);
			break;
		default:
			subti = proto_tree_add_item(meta_tree, hf_meta_item, tvb, offs - 4,
				aligned_len + 4, FALSE);
			item_tree = proto_item_add_subtree(subti, ett_meta_item);
			proto_tree_add_uint(item_tree, hf_meta_item_id, tvb, offs - 4, 2, id);
			proto_tree_add_uint(item_tree, hf_meta_item_type, tvb, offs - 2, 1, type);
			proto_tree_add_uint(item_tree, hf_meta_item_len,
				tvb, offs - 1, 1, len);
			if (len > 0)
				proto_tree_add_item(item_tree, hf_meta_item_data,
					tvb, offs, len, ENC_NA);
	}
	return total_len;
}

/*
 * offs: current offset within tvb
 * header_length: length of meta header
 */
static gint32 evaluate_meta_items(guint16 schema, tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *meta_tree, guint16 offs, gint32 header_length)
{
	gint16 item_len;
	gint32 total_len = 0;
	while (total_len < header_length) {
		switch (schema) {
			case META_SCHEMA_DXT:
				item_len = evaluate_meta_item_dxt(meta_tree, tvb, pinfo, offs + total_len);
				break;
			case META_SCHEMA_PCAP:
				item_len = evaluate_meta_item_pcap(meta_tree, tvb, pinfo, offs + total_len);
				break;
			default:
				item_len = skip_item(meta_tree, tvb, pinfo, offs + total_len);
		}
		if (item_len < 4) { /* 4 is the minimum length of an item: id + type + length field */
			proto_item *malformed;
			malformed = proto_tree_add_protocol_format(meta_tree,
				proto_malformed, tvb, offs, -1, "[Malformed Packet: %s]", pinfo->current_proto);
			expert_add_info_format(pinfo, malformed, PI_MALFORMED, PI_ERROR,
				"Malformed Packet (wrong item encoding)");
			return -1;
		}
		total_len += item_len;
	}
	return total_len;
}

static void
dissect_meta(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
#define META_HEADER_SIZE 8
	guint16 schema, proto, hdrlen, reserved;
	gint32 item_len;
	guint32 aal2_ext, atm_hdr;
	proto_tree *meta_tree = NULL;
	proto_item *ti = NULL;
	tvbuff_t *next_tvb;
	dissector_handle_t next_dissector = data_handle;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "META");

	schema = tvb_get_letohs(tvb, 0);
	hdrlen = tvb_get_letohs(tvb, 2);
	proto = tvb_get_letohs(tvb, 4);
	reserved = tvb_get_letohs(tvb, 6);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_meta, tvb, 0, hdrlen + 4, FALSE);
		meta_tree = proto_item_add_subtree(ti, ett_meta);
		proto_tree_add_uint(meta_tree, hf_meta_schema, tvb, 0, 2, schema);
		proto_tree_add_uint(meta_tree, hf_meta_hdrlen, tvb, 2, 2, hdrlen);
		proto_tree_add_uint(meta_tree, hf_meta_proto, tvb, 4, 2, proto);
		proto_tree_add_uint(meta_tree, hf_meta_reserved, tvb, 6, 2, reserved);
	}
	item_len = evaluate_meta_items(schema, tvb, pinfo, meta_tree, META_HEADER_SIZE, hdrlen);

	if (item_len < 0) {
		/* evaluate_meta_items signalled an error */
		return; /* stop parsing */
	}

	if (hdrlen != item_len) {
		expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Invalid Header Length");
		proto_tree_add_text(tree, tvb, hdrlen+4, -1, "[Malformed Packet]");
		return;
	}

	/* find next subdissector based on the chosen schema */
	switch (schema) {
		case META_SCHEMA_PCAP:
			/* TODO */
			break;
		case META_SCHEMA_DXT:
			switch (proto) {
				case META_PROTO_DXT_ETHERNET:
					next_dissector = ethwithoutfcs_handle;
					break;
				case META_PROTO_DXT_ETHERNET_CRC:
					next_dissector = ethwithfcs_handle;
					break;
				case META_PROTO_DXT_FP_HINT:
					next_dissector = fphint_handle;
					break;
				case META_PROTO_DXT_ATM:
					next_dissector = atm_untrunc_handle;
					pinfo->pseudo_header->atm.aal = AAL_OAMCELL;
					pinfo->pseudo_header->atm.type = TRAF_UNKNOWN;
					break;
				case META_PROTO_DXT_ATM_AAL2:
					aal2_ext = tvb_get_ntohl(tvb, item_len + META_HEADER_SIZE); item_len += 4;
					atm_hdr = tvb_get_ntohl(tvb, item_len + META_HEADER_SIZE); item_len += 4;
					memset(&pinfo->pseudo_header->atm, 0, sizeof(pinfo->pseudo_header->atm));
					pinfo->pseudo_header->atm.aal = AAL_2;
					/* pinfo->pseudo_header->atm.flags = pinfo->p2p_dir; */
					pinfo->pseudo_header->atm.vpi = ((atm_hdr & 0x0ff00000) >> 20);
					pinfo->pseudo_header->atm.vci = ((atm_hdr & 0x000ffff0) >>  4);
					pinfo->pseudo_header->atm.aal2_cid = aal2_ext & 0x000000ff;
					pinfo->pseudo_header->atm.type = TRAF_UMTS_FP;
					next_dissector = atm_untrunc_handle;
					break;
				case META_PROTO_DXT_ERF_AAL5:
					/* fake erf pseudo header */
					memset(&pinfo->pseudo_header->erf, 0, sizeof(pinfo->pseudo_header->erf));
					pinfo->pseudo_header->erf.phdr.type = ERF_TYPE_AAL5;
					/* store p2p direction in ERF flags */
					pinfo->pseudo_header->erf.phdr.flags |= pinfo->p2p_dir;
					next_dissector = erf_handle;
					break;
			}
	}
	next_tvb = tvb_new_subset(tvb, item_len + META_HEADER_SIZE, -1, -1);
	call_dissector(next_dissector, next_tvb, pinfo, tree);
}

void
proto_register_meta(void)
{
	static hf_register_info hf[] = {
		/* metadata header */
		{ &hf_meta_schema, { "Schema", "meta.schema", FT_UINT16, BASE_DEC, VALS(meta_schema_vals), 0, NULL, HFILL } },
		{ &hf_meta_hdrlen, { "Header Length", "meta.hdrlen", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_meta_proto, { "Protocol", "meta.proto", FT_UINT16, BASE_DEC, VALS(meta_proto_vals), 0, NULL, HFILL } },
		{ &hf_meta_reserved, { "Reserved", "meta.reserved", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },

		/* general meta item */
		{ &hf_meta_item, { "Unknown Item", "meta.item", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_id, { "Item ID", "meta.item.id", FT_UINT16, BASE_HEX, VALS(meta_id_vals), 0x0, NULL, HFILL } },
		{ &hf_meta_item_type, { "Item Type", "meta.item.type", FT_UINT8, BASE_HEX, VALS(meta_type_vals), 0x0, NULL, HFILL } },
		{ &hf_meta_item_len, { "Item Length", "meta.item.len", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_data, { "Item Data", "meta.item.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		/* specific meta items */
		{ &hf_meta_item_direction, { "Direction", "meta.direction", FT_UINT8, BASE_DEC, VALS(meta_direction_vals), 0, NULL, HFILL } },
		{ &hf_meta_item_ts, { "Timestamp", "meta.timestamp", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_phylinkid, { "Physical Link ID", "meta.phylinkid", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_nsapi, { "NSAPI", "meta.nsapi", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_imsi, { "IMSI", "meta.imsi", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_imei, { "IMEI", "meta.imei", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_signaling, { "Signaling", "meta.signaling", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_incomplete, { "Incomplete", "meta.incomplete", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_deciphered, { "Deciphered", "meta.deciphered", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_apn, { "APN", "meta.apn", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_rat, { "RAT", "meta.rat", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_aal5proto, { "AAL5 Protocol Type", "meta.aal5proto", FT_UINT8, BASE_DEC, VALS(meta_aal5proto_vals), 0, NULL, HFILL } },
		{ &hf_meta_item_cell, { "Cell", "meta.cell", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },

		{ &hf_meta_item_localdevid, { "Local Device ID", "meta.localdevid", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_remotedevid, { "Remote Device ID", "meta.remotedevid", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_tapgroupid, { "Tap Group ID", "meta.tapgroupid", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_tlli, { "TLLI", "meta.tlli", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_calling, { "Calling Station ID", "meta.calling", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_meta_item_called, { "Called Station ID", "meta.called", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
	};

	static gint *ett[] = {
		&ett_meta,
		&ett_meta_item
	};

	proto_meta = proto_register_protocol("Metadata", "META", "meta");
	register_dissector("meta", dissect_meta, proto_meta);

	proto_register_field_array(proto_meta, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_meta(void)
{
	dissector_handle_t meta_handle;
	meta_handle = find_dissector("meta");
	/* enable once WTAP_ENCAP_META exists
	dissector_add_uint("wtap_encap", WTAP_ENCAP_META, meta_handle);
	*/

	data_handle = find_dissector("data");
	alcap_handle = find_dissector("alcap");
	atm_untrunc_handle = find_dissector("atm_untruncated");
	nbap_handle = find_dissector("nbap");
	sscf_nni_handle = find_dissector("sscf-nni");
	ethwithfcs_handle = find_dissector("eth_withfcs");
	ethwithoutfcs_handle = find_dissector("eth_withoutfcs");
	fphint_handle = find_dissector("fp_hint");
	erf_handle = find_dissector("erf");
}
