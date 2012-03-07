/* packet-llc.c
 * Routines for IEEE 802.2 LLC layer
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * $Id: packet-llc.c 35224 2010-12-20 05:35:29Z guy $
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
#include <epan/oui.h>
#include <epan/xdlc.h>
#include <epan/etypes.h>
#include <epan/llcsaps.h>
#include <epan/bridged_pids.h>
#include <epan/ppptypes.h>
#include <epan/arcnet_pids.h>
#include <epan/conversation.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-ip.h"
#include "packet-ipx.h"
#include "packet-netbios.h"
#include "packet-vines.h"
#include "packet-sll.h"
#include <epan/sna-utils.h>

#include "packet-llc.h"

#define UDP_PORT_LLC1   12000
#define UDP_PORT_LLC2   12001
#define UDP_PORT_LLC3   12002
#define UDP_PORT_LLC4   12003
#define UDP_PORT_LLC5   12004

static int proto_llc = -1;
static int hf_llc_dsap = -1;
static int hf_llc_ssap = -1;
static int hf_llc_dsap_ig = -1;
static int hf_llc_ssap_cr = -1;
static int hf_llc_ctrl = -1;
static int hf_llc_n_r = -1;
static int hf_llc_n_s = -1;
static int hf_llc_p = -1;
static int hf_llc_p_ext = -1;
static int hf_llc_f = -1;
static int hf_llc_f_ext = -1;
static int hf_llc_s_ftype = -1;
static int hf_llc_u_modifier_cmd = -1;
static int hf_llc_u_modifier_resp = -1;
static int hf_llc_ftype_i = -1;
static int hf_llc_ftype_s_u = -1;
static int hf_llc_ftype_s_u_ext = -1;
static int hf_llc_type = -1;
static int hf_llc_oui = -1;
static int hf_llc_pid = -1;

static int proto_basicxid = -1;
static int hf_llc_xid_format = -1;
static int hf_llc_xid_types = -1;
static int hf_llc_xid_wsize = -1;

static gint ett_llc = -1;
static gint ett_llc_ctrl = -1;
static gint ett_llc_basicxid = -1;

static dissector_table_t dsap_subdissector_table;
static dissector_table_t xid_subdissector_table;

static dissector_table_t ethertype_subdissector_table;
static dissector_table_t hpteam_subdissector_table;

static dissector_handle_t bpdu_handle;
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t eth_withfcs_handle;
static dissector_handle_t fddi_handle;
static dissector_handle_t tr_handle;
static dissector_handle_t turbo_handle;
static dissector_handle_t mesh_handle;
static dissector_handle_t data_handle;

/*
 * Group/Individual bit, in the DSAP.
 */
#define	DSAP_GI_BIT	0x01

/*
 * Command/Response bit, in the SSAP.
 *
 * The low-order bit of the SSAP apparently determines whether this
 * is a request or a response.  (RFC 1390, "Transmission of IP and
 * ARP over FDDI Networks", says
 *
 *	Command frames are identified by having the low order
 *	bit of the SSAP address reset to zero.  Response frames
 *	have the low order bit of the SSAP address set to one.
 *
 * and a page I've seen seems to imply that's part of 802.2.)
 */
#define	SSAP_CR_BIT	0x01

/*
 * Mask to extrace the SAP number from the DSAP or the SSAP.
 */
#define	SAP_MASK	0xFE

/*
 * These are for SSAP and DSAP, wth last bit always zero.
 * XXX - some DSAPs come in separate "individual" and "group" versions,
 * with the last bit 0 and 1, respectively (e.g., LLC Sub-layer Management,
 * IBM SNA Path Control, IBM Net Management), but, whilst 0xFE is
 * the ISO Network Layer Protocol, 0xFF is the Global LSAP.
 */
const value_string sap_vals[] = {
	{ SAP_NULL,           "NULL LSAP" },
	{ SAP_LLC_SLMGMT,     "LLC Sub-Layer Management" },
	{ SAP_SNA_PATHCTRL,   "SNA Path Control" },
	{ SAP_IP,             "TCP/IP" },
	{ SAP_SNA1,           "SNA" },
	{ SAP_SNA2,           "SNA" },
	{ SAP_PROWAY_NM_INIT, "PROWAY (IEC955) Network Management and Initialization" },
	{ SAP_NETWARE1,       "NetWare (unofficial?)" },
	{ SAP_OSINL1,         "ISO Network Layer (OSLAN 1)" },
	{ SAP_TI,             "Texas Instruments" },
	{ SAP_OSINL2,         "ISO Network Layer (unofficial?)" },
	{ SAP_OSINL3,         "ISO Network Layer (unofficial?)" },
	{ SAP_BPDU,           "Spanning Tree BPDU" },
	{ SAP_RS511,          "EIA RS-511 Manufacturing Message Service" },
	{ SAP_OSINL4,         "ISO Network Layer (OSLAN 2)" },
	{ SAP_X25,            "ISO 8208 (X.25 over 802.2)" },
	/*
	 * XXX - setting the group bit of SAP_X25 make 0x7F; is this just
	 * a group version of that?
	 */
	{ 0x7F,               "ISO 802.2" },
	{ SAP_XNS,            "XNS" },
	{ SAP_BACNET,         "BACnet" },
	{ SAP_NESTAR,         "Nestar" },
	{ SAP_PROWAY_ASLM,    "PROWAY (IEC955) Active Station List Maintenance" },
	{ SAP_ARP,            "ARP" },	/* XXX - hand to "dissect_arp()"? */
	{ SAP_HPJD,           "HP JetDirect Printer" },
	{ SAP_SNAP,           "SNAP" },
	{ SAP_VINES1,         "Banyan Vines" },
	{ SAP_VINES2,         "Banyan Vines" },
	{ SAP_NETWARE2,       "NetWare" },
	{ SAP_NETBIOS,        "NetBIOS" },
	{ SAP_IBMNM,          "IBM Net Management" },
	{ SAP_HPEXT,          "HP Extended LLC" },
	{ SAP_UB,             "Ungermann-Bass" },
	{ SAP_RPL,            "Remote Program Load" },
	{ SAP_OSINL5,         "ISO Network Layer" },
	{ SAP_GLOBAL,         "Global LSAP" },
	{ 0x00,               NULL }
};

/*
 * See
 *
 * http://standards.ieee.org/regauth/oui/oui.txt
 *
 * http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/vlan.htm
 *
 * for the PIDs for VTP and DRiP that go with an OUI of OUI_CISCO.
 */
const value_string oui_vals[] = {
	{ OUI_ENCAP_ETHER,	"Encapsulated Ethernet" },
	{ OUI_XEROX,		"Xerox" },
/*
http://www.cisco.com/univercd/cc/td/doc/product/software/ios113ed/113ed_cr/ibm_r/brprt1/brsrb.htm
*/
	{ OUI_CISCO,			"Cisco" },
	{ OUI_NORTEL,			"Nortel Discovery Protocol" },
	{ OUI_CISCO_90,			"Cisco IOS 9.0 Compatible" },
	{ OUI_FORCE10,			"Force10 Networks" },
	{ OUI_ERICSSON,			"Ericsson Group" },
	{ OUI_CATENA,			"Catena Networks" },
	{ OUI_SONY_ERICSSON,	"Sony Ericsson Mobile Communications AB" },
	{ OUI_SONY_ERICSSON_2,	"Sony Ericsson Mobile Communications AB" },
	{ OUI_PROFINET,			"PROFIBUS Nutzerorganisation e.V." },
	{ OUI_SONY_ERICSSON_3,	"Sony Ericsson Mobile Communications AB" },
	{ OUI_CIMETRICS,		"Cimetrics" },
	{ OUI_IEEE_802_3,		"IEEE 802.3" },
	{ OUI_MEDIA_ENDPOINT,	"Media (TIA TR-41 Committee)" },
	{ OUI_SONY_ERICSSON_4,	"Sony Ericsson Mobile Communications AB" },
	{ OUI_ERICSSON_MOBILE,	"Ericsson Mobile Platforms" },
	{ OUI_SONY_ERICSSON_5,	"Sony Ericsson Mobile Communications AB" },
	{ OUI_SONY_ERICSSON_6,	"Sony Ericsson Mobile Communications AB" },
	{ OUI_SONY_ERICSSON_7,	"Sony Ericsson Mobile Communications AB" },
	{ OUI_SONY_ERICSSON_8,	"Sony Ericsson Mobile Communications AB" },
	{ OUI_TURBOCELL,		"Karlnet (Turbocell)" },
	{ OUI_CISCOWL,			"Cisco Wireless (Aironet) L2" },
	{ OUI_MARVELL,			"Marvell Semiconductor" },
	{ OUI_BRIDGED,			"Frame Relay or ATM bridged frames" },
	{ OUI_IEEE_802_1,		"IEEE 802.1 Committee" },
	{ OUI_ATM_FORUM,		"ATM Forum" },
	{ OUI_EXTREME,			"Extreme Networks" },
	/* RFC 2427, RFC 2684 */
	{ OUI_CABLE_BPDU,		"DOCSIS Spanning Tree" }, /* DOCSIS spanning tree BPDU */
	{ OUI_SIEMENS,			"Siemens AG" },
	{ OUI_APPLE_ATALK,		"Apple (AppleTalk)" },
	{ OUI_HP,				"Hewlett-Packard" },
	{ OUI_HP_2,				"Hewlett-Packard" },
	/* Registry Name: PPP Vendor Specific OUI Options */
	{ OUI_3GPP2,			"3GPP2 Vendor specific packet ID" },
	{ OUI_ERICSSON_2,		"Ericsson Group" },
	{ 0,	NULL }
};

static const value_string format_vals[] = {
	{ 0x81,        "LLC basic format" },
	{ 0,           NULL }
};

/*
 * Mask to extract the type from XID frame.
 */
#define	TYPES_MASK	0x1F

static const value_string type_vals[] = {
	{ 1,           "Type 1 LLC (Class I LLC)" },
	{ 2,           "Type 2 LLC" },
	{ 3,           "Type 1 and Type 2 LLCs (Class II LLC)" },
	{ 4,           "Type 3 LLC" },
	{ 5,           "Type 1 and Type 3 LLCs (Class III LLC)" },
	{ 6,           "Type 2 and Type 3 LLCs" },
	{ 7,           "Type 1 and Type 2 and Type 3 LLCs (Class IV LLC)" },
	{ 0,           NULL }
};

/*
 * Hash table for translating OUIs to an oui_info_t.
 */
static GHashTable *oui_info_table = NULL;

/*
 * Add an entry for a new OUI.
 */
void
llc_add_oui(guint32 oui, const char *table_name, const char *table_ui_name,
    hf_register_info *hf_item)
{
	oui_info_t *new_info;

	new_info = g_malloc(sizeof (oui_info_t));
	new_info->table = register_dissector_table(table_name,
	    table_ui_name, FT_UINT16, BASE_HEX);
	new_info->field_info = hf_item;

	/*
	 * Create the hash table for OUI information, if it doesn't
	 * already exist.
	 */
	if (oui_info_table == NULL) {
		oui_info_table = g_hash_table_new(g_direct_hash,
		    g_direct_equal);
	}
	g_hash_table_insert(oui_info_table, GUINT_TO_POINTER(oui), new_info);
}

void
capture_llc(const guchar *pd, int offset, int len, packet_counts *ld) {

	int		is_snap;
	guint16		control;
	int		llc_header_len;

	if (!BYTES_ARE_IN_FRAME(offset, len, 2)) {
		ld->other++;
		return;
	}
	is_snap = (pd[offset] == SAP_SNAP) && (pd[offset+1] == SAP_SNAP);
	llc_header_len = 2;	/* DSAP + SSAP */

	/*
	 * XXX - the page referred to in the comment above about the
	 * Command/Response bit also implies that LLC Type 2 always
	 * uses extended operation, so we don't need to determine
	 * whether it's basic or extended operation; is that the case?
	 */
	control = get_xdlc_control(pd, offset+2, pd[offset+1] & SSAP_CR_BIT);
	llc_header_len += XDLC_CONTROL_LEN(control, TRUE);
	if (!BYTES_ARE_IN_FRAME(offset, len, llc_header_len)) {
		ld->other++;
		return;
	}

	if (!XDLC_IS_INFORMATION(control)) {
		ld->other++;
		return;
	}
	if (is_snap)
		capture_snap(pd, offset+llc_header_len, len, ld);
	else {
		/* non-SNAP */
		switch (pd[offset]) {

		case SAP_IP:
			capture_ip(pd, offset + llc_header_len, len, ld);
			break;

		case SAP_NETWARE1:
		case SAP_NETWARE2:
			capture_ipx(ld);
			break;

		case SAP_NETBIOS:
			capture_netbios(ld);
			break;

		case SAP_VINES1:
		case SAP_VINES2:
			capture_vines(ld);
			break;

		default:
			ld->other++;
			break;
		}
	}
}

void
capture_snap(const guchar *pd, int offset, int len, packet_counts *ld)
{
	guint32		oui;
	guint16		etype;

	if (!BYTES_ARE_IN_FRAME(offset, len, 5)) {
		ld->other++;
		return;
	}

	oui = pd[offset] << 16 | pd[offset+1] << 8 | pd[offset+2];
	etype = pntohs(&pd[offset+3]);
	switch (oui) {

	case OUI_ENCAP_ETHER:
	case OUI_CISCO_90:
	case OUI_APPLE_ATALK:
		/* No, I have no idea why Apple used
		   one of their own OUIs, rather than
		   OUI_ENCAP_ETHER, and an Ethernet
		   packet type as protocol ID, for
		   AppleTalk data packets - but used
		   OUI_ENCAP_ETHER and an Ethernet
		   packet type for AARP packets. */
		capture_ethertype(etype, pd, offset+5, len, ld);
		break;

	case OUI_CISCO:
		capture_ethertype(etype, pd, offset+5, len, ld);
		break;

	case OUI_MARVELL:
		/*
		 * OLPC packet.  The PID is an Ethertype, but
		 * there's a mesh header between the PID and
		 * the payload.  (We assume the header is
		 * 5 bytes, for now).
		 */
		capture_ethertype(etype, pd, offset+5+5, len, ld);
		break;

	default:
		ld->other++;
		break;
	}
}

/* Used only for U frames */
static const xdlc_cf_items llc_cf_items = {
	NULL,
	NULL,
	&hf_llc_p,
	&hf_llc_f,
	NULL,
	&hf_llc_u_modifier_cmd,
	&hf_llc_u_modifier_resp,
	NULL,
	&hf_llc_ftype_s_u
};

/* Used only for I and S frames */
static const xdlc_cf_items llc_cf_items_ext = {
	&hf_llc_n_r,
	&hf_llc_n_s,
	&hf_llc_p_ext,
	&hf_llc_f_ext,
	&hf_llc_s_ftype,
	NULL,
	NULL,
	&hf_llc_ftype_i,
	&hf_llc_ftype_s_u_ext
};

static void
dissect_basicxid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*xid_tree = NULL;
	proto_item	*ti = NULL;
	guint8		format, types, wsize;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "XID");
	col_clear(pinfo->cinfo, COL_INFO);

	format = tvb_get_guint8(tvb, 0);
	if (tree) {
		ti = proto_tree_add_item(tree, proto_basicxid, tvb, 0, -1, FALSE);
		xid_tree = proto_item_add_subtree(ti, ett_llc_basicxid);
		proto_tree_add_uint(xid_tree, hf_llc_xid_format, tvb, 0,
			1, format);
	} else
		xid_tree = NULL;
	col_append_str(pinfo->cinfo, COL_INFO,
		    "Basic Format");

	types = tvb_get_guint8(tvb, 1);
	if (tree) {
		proto_tree_add_uint(xid_tree, hf_llc_xid_types, tvb, 1,
			1, types & TYPES_MASK);
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,
		    "; %s", val_to_str(types & TYPES_MASK, type_vals, "0x%02x")
		);
	}
	wsize = tvb_get_guint8(tvb, 2);
	if (tree) {
		proto_tree_add_uint(xid_tree, hf_llc_xid_wsize, tvb, 2,
			1, (wsize & 0xFE) >> 1);
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,
		    "; Window Size %d", (wsize & 0xFE) >> 1);
	}
}

static void
dissect_llc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*llc_tree = NULL;
	proto_item	*ti = NULL;
	int		is_snap;
	guint16		control;
	int		llc_header_len;
	guint8		dsap, ssap, format;
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LLC");
	col_clear(pinfo->cinfo, COL_INFO);

	dsap = tvb_get_guint8(tvb, 0);
	if (tree) {
		ti = proto_tree_add_item(tree, proto_llc, tvb, 0, -1, FALSE);
		llc_tree = proto_item_add_subtree(ti, ett_llc);
		proto_tree_add_uint(llc_tree, hf_llc_dsap, tvb, 0,
			1, dsap & SAP_MASK);
		proto_tree_add_boolean(llc_tree, hf_llc_dsap_ig, tvb, 0,
			1, dsap & DSAP_GI_BIT);
	} else
		llc_tree = NULL;

	ssap = tvb_get_guint8(tvb, 1);
	if (tree) {
		proto_tree_add_uint(llc_tree, hf_llc_ssap, tvb, 1,
			1, ssap & SAP_MASK);
		proto_tree_add_boolean(llc_tree, hf_llc_ssap_cr, tvb, 1,
			1, ssap & SSAP_CR_BIT);
	} else
		llc_tree = NULL;

	is_snap = (dsap == SAP_SNAP) && (ssap == SAP_SNAP);
	llc_header_len = 2;	/* DSAP + SSAP */

	/*
	 * XXX - the page referred to in the comment above about the
	 * Command/Response bit also implies that LLC Type 2 always
	 * uses extended operation, so we don't need to determine
	 * whether it's basic or extended operation; is that the case?
	 */
	control = dissect_xdlc_control(tvb, 2, pinfo, llc_tree,
				hf_llc_ctrl, ett_llc_ctrl,
				&llc_cf_items, &llc_cf_items_ext,
				NULL, NULL, ssap & SSAP_CR_BIT, TRUE, FALSE);
	llc_header_len += XDLC_CONTROL_LEN(control, TRUE);
	if (is_snap)
		llc_header_len += 5;	/* 3 bytes of OUI, 2 bytes of protocol ID */

	if (tree)
		proto_item_set_len(ti, llc_header_len);

	if (is_snap) {
		dissect_snap(tvb, 2+XDLC_CONTROL_LEN(control, TRUE), pinfo, tree, llc_tree, control,
		    hf_llc_oui, hf_llc_type, hf_llc_pid, 2);
	}
	else {
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_fstr(pinfo->cinfo, COL_INFO,
			    "; DSAP %s %s, SSAP %s %s",
			    val_to_str(dsap & SAP_MASK, sap_vals, "0x%02x"),
			    dsap & DSAP_GI_BIT ?
			      "Group" : "Individual",
			    val_to_str(ssap & SAP_MASK, sap_vals, "0x%02x"),
			    ssap & SSAP_CR_BIT ?
			      "Response" : "Command"
			);
		}

		if (tvb_length_remaining(tvb, llc_header_len) > 0) {
			next_tvb = tvb_new_subset_remaining(tvb, llc_header_len);
			if (XDLC_IS_INFORMATION(control)) {
				/*
				 * Non-SNAP I or UI frame.
				 * Try the regular LLC subdissector table
				 * with the DSAP.
				 */
				if (!dissector_try_uint(dsap_subdissector_table,
				    dsap, next_tvb, pinfo, tree)) {
					call_dissector(data_handle, next_tvb,
					    pinfo, tree);
				}
			} else if ((control & (XDLC_U_MODIFIER_MASK|XDLC_U))
			    == (XDLC_XID|XDLC_U)) {
				/*
				 * Non-SNAP XID frame.
				 * Test for LLC basic format first
				 */
				format = tvb_get_guint8(next_tvb, 0);
				if (format == 0x81) {
				    dissect_basicxid(next_tvb, pinfo, tree);
				} else {
				/*
				 * Try the XID LLC subdissector table
				 * with the DSAP.
				 */
				    if (!dissector_try_uint(
					xid_subdissector_table, dsap, next_tvb,
					pinfo, tree)) {
					    call_dissector(data_handle,
						next_tvb, pinfo, tree);
				    }
				}
			} else {
				call_dissector(data_handle, next_tvb, pinfo,
				    tree);
			}
		}
	}
}

/*
 * Dissect SNAP header; used elsewhere, e.g. in the Frame Relay dissector.
 */
void
dissect_snap(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
    proto_tree *snap_tree, int control, int hf_oui, int hf_type, int hf_pid,
    int bridge_pad)
{
	guint32		oui;
	guint16		etype;
	tvbuff_t	*next_tvb;
	oui_info_t	*oui_info;
	dissector_table_t subdissector_table;
	int		hf;
	int		mesh_header_len;

	/*
	 * XXX - what about non-UI frames?
	 */
	oui =	tvb_get_ntoh24(tvb, offset);
	etype = tvb_get_ntohs(tvb, offset+3);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,
		    "; SNAP, OUI 0x%06X (%s), PID 0x%04X",
		    oui, val_to_str(oui, oui_vals, "Unknown"), etype);
	}
	if (tree) {
		proto_tree_add_uint(snap_tree, hf_oui, tvb, offset, 3, oui);
	}

	switch (oui) {

	case OUI_HP_2:
		oui_info = get_snap_oui_info(oui);
		hf = *oui_info->field_info->p_id;
		subdissector_table = oui_info->table;
		proto_tree_add_uint(snap_tree, hf, tvb, offset+3, 2, etype);
		next_tvb = tvb_new_subset_remaining(tvb, offset+5);

		if(!dissector_try_uint(hpteam_subdissector_table,etype, next_tvb, pinfo, tree))
	 		call_dissector(data_handle, next_tvb, pinfo, tree);
		break;

	case OUI_ENCAP_ETHER:
	case OUI_CISCO_90:
	case OUI_APPLE_ATALK:
		/* No, I have no idea why Apple used
		   one of their own OUIs, rather than
		   OUI_ENCAP_ETHER, and an Ethernet
		   packet type as protocol ID, for
		   AppleTalk data packets - but used
		   OUI_ENCAP_ETHER and an Ethernet
		   packet type for AARP packets. */
		if (XDLC_IS_INFORMATION(control)) {
			if (tree) {
				proto_tree_add_uint(snap_tree, hf_type,
				    tvb, offset+3, 2, etype);
			}
			next_tvb = tvb_new_subset_remaining(tvb, offset+5);
			if (!dissector_try_uint(ethertype_subdissector_table,
			    etype, next_tvb, pinfo, tree))
				call_dissector(data_handle, next_tvb, pinfo,
				    tree);
		} else {
			next_tvb = tvb_new_subset_remaining(tvb, offset+5);
			call_dissector(data_handle, next_tvb, pinfo, tree);
		}
		break;

	case OUI_BRIDGED:
		/*
		 * MAC frames bridged over ATM (RFC 2684) or Frame Relay
		 * (RFC 2427).
		 *
		 * We have to figure out how much padding to put
		 * into the frame.  We were handed a "bridge_pad"
		 * argument which should be 0 for Frame Relay and
		 * 2 for ATM; we add to that the amount of padding
		 * common to both bridging types.
		 */
		if (tree) {
			proto_tree_add_uint(snap_tree, hf_pid, tvb, offset+3, 2,
			    etype);
		}

		switch (etype) {

		case BPID_ETH_WITH_FCS:
			next_tvb = tvb_new_subset_remaining(tvb, offset+5+bridge_pad);
			call_dissector(eth_withfcs_handle, next_tvb, pinfo,
			    tree);
			break;

		case BPID_ETH_WITHOUT_FCS:
			next_tvb = tvb_new_subset_remaining(tvb, offset+5+bridge_pad);
			call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
			break;

		case BPID_802_5_WITH_FCS:
		case BPID_802_5_WITHOUT_FCS:
			/*
			 * We treat the last padding byte as the Access
			 * Control byte, as that's what the Token
			 * Ring dissector expects the first byte to
			 * be.
			 */
			next_tvb = tvb_new_subset_remaining(tvb, offset+5+bridge_pad);
			call_dissector(tr_handle, next_tvb, pinfo, tree);
			break;

		case BPID_FDDI_WITH_FCS:
		case BPID_FDDI_WITHOUT_FCS:
			next_tvb = tvb_new_subset_remaining(tvb, offset+5+1+bridge_pad);
			call_dissector(fddi_handle, next_tvb, pinfo, tree);
			break;

		case BPID_BPDU:
			next_tvb = tvb_new_subset_remaining(tvb, offset+5);
			call_dissector(bpdu_handle, next_tvb, pinfo, tree);
			break;

		default:
			next_tvb = tvb_new_subset_remaining(tvb, offset+5);
			call_dissector(data_handle, next_tvb, pinfo, tree);
			break;
		}
		break;

	case OUI_CABLE_BPDU:    /* DOCSIS cable modem spanning tree BPDU */
		if (tree) {
			proto_tree_add_uint(snap_tree, hf_pid, tvb, offset+3, 2,
			    etype);
		}
		next_tvb = tvb_new_subset_remaining(tvb, offset+5);
		call_dissector(bpdu_handle, next_tvb, pinfo, tree);
		break;

	case OUI_TURBOCELL:
		next_tvb = tvb_new_subset_remaining(tvb, offset+3);
		call_dissector(turbo_handle, next_tvb, pinfo, tree);
		break;

	case OUI_MARVELL:
		/*
		 * OLPC packet.  The PID is an Ethertype, but
		 * there's a mesh header between the PID and
		 * the payload.
		 */
		if (XDLC_IS_INFORMATION(control)) {
			if (tree) {
				proto_tree_add_uint(snap_tree, hf_type,
				    tvb, offset+3, 2, etype);
			}
			next_tvb = tvb_new_subset_remaining(tvb, offset+5);
			mesh_header_len = call_dissector(mesh_handle,
			    next_tvb, pinfo, tree);
			next_tvb = tvb_new_subset_remaining(tvb, offset+5+mesh_header_len);
			if (!dissector_try_uint(ethertype_subdissector_table,
			    etype, next_tvb, pinfo, tree))
				call_dissector(data_handle, next_tvb, pinfo,
				    tree);
		} else {
			next_tvb = tvb_new_subset_remaining(tvb, offset+5);
			call_dissector(data_handle, next_tvb, pinfo, tree);
		}
		break;

	default:
		/*
		 * Do we have information for this OUI?
		 */
		oui_info = get_snap_oui_info(oui);
		if (oui_info != NULL) {
			/*
			 * Yes - use it.
			 */
			hf = *oui_info->field_info->p_id;
			subdissector_table = oui_info->table;
		} else {
			/*
			 * No, use hf_pid for the PID and just dissect
			 * the payload as data.
			 */
			hf = hf_pid;
			subdissector_table = NULL;
		}
		if (tree) {
			proto_tree_add_uint(snap_tree, hf, tvb, offset+3, 2,
			    etype);
		}
		next_tvb = tvb_new_subset_remaining(tvb, offset+5);
		if (XDLC_IS_INFORMATION(control)) {
			if (subdissector_table != NULL) {
				/* do lookup with the subdissector table */
				if (dissector_try_uint(subdissector_table,
				    etype, next_tvb, pinfo, tree))
					break;
			}
		}
		call_dissector(data_handle, next_tvb, pinfo, tree);
		break;
	}
}

/*
 * Return the oui_info_t for the PID for a particular OUI value, or NULL
 * if there isn't one.
 */
oui_info_t *
get_snap_oui_info(guint32 oui)
{
	if (oui_info_table != NULL) {
		return g_hash_table_lookup(oui_info_table,
		    GUINT_TO_POINTER(oui));
	} else
		return NULL;
}

void
proto_register_llc(void)
{
	static struct true_false_string ig_bit = { "Group", "Individual" };
	static struct true_false_string cr_bit = { "Response", "Command" };

	static hf_register_info hf[] = {
		{ &hf_llc_dsap,
		{ "DSAP",	"llc.dsap", FT_UINT8, BASE_HEX,
			VALS(sap_vals), 0x0, "DSAP - 7 Most Significant Bits only", HFILL }},

		{ &hf_llc_dsap_ig,
		{ "IG Bit",	"llc.dsap.ig", FT_BOOLEAN, BASE_NONE,
			TFS(&ig_bit), 0x0, "Individual/Group - Least Significant Bit only", HFILL }},

		{ &hf_llc_ssap,
		{ "SSAP", "llc.ssap", FT_UINT8, BASE_HEX,
			VALS(sap_vals), 0x0, "SSAP - 7 Most Significant Bits only", HFILL }},

		{ &hf_llc_ssap_cr,
		{ "CR Bit", "llc.ssap.cr", FT_BOOLEAN, BASE_NONE,
			TFS(&cr_bit), 0x0, "Command/Response - Least Significant Bit only", HFILL }},

		{ &hf_llc_ctrl,
		{ "Control", "llc.control", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_llc_n_r,
		{ "N(R)", "llc.control.n_r", FT_UINT16, BASE_DEC,
			NULL, XDLC_N_R_EXT_MASK, NULL, HFILL }},

		{ &hf_llc_n_s,
		{ "N(S)", "llc.control.n_s", FT_UINT16, BASE_DEC,
			NULL, XDLC_N_S_EXT_MASK, NULL, HFILL }},

		{ &hf_llc_p,
		{ "Poll", "llc.control.p", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), XDLC_P_F, NULL, HFILL }},

		{ &hf_llc_p_ext,
		{ "Poll", "llc.control.p", FT_BOOLEAN, 16,
			TFS(&tfs_set_notset), XDLC_P_F_EXT, NULL, HFILL }},

		{ &hf_llc_f,
		{ "Final", "llc.control.f", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), XDLC_P_F, NULL, HFILL }},

		{ &hf_llc_f_ext,
		{ "Final", "llc.control.f", FT_BOOLEAN, 16,
			TFS(&tfs_set_notset), XDLC_P_F_EXT, NULL, HFILL }},

		{ &hf_llc_s_ftype,
		{ "Supervisory frame type", "llc.control.s_ftype", FT_UINT16, BASE_HEX,
			VALS(stype_vals), XDLC_S_FTYPE_MASK, NULL, HFILL }},

		{ &hf_llc_u_modifier_cmd,
		{ "Command", "llc.control.u_modifier_cmd", FT_UINT8, BASE_HEX,
			VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK, NULL, HFILL }},

		{ &hf_llc_u_modifier_resp,
		{ "Response", "llc.control.u_modifier_resp", FT_UINT8, BASE_HEX,
			VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK, NULL, HFILL }},

		{ &hf_llc_ftype_i,
		{ "Frame type", "llc.control.ftype", FT_UINT16, BASE_HEX,
			VALS(ftype_vals), XDLC_I_MASK, NULL, HFILL }},

		{ &hf_llc_ftype_s_u,
		{ "Frame type", "llc.control.ftype", FT_UINT8, BASE_HEX,
			VALS(ftype_vals), XDLC_S_U_MASK, NULL, HFILL }},

		{ &hf_llc_ftype_s_u_ext,
		{ "Frame type", "llc.control.ftype", FT_UINT16, BASE_HEX,
			VALS(ftype_vals), XDLC_S_U_MASK, NULL, HFILL }},

		/* registered here but handled in ethertype.c */
		{ &hf_llc_type,
		{ "Type", "llc.type", FT_UINT16, BASE_HEX,
			VALS(etype_vals), 0x0, NULL, HFILL }},

		{ &hf_llc_oui,
		{ "Organization Code",	"llc.oui", FT_UINT24, BASE_HEX,
			VALS(oui_vals), 0x0, NULL, HFILL }},

		{ &hf_llc_pid,
		{ "Protocol ID", "llc.pid", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }}
	};
	static gint *ett[] = {
		&ett_llc,
		&ett_llc_ctrl
	};

	proto_llc = proto_register_protocol("Logical-Link Control", "LLC", "llc");
	proto_register_field_array(proto_llc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	dsap_subdissector_table = register_dissector_table("llc.dsap",
	  "LLC SAP", FT_UINT8, BASE_HEX);
	xid_subdissector_table = register_dissector_table("llc.xid_dsap",
	  "LLC XID SAP", FT_UINT8, BASE_HEX);

	register_dissector("llc", dissect_llc, proto_llc);
}

void
proto_register_basicxid(void)
{
	static hf_register_info hf[] = {
		{ &hf_llc_xid_format,
		{ "XID Format", "basicxid.llc.xid.format", FT_UINT8, BASE_HEX,
			VALS(format_vals), 0x0, NULL, HFILL }},

		{ &hf_llc_xid_types,
		{ "LLC Types/Classes", "basicxid.llc.xid.types", FT_UINT8, BASE_HEX,
			VALS(type_vals), 0x0, NULL, HFILL }},

		{ &hf_llc_xid_wsize,
		{ "Receive Window Size", "basicxid.llc.xid.wsize", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }}
	};
	static gint *ett[] = {
		&ett_llc_basicxid
	};

	proto_basicxid = proto_register_protocol("Logical-Link Control Basic Format XID", "Basic Format XID", "basicxid");
	proto_register_field_array(proto_basicxid, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("basicxid", dissect_basicxid, proto_basicxid);
}

static void
register_hf(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
	oui_info_t *info = value;

	proto_register_field_array(proto_llc, info->field_info, 1);
}

void
proto_reg_handoff_llc(void)
{
	dissector_handle_t llc_handle;

	/*
	 * Get handles for the BPDU, Ethernet, FDDI, Token Ring and
	 * Turbocell dissectors.
	 */
	bpdu_handle = find_dissector("bpdu");
	eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
	eth_withfcs_handle = find_dissector("eth_withfcs");
	fddi_handle = find_dissector("fddi");
	tr_handle = find_dissector("tr");
	turbo_handle = find_dissector("turbocell");
	mesh_handle = find_dissector("mesh");
	data_handle = find_dissector("data");

	/*
	 * Get the Ethertype dissector table.
	 */
	ethertype_subdissector_table = find_dissector_table("ethertype");
	hpteam_subdissector_table = find_dissector_table("llc.hpteam_pid");

	llc_handle = find_dissector("llc");
	dissector_add_uint("wtap_encap", WTAP_ENCAP_ATM_RFC1483, llc_handle);
	dissector_add_uint("sll.ltype", LINUX_SLL_P_802_2, llc_handle);
	/* RFC 2043 */
	dissector_add_uint("ppp.protocol", PPP_LLC, llc_handle);
	/* RFC 2353 */
	dissector_add_uint("udp.port", UDP_PORT_LLC1, llc_handle);
	dissector_add_uint("udp.port", UDP_PORT_LLC2, llc_handle);
	dissector_add_uint("udp.port", UDP_PORT_LLC3, llc_handle);
	dissector_add_uint("udp.port", UDP_PORT_LLC4, llc_handle);
	dissector_add_uint("udp.port", UDP_PORT_LLC5, llc_handle);
	/* IP-over-FC when we have the full FC frame */
	dissector_add_uint("fc.ftype", FC_FTYPE_IP, llc_handle);

	/*
	 * BACNET-over-ARCNET is really BACNET-over-802.2 LLC-over-ARCNET,
	 * apparently.
	 */
	dissector_add_uint("arcnet.protocol_id", ARCNET_PROTO_BACNET, llc_handle);
	dissector_add_uint("ethertype", ETHERTYPE_JUMBO_LLC, llc_handle);

	/*
	 * Register all the fields for PIDs for various OUIs.
	 */
	if (oui_info_table != NULL)
		g_hash_table_foreach(oui_info_table, register_hf, NULL);
}
