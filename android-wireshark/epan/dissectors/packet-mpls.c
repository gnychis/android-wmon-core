/* packet-mpls.c
 * Routines for MPLS data packet disassembly
 * RFC 3032
 *
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
 *
 * (c) Copyright 2006, _FF_ Francesco Fondelli <francesco.fondelli@gmail.com>
 *     - added MPLS OAM support, ITU-T Y.1711
 *     - PW Associated Channel Header dissection as per RFC 4385
 *     - PW MPLS Control Word dissection as per RFC 4385
 *     - mpls subdissector table indexed by label value
 *     - enhanced "what's past last mpls label?" heuristic
 *
 * $Id: packet-mpls.c 35224 2010-12-20 05:35:29Z guy $
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

/*
 * NOTES
 *
 * This module defines routines to handle Ethernet-encapsulated MPLS IP packets.
 * It should implement all the functionality in <draft-ietf-mpls-label-encaps-07.txt>
 * Multicast MPLS support is not tested yet
 */

/* FF NOTES
 *
 * The OAM patch should dissect OAM pdus as described in ITU-T Y.1711
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/ppptypes.h>
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include "packet-ppp.h"
#include "packet-mpls.h"
#include "packet-pw-common.h"

static gint proto_mpls = -1;
static gint proto_pw_ach = -1;
static gint proto_pw_mcw = -1;

static gint ett_mpls = -1;
static gint ett_mpls_pw_ach = -1;
static gint ett_mpls_pw_mcw = -1;
static gint ett_mpls_oam = -1;

void proto_reg_handoff_mpls(void);

const value_string special_labels[] = {
    {LABEL_IP4_EXPLICIT_NULL,	"IPv4 Explicit-Null"},
    {LABEL_ROUTER_ALERT,	"Router Alert"},
    {LABEL_IP6_EXPLICIT_NULL,	"IPv6 Explicit-Null"},
    {LABEL_IMPLICIT_NULL,	"Implicit-Null"},
    {LABEL_OAM_ALERT,		"OAM Alert"},
    {0, NULL }
};

/* MPLS filter values */
enum mpls_filter_keys {
    /* MPLS encap properties */
    MPLSF_LABEL,
    MPLSF_EXP,
    MPLSF_BOTTOM_OF_STACK,
    MPLSF_TTL,
    MPLSF_MAX
};

static dissector_handle_t dissector_data;
static dissector_handle_t dissector_ipv6;
static dissector_handle_t dissector_ip;
static dissector_handle_t dissector_bfd;
static dissector_handle_t dissector_pw_eth_heuristic;
static dissector_handle_t dissector_pw_fr;
static dissector_handle_t dissector_pw_hdlc_nocw_fr;
static dissector_handle_t dissector_pw_hdlc_nocw_hdlc_ppp;
static dissector_handle_t dissector_pw_eth_cw;
static dissector_handle_t dissector_pw_eth_nocw;
static dissector_handle_t dissector_pw_satop;
static dissector_handle_t dissector_itdm;
static dissector_handle_t dissector_mpls_pw_atm_n1_cw;
static dissector_handle_t dissector_mpls_pw_atm_n1_nocw;
static dissector_handle_t dissector_mpls_pw_atm_11_aal5pdu;
static dissector_handle_t dissector_mpls_pw_atm_aal5_sdu;
static dissector_handle_t dissector_pw_cesopsn;

enum mpls_default_dissector_t {
    MDD_PW_ETH_HEUR = 0
    ,MDD_PW_SATOP
    ,MDD_PW_CESOPSN
    ,MDD_MPLS_PW_FR_DLCI
    ,MDD_MPLS_PW_HDLC_NOCW_FRPORT
    ,MDD_MPLS_PW_HDLC_NOCW_HDLC_PPP
    ,MDD_MPLS_PW_ETH_CW
    ,MDD_MPLS_PW_ETH_NOCW
    ,MDD_MPLS_PW_GENERIC
    ,MDD_ITDM
    ,MDD_MPLS_PW_ATM_N1_CW
    ,MDD_MPLS_PW_ATM_N1_NOCW
    ,MDD_MPLS_PW_ATM_11_OR_AAL5_PDU
    ,MDD_MPLS_PW_ATM_AAL5_SDU
};

/* TODO the content of mpls_default_payload menu
 * should be automatically built like mpls "decode as..." menu;
 * this way, mpls_default_payload will be automatically filled up when
 * new mpls-specific dissector added.
 */
static enum_val_t mpls_default_payload_defs[] = {
    {
        "pw satop"
        ,pwc_longname_pw_satop
        ,MDD_PW_SATOP
    },
    {
        "pw cesopsn"
        ,pwc_longname_pw_cesopsn
        ,MDD_PW_CESOPSN
    },
    {
        "mpls pw ethernet heuristic"
        ,"Ethernet MPLS PW (CW is heuristically detected)"
        ,MDD_PW_ETH_HEUR
    },
    {
        "mpls pw fr dlci"
        ,"Frame relay DLCI MPLS PW"
        ,MDD_MPLS_PW_FR_DLCI
    },
    {
        "mpls pw hdlc no_cw fr_port"
        ,"HDLC MPLS PW (no CW), FR Port mode"
        ,MDD_MPLS_PW_HDLC_NOCW_FRPORT
    },
    {
        "mpls pw hdlc no_cw hdlc payload_ppp"
        ,"HDLC MPLS PW (no CW), HDLC mode, PPP payload"
        ,MDD_MPLS_PW_HDLC_NOCW_HDLC_PPP
    },
    {
        "mpls pw ethernet cw"
        ,"Ethernet MPLS PW (with CW)"
        ,MDD_MPLS_PW_ETH_CW
    },
    {
        "mpls pw ethernet no_cw"
        ,"Ethernet MPLS PW (no CW, early implementations)"
        ,MDD_MPLS_PW_ETH_NOCW
    },
    {
        "mpls pw generic cw"
        ,"Generic MPLS PW (with Generic/Preferred MPLS CW)"
        ,MDD_MPLS_PW_GENERIC
    },
    {
        "itdm"
        ,"Internal TDM"
        ,MDD_ITDM
    },
    {
        "mpls pw atm n_to_one cw"
        ,pwc_longname_pw_atm_n1_cw
        ,MDD_MPLS_PW_ATM_N1_CW
    },
    {
        "mpls pw atm n_to_one no_cw"
        ,pwc_longname_pw_atm_n1_nocw
        ,MDD_MPLS_PW_ATM_N1_NOCW
    },
    {
        "mpls pw atm one_to_one or aal5_pdu"
        ,pwc_longname_pw_atm_11_or_aal5_pdu
        ,MDD_MPLS_PW_ATM_11_OR_AAL5_PDU
    },
    {
        "mpls pw atm aal5_sdu"
        ,pwc_longname_pw_atm_aal5_sdu
        ,MDD_MPLS_PW_ATM_AAL5_SDU
    },
    {
        NULL
        ,NULL
        ,-1
    }
};

static int mpls_filter[MPLSF_MAX];

static gint mpls_default_payload = 0;
static gboolean mpls_pref_pwac_all_as_bfd_xipv4 = FALSE;
static gboolean mpls_pref_pwac_0x0_as_bfd = FALSE;
static gboolean mpls_pref_pwac_try_ppp = TRUE;

static int hf_mpls_1st_nibble = -1;

static int hf_mpls_pw_ach_ver = -1;
static int hf_mpls_pw_ach_res = -1;
static int hf_mpls_pw_ach_channel_type = -1;

static int hf_mpls_pw_mcw_flags = -1;
static int hf_mpls_pw_mcw_length = -1;
static int hf_mpls_pw_mcw_sequence_number = -1;

static int hf_mpls_oam_function_type = -1;
static int hf_mpls_oam_ttsi = -1;
static int hf_mpls_oam_frequency = -1;
static int hf_mpls_oam_defect_type = -1;
static int hf_mpls_oam_defect_location = -1;
static int hf_mpls_oam_bip16 = -1;

static const value_string oam_function_type_vals[] = {
    {0x00,	"Reserved"},
    {0x01,	"CV (Connectivity Verification)"},
    {0x02,	"FDI (Forward Defect Indicator)"},
    {0x03,	"BDI (Backward Defect Indicator)"},
    {0x04,	"Reserved for Performance packets"},
    {0x05,	"Reserved for LB-Req (Loopback Request)"},
    {0x06,	"Reserved for LB-Rsp (Loopback Response)"},
    {0x07,	"FDD (Fast Failure Detection)"},
    {0, NULL }
};

static const value_string oam_frequency_vals[] = {
    {0x00,	"Reserved"},
    {0x01,	"10 ms"},
    {0x02,	"20 ms"},
    {0x03,	"50 ms (default value)"},
    {0x04,	"100 ms"},
    {0x05,	"200 ms"},
    {0x06,	"500 ms"},
    /* 7-255 Reserved */
    {0, NULL }
};

static const value_string oam_defect_type_vals[] = {
    {0x0000,	"Reserved"},
    {0x0101,	"dServer"},
    {0x0102,	"dPeerME"},
    {0x0201,	"dLOCV"},
    {0x0202,	"dTTSI_Mismatch"},
    {0x0203,	"dTTSI_Mismerge"},
    {0x0204,	"dExcess"},
    {0x02FF,	"dUnknown"},
    {0xFFFF,	"Reserved"},
    {0, NULL }
};

#if 0 /*not used yet*/
/*
 * MPLS PW types
 * http://www.iana.org/assignments/pwe3-parameters
 */
static const value_string mpls_pw_types[] = {
	{ 0x0001, "Frame Relay DLCI ( Martini Mode )"              },
	{ 0x0002, "ATM AAL5 SDU VCC transport"                     },
	{ 0x0003, "ATM transparent cell transport"                 },
	{ 0x0004, "Ethernet Tagged Mode"                           },
	{ 0x0005, "Ethernet"                                       },
	{ 0x0006, "HDLC"                                           },
	{ 0x0007, "PPP"                                            },
	{ 0x0008, "SONET/SDH Circuit Emulation Service Over MPLS"  },
	{ 0x0009, "ATM n-to-one VCC cell transport"                },
	{ 0x000A, "ATM n-to-one VPC cell transport"                },
	{ 0x000B, "IP Layer2 Transport"                            },
	{ 0x000C, "ATM one-to-one VCC Cell Mode"                   },
	{ 0x000D, "ATM one-to-one VPC Cell Mode"                   },
	{ 0x000E, "ATM AAL5 PDU VCC transport"                     },
	{ 0x000F, "Frame-Relay Port mode"                          },
	{ 0x0010, "SONET/SDH Circuit Emulation over Packet"        },
	{ 0x0011, "Structure-agnostic E1 over Packet"              },
	{ 0x0012, "Structure-agnostic T1 (DS1) over Packet"        },
	{ 0x0013, "Structure-agnostic E3 over Packet"              },
	{ 0x0014, "Structure-agnostic T3 (DS3) over Packet"        },
	{ 0x0015, "CESoPSN basic mode"                             },
	{ 0x0016, "TDMoIP AAL1 Mode"                               },
	{ 0x0017, "CESoPSN TDM with CAS"                           },
	{ 0x0018, "TDMoIP AAL2 Mode"                               },
	{ 0x0019, "Frame Relay DLCI"                               },
	{ 0x001A, "ROHC Transport Header-compressed Packets"       },/*[RFC4995][RFC4901]*/
	{ 0x001B, "ECRTP Transport Header-compressed Packets"      },/*[RFC3545][RFC4901]*/
	{ 0x001C, "IPHC Transport Header-compressed Packets"       },/*[RFC2507][RFC4901]*/
	{ 0x001D, "cRTP Transport Header-compressed Packets"       },/*[RFC2508][RFC4901]*/
	{ 0x001E, "ATM VP Virtual Trunk"                           },/*[MFA9]*/
	{ 0x001F, "Reserved"                                       },/*[Bryant]  2008-04-17*/
	{ 0, NULL }
};
#endif

/*
 * MPLS PW Associated Channel Types
 * as per http://www.iana.org/assignments/pwe3-parameters
 * and http://tools.ietf.org/html/draft-ietf-pwe3-vccv-bfd-05 clause 3.2
 */
static const value_string mpls_pwac_types[] = {
        { 0x0007, "BFD Control, PW-ACH-encapsulated (BFD Without IP/UDP Headers)" },
	{ 0x0021, "IPv4 packet" },
	{ 0x0057, "IPv6 packet" },
	{ 0, NULL }
};


static dissector_table_t ppp_subdissector_table;
static dissector_table_t mpls_subdissector_table;

/*
 * Given a 4-byte MPLS label starting at offset "offset", in tvbuff "tvb",
 * decode it.
 * Return the label in "label", EXP bits in "exp",
 * bottom_of_stack in "bos", and TTL in "ttl"
 */
void decode_mpls_label(tvbuff_t *tvb, int offset,
		       guint32 *label, guint8 *exp,
		       guint8 *bos, guint8 *ttl)
{
    guint8 octet0 = tvb_get_guint8(tvb, offset+0);
    guint8 octet1 = tvb_get_guint8(tvb, offset+1);
    guint8 octet2 = tvb_get_guint8(tvb, offset+2);

    *label = (octet0 << 12) + (octet1 << 4) + ((octet2 >> 4) & 0xff);
    *exp = (octet2 >> 1) & 0x7;
    *bos = (octet2 & 0x1);
    *ttl = tvb_get_guint8(tvb, offset+3);
}

/*
 * FF: PW Associated Channel Header dissection as per RFC 4385.
 */
static void
dissect_pw_ach(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *mpls_pw_ach_tree = NULL;
    proto_item  *ti = NULL;
    tvbuff_t    *next_tvb = NULL;
    guint8      ver = 0;
    guint16     res = 0;
    guint16     channel_type = 0;

    if (tvb_reported_length_remaining(tvb, 0) < 4) {
        if (tree)
            proto_tree_add_text(tree, tvb, 0, -1, "Error processing Message");
        return;
    }
    ver = (tvb_get_guint8(tvb, 0) & 0x0F);
    res = tvb_get_guint8(tvb, 1);
    channel_type = tvb_get_ntohs(tvb, 2);
    if (tree) {
        ti = proto_tree_add_item(tree, proto_pw_ach, tvb, 0, 4, FALSE);
        mpls_pw_ach_tree = proto_item_add_subtree(ti, ett_mpls_pw_ach);
        if (mpls_pw_ach_tree == NULL)
            return;
        proto_tree_add_uint_format(mpls_pw_ach_tree, hf_mpls_pw_ach_ver,
                                   tvb, 0, 1, ver, "Version: %d", ver);
        ti = proto_tree_add_uint_format(mpls_pw_ach_tree, hf_mpls_pw_ach_res,
                                        tvb, 1, 1, res, "Reserved: 0x%02x", res);
        if (res != 0)
            proto_tree_add_text(mpls_pw_ach_tree, tvb, 1, 1,
                "Error: this byte is reserved and must be 0");
        else
            PROTO_ITEM_SET_HIDDEN(ti);
        proto_tree_add_uint_format(mpls_pw_ach_tree, hf_mpls_pw_ach_channel_type,
                                   tvb, 2, 2, channel_type,
                                   "Channel Type: %s (0x%04x)",
                                   val_to_str(channel_type, mpls_pwac_types, "Unknown"),
                                              channel_type);
    }
    next_tvb = tvb_new_subset_remaining(tvb, 4);

    if (0x21 == channel_type /*IPv4, RFC4385 clause 6.*/)
    {
        call_dissector(dissector_ip, next_tvb, pinfo, tree);
    }
    else if (0x7 == channel_type /*PWACH-encapsulated BFD, draft-ietf-pwe3-vccv-bfd-05 3.2*/
            || mpls_pref_pwac_all_as_bfd_xipv4)
    {
        call_dissector(dissector_bfd, next_tvb, pinfo, tree);
    }
    else if (0x57 == channel_type /*IPv6, RFC4385 clause 6.*/)
    {
        call_dissector(dissector_ipv6, next_tvb, pinfo, tree);
    }
    else if (0x0 == channel_type && mpls_pref_pwac_0x0_as_bfd)
    {
        call_dissector(dissector_bfd, next_tvb, pinfo, tree);
    }
    else if (mpls_pref_pwac_try_ppp)
    {
        /* XXX perhaps this code should be reconsidered */
        /* non-standard extension, therefore controlled by option*/
        /* appeared in revision 10862 from Carlos M. Pignataro */
        if (!dissector_try_uint(ppp_subdissector_table, channel_type,
                            next_tvb, pinfo, tree)) {
            call_dissector(dissector_data, next_tvb, pinfo, tree);
        }
    }
    else
    {
        call_dissector(dissector_data, next_tvb, pinfo, tree);
    }
}

gboolean dissect_try_cw_first_nibble( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	guint8 nibble;
	nibble = (tvb_get_guint8(tvb, 0 ) >> 4) & 0x0F;
	switch ( nibble )
	{
	case 6:
		call_dissector( dissector_ipv6, tvb, pinfo, tree);
		return TRUE;
	case 4:
		call_dissector( dissector_ip, tvb, pinfo, tree);
		return TRUE;
	case 1:
		dissect_pw_ach( tvb, pinfo, tree );
		return TRUE;
	default:
		break;
	}
	return FALSE;
}

/*
 * FF: Generic/Preferred PW MPLS Control Word dissection as per RFC 4385.
 */
static void
dissect_pw_mcw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *mpls_pw_mcw_tree = NULL;
    proto_item  *ti = NULL;
    tvbuff_t    *next_tvb = NULL;
    guint8      flags = 0;
    guint8      frg = 0;
    guint8      length = 0;
    guint16     sequence_number = 0;

    if (tvb_reported_length_remaining(tvb, 0) < 4) {
        if (tree)
            proto_tree_add_text(tree, tvb, 0, -1, "Error processing Message");
        return;
    }

    if ( dissect_try_cw_first_nibble( tvb, pinfo, tree ))
       return;

    /* bits 4 to 7 and FRG bits are displayed together */
    flags = (tvb_get_guint8(tvb, 0) & 0x0F) << 2;
    frg = (tvb_get_guint8(tvb, 1) & 0xC0) >> 6;
    flags |= frg;
    length = tvb_get_guint8(tvb, 1) & 0x3F;
    sequence_number = tvb_get_ntohs(tvb, 2);
    if (tree) {
        ti = proto_tree_add_item(tree, proto_pw_mcw, tvb, 0, 4, FALSE);
        mpls_pw_mcw_tree = proto_item_add_subtree(ti, ett_mpls_pw_mcw);
        if (mpls_pw_mcw_tree == NULL)
            return;
        proto_tree_add_uint_format(mpls_pw_mcw_tree, hf_mpls_pw_mcw_flags,
                                   tvb, 0, 1, flags, "Flags: 0x%02x", flags);
        ti = proto_tree_add_uint_format(mpls_pw_mcw_tree, hf_mpls_pw_mcw_length,
                                        tvb, 1, 1, length, "Length: %u", length);
        proto_tree_add_uint_format(mpls_pw_mcw_tree, hf_mpls_pw_mcw_sequence_number,
                                   tvb, 2, 2, sequence_number,
                                   "Sequence Number: %d", sequence_number);
    }
    next_tvb = tvb_new_subset_remaining(tvb, 4);
    call_dissector( dissector_data, next_tvb, pinfo, tree );
}

static void
dissect_mpls_oam_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *mpls_tree,
		     int offset, guint8 exp, guint8 bos, guint8 ttl)
{
    proto_tree  *mpls_oam_tree = NULL;
    proto_item  *ti = NULL;
    int functype = -1;
    const guint8 allone[] = { 0xff, 0xff };
    const guint8 allzero[] = { 0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00 };

    /* if called with main tree == null just set col info with func type string and return */
    if (!tree) {
	if (check_col(pinfo->cinfo, COL_INFO)) {
	    if (tvb_bytes_exist(tvb, offset, 1)) {
		functype = tvb_get_guint8(tvb, offset);
		col_append_fstr(pinfo->cinfo, COL_INFO, " (OAM: %s)",
				(functype == 0x01) ? "CV"  :
				(functype == 0x02) ? "FDI" :
				(functype == 0x03) ? "BDI" :
				(functype == 0x07) ? "FDD" : "reserved/unknown");
	    }
	}
	return;
    }

    /* sanity checks */
    if (!mpls_tree)
	return;

    if (!tvb_bytes_exist(tvb, offset, 44)) {
	/* ITU-T Y.1711, 5.3: OAM pdus must have a minimum payload length of 44 bytes */
	proto_tree_add_text(mpls_tree, tvb, offset, -1, "Error: must have a minimum payload length of 44 bytes");
	return;
    }

    ti = proto_tree_add_text(mpls_tree, tvb, offset, 44, "MPLS Operation & Maintenance");
    mpls_oam_tree = proto_item_add_subtree(ti, ett_mpls_oam);

    if (!mpls_oam_tree)
	return;

    /* checks for exp, bos and ttl encoding */

    if (exp!=0)
	proto_tree_add_text(mpls_oam_tree, tvb, offset - 2, 1, "Warning: Exp bits should be 0 for OAM");

    if (bos!=1)
	proto_tree_add_text(mpls_oam_tree, tvb, offset - 2, 1, "Warning: S bit should be 1 for OAM");

    if (ttl!=1)
	proto_tree_add_text(mpls_oam_tree, tvb, offset - 1, 1, "Warning: TTL should be 1 for OAM");

    /* starting dissection */

    functype = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(mpls_oam_tree, hf_mpls_oam_function_type, tvb, offset, 1, TRUE);
    offset++;

    switch(functype) {
    case 0x01: /* CV */
	{
	    guint32 lsrid_ipv4addr;

	    /* 3 octets reserved (all 0x00) */
	    if (tvb_memeql(tvb, offset, allzero, 3) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 3,
				    "Error: these bytes are reserved and must be 0x00");
	    }
	    offset+=3;

	    /* ttsi (ipv4 flavor as in RFC 2373) */
	    if (tvb_memeql(tvb, offset, allzero, 10) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 10,
				    "Error: these bytes are padding and must be 0x00");
	    }
	    offset+=10;

	    if (tvb_memeql(tvb, offset, allone, 2) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 2,
				    "Error: these bytes are padding and must be 0xFF");
	    }
	    offset+=2;

	    lsrid_ipv4addr = tvb_get_ipv4(tvb, offset);
	    proto_tree_add_text(mpls_oam_tree, tvb, offset, 4, "LSR ID: %s", ip_to_str((guint8 *)&lsrid_ipv4addr));
	    offset+=4;

	    proto_tree_add_text(mpls_oam_tree, tvb, offset, 4, "LSP ID: %d", tvb_get_ntohl(tvb, offset));
	    offset+=4;

	    /* 18 octets of padding (all 0x00) */
	    if (tvb_memeql(tvb, offset, allzero, 18) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 18,
				    "Error: these bytes are padding and must be 0x00");
	    }
	    offset+=18;
	}
	break;

    case 0x02: /* FDI */
    case 0x03: /* BDI */
	{
	    guint32 lsrid_ipv4addr;

	    /* 1 octets reserved (all 0x00) */
	    if (tvb_memeql(tvb, offset, allzero, 1) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 3,
				    "Error: this byte is reserved and must be 0x00");
	    }
	    offset++;

	    proto_tree_add_item(mpls_oam_tree, hf_mpls_oam_defect_type, tvb, offset, 2, TRUE);
	    offset+=2;

	    /* ttsi (ipv4 flavor as in RFC 2373) is optional if not used must be set to all 0x00 */
	    if (tvb_memeql(tvb, offset, allzero, 20) == 0) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 20, "TTSI not preset (optional for FDI/BDI)");
		offset+=20;
	    } else {
		if (tvb_memeql(tvb, offset, allzero, 10) == -1) {
		    proto_tree_add_text(mpls_oam_tree, tvb, offset, 10,
					"Error: these bytes are padding and must be 0x00");
		}
		offset+=10;

		if (tvb_memeql(tvb, offset, allone, 2) == -1) {
		    proto_tree_add_text(mpls_oam_tree, tvb, offset, 2,
					"Error: these bytes are padding and must be 0xFF");
		}
		offset+=2;

		lsrid_ipv4addr = tvb_get_ipv4(tvb, offset);
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 4, "LSR ID: %s", ip_to_str((guint8 *)&lsrid_ipv4addr));
		offset+=4;

		proto_tree_add_text(mpls_oam_tree, tvb, offset, 4, "LSP ID: %d", tvb_get_ntohl(tvb, offset));
		offset+=4;
	    }

	    /* defect location */
	    proto_tree_add_item(mpls_oam_tree, hf_mpls_oam_defect_location, tvb, offset, 4, TRUE);
	    offset+=4;

	    /* 14 octets of padding (all 0x00) */
	    if (tvb_memeql(tvb, offset, allzero, 14) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 14,
				    "Error: these bytes are padding and must be 0x00");
	    }
	    offset+=14;
	}
	break;

    case 0x07: /* FDD */
	{
	    guint32 lsrid_ipv4addr;

	    /* 3 octets reserved (all 0x00) */
	    if (tvb_memeql(tvb, offset, allzero, 3) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 3,
				    "Error: these bytes are reserved and must be 0x00");
	    }
	    offset+=3;

	    /* ttsi (ipv4 flavor as in RFC 2373) */
	    if (tvb_memeql(tvb, offset, allzero, 10) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 10,
				    "Error: these bytes are padding and must be 0x00");
	    }
	    offset+=10;

	    if (tvb_memeql(tvb, offset, allone, 2) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 2,
				    "Error: these bytes are padding and must be 0xFF");
	    }
	    offset+=2;

	    lsrid_ipv4addr = tvb_get_ipv4(tvb, offset);
	    proto_tree_add_text(mpls_oam_tree, tvb, offset, 4, "LSR ID: %s", ip_to_str((guint8 *)&lsrid_ipv4addr));
	    offset+=4;

	    proto_tree_add_text(mpls_oam_tree, tvb, offset, 4, "LSP ID: %d", tvb_get_ntohl(tvb, offset));
	    offset+=4;

	    proto_tree_add_item(mpls_oam_tree, hf_mpls_oam_frequency, tvb, offset, 1, TRUE);
	    offset++;

	    /* 17 octets of padding (all 0x00) */
	    if (tvb_memeql(tvb, offset, allzero, 17) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 17,
				    "Error: these bytes are padding and must be 0x00");
	    }
	    offset+=17;
	}
	break;

    default:
	proto_tree_add_text(mpls_oam_tree, tvb, offset - 1, -1, "Unknown MPLS OAM pdu");
	return;
    }

    /* BIP16 */
    proto_tree_add_item(mpls_oam_tree, hf_mpls_oam_bip16, tvb, offset, 2, TRUE);
    offset+=2;
}

static void
dissect_mpls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    guint32 label = LABEL_INVALID;
    guint8 exp;
    guint8 bos;
    guint8 ttl;
    proto_tree  *mpls_tree = NULL;
    proto_item  *ti;
    tvbuff_t *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPLS");

    col_set_str(pinfo->cinfo, COL_INFO, "MPLS Label Switched Packet");

    /* Start Decoding Here. */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {

	decode_mpls_label(tvb, offset, &label, &exp, &bos, &ttl);
	pinfo->mpls_label = label;

	if (tree) {

	    ti = proto_tree_add_item(tree, proto_mpls, tvb, offset, 4, FALSE);
	    mpls_tree = proto_item_add_subtree(ti, ett_mpls);

	    proto_item_append_text(ti, ", Label: %u", label);
	    if (label <= LABEL_MAX_RESERVED){
		proto_tree_add_uint_format(mpls_tree, mpls_filter[MPLSF_LABEL], tvb,
				    offset, 3, label, "MPLS Label: %u (%s)",
				    label, val_to_str(label, special_labels,
						      "Reserved - Unknown"));
		proto_item_append_text(ti, " (%s)", val_to_str(label, special_labels,
					"Reserved - Unknown"));
	    } else {
		proto_tree_add_uint_format(mpls_tree, mpls_filter[MPLSF_LABEL], tvb,
				    offset, 3, label, "MPLS Label: %u", label);
	    }

	    proto_tree_add_uint(mpls_tree,mpls_filter[MPLSF_EXP], tvb,
				offset+2,1, exp);
	    proto_item_append_text(ti, ", Exp: %u", exp);

	    proto_tree_add_uint(mpls_tree,mpls_filter[MPLSF_BOTTOM_OF_STACK], tvb,
				offset+2,1, bos);
	    proto_item_append_text(ti, ", S: %u", bos);

	    proto_tree_add_uint(mpls_tree,mpls_filter[MPLSF_TTL], tvb,
				offset+3,1, ttl);
	    proto_item_append_text(ti, ", TTL: %u", ttl);
	}

	if (label == LABEL_OAM_ALERT) {
	    /* OAM pdus are injected in normal data plane flow in order to test a LSP,
	     * they carry no user data.
	     */
	    dissect_mpls_oam_pdu(tvb, pinfo, tree, mpls_tree, offset + 4, exp, bos, ttl);
	    return;
	}

	offset += 4;
	if (bos) break;
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    if ( !dissector_try_uint(mpls_subdissector_table, label, next_tvb, pinfo, tree))
    {
        switch ( mpls_default_payload )
        {
        case MDD_PW_SATOP:
               call_dissector(dissector_pw_satop, next_tvb, pinfo, tree);
               break;
        case MDD_PW_CESOPSN:
               call_dissector(dissector_pw_cesopsn, next_tvb, pinfo, tree);
               break;
        case MDD_PW_ETH_HEUR:
               call_dissector(dissector_pw_eth_heuristic, next_tvb, pinfo, tree);
               break;
        case MDD_MPLS_PW_FR_DLCI:
               call_dissector(dissector_pw_fr, next_tvb, pinfo, tree);
               break;
        case MDD_MPLS_PW_HDLC_NOCW_FRPORT:
               call_dissector(dissector_pw_hdlc_nocw_fr, next_tvb, pinfo, tree);
               break;
        case MDD_MPLS_PW_HDLC_NOCW_HDLC_PPP:
               call_dissector(dissector_pw_hdlc_nocw_hdlc_ppp, next_tvb, pinfo, tree);
               break;
        case MDD_MPLS_PW_ETH_CW:
               call_dissector(dissector_pw_eth_cw, next_tvb, pinfo, tree);
               break;
        case MDD_MPLS_PW_ETH_NOCW:
               call_dissector(dissector_pw_eth_nocw, next_tvb, pinfo, tree);
               break;
        case MDD_ITDM:
               call_dissector(dissector_itdm, next_tvb, pinfo, tree);
               break;
        case MDD_MPLS_PW_ATM_N1_CW:
               call_dissector(dissector_mpls_pw_atm_n1_cw, next_tvb, pinfo, tree);
               break;
        case MDD_MPLS_PW_ATM_N1_NOCW:
               call_dissector(dissector_mpls_pw_atm_n1_nocw, next_tvb, pinfo, tree);
               break;
        case MDD_MPLS_PW_ATM_11_OR_AAL5_PDU:
               call_dissector(dissector_mpls_pw_atm_11_aal5pdu, next_tvb, pinfo, tree);
               break;
        case MDD_MPLS_PW_ATM_AAL5_SDU:
               call_dissector(dissector_mpls_pw_atm_aal5_sdu, next_tvb, pinfo, tree);
               break;
        default: /*fallthrough*/
	case MDD_MPLS_PW_GENERIC:
               dissect_pw_mcw(next_tvb, pinfo, tree);
               break;
        }
    }
}

void
proto_register_mpls(void)
{
	static hf_register_info mplsf_info[] = {

		/* MPLS header fields */
		{&mpls_filter[MPLSF_LABEL],
		 {"MPLS Label", "mpls.label", FT_UINT32, BASE_DEC, VALS(special_labels), 0x0,
		  NULL, HFILL }},

		{&mpls_filter[MPLSF_EXP],
		 {"MPLS Experimental Bits", "mpls.exp", FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{&mpls_filter[MPLSF_BOTTOM_OF_STACK],
		 {"MPLS Bottom Of Label Stack", "mpls.bottom", FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		{&mpls_filter[MPLSF_TTL],
		 {"MPLS TTL", "mpls.ttl", FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		/* 1st nibble */
		 {&hf_mpls_1st_nibble,
		 {"MPLS 1st nibble", "mpls.1st_nibble", FT_UINT8,
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

		/* PW Associated Channel Header fields */
		{&hf_mpls_pw_ach_ver,
		 {"PW Associated Channel Version", "pwach.ver", FT_UINT8, BASE_DEC,
		  NULL, 0x0, NULL, HFILL }},

		{&hf_mpls_pw_ach_res,
		 {"Reserved", "pwach.res", FT_UINT8, BASE_DEC,
		  NULL, 0x0, NULL, HFILL }},

		{&hf_mpls_pw_ach_channel_type,
		 {"PW Associated Channel Type", "pwach.channel_type", FT_UINT16, BASE_HEX,
		  NULL, 0x0, NULL, HFILL }},

		/* Generic/Preferred PW MPLS Control Word fields */
		{&hf_mpls_pw_mcw_flags,
		 {"Generic/Preferred PW MPLS Control Word Flags", "pwmcw.flags", FT_UINT8,
		  BASE_HEX, NULL, 0x0, NULL,
		  HFILL }},

		{&hf_mpls_pw_mcw_length,
		 {"Generic/Preferred PW MPLS Control Word Length", "pwmcw.length", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL,
		  HFILL }},

		{&hf_mpls_pw_mcw_sequence_number,
		 {"Generic/Preferred PW MPLS Control Word Sequence Number",
		  "pwmcw.sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }},

		/* OAM header fields */
		{&hf_mpls_oam_function_type,
		 {"Function Type", "mpls.oam.function_type", FT_UINT8,
		  BASE_HEX, VALS(oam_function_type_vals), 0x0, "Function Type codepoint", HFILL }},

		{&hf_mpls_oam_ttsi,
		 {"Trail Termination Source Identifier", "mpls.oam.ttsi", FT_UINT32,
		  BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_mpls_oam_frequency,
		 {"Frequency", "mpls.oam.frequency", FT_UINT8,
		  BASE_HEX, VALS(oam_frequency_vals), 0x0, "Frequency of probe injection", HFILL }},

		{&hf_mpls_oam_defect_type,
		 {"Defect Type", "mpls.oam.defect_type", FT_UINT16,
		  BASE_HEX, VALS(oam_defect_type_vals), 0x0, NULL, HFILL }},

		{&hf_mpls_oam_defect_location,
		 {"Defect Location (AS)", "mpls.oam.defect_location", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "Defect Location", HFILL }},

		{&hf_mpls_oam_bip16,
		 {"BIP16", "mpls.oam.bip16", FT_UINT16,
		  BASE_HEX, NULL, 0x0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_mpls,
		&ett_mpls_pw_ach,
		&ett_mpls_pw_mcw,
		&ett_mpls_oam,
	};
	module_t * module_mpls;

	/* FF: mpls subdissector table is indexed by label */
	mpls_subdissector_table = register_dissector_table("mpls.label",
                                                           "MPLS protocol",
                                                           FT_UINT32, BASE_DEC);
	proto_mpls = proto_register_protocol("MultiProtocol Label Switching Header",
                                             "MPLS", "mpls");
	proto_pw_ach = proto_register_protocol("PW Associated Channel Header",
					       "PW Associated Channel", "pwach");
	proto_pw_mcw = proto_register_protocol("PW MPLS Control Word (generic/preferred)",
					       "Generic PW (with CW)", "pwmcw");

	proto_register_field_array(proto_mpls, mplsf_info, array_length(mplsf_info));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("mpls", dissect_mpls, proto_mpls);
	register_dissector("mplspwcw", dissect_pw_mcw, proto_pw_mcw );

	module_mpls = prefs_register_protocol( proto_mpls, proto_reg_handoff_mpls );

	prefs_register_enum_preference(	module_mpls,
					"mplspref.payload",
					"Default decoder for MPLS payload",
					"Default decoder for MPLS payload",
					&mpls_default_payload,
					mpls_default_payload_defs,
					FALSE );
	prefs_register_bool_preference(module_mpls
		,"mplspref.pwac_0x0_as_bfd"
		,"Assume PWAC Channel Type 0x0 is raw BFD"
		,"draft-ietf-pwe3-vccv-bfd-05 states that PWAC Channel Type 0x07 must be used"
		" when VCCV carries PW-ACH-encapsulated BFD (i.e., BFD without IP/UDP Headers, or \"raw\" BFD)"
		"\n\n"
		"Legacy or buggy devices may not comply to this and use Channel Type 0x0 for BFD."
		" Enable this preference to decode such BFD traffic."
		" Disable for standard behavior of PWAC dissector (default)."
		,&mpls_pref_pwac_0x0_as_bfd);
	prefs_register_bool_preference(module_mpls
		,"mplspref.pwac_all_as_bfd_xip"
		,"Assume that all PWAC Channel Types (except 0x21) are raw BFD"
		,"draft-ietf-pwe3-vccv-bfd-05 states that PWAC Channel Type 0x07 must be used"
		" when VCCV carries PW-ACH-encapsulated BFD (i.e., \"raw\" BFD)"
		"\n\n"
		"Legacy or buggy devices may not comply to this and use voluntary Channel Type for BFD."
		" Enable this preference to decode all PWAC Channel Types as raw BFD,"
		" except Channel Type 0x21 (IPv4)."
		" Disable for standard behavior of PWAC dissector (default)."
		,&mpls_pref_pwac_all_as_bfd_xipv4);
	prefs_register_bool_preference(module_mpls
		,"mplspref.pwac_try_ppp"
		,"As a last resort, try to decode PWAC payloads as PPP traffic"
		,"Legacy devices may use MPLS PW Associated Channel for PPP traffic."
		"\n\n"
		"Enable this preference to allow PWAC dissector to try PPP,"
		" if no other suitable dissector found (default)."
		,&mpls_pref_pwac_try_ppp);
}

void
proto_reg_handoff_mpls(void)
{
	static gboolean initialized=FALSE;

	if ( !initialized )
	{
		dissector_handle_t mpls_handle;

		ppp_subdissector_table = find_dissector_table("ppp.protocol");

		mpls_handle = find_dissector("mpls");
		dissector_add_uint("ethertype", ETHERTYPE_MPLS, mpls_handle);
		dissector_add_uint("ethertype", ETHERTYPE_MPLS_MULTI, mpls_handle);
		dissector_add_uint("ppp.protocol", PPP_MPLS_UNI, mpls_handle);
		dissector_add_uint("ppp.protocol", PPP_MPLS_MULTI, mpls_handle);
		dissector_add_uint("chdlctype", ETHERTYPE_MPLS, mpls_handle);
		dissector_add_uint("chdlctype", ETHERTYPE_MPLS_MULTI, mpls_handle);
		dissector_add_uint("gre.proto", ETHERTYPE_MPLS, mpls_handle);
		dissector_add_uint("gre.proto", ETHERTYPE_MPLS_MULTI, mpls_handle);
		dissector_add_uint("ip.proto", IP_PROTO_MPLS_IN_IP, mpls_handle);

		mpls_handle = find_dissector("mplspwcw");
		dissector_add_uint( "mpls.label", LABEL_INVALID, mpls_handle );

		dissector_data 			= find_dissector("data");
		dissector_ipv6 			= find_dissector("ipv6");
		dissector_ip 			= find_dissector("ip");
		dissector_bfd			= find_dissector("bfd");
		dissector_pw_eth_heuristic 	= find_dissector("pw_eth_heuristic");
		dissector_pw_fr 		= find_dissector("pw_fr");
		dissector_pw_hdlc_nocw_fr 	= find_dissector("pw_hdlc_nocw_fr");
		dissector_pw_hdlc_nocw_hdlc_ppp = find_dissector("pw_hdlc_nocw_hdlc_ppp");
		dissector_pw_eth_cw 		= find_dissector("pw_eth_cw");
		dissector_pw_eth_nocw 		= find_dissector("pw_eth_nocw");
		dissector_pw_satop 		= find_dissector("pw_satop_mpls");
		dissector_itdm 			= find_dissector("itdm");
		dissector_mpls_pw_atm_n1_cw	= find_dissector("mpls_pw_atm_n1_cw");
		dissector_mpls_pw_atm_n1_nocw	= find_dissector("mpls_pw_atm_n1_nocw");
		dissector_mpls_pw_atm_11_aal5pdu= find_dissector("mpls_pw_atm_11_or_aal5_pdu");
		dissector_mpls_pw_atm_aal5_sdu	= find_dissector("mpls_pw_atm_aal5_sdu");
		dissector_pw_cesopsn		= find_dissector("pw_cesopsn_mpls");

		initialized = TRUE;
	}
}
