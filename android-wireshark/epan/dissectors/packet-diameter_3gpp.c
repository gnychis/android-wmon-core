/* packet-diameter_3gpp.c
 * Routines for dissecting 3GPP OctetSting AVP:s
 * Copyright 2008, Anders Broman <anders.broman[at]ericsson.com>
 *
 * $Id: packet-diameter_3gpp.c 36497 2011-04-06 15:01:42Z etxrab $
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

 /* This dissector registers a dissector table for 3GPP Vendor specific
  * AVP:s which will be called from the Diameter dissector to dissect
  * the content of AVP:s of the OctetString type(or similar).
  */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/asn1.h>

#include "packet-gsm_map.h"
#include "packet-gsm_a_common.h"
#include "packet-e164.h"
#include "packet-e212.h"

/* Initialize the protocol and registered fields */
static int proto_diameter_3gpp			= -1;

static int hf_diameter_3gpp_msisdn					= -1;
static int hf_diameter_3gpp_user_data				= -1;
static int hf_diameter_3gpp_ipaddr					= -1;
static int hf_diameter_3gpp_mbms_required_qos_prio	= -1;
static int hf_diameter_3gpp_tmgi					= -1;
static int hf_diameter_mbms_service_id				= -1;
static int hf_diameter_address_digits = -1;
static int hf_diameter_3gpp_spare_bits = -1;
static int hf_diameter_3gpp_feature_list_flags = -1;
static int hf_diameter_3gpp_feature_list_flags_bit0 = -1;
static int hf_diameter_3gpp_feature_list_flags_bit1 = -1;
static int hf_diameter_3gpp_feature_list_flags_bit2 = -1;
static int hf_diameter_3gpp_ulr_flags = -1;
static int hf_diameter_3gpp_ulr_flags_bit0 = -1;
static int hf_diameter_3gpp_ulr_flags_bit1 = -1;
static int hf_diameter_3gpp_ulr_flags_bit2 = -1;
static int hf_diameter_3gpp_ulr_flags_bit3 = -1;
static int hf_diameter_3gpp_ulr_flags_bit4 = -1;
static int hf_diameter_3gpp_ulr_flags_bit5 = -1;
static int hf_diameter_3gpp_ulr_flags_bit6 = -1;
static int hf_diameter_3gpp_ula_flags = -1;
static int hf_diameter_3gpp_ula_flags_bit0 = -1;
static int hf_diameter_3gpp_dsr_flags = -1;
static int hf_diameter_3gpp_dsr_flags_bit0 = -1;
static int hf_diameter_3gpp_dsr_flags_bit1 = -1;
static int hf_diameter_3gpp_dsr_flags_bit2 = -1;
static int hf_diameter_3gpp_dsr_flags_bit3 = -1;
static int hf_diameter_3gpp_dsr_flags_bit4 = -1;
static int hf_diameter_3gpp_dsr_flags_bit5 = -1;
static int hf_diameter_3gpp_dsr_flags_bit6 = -1;
static int hf_diameter_3gpp_dsr_flags_bit7 = -1;
static int hf_diameter_3gpp_dsr_flags_bit8 = -1;
static int hf_diameter_3gpp_dsr_flags_bit9 = -1;
static int hf_diameter_3gpp_dsr_flags_bit10 = -1;
static int hf_diameter_3gpp_dsr_flags_bit11 = -1;
static int hf_diameter_3gpp_dsr_flags_bit12 = -1;
static int hf_diameter_3gpp_dsr_flags_bit13 = -1;
static int hf_diameter_3gpp_dsa_flags = -1;
static int hf_diameter_3gpp_dsa_flags_bit0 = -1;
static int hf_diameter_3gpp_ida_flags = -1;
static int hf_diameter_3gpp_ida_flags_bit0 = -1;
static int hf_diameter_3gpp_pua_flags = -1;
static int hf_diameter_3gpp_pua_flags_bit0 = -1;
static int hf_diameter_3gpp_pua_flags_bit1 = -1;
static int hf_diameter_3gpp_nor_flags = -1;
static int hf_diameter_3gpp_nor_flags_bit0 = -1;
static int hf_diameter_3gpp_nor_flags_bit1 = -1;
static int hf_diameter_3gpp_nor_flags_bit2 = -1;
static int hf_diameter_3gpp_nor_flags_bit3 = -1;
static int hf_diameter_3gpp_nor_flags_bit4 = -1;
static int hf_diameter_3gpp_idr_flags = -1;
static int hf_diameter_3gpp_idr_flags_bit0 = -1;
static int hf_diameter_3gpp_idr_flags_bit1 = -1;
static int hf_diameter_3gpp_idr_flags_bit2 = -1;
static int hf_diameter_3gpp_idr_flags_bit3 = -1;
static int hf_diameter_3gpp_idr_flags_bit4 = -1;
static gint diameter_3gpp_msisdn_ett				= -1;
static gint diameter_3gpp_feature_list_ett = -1;
static gint diameter_3gpp_tmgi_ett					= -1;
static gint diameter_3gpp_ulr_flags_ett = -1;
static gint diameter_3gpp_ula_flags_ett = -1;
static gint diameter_3gpp_dsr_flags_ett = -1;
static gint diameter_3gpp_dsa_flags_ett = -1;
static gint diameter_3gpp_ida_flags_ett = -1;
static gint diameter_3gpp_pua_flags_ett = -1;
static gint diameter_3gpp_nor_flags_ett = -1;
static gint diameter_3gpp_idr_flags_ett = -1;

/* Dissector handles */
static dissector_handle_t xml_handle;


/* AVP Code: 630 Feature-List
 * imscxdx.xml
 * IMS Cx Dx AVPS 3GPP TS 29.229
 */

static int
dissect_diameter_3gpp_feature_list(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	proto_item* item;
	proto_tree *sub_tree;
	int offset = 0;
    guint32 bit_offset;

	item       = proto_tree_add_item(tree, hf_diameter_3gpp_feature_list_flags, tvb, offset, 4, FALSE);
	sub_tree   = proto_item_add_subtree(item, diameter_3gpp_feature_list_ett);

    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 29, FALSE);
    bit_offset+=29;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list_flags_bit2, tvb, bit_offset, 1, FALSE);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list_flags_bit1, tvb, bit_offset, 1, FALSE);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list_flags_bit0, tvb, bit_offset, 1, FALSE);
    bit_offset++;

    offset = bit_offset>>3;
	return offset;

}

/* AVP Code: 701 MSISDN */
static int
dissect_diameter_3gpp_msisdn(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	proto_item* item;
	proto_tree *sub_tree;
	int offset = 0;
	const char     *digit_str;

	item = proto_tree_add_item(tree, hf_diameter_3gpp_msisdn, tvb, offset, 6, FALSE);
	sub_tree = proto_item_add_subtree(item,diameter_3gpp_msisdn_ett);

	dissect_e164_cc(tvb, sub_tree, offset, TRUE);

	digit_str = unpack_digits(tvb, 1);
	proto_tree_add_string(sub_tree, hf_diameter_address_digits, tvb, 1, -1, digit_str);

	return tvb_length(tvb);

}

/* AVP Code: 702 User-Data 
 * TGPPSh.xml
 * The AVP codes from 709 to799 are reserved for TS 29.329
 */
/* AVP Code: 606 User-Data 
 * imscxdx.xml
 * IMS Cx Dx AVPS 3GPP TS 29.229
 */
static int
dissect_diameter_3gpp_user_data(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	guint8		word[6];
	int length = tvb_length(tvb);

	/* If there is less than 38 characters this is not XML
	 * <?xml version="1.0" encoding="UTF-8"?>
	 */
	if(length < 38)
		return length;

	tvb_get_nstringz0(tvb, 0, sizeof(word),word);
	if (g_ascii_strncasecmp(word, "<?xml", 5) == 0){
		call_dissector(xml_handle, tvb, pinfo, tree);
	}

	return length;

}

/* AVP Code: 900 TMGI */
static int
dissect_diameter_3gpp_tmgi(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	proto_item* item;
	proto_tree *sub_tree;
	int offset = 0;

	item = proto_tree_add_item(tree, hf_diameter_3gpp_tmgi, tvb, offset, 6, FALSE);
	sub_tree = proto_item_add_subtree(item,diameter_3gpp_tmgi_ett);

	/* MBMS Service ID consisting of three octets. MBMS Service ID consists of a 6-digit
	 * fixed-length hexadecimal number between 000000 and FFFFFF.
	 * MBMS Service ID uniquely identifies an MBMS bearer service within a PLMN.
	 */

	proto_tree_add_item(sub_tree, hf_diameter_mbms_service_id, tvb, offset, 3, FALSE);
	offset = offset+3;
	offset = dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, offset, TRUE);

	return offset;

}

/* AVP Code: 903 MBMS-Service-Area */

/* AVP Code: 918 MBMS-BMSC-SSM-IP-Address */
static int
dissect_diameter_3gpp_ipaddr(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	int offset = 0;

	proto_tree_add_item(tree, hf_diameter_3gpp_ipaddr, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;

}

/* AVP Code: 913 MBMS-Required-QoS */
static int
dissect_diameter_3gpp_mbms_required_qos(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_) {

	int offset = 0;
	guint length;

	/* Octet
	 * 1		Allocation/Retention Priority as specified in 3GPP TS 23.107.
	 *			This octet encodes each priority level defined in 3GPP TS 23.107
	 *			as the binary value of the priority level. It specifies the relative
	 *			importance of the actual MBMS bearer service compared to other MBMS
	 *			and non-MBMS bearer services for allocation and retention of the
	 *			MBMS bearer service.
	 * 2-N		QoS Profile as specified by the Quality-of-Service information element,
	 *			from octet 3 onwards, in 3GPP TS 24.008
	 */
	proto_tree_add_item(tree, hf_diameter_3gpp_mbms_required_qos_prio, tvb, offset, 1, FALSE);
	offset++;
	length = tvb_length(tvb) - 1;
	de_sm_qos(tvb, tree,  pinfo, offset,length, NULL, 0);
	return offset+length;

}

/* AVP Code: 1405 ULR-Flags */
static int
dissect_diameter_3gpp_ulr_flags(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	proto_item* item;
	proto_tree *sub_tree;
	int offset = 0;
	guint32 bit_offset;

	item = proto_tree_add_item(tree, hf_diameter_3gpp_ulr_flags, tvb, offset, 4, FALSE);
	sub_tree = proto_item_add_subtree(item, diameter_3gpp_ulr_flags_ett);
	bit_offset = 0;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 25, FALSE);
	bit_offset+=25;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit6, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit5, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit4, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit3, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit2, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit1, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit0, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	offset = bit_offset>>3;
	return offset;

}

/* AVP Code: 1406 ULA-Flags */
static int
dissect_diameter_3gpp_ula_flags(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	proto_item* item;
	proto_tree *sub_tree;
	int offset = 0;
	guint32 bit_offset;

	item = proto_tree_add_item(tree, hf_diameter_3gpp_ula_flags, tvb, offset, 4, FALSE);
	sub_tree = proto_item_add_subtree(item, diameter_3gpp_ula_flags_ett);
	bit_offset = 0;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 31, FALSE);
	bit_offset+=31;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ula_flags_bit0, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	offset = bit_offset>>3;
	return offset;

}

/* AVP Code: 1421 DSR-Flags */
static int
dissect_diameter_3gpp_dsr_flags(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	proto_item* item;
	proto_tree *sub_tree;
	int offset = 0;
	guint32 bit_offset;

	item = proto_tree_add_item(tree, hf_diameter_3gpp_dsr_flags, tvb, offset, 4, FALSE);
	sub_tree = proto_item_add_subtree(item, diameter_3gpp_dsr_flags_ett);
	bit_offset = 0;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 18, FALSE);
	bit_offset+=18;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit13, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit12, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit11, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit10, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit9, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit8, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit7, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit6, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit5, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit4, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit3, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit2, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit1, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit0, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	offset = bit_offset>>3;
	return offset;

}

/* AVP Code: 1422 DSA-Flags */
static int
dissect_diameter_3gpp_dsa_flags(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	proto_item* item;
	proto_tree *sub_tree;
	int offset = 0;
	guint32 bit_offset;

	item = proto_tree_add_item(tree, hf_diameter_3gpp_dsa_flags, tvb, offset, 4, FALSE);
	sub_tree = proto_item_add_subtree(item, diameter_3gpp_dsa_flags_ett);
	bit_offset = 0;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 31, FALSE);
	bit_offset+=31;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsa_flags_bit0, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	offset = bit_offset>>3;
	return offset;

}

/* AVP Code: 1441 IDA-Flags */
static int
dissect_diameter_3gpp_ida_flags(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	proto_item* item;
	proto_tree *sub_tree;
	int offset = 0;
	guint32 bit_offset;

	item = proto_tree_add_item(tree, hf_diameter_3gpp_ida_flags, tvb, offset, 4, FALSE);
	sub_tree = proto_item_add_subtree(item, diameter_3gpp_ida_flags_ett);
	bit_offset = 0;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 31, FALSE);
	bit_offset+=31;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ida_flags_bit0, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	offset = bit_offset>>3;
	return offset;

}

/* AVP Code: 1442 PUA-Flags */
static int
dissect_diameter_3gpp_pua_flags(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	proto_item* item;
	proto_tree *sub_tree;
	int offset = 0;
	guint32 bit_offset;

	item = proto_tree_add_item(tree, hf_diameter_3gpp_pua_flags, tvb, offset, 4, FALSE);
	sub_tree = proto_item_add_subtree(item, diameter_3gpp_pua_flags_ett);
	bit_offset = 0;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 30, FALSE);
	bit_offset+=30;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_pua_flags_bit1, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_pua_flags_bit0, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	offset = bit_offset>>3;
	return offset;


}

/* AVP Code: 1443 NOR-Flags */
static int
dissect_diameter_3gpp_nor_flags(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	proto_item* item;
	proto_tree *sub_tree;
	int offset = 0;
	guint32 bit_offset;

	item = proto_tree_add_item(tree, hf_diameter_3gpp_nor_flags, tvb, offset, 4, FALSE);
	sub_tree = proto_item_add_subtree(item, diameter_3gpp_nor_flags_ett);
	bit_offset = 0;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 27, FALSE);
	bit_offset+=27;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit4, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit3, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit2, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit1, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit0, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	offset = bit_offset>>3;
	return offset;

}

/* AVP Code: 1490 IDR-Flags */
static int
dissect_diameter_3gpp_idr_flags(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	proto_item* item;
	proto_tree *sub_tree;
	int offset = 0;
	guint32 bit_offset;

	item = proto_tree_add_item(tree, hf_diameter_3gpp_idr_flags, tvb, offset, 4, FALSE);
	sub_tree = proto_item_add_subtree(item, diameter_3gpp_idr_flags_ett);
	bit_offset = 0;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 27, FALSE);
	bit_offset+=27;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit4, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit3, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit2, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit1, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit0, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	offset = bit_offset>>3;
	return offset;

}

void
proto_reg_handoff_diameter_3gpp(void)
{

	/* AVP Code: 5 3GPP-GPRS Negotiated QoS profile */
	/* Registered by packet-gtp.c */

	/* AVP Code: 22 3GPP-User-Location-Info
	 * Registered by packet-gtpv2.c
	 */

	/* AVP Code: 606 User-Data */
	dissector_add_uint("diameter.3gpp", 606, new_create_dissector_handle(dissect_diameter_3gpp_user_data, proto_diameter_3gpp));

	/* AVP Code: 630 Feature-List */
	dissector_add_uint("diameter.3gpp", 630, new_create_dissector_handle(dissect_diameter_3gpp_feature_list, proto_diameter_3gpp));

	/* AVP Code: 701 MSISDN */
	dissector_add_uint("diameter.3gpp", 701, new_create_dissector_handle(dissect_diameter_3gpp_msisdn, proto_diameter_3gpp));

	/* AVP Code: 702 User-Data */
	dissector_add_uint("diameter.3gpp", 702, new_create_dissector_handle(dissect_diameter_3gpp_user_data, proto_diameter_3gpp));

	/* AVP Code: 900 TMGI */
	dissector_add_uint("diameter.3gpp", 900, new_create_dissector_handle(dissect_diameter_3gpp_tmgi, proto_diameter_3gpp));

	/* AVP Code: 904 MBMS-Session-Duration  Registered by packet-gtp.c */
	/* AVP Code: 903 MBMS-Service-Area Registered by packet-gtp.c */

	/* AVP Code: 911 MBMS-Time-To-Data-Transfer  Registered by packet-gtp.c */
	/* Registered by packet-gtp.c */

	/* AVP Code: 913 MBMS-Required-QoS */
	dissector_add_uint("diameter.3gpp", 913, new_create_dissector_handle(dissect_diameter_3gpp_mbms_required_qos, proto_diameter_3gpp));

	/* AVP Code: 918 MBMS-BMSC-SSM-IP-Address */
	dissector_add_uint("diameter.3gpp", 918, new_create_dissector_handle(dissect_diameter_3gpp_ipaddr, proto_diameter_3gpp));

	/* AVP Code: 1405 ULR-Flags */
	dissector_add_uint("diameter.3gpp", 1405, new_create_dissector_handle(dissect_diameter_3gpp_ulr_flags, proto_diameter_3gpp));

	/* AVP Code: 1406 ULA-Flags */
	dissector_add_uint("diameter.3gpp", 1406, new_create_dissector_handle(dissect_diameter_3gpp_ula_flags, proto_diameter_3gpp));

	/* AVP Code: 1421 DSR-Flags */
	dissector_add_uint("diameter.3gpp", 1421, new_create_dissector_handle(dissect_diameter_3gpp_dsr_flags, proto_diameter_3gpp));

	/* AVP Code: 1422 DSA-Flags */
	dissector_add_uint("diameter.3gpp", 1422, new_create_dissector_handle(dissect_diameter_3gpp_dsa_flags, proto_diameter_3gpp));

	/* AVP Code: 1441 IDA-Flags */
	dissector_add_uint("diameter.3gpp", 1441, new_create_dissector_handle(dissect_diameter_3gpp_ida_flags, proto_diameter_3gpp));

	/* AVP Code: 1442 PUA-Flags */
	dissector_add_uint("diameter.3gpp", 1442, new_create_dissector_handle(dissect_diameter_3gpp_pua_flags, proto_diameter_3gpp));

	/* AVP Code: 1443 NOR-Flags */
	dissector_add_uint("diameter.3gpp", 1443, new_create_dissector_handle(dissect_diameter_3gpp_nor_flags, proto_diameter_3gpp));

	/* AVP Code: 1490 IDR-Flags */
	dissector_add_uint("diameter.3gpp", 1490, new_create_dissector_handle(dissect_diameter_3gpp_idr_flags, proto_diameter_3gpp));

	xml_handle = find_dissector("xml");
}

void
proto_register_diameter_3gpp(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_diameter_3gpp_msisdn,
			{ "MSISDN",           "diameter.3gpp.msisdn",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_user_data,
			{ "User data",           "diameter.3gpp.user_data",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ipaddr,
			{ "IPv4 Address",           "diameter.3gpp.ipaddr",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_mbms_required_qos_prio,
			{ "Allocation/Retention Priority",           "diameter.3gpp.mbms_required_qos_prio",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_tmgi,
			{ "TMGI",           "diameter.3gpp.tmgi",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_mbms_service_id,
			{ "MBMS Service ID",           "diameter.3gpp.mbms_service_id",
			FT_UINT24, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_address_digits,
			{ "Address digits", "diameter.3gpp.address_digits",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_spare_bits,
			{ "Spare bit(s)", "diameter.3gpp.spare_bits",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_feature_list_flags,
			{ "Feature-List Flags", "diameter.3gpp.feature_list_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_feature_list_flags_bit0,
			{ "Shared IFC Sets", "diameter.3gpp.feature_list_flags_bit0",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_feature_list_flags_bit1,
			{ "Alias Indication", "diameter.3gpp.feature_list_flags_bit1",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_feature_list_flags_bit2,
			{ "IMS Restoration Indication", "diameter.3gpp.feature_list_flags_bit2",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ulr_flags,
			{ "ULR Flags", "diameter.3gpp.ulr_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ulr_flags_bit0,
			{ "Single-Registration-Indication", "diameter.3gpp.ulr_flags_bit0",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ulr_flags_bit1,
			{ "S6a/S6d-Indicator", "diameter.3gpp.ulr_flags_bit1",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ulr_flags_bit2,
			{ "Skip-Subscriber-Data", "diameter.3gpp.ulr_flags_bit2",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ulr_flags_bit3,
			{ "GPRS-Subscription-Data-Indicator", "diameter.3gpp.ulr_flags_bit3",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ulr_flags_bit4,
			{ "Node-Type-Indicator", "diameter.3gpp.ulr_flags_bit4",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ulr_flags_bit5,
			{ "Initial-Attach-Indicator", "diameter.3gpp.ulr_flags_bit5",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ulr_flags_bit6,
			{ "PS-LCS-Not-Supported-By-UE", "diameter.3gpp.ulr_flags_bit6",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ula_flags,
			{ "ULA Flags", "diameter.3gpp.ula_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ula_flags_bit0,
			{ "Separation Indication", "diameter.3gpp.ula_flags_bit0",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags,
			{ "DSR Flags", "diameter.3gpp.dsr_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit0,
			{ "Regional Subscription Withdrawal", "diameter.3gpp.dsr_flags_bit0",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit1,
			{ "Complete APN Configuration Profile Withdrawal", "diameter.3gpp.dsr_flags_bit1",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit2,
			{ "Subscribed Charging Characteristics Withdrawal", "diameter.3gpp.dsr_flags_bit2",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit3,
			{ "PDN subscription contexts Withdrawal", "diameter.3gpp.dsr_flags_bit3",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit4,
			{ "STN-SR", "diameter.3gpp.dsr_flags_bit4",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit5,
			{ "Complete PDP context list Withdrawal", "diameter.3gpp.dsr_flags_bit5",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit6,
			{ "PDP contexts Withdrawal", "diameter.3gpp.dsr_flags_bit6",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit7,
			{ "Roaming Restricted due to unsupported feature", "diameter.3gpp.dsr_flags_bit7",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit8,
			{ "Trace Data Withdrawal", "diameter.3gpp.dsr_flags_bit8",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit9,
			{ "CSG Deleted", "diameter.3gpp.dsr_flags_bit9",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit10,
			{ "APN-OI-Replacement", "diameter.3gpp.dsr_flags_bit10",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit11,
			{ "GMLC List Withdrawal", "diameter.3gpp.dsr_flags_bit11",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit12,
			{ "LCS Withdrawal", "diameter.3gpp.dsr_flags_bit12",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsr_flags_bit13,
			{ "SMS Withdrawal", "diameter.3gpp.dsr_flags_bit13",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsa_flags,
			{ "DSA Flags", "diameter.3gpp.dsa_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_dsa_flags_bit0,
			{ "Network Node area restricted", "diameter.3gpp.dsa_flags_bit0",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ida_flags,
			{ "IDA Flags", "diameter.3gpp.ida_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_ida_flags_bit0,
			{ "Network Node area restricted", "diameter.3gpp.ida_flags_bit0",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_pua_flags,
			{ "PUA Flags", "diameter.3gpp.pua_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_pua_flags_bit0,
			{ "Freeze M-TMSI", "diameter.3gpp.pua_flags_bit0",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_pua_flags_bit1,
			{ "Freeze P-TMSI", "diameter.3gpp.pua_flags_bit1",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_nor_flags,
			{ "NOR Flags", "diameter.3gpp.nor_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_nor_flags_bit0,
			{ "Single-Registration-Indication", "diameter.3gpp.nor_flags_bit0",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_nor_flags_bit1,
			{ "SGSN area restricted", "diameter.3gpp.nor_flags_bit1",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_nor_flags_bit2,
			{ "Ready for SM", "diameter.3gpp.nor_flags_bit2",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_nor_flags_bit3,
			{ "UE Reachable", "diameter.3gpp.nor_flags_bit3",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_nor_flags_bit4,
			{ "Delete all APN and PDN GW identity pairs", "diameter.3gpp.nor_flags_bit4",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_idr_flags,
			{ "IDR Flags", "diameter.3gpp.idr_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_idr_flags_bit0,
			{ "UE Reachability Request", "diameter.3gpp.idr_flags_bit0",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_idr_flags_bit1,
			{ "T-ADS Data Request", "diameter.3gpp.idr_flags_bit1",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_idr_flags_bit2,
			{ "EPS User State Request", "diameter.3gpp.idr_flags_bit2",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_idr_flags_bit3,
			{ "EPS Location Information Request", "diameter.3gpp.idr_flags_bit3",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
		{ &hf_diameter_3gpp_idr_flags_bit4,
			{ "Current Location Request", "diameter.3gpp.idr_flags_bit4",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
			NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&diameter_3gpp_msisdn_ett,
		&diameter_3gpp_feature_list_ett,
		&diameter_3gpp_tmgi_ett,
		&diameter_3gpp_ulr_flags_ett,
		&diameter_3gpp_ula_flags_ett,
		&diameter_3gpp_dsr_flags_ett,
		&diameter_3gpp_dsa_flags_ett,
		&diameter_3gpp_ida_flags_ett,
		&diameter_3gpp_pua_flags_ett,
		&diameter_3gpp_nor_flags_ett,
		&diameter_3gpp_idr_flags_ett,
	};

	/* Required function calls to register the header fields and subtrees used */
	proto_diameter_3gpp = proto_register_protocol("Diameter 3GPP","Diameter3GPP", "diameter3gpp");
	proto_register_field_array(proto_diameter_3gpp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
