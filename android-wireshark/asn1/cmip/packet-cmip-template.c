/* packet-cmip.c
 * Routines for X.711 CMIP packet dissection
 *   Ronnie Sahlberg 2004
 *
 * $Id: packet-cmip-template.c 35894 2011-02-10 10:11:38Z stig $
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
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-x509if.h"
#include "packet-cmip.h"

#define PNAME  "X711 CMIP"
#define PSNAME "CMIP"
#define PFNAME "cmip"

/* XXX some stuff we need until we can get rid of it */
#include "packet-ses.h"
#include "packet-pres.h"

/* Initialize the protocol and registered fields */
static int proto_cmip = -1;
static int hf_cmip_actionType_OID = -1;
static int hf_cmip_eventType_OID = -1;
static int hf_cmip_attributeId_OID = -1;
static int hf_cmip_errorId_OID = -1;
static int hf_DiscriminatorConstruct = -1;
static int hf_Destination = -1;
static int hf_NameBinding = -1;
static int hf_ObjectClass = -1;
#include "packet-cmip-hf.c"

/* Initialize the subtree pointers */
static gint ett_cmip = -1;
#include "packet-cmip-ett.c"

static guint32 opcode;

/* Dissector table */
static dissector_table_t attribute_id_dissector_table;

#include "packet-cmip-table.c"

static int opcode_type;
#define OPCODE_INVOKE        1
#define OPCODE_RETURN_RESULT 2
#define OPCODE_RETURN_ERROR  3
#define OPCODE_REJECT        4

static int attributeform;
#define ATTRIBUTE_LOCAL_FORM  0
#define ATTRIBUTE_GLOBAL_FORM 1
static int attribute_local_id;
static const char *attribute_identifier_id;

static const char *attributevalueassertion_id;

static const char *object_identifier_id;

static int objectclassform;
#define OBJECTCLASS_LOCAL_FORM  0
#define OBJECTCLASS_GLOBAL_FORM 1
static const char *objectclass_identifier_id;

#include "packet-cmip-val.h"
#include "packet-cmip-fn.c"




/* XXX this one should be broken out later and moved into the conformance file */
static void
dissect_cmip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	static struct SESSION_DATA_STRUCTURE* session;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	session = (struct SESSION_DATA_STRUCTURE*)pinfo->private_data;

	/* do we have spdu type from the session dissector?  */
	if( !session ){
		proto_tree_add_text(tree, tvb, 0, -1,
			"Internal error:can't get spdu type from session dissector.");
		return;
	} else {
		if(session->spdu_type == 0 ) {
			proto_tree_add_text(tree, tvb, 0, -1,
				"Internal error:wrong spdu type %x from session dissector.",session->spdu_type);
			return;
		}
	}

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_cmip, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_cmip);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMIP");
  	col_clear(pinfo->cinfo, COL_INFO);
	switch(session->spdu_type){
		case SES_CONNECTION_REQUEST:
		case SES_CONNECTION_ACCEPT:
		case SES_DISCONNECT:
		case SES_FINISH:
		case SES_REFUSE:
			dissect_cmip_CMIPUserInfo(FALSE,tvb,0,&asn1_ctx,tree,-1);
			break;
		case SES_ABORT:
			dissect_cmip_CMIPAbortInfo(FALSE,tvb,0,&asn1_ctx,tree,-1);
			break;
		case SES_DATA_TRANSFER:
			dissect_cmip_ROS(FALSE,tvb,0,&asn1_ctx,tree,-1);
			break;
		default:
			;
	}
}

/*--- proto_register_cmip ----------------------------------------------*/
void proto_register_cmip(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cmip_actionType_OID,
      { "actionType", "cmip.actionType_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_eventType_OID,
      { "eventType", "cmip.eventType_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_attributeId_OID,
      { "attributeId", "cmip.attributeId_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_errorId_OID,
      { "errorId", "cmip.errorId_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
   { &hf_DiscriminatorConstruct,
      { "DiscriminatorConstruct", "cmip.DiscriminatorConstruct",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_Destination,
      { "Destination", "cmip.Destination",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_NameBinding,
      { "NameBinding", "cmip.NameBinding",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ObjectClass,
      { "ObjectClass", "cmip.ObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        NULL, HFILL }},

#include "packet-cmip-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_cmip,
#include "packet-cmip-ettarr.c"
  };

  /* Register protocol */
  proto_cmip = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cmip, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
#include "packet-cmip-dis-tab.c"
    oid_add_from_string("discriminatorId(1)","2.9.3.2.7.1");

  attribute_id_dissector_table = register_dissector_table("cmip.attribute_id", "CMIP Attribute Id", FT_UINT32, BASE_DEC);

}


/*--- proto_reg_handoff_cmip -------------------------------------------*/
void proto_reg_handoff_cmip(void) {
	register_ber_oid_dissector("2.9.0.0.2", dissect_cmip, proto_cmip, "cmip");
	register_ber_oid_dissector("2.9.1.1.4", dissect_cmip, proto_cmip, "joint-iso-itu-t(2) ms(9) cmip(1) cmip-pci(1) abstractSyntax(4)");

	oid_add_from_string("2.9.3.2.3.1","managedObjectClass(3) alarmRecord(1)");  
	oid_add_from_string("2.9.3.2.3.2","managedObjectClass(3) attributeValueChangeRecord(2)");
	oid_add_from_string("2.9.3.2.3.3","managedObjectClass(3) discriminator(3)");
	oid_add_from_string("2.9.3.2.3.4","managedObjectClass(3) eventForwardingDiscriminator(4)");
	oid_add_from_string("2.9.3.2.3.5","managedObjectClass(3) eventLogRecord(5)");
	oid_add_from_string("2.9.3.2.3.6","managedObjectClass(3) log(6)");
	oid_add_from_string("2.9.3.2.3.7","managedObjectClass(3) logRecord(7)");
	oid_add_from_string("2.9.3.2.3.8","managedObjectClass(3) objectCreationRecord(8)");
	oid_add_from_string("2.9.3.2.3.9","managedObjectClass(3) objectDeletionRecord(9)");
	oid_add_from_string("2.9.3.2.3.10","managedObjectClass(3) relationshipChangeRecord(10)");
	oid_add_from_string("2.9.3.2.3.11","managedObjectClass(3) securityAlarmReportRecord(11)");
	oid_add_from_string("2.9.3.2.3.12","managedObjectClass(3) stateChangeRecord(12)");
	oid_add_from_string("2.9.3.2.3.13","managedObjectClass(3) system(13)");
	oid_add_from_string("2.9.3.2.3.14","managedObjectClass(3) top(14)");
	oid_add_from_string("2.9.3.2.4.14","administrativeStatePackage(14)");
	oid_add_from_string("2.9.1.1.4","joint-iso-itu-t(2) ms(9) cmip(1) cmip-pci(1) abstractSyntax(4)");

/*#include "packet-cmip-dis-tab.c" */
}

