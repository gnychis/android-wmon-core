/* packet-hnbap-template.c
 * Routines for UMTS Node B Application Part(HNBAP) packet dissection
 * Copyright 2010 Neil Piercy, ip.access Limited <Neil.Piercy@ipaccess.com>
 *
 * $Id: packet-hnbap-template.c 35224 2010-12-20 05:35:29Z guy $
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
 *
 * Ref: 3GPP TS 25.469 version 8.4.0 Release 8
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/sctpppids.h>
#include <epan/asn1.h>
#include <epan/prefs.h>

#include "packet-per.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "UTRAN Iuh interface HNBAP signalling"
#define PSNAME "HNBAP"
#define PFNAME "hnbap"
/* Dissector will use SCTP PPID 20 or SCTP port. IANA assigned port = 29169*/
#define SCTP_PORT_HNBAP              29169

#include "packet-hnbap-val.h"

/* Initialize the protocol and registered fields */
static int proto_hnbap = -1;

#include "packet-hnbap-hf.c"

/* Initialize the subtree pointers */
static int ett_hnbap = -1;

#include "packet-hnbap-ett.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint global_sctp_port = SCTP_PORT_HNBAP;

/* Dissector tables */
static dissector_table_t hnbap_ies_dissector_table;
static dissector_table_t hnbap_extension_dissector_table;
static dissector_table_t hnbap_proc_imsg_dissector_table;
static dissector_table_t hnbap_proc_sout_dissector_table;
static dissector_table_t hnbap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void proto_reg_handoff_hnbap(void);

#include "packet-hnbap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(hnbap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(hnbap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}
#if 0
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureCode) return 0;
  return (dissector_try_string(hnbap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureCode) return 0;
  return (dissector_try_string(hnbap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureCode) return 0;
  return (dissector_try_string(hnbap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}
#endif

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(hnbap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(hnbap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(hnbap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static void
dissect_hnbap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *hnbap_item = NULL;
    proto_tree  *hnbap_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HNBAP");

    /* create the hnbap protocol tree */
    hnbap_item = proto_tree_add_item(tree, proto_hnbap, tvb, 0, -1, FALSE);
    hnbap_tree = proto_item_add_subtree(hnbap_item, ett_hnbap);

    dissect_HNBAP_PDU_PDU(tvb, pinfo, hnbap_tree);
}

/*--- proto_register_hnbap -------------------------------------------*/
void proto_register_hnbap(void) {
module_t *hnbap_module;

  /* List of fields */

  static hf_register_info hf[] = {

#include "packet-hnbap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
          &ett_hnbap,
#include "packet-hnbap-ettarr.c"
  };


  /* Register protocol */
  proto_hnbap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_hnbap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  register_dissector("hnbap", dissect_hnbap, proto_hnbap);

  /* Register dissector tables */
  hnbap_ies_dissector_table = register_dissector_table("hnbap.ies", "HNBAP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  hnbap_extension_dissector_table = register_dissector_table("hnbap.extension", "HNBAP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  hnbap_proc_imsg_dissector_table = register_dissector_table("hnbap.proc.imsg", "HNBAP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  hnbap_proc_sout_dissector_table = register_dissector_table("hnbap.proc.sout", "HNBAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  hnbap_proc_uout_dissector_table = register_dissector_table("hnbap.proc.uout", "HNBAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);

  hnbap_module = prefs_register_protocol(proto_hnbap, proto_reg_handoff_hnbap);
  prefs_register_uint_preference(hnbap_module, "port", "HNBAP SCTP Port", "Set the port for HNBAP messages (Default of 29169)", 10, &global_sctp_port);
}


/*--- proto_reg_handoff_hnbap ---------------------------------------*/
void
proto_reg_handoff_hnbap(void)
{
        static gboolean initialized = FALSE;
        static dissector_handle_t hnbap_handle;
        static guint sctp_port;

        if (!initialized) {
                hnbap_handle = find_dissector("hnbap");
                dissector_add_uint("sctp.ppi", HNBAP_PAYLOAD_PROTOCOL_ID, hnbap_handle);
                initialized = TRUE;
#include "packet-hnbap-dis-tab.c"

        } else {
                dissector_delete_uint("sctp.port", sctp_port, hnbap_handle);
        }
        /* Set our port number for future use */
        sctp_port = global_sctp_port;
        dissector_add_uint("sctp.port", sctp_port, hnbap_handle);
}
