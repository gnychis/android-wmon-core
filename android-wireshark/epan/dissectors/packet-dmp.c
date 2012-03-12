/* packet-dmp.c
 *
 * Routines for STANAG 4406 Direct Message Profile packet disassembly.
 * A protocol for optimised transfer of time-critical short messages
 * for use with a reliable bearer service.  Checksum and retransmission
 * mechanisms are activated when using unreliable bearer services.
 *
 * Copyright 2006, Stig Bjorlykke <stig@bjorlykke.org>, Thales Norway AS
 *
 * $Id: packet-dmp.c 36353 2011-03-26 15:59:57Z stig $
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
 * TODO:
 * - Add Transmission/Retransmission statistics
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <math.h>

#include <epan/packet.h>
#include <epan/address.h>
#include <epan/addr_resolv.h>
#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/expert.h>
#include <epan/crc16.h>
#include <epan/asn1.h>

#include "packet-p1.h"
#include "packet-p22.h"

#define PNAME  "Direct Message Profile"
#define PSNAME "DMP"
#define PFNAME "dmp"

/* Default UDP Port Number */
#define DEFAULT_DMP_PORT_RANGE "5031"

/* Protocol Identifier */
#define PROT_NAT 0x0D
#define PROT_DMP 0x1D

/* Version supported */
#define DMP_VERSION_1  1

/* Message Type (dmp.msg_type) */
#define STANAG   0x0
#define IPM      0x1
#define REPORT   0x2
#define NOTIF    0x3
#define ACK      0x4

/* Report Type (dmp.report_type) */
#define DR       0x0
#define NDR      0x1

/* Notification Type (dmp.notif_type) */
#define RN       0x0
#define NRN      0x1
#define ON       0x2

/* Address Encoding (dmp.addr_enc) */
#define DIRECT_ADDR   0x0
#define EXTENDED_ADDR 0x1

/* Address type (internal values) */
#define ORIGINATOR   1
#define P1_ADDRESS   2
#define P2_ADDRESS   3

/* Extended Address Form (dmp_addr_form) */
#define P1_DIRECT             0x0
#define P2_DIRECT             0x1
#define P1_EXTENDED           0x2
#define P2_EXTENDED           0x3
#define P1_P2_DIRECT          0x4
#define P1_DIRECT_P2_EXTENDED 0x5
#define P1_EXTENDED_P2_DIRECT 0x6
#define P1_P2_EXTENDED        0x7

/* Extended Address Type */
#define ASN1_BER 0x0
#define ASN1_PER 0x1

/* Security Policy (dmp_sec_pol) */
#define NATO              0x4
#define NATIONAL          0x5
#define EXTENDED_NATIONAL 0x6
#define EXTENDED_MISSION  0x7

/* Body Format (dmp.body_format) */
#define FREE_TEXT         0x0
#define FREE_TEXT_SUBJECT 0x1
#define STRUCTURED        0x2

/* Encoded Information Types */
#define EIT_BILATERAL     0x3

/* Compression Algorithm */
#define ALGORITHM_NONE    0x0
#define ALGORITHM_ZLIB    0x1

/* Type of structured id to print */
#define STRUCT_ID_NONE     0
#define STRUCT_ID_UINT8    1
#define STRUCT_ID_UINT16   2
#define STRUCT_ID_UINT32   3
#define STRUCT_ID_UINT64   4
#define STRUCT_ID_STRING   5
#define STRUCT_ID_ZSTRING  6

/* Maximum lengths */
#define MAX_SIC_LEN         30

void proto_reg_handoff_dmp (void);

static int proto_dmp = -1;

static int hf_dmp_id = -1;

static int hf_envelope = -1;
static int hf_envelope_protocol_id = -1;
static int hf_envelope_version = -1;
static int hf_envelope_hop_count = -1;
static int hf_envelope_rec_present = -1;
static int hf_envelope_addr_enc = -1;
static int hf_envelope_checksum = -1;
static int hf_envelope_type = -1;
static int hf_envelope_msg_id = -1;
static int hf_envelope_subm_time = -1;
static int hf_envelope_subm_time_value = -1;
static int hf_envelope_time_diff_present = -1;
static int hf_envelope_time_diff = -1;
static int hf_envelope_time_diff_value = -1;
static int hf_envelope_flags = -1;
static int hf_envelope_content_id_discarded = -1;
static int hf_envelope_recip_reassign_prohib = -1;
static int hf_envelope_dl_expansion_prohib = -1;
static int hf_envelope_recipients = -1;
static int hf_envelope_ext_recipients = -1;

static int hf_message_content = -1;
static int hf_report_content = -1;
static int hf_notif_content = -1;

static int hf_addr_recipient = -1;
static int hf_addr_originator = -1;
static int hf_addr_reporting_name = -1;
static int hf_addr_dir_addr_ext = -1;
static int hf_addr_dir_rec_no = -1;
static int hf_addr_dir_rec_no1 = -1;
static int hf_addr_dir_rec_no2 = -1;
static int hf_addr_dir_rec_no3 = -1;
static int hf_addr_dir_rec_no_generated = -1;
static int hf_addr_dir_rep_req1 = -1;
static int hf_addr_dir_rep_req2 = -1;
static int hf_addr_dir_rep_req3 = -1;
static int hf_addr_dir_not_req1 = -1;
static int hf_addr_dir_not_req2 = -1;
static int hf_addr_dir_not_req3 = -1;
static int hf_addr_dir_action = -1;
static int hf_addr_dir_address = -1;
static int hf_addr_dir_address1 = -1;
static int hf_addr_dir_address2 = -1;
static int hf_addr_dir_address3 = -1;
static int hf_addr_dir_address_generated = -1;

static int hf_addr_ext_form = -1;
static int hf_addr_ext_form_orig = -1;
static int hf_addr_ext_action = -1;
static int hf_addr_ext_rep_req = -1;
static int hf_addr_ext_not_req = -1;
static int hf_addr_ext_rec_ext = -1;
static int hf_addr_ext_rec_no = -1;
static int hf_addr_ext_rec_no1 = -1;
static int hf_addr_ext_rec_no2 = -1;
static int hf_addr_ext_rec_no_generated = -1;
static int hf_addr_ext_address = -1;
static int hf_addr_ext_type = -1;
static int hf_addr_ext_type_ext = -1;
static int hf_addr_ext_length = -1;
static int hf_addr_ext_length1 = -1;
static int hf_addr_ext_length2 = -1;
static int hf_addr_ext_length_generated = -1;
static int hf_addr_ext_asn1_ber = -1;
static int hf_addr_ext_asn1_per = -1;
static int hf_addr_ext_unknown = -1;

static int hf_message_body = -1;
static int hf_message_st_type = -1;
static int hf_message_precedence = -1;
static int hf_message_importance = -1;
static int hf_message_body_format = -1;
static int hf_message_sec_class_nat = -1;
static int hf_message_sec_class_val = -1;
static int hf_message_sec_pol = -1;
static int hf_message_heading_flags = -1;
static int hf_message_auth_users = -1;
static int hf_message_subject_disc = -1;
static int hf_message_national_policy_id = -1;
static int hf_message_mission_policy_id = -1;
static int hf_message_sec_cat_nat = -1;
static int hf_message_sec_cat_val = -1;
static int hf_message_sec_cat_cl = -1;
static int hf_message_sec_cat_cs = -1;
static int hf_message_sec_cat_ex = -1;
static int hf_message_sec_cat_ne = -1;
static int hf_message_sec_cat_bit0 = -1;
static int hf_message_sec_cat_bit1 = -1;
static int hf_message_sec_cat_bit2 = -1;
static int hf_message_sec_cat_bit3 = -1;
static int hf_message_sec_cat_bit4 = -1;
static int hf_message_sec_cat_bit5 = -1;
static int hf_message_sec_cat_bit6 = -1;
static int hf_message_sec_cat_bit7 = -1;
static int hf_message_exp_time = -1;
static int hf_message_exp_time_val = -1;
static int hf_message_dtg = -1;
static int hf_message_dtg_sign = -1;
static int hf_message_dtg_val = -1;
static int hf_message_sic = -1;
static int hf_message_sic_key = -1;
static int hf_message_sic_key_values = -1;
static int hf_message_sic_key_type = -1;
static int hf_message_sic_key_chars = -1;
static int hf_message_sic_key_num = -1;
static int hf_message_sic_bitmap = -1;
static int hf_message_sic_bits = -1;
static int hf_message_sic_bits_any = -1;
static int hf_message_subj_id = -1;
static int hf_message_subject = -1;
static int hf_message_eit = -1;
static int hf_message_compr = -1;
static int hf_message_body_data = -1;
static int hf_message_body_plain = -1;
static int hf_message_bodyid_uint8 = -1;
static int hf_message_bodyid_uint16 = -1;
static int hf_message_bodyid_uint32 = -1;
static int hf_message_bodyid_uint64 = -1;
static int hf_message_bodyid_string = -1;
static int hf_message_bodyid_zstring = -1;
static int hf_message_body_structured = -1;
static int hf_message_body_uncompr = -1;
static int hf_message_body_uncompressed = -1;

static int hf_delivery_report = -1;
static int hf_non_delivery_report = -1;
static int hf_report_type = -1;
static int hf_report_info_present_dr = -1;
static int hf_report_addr_enc_dr = -1;
static int hf_report_del_time = -1;
static int hf_report_addr_enc_ndr = -1;
static int hf_report_reason = -1;
static int hf_report_info_present_ndr = -1;
static int hf_report_diagn = -1;
static int hf_report_suppl_info_len = -1;
static int hf_report_suppl_info = -1;

static int hf_receipt_notif = -1;
static int hf_non_receipt_notif = -1;
static int hf_other_notif = -1;
static int hf_notif_type = -1;
static int hf_notif_rec_time = -1;
static int hf_notif_rec_time_val = -1;
static int hf_notif_suppl_info_len = -1;
static int hf_notif_suppl_info = -1;
static int hf_notif_non_rec_reason = -1;
static int hf_notif_discard_reason = -1;
static int hf_notif_on_type = -1;
static int hf_notif_acp127 = -1;
static int hf_notif_acp127recip = -1;

static int hf_ack = -1;
static int hf_ack_reason = -1;
static int hf_ack_diagnostic = -1;
static int hf_ack_recips = -1;

static int hf_checksum = -1;
static int hf_checksum_good = -1;
static int hf_checksum_bad = -1;

static int hf_analysis_ack_time = -1;
static int hf_analysis_total_time = -1;
static int hf_analysis_retrans_time = -1;
static int hf_analysis_total_retrans_time = -1;
static int hf_analysis_msg_num = -1;
static int hf_analysis_msg_missing = -1;
static int hf_analysis_retrans_no = -1;
static int hf_analysis_ack_num = -1;
static int hf_analysis_ack_missing = -1;
static int hf_analysis_ack_dup_no = -1;
static int hf_analysis_rep_num = -1;
static int hf_analysis_rep_time = -1;
static int hf_analysis_not_num = -1;
static int hf_analysis_not_time = -1;
static int hf_analysis_msg_resend_from = -1;
static int hf_analysis_rep_resend_from = -1;
static int hf_analysis_not_resend_from = -1;
static int hf_analysis_ack_resend_from = -1;

static int hf_reserved_0x01 = -1;
static int hf_reserved_0x02 = -1;
static int hf_reserved_0x04 = -1;
static int hf_reserved_0x07 = -1;
static int hf_reserved_0x08 = -1;
static int hf_reserved_0x1F = -1;
static int hf_reserved_0x20 = -1;
static int hf_reserved_0x40 = -1;
static int hf_reserved_0xC0 = -1;
static int hf_reserved_0xE0 = -1;
static int hf_reserved_0x8000 = -1;

static gint ett_dmp = -1;
static gint ett_envelope = -1;
static gint ett_envelope_version = -1;
static gint ett_envelope_hop_count = -1;
static gint ett_envelope_rec_present = -1;
static gint ett_envelope_addr_enc = -1;
static gint ett_envelope_checksum = -1;
static gint ett_envelope_cont_type = -1;
static gint ett_envelope_subm_time = -1;
static gint ett_envelope_time_diff = -1;
static gint ett_envelope_flags = -1;
static gint ett_envelope_recipients = -1;
static gint ett_envelope_ext_recipients = -1;
static gint ett_envelope_addresses = -1;

static gint ett_address = -1;
static gint ett_address_direct = -1;
static gint ett_address_rec_no = -1;
static gint ett_address_extended = -1;
static gint ett_address_ext_form = -1;
static gint ett_address_ext_rec_no = -1;
static gint ett_address_ext_action = -1;
static gint ett_address_ext_rep_req = -1;
static gint ett_address_ext_not_req = -1;
static gint ett_address_ext_type = -1;
static gint ett_address_ext_length = -1;

static gint ett_content = -1;

static gint ett_message = -1;
static gint ett_message_st_type = -1;
static gint ett_message_reserved = -1;
static gint ett_message_precedence = -1;
static gint ett_message_importance = -1;
static gint ett_message_body_format = -1;
static gint ett_message_sec_class = -1;
static gint ett_message_sec_pol = -1;
static gint ett_message_sec_cat = -1;
static gint ett_message_heading_flags = -1;
static gint ett_message_exp_time = -1;
static gint ett_message_dtg = -1;
static gint ett_message_sic = -1;
static gint ett_message_sic_key = -1;
static gint ett_message_sic_bitmap = -1;
static gint ett_message_sic_bits = -1;
static gint ett_message_eit = -1;
static gint ett_message_compr = -1;
static gint ett_message_body_reserved = -1;
static gint ett_message_body = -1;
static gint ett_message_body_uncompr = -1;

static gint ett_report = -1;
static gint ett_report_type = -1;
static gint ett_report_info_present_dr = -1;
static gint ett_report_info_present_ndr = -1;
static gint ett_report_addr_enc_dr = -1;
static gint ett_report_addr_enc_ndr = -1;
static gint ett_report_reserved = -1;
static gint ett_report_del_time = -1;
static gint ett_report_reason = -1;
static gint ett_report_suppl_info = -1;
static gint ett_report_diagn = -1;

static gint ett_notif = -1;
static gint ett_notif_type = -1;
static gint ett_notif_rec_time = -1;
static gint ett_notif_suppl_info = -1;
static gint ett_notif_acp127recip = -1;

static gint ett_ack = -1;
static gint ett_ack_recips = -1;

static gint ett_checksum = -1;

static gint ett_analysis = -1;

static dissector_handle_t dmp_handle;

typedef struct _dmp_id_key {
  guint   id;
  address src;
  address dst;
} dmp_id_key;

typedef struct _dmp_id_val {
  gint     msg_type;                   /* Message type                   */
  guint    prev_msg_id;                /* Previous message package num   */
  guint    msg_id;                     /* Message package num            */
  guint    ack_id;                     /* Acknowledgement package num    */
  guint    rep_id;                     /* Report package num             */
  guint    not_id;                     /* Notification package num       */
  nstime_t msg_time;                   /* Message receive time           */
  nstime_t first_msg_time;             /* First message receive time     */
  nstime_t prev_msg_time;              /* Previous message receive time  */
  nstime_t rep_not_msg_time;           /* Report or Notification time    */
  guint32  msg_resend_count;           /* Message resend counter         */
  guint32  ack_resend_count;           /* Acknowledgement resend counter */
} dmp_id_val;

static GHashTable *dmp_id_hash_table = NULL;

/* Global values used in several functions */
static struct dmp_data {
  gint     version;
  gint     prot_id;
  gint     addr_enc;
  gint     checksum;
  gint     msg_type;
  gint     st_type;
  gint     prec;
  gint     body_format;
  gint     notif_type;
  gchar   *struct_id;
  gint32   subm_time;
  guint8   ack_reason;
  guint16  msg_id;
  guint16  subj_id;
  gboolean dr;
  gboolean ndr;
  gboolean ack_rec_present;
  dmp_id_val *id_val;
} dmp;

/* User definable values */
static range_t *global_dmp_port_range;
static gboolean use_seq_ack_analysis = TRUE;
static gboolean dmp_align = FALSE;
static gboolean dmp_subject_as_id = FALSE;
static gint     dmp_struct_format = STRUCT_ID_NONE;
static guint    dmp_struct_offset = 0;
static guint    dmp_struct_length = 1;

static const true_false_string addr_enc = {
  "Use Extended Encoding", "Use Direct Encoding"
};

static const true_false_string dtg_sign = {
  "Future", "Past"
};

static const true_false_string report_type = {
  "Non-Delivery Report", "Delivery Report"
};

static const value_string version_vals[] = {
  { 0x0, "1"       },
  { 0x1, "Unknown" },
  { 0x2, "Unknown" },
  { 0x3, "Unknown" },
  { 0x4, "Unknown" },
  { 0x5, "Unknown" },
  { 0x6, "Unknown" },
  { 0x7, "Unknown" },
  { 0,   NULL } };

static const value_string type_vals[] = {
  { 0x0, "Message"          },
  { 0x1, "Message (E-Mail)" },
  { 0x2, "Report"           },
  { 0x3, "Notification"     },
  { 0x4, "Acknowledgement"  },
  { 0x5, "Unknown Content"  },
  { 0x6, "Unknown Content"  },
  { 0x7, "Unknown Content"  },
  { 0,   NULL } };

static const value_string report_vals[] = {
  { 0x0, "No Report"           },
  { 0x1, "Delivery Report"     },
  { 0x2, "Non-Delivery Report" },
  { 0x3, "Reserved"            },
  { 0,   NULL } };

static const value_string report_vals_ext[] = {
  { 0x0, "No Report"                 },
  { 0x1, "Delivery Report"           },
  { 0x2, "Non-Delivery Report"       },
  { 0x3, "Recipient Number Extended" },
  { 0,   NULL } };

/* Note the space in front of these values */
static const value_string report_vals_short[] = {
  { 0x1, " DR"   },
  { 0x2, " NDR"  },
  { 0,   NULL } };

static const value_string notif_vals[] = {
  { 0x0, "No Notification"          },
  { 0x1, "Receipt Notification"     },
  { 0x2, "Non-Receipt Notification" },
  { 0x3, "Reserved"                 },
  { 0,   NULL } };

static const value_string notif_vals_ext[] = {
  { 0x0, "No Notification"          },
  { 0x1, "Receipt Notification"     },
  { 0x2, "Non-Receipt Notification" },
  { 0x3, "Direct Address Extended"  },
  { 0,   NULL } };

/* Note the space in front of these values */
static const value_string notif_vals_short[] = {
  { 0x1, " RN"   },
  { 0x2, " NRN"  },
  { 0,   NULL } };

static const value_string notif_type [] = {
  { 0x0, "Receipt Notification (RN)"      },
  { 0x1, "Non-Receipt Notification (NRN)" },
  { 0x2, "Other Notification (ON)"        },
  { 0x3, "Unknown Notification"           },
  { 0,   NULL } };

/* Note the space behind these values */
static const value_string addr_type_str [] = {
  { ORIGINATOR, ""         },
  { P1_ADDRESS, "P1 "      },
  { P2_ADDRESS, "P2/P722 " },
  { 0,          NULL } };

static const value_string addr_form [] = {
  { 0x0, "P1 Direct"                       },
  { 0x1, "P22/P772 Direct"                 },
  { 0x2, "P1 Extended"                     },
  { 0x3, "P22/P772 Extended"               },
  { 0x4, "P1 and P22/P772 Direct"          },
  { 0x5, "P1 Direct and P22/P772 Extended" },
  { 0x6, "P1 Extended and P22/P772 Direct" },
  { 0x7, "P1 and P22/P772 Extended"        },
  { 0,   NULL } };

static const value_string addr_form_orig [] = {
  { 0x0, "Direct"           },
  { 0x1, "Reserved"         },
  { 0x2, "Extended"         },
  { 0x3, "Reserved"         },
  { 0x4, "Reserved"         },
  { 0x5, "Reserved"         },
  { 0x6, "Reserved"         },
  { 0x7, "Reserved"         },
  { 0,   NULL } };

static const value_string ext_addr_type [] = {
  { 0x0, "ASN.1 BER-encoded OR-name" },
  { 0x1, "ASN.1 PER-encoded OR-name" },
  { 0x2, "Reserved" },
  { 0x3, "Reserved" },
  { 0x4, "Reserved" },
  { 0x5, "Reserved" },
  { 0x6, "Reserved" },
  { 0x7, "Address Length Extended" },
  { 0,   NULL } };

static const value_string ext_addr_type_ext [] = {
  { 0x0, "ASN.1 BER-encoded OR-name" },
  { 0x1, "ASN.1 PER-encoded OR-name" },
  { 0x2, "Reserved" },
  { 0x3, "Reserved" },
  { 0x4, "Reserved" },
  { 0x5, "Reserved" },
  { 0x6, "Reserved" },
  { 0x7, "Reserved" },
  { 0,   NULL } };

static const value_string ext_addr_type_short [] = {
  { 0x0, "OR-name (BER)" },
  { 0x1, "OR-name (PER)" },
  { 0x2, "Reserved" },
  { 0x3, "Reserved" },
  { 0x4, "Reserved" },
  { 0x5, "Reserved" },
  { 0x6, "Reserved" },
  { 0x7, "Reserved" },
  { 0,   NULL } };

static const value_string message_type_vals[] = {
  { 0x0, "Operation" },
  { 0x1, "Project"   },
  { 0x2, "Exercise"  },
  { 0x3, "Drill"     },
  { 0,   NULL } };

static const value_string precedence[] = {
  { 0x0, "Deferred"  },
  { 0x1, "Routine"   },
  { 0x2, "Priority"  },
  { 0x3, "Immediate" },
  { 0x4, "Flash"     },
  { 0x5, "Override"  },
  { 0x6, "Priority, Info Precedence: Routine"   },
  { 0x7, "Immediate, Info Precedence: Routine"  },
  { 0,   NULL } };

static const value_string importance[] = {
  { 0x0, "Low"      },
  { 0x1, "Reserved" },
  { 0x2, "Normal"   },
  { 0x3, "Reserved" },
  { 0x4, "High"     },
  { 0x5, "Reserved" },
  { 0x6, "Reserved" },
  { 0x7, "Reserved" },
  { 0,   NULL } };

static const value_string sec_class[] = {
  { 0x0, "Unmarked"     },
  { 0x1, "Unclassified" },
  { 0x2, "Reserved"     },
  { 0x3, "Restricted"   },
  { 0x4, "Reserved"     },
  { 0x5, "Confidential" },
  { 0x6, "Secret"       },
  { 0x7, "Top secret"   },
  { 0,   NULL } };

static const value_string sec_pol[] = {
  { 0x0, "Network defined"                   },
  { 0x1, "Network defined"                   },
  { 0x2, "Network defined"                   },
  { 0x3, "Network defined"                   },
  { 0x4, "NATO"                              },
  { 0x5, "National (nation of local server)" },
  { 0x6, "Extended, National"                },
  { 0x7, "Extended, Mission Defined"         },
  { 0,   NULL } };

static const value_string nat_pol_id[] = {
  { 0x00, "Unused"              },
  { 0x01, "Belgium (BE)"        },
  { 0x02, "Bulgaria (BG)"       },
  { 0x03, "Canada (CA)"         },
  { 0x04, "Czech Republic (CZ)" },
  { 0x05, "Denmark (DK)"        },
  { 0x06, "Estonia (ES)"        },
  { 0x07, "France (FR)"         },
  { 0x08, "Germany (DE)"        },
  { 0x09, "Greece (GR)"         },
  { 0x0A, "Hungary (HU)"        },
  { 0x0B, "Iceland (IS)"        },
  { 0x0C, "Italy (IT)"          },
  { 0x0D, "Latvia (LV)"         },
  { 0x0E, "Lithuania (LT)"      },
  { 0x0F, "Luxemburg (LU)"      },
  { 0x10, "Netherlands (NL)"    },
  { 0x11, "Norway (NO)"         },
  { 0x12, "Poland (PL)"         },
  { 0x13, "Portugal (PT)"       },
  { 0x14, "Romania (RO)"        },
  { 0x15, "Slovakia (SK)"       },
  { 0x16, "Slovenia (SI)"       },
  { 0x17, "Spain (ES)"          },
  { 0x18, "Turkey (TR)"         },
  { 0x19, "United Kingdom (GB)" },
  { 0x1A, "United States (US)"  },
  { 0xFF, "Reserved"            },
  { 0,    NULL } };

static const value_string sic_key_type[] = {
  { 0xc, "2 or more 3-character SICs"      },
  { 0xd, "1 or more 3-to-8 character SICs" },
  { 0,   NULL } };

static const true_false_string sic_key_chars = {
  "Any", "[A-Z0-9] only"
};

static const value_string sic_key_num[] = {
  { 0, "1"  },
  { 1, "2"  },
  { 2, "3"  },
  { 3, "4"  },
  { 4, "5"  },
  { 5, "6"  },
  { 6, "7"  },
  { 7, "8"  },
  { 0, NULL } };


static const value_string sic_bit_vals[] = {
  { 0,   "length:6, bytes:4" },
  { 1,   "length:6, bytes:4" },
  { 2,   "length:6, bytes:4" },
  { 3,   "length:6, bytes:4" },
  { 4,   "length:6, bytes:4" },
  { 5,   "length:6, bytes:4" },
  { 6,   "length:6, bytes:4" },
  { 7,   "length:6, bytes:4" },
  { 8,   "length:6, bytes:4" },
  { 9,   "reserved"          },
  { 10,  "length:5, bytes:4" },
  { 11,  "length:8, bytes:6" },
  { 12,  "length:4, bytes:3" },
  { 13,  "length:4, bytes:3" },
  { 14,  "length:7, bytes:5" },
  { 15,  "length:7, bytes:5" },
  { 0,   NULL } };

static const value_string sic_bit_any_vals[] = {
  { 0,   "length:5, bytes:4" },
  { 1,   "length:5, bytes:4" },
  { 2,   "length:5, bytes:4" },
  { 3,   "length:5, bytes:4" },
  { 4,   "length:5, bytes:4" },
  { 5,   "length:5, bytes:4" },
  { 6,   "length:5, bytes:4" },
  { 7,   "length:5, bytes:4" },
  { 8,   "length:5, bytes:4" },
  { 9,   "length:8, bytes:7" },
  { 10,  "length:4, bytes:4" },
  { 11,  "length:7, bytes:6" },
  { 12,  "length:6, bytes:5" },
  { 13,  "length:6, bytes:5" },
  { 14,  "length:6, bytes:5" },
  { 15,  "length:6, bytes:5" },
  { 0,   NULL } };

static const value_string body_format_vals[] = {
  { 0x0, "Free text"                    },
  { 0x1, "Free text including subject"  },
  { 0x2, "Structured"                   },
  { 0x3, "Reserved"                     },
  { 0,   NULL } };

static const value_string eit_vals[] = {
  { 0x0, "Empty"                             },
  { 0x1, "IA5-text"                          },
  { 0x2, "General text"                      },
  { 0x3, "Bilaterally defined (binary data)" },
  { 0x4, "AdatP-3"                           },
  { 0x5, "Reserved"                          },
  { 0x6, "Reserved"                          },
  { 0x7, "Reserved"                          },
  { 0,   NULL } };

static const value_string compression_vals[] = {
  { 0x0, "No compression"  },
  { 0x1, "ZLib compressed" },
  { 0x2, "Reserved"        },
  { 0x3, "Reserved"        },
  { 0,   NULL } };

static const value_string ack_reason [] = {
  { 0x00, "Successful, positive acknowledgement" },
  { 0x01, "Unspecified error"                    },
  { 0x02, "Checksum incorrect"                   },
  { 0,    NULL } };

static const value_string non_del_reason [] = {
  { 0x3D, "Unknown reason"                     },
  { 0x3E, "Reason code greater than 0x3c (60)" },
  { 0x3F, "Reserved"                           },
  { 0,    NULL } };

static const value_string non_del_diagn [] = {
  { 0x7C, "Diagnostic not specified"                },
  { 0x7D, "Unknown diagnostic"                      },
  { 0x7E, "Diagnostic code greater than 0x7b (123)" },
  { 0x7F, "Reserved"                                },
  { 0,    NULL } };

static const value_string discard_reason [] = {
  { 0xFE, "Discard Reason absent" },
  { 0xFF, "Reserved"              },
  { 0,    NULL } };

static const value_string on_type [] = {
  { 0x00, "acp127-nn" },
  { 0x01, "acp127-pn" },
  { 0x02, "acp127-tn" },
  { 0,    NULL } };

static const value_string ack_msg_type [] = {
  { STANAG, " (message)" },
  { IPM,    " (e-mail)"  },
  { REPORT, " (report)"  },
  { NOTIF,  " (notif)"   },
  { ACK,    " (ack)"     },
  { 0,      NULL } };

static enum_val_t struct_id_options[] = {
  { "none",    "None",                        STRUCT_ID_NONE     },
  { "1byte",   "1 Byte value",                STRUCT_ID_UINT8    },
  { "2byte",   "2 Byte value",                STRUCT_ID_UINT16   },
  { "4byte",   "4 Byte value",                STRUCT_ID_UINT32   },
  { "8byte",   "8 Byte value",                STRUCT_ID_UINT64   },
  { "fstring", "Fixed text string",           STRUCT_ID_STRING   },
  { "zstring", "Zero terminated text string", STRUCT_ID_ZSTRING  },
  { NULL,      NULL,                          0                  }
};

static const gchar *msg_type_to_str (void)
{
  const gchar *msg_type;
  gboolean     have_msg = FALSE;

  switch (dmp.msg_type) {

  case STANAG:
    /* Include message type and precedence */
    msg_type = ep_strdup_printf ("%s (%s) [%s]",
                val_to_str (dmp.msg_type, type_vals, "Unknown"),
                val_to_str (dmp.st_type, message_type_vals, "Unknown"),
                (dmp.prec == 0x6 || dmp.prec == 0x7) ?
                val_to_str (dmp.prec-4, precedence, "Unknown") :
                val_to_str (dmp.prec, precedence, "Unknown"));
    break;

  case IPM:
    /* Include importance */
    msg_type = ep_strdup_printf ("%s [%s]",
                val_to_str (dmp.msg_type, type_vals, "Unknown"),
                val_to_str (dmp.prec, importance, "Unknown"));
    break;

  case REPORT:
    /* Include report types included */
    msg_type = ep_strdup_printf ("Report (%s%s%s)",
                dmp.dr ? "DR" : "", (dmp.dr && dmp.ndr) ? " and " : "",
                dmp.ndr ? "NDR" : "");
    break;

  case NOTIF:
    msg_type = val_to_str (dmp.notif_type, notif_type, "Unknown");
    break;

  case ACK:
    /* If we have msg_time we have a matching packet */
    have_msg = (dmp.id_val &&
                (dmp.id_val->msg_time.secs>0 || dmp.id_val->msg_time.nsecs>0));
    msg_type = ep_strdup_printf ( "Acknowledgement%s%s",
                have_msg ? val_to_str (dmp.id_val->msg_type, ack_msg_type,
                                       " (unknown:%d)") : "",
                dmp.ack_reason ? " [negative]" : "");
    break;

  default:
    msg_type = "Unknown";
    break;
  }

  return msg_type;
}

static const gchar *non_del_reason_str (guint32 value)
{
  if (value < 0x3D) {
    /* Standard values according to P1 */
    return val_to_str (value, p1_NonDeliveryReasonCode_vals, "Unknown");
  } else {
    return val_to_str (value, non_del_reason, "Unknown");
  }
}

static const gchar *non_del_diagn_str (guint32 value)
{
  if (value < 0x7C) {
    /* Standard values according to P1 */
    return val_to_str (value, p1_NonDeliveryDiagnosticCode_vals, "Unknown");
  } else {
    return val_to_str (value, non_del_diagn, "Unknown");
  }
}

static const gchar *nrn_reason_str (guint32 value)
{
  /* Standard values according to P22 */
  return val_to_str (value, p22_NonReceiptReasonField_vals, "Reserved");
}

static const gchar *discard_reason_str (guint32 value)
{
  if (value < 0xFE) {
    /* Standard values according to P22 */
    return val_to_str (value, p22_DiscardReasonField_vals, "Reserved");
  } else {
    return val_to_str (value, discard_reason, "Unknown");
  }
}

/* Ref chapter 6.2.8.10 TimeDifference */
static gint32 dmp_dec_time_diff (guint8 dmp_time_diff)
{
  gint32 time_diff = 0;

  if (dmp_time_diff <= 0x01) {
    /* Reserved - low value */
    time_diff = -1;
  } else if (dmp_time_diff <= 0x1D) {
    /* Number of 2-second units (2-58 seconds) */
    time_diff = dmp_time_diff * 2;
  } else if (dmp_time_diff <= 0x91) {
    /* Number of 15-second units (1 min - 29 min 45 sec) */
    time_diff = (dmp_time_diff - 0x1D + 3) * 15;
  } else if (dmp_time_diff  <= 0xDF) {
    /* Number of 5-minute units (30 min - 6 hours 55 min) */
    time_diff = (dmp_time_diff - 0x91 + 5) * 5*60;
  } else if (dmp_time_diff <= 0xF7) {
    /* Number of 30-minute units (7 hours - 18 hours 30 min) */
    time_diff = (dmp_time_diff - 0xDF + 7) * 30*60;
  } else {
    /* Reserved - high value */
    time_diff = -2;
  }

  return time_diff;
}

/*
 * Ref chapter 6.3.7.2.10 ExpiryTime
 * and chapter 6.3.9.2.2  DeliveryTime
 */
static gint32 dmp_dec_exp_del_time (guint8 timev, gboolean expiry_time)
{
  gint32 time_value = 0;

  if (expiry_time && (timev == 0x00)) {
    /* No expiry time */
    time_value = -1;
  } else if (timev <= 0x1D) {
    /* Number of 2-second units (2-58 seconds) */
    time_value = timev * 2;
  } else if (timev <= 0x91) {
    /* Number of 15-second units (1 min - 29 min 45 sec) */
    time_value = (timev - 0x1D + 3) * 15;
  } else if (timev <= 0xBB) {
    /* Number of 5-minute units (30 min - 3 hours 55 min) */
    time_value = (timev - 0x91 + 5) * 5*60;
  } else if (timev <= 0xE3) {
    /* Number of 30-minute units (4 hours - 23 hours 30 min) */
    time_value = (timev - 0xBB + 7) * 30*60;
  } else if (timev < 0xFF) {
    /* Number of 2-hour units (24 - 78 hours) */
    time_value = (timev - 0xE3 + 11) * 2*3600;
  } else {
    /* Reserved */
    time_value = -2;
  }

  return time_value;
}

static gint32 dmp_dec_exp_time (guint8 expiry_time)
{
  return dmp_dec_exp_del_time (expiry_time, TRUE);
}

static gint32 dmp_dec_del_time (guint8 delivery_time)
{
  return dmp_dec_exp_del_time (delivery_time, FALSE);
}

/* Ref chapter 6.3.7.2.11 DTG */
static gint32 dmp_dec_dtg (guint32 dtg)
{
  gint32 value;

  if (dtg == 0x00) {
    /* Not present */
    return -1;
  } else if (dtg <= 0x3C) {
    /* Number of minutes (0-59 min) */
    value = (dtg - 1) * 60;
  } else if (dtg <= 0x64) {
    /* Number of 15-minute units (1 hour - 10 hours 45 min) */
    value = (dtg - 0x3C + 3) * 15 * 60;
  } else if (dtg < 0x7F) {
    /* Number of hours (11-36 hours) */
    value = (dtg - 0x64 + 10) * 3600;
  } else {
    /* Reserved */
    return -2;
  }

  return value;
}

/*
 * Ref chapter 7.10.11.1 Submission time
 *
 * start_time                 (current time)
 * delta1     = E             (encoded submission time)
 * delta2     = C             (encoded current time)
 * 0x01C2     = Pn + 15min    (maximum point for S1)
 * 0x7E38     = Pn+1 - 15min  (minimum point for S3)
 * 0x7FF8     = Pn+1          (length of P (period))
 */
static gint32 dmp_dec_subm_time (guint16 delta1, gint32 start_time)
{
  gint32  subm_time = start_time;
  guint16 delta2;

  delta2 = (guint16) ((subm_time / 2) % 0x7FF8);

  if ((delta1 < 0x01C2) && (delta2 >= delta1 + 0x7E38)) {
    subm_time += 2 * (0x7FF8 - delta2 + delta1);
  } else if ((delta1 >= 0x01C2) && (delta2 < delta1 - 0x01C2)) {
    subm_time -= 2 * (0x7FF8 - delta1 + delta2);
  } else {
    subm_time -= 2 * (delta2 - delta1);
  }

  return subm_time;
}

/* Ref chapter 6.3.7.2.12 SIC */
static gboolean dmp_dec_xbyte_sic (guint64 bin, gchar *sic,
                                   guint8 no_char, gboolean any)
{
  gboolean failure = FALSE;
  gdouble  multiplier;
  guint8   i;
  guint64  p, tmp;

  if (no_char >= MAX_SIC_LEN) {
    /* Illegal length */
    g_snprintf (sic, MAX_SIC_LEN, "Illegal length: %d", no_char);
    return TRUE;
  }

  if (any) {
    multiplier = 74.0;
  } else {
    multiplier = 36.0;
  }

  for (i = 0; i < no_char; i++) {
    p = (guint64) pow (multiplier, no_char - 1 - i);
    tmp = bin / p;
    bin -= tmp * p;
    sic[i] = (gchar) tmp;
    if (sic[i] <= 9) {
      sic[i] += '0';
    } else if (sic[i] <= 35) {
      sic[i] += ('A' - 10);
    } else if (!any) {
      sic[i] = '*';
      failure = TRUE;
    } else if (sic[i] <= 61) {
      sic[i] += ('a' - 36);
    } else if (sic[i] == 62) {
      sic[i] = '\'';
    } else if (sic[i] == 63) {
      sic[i] = '(';
    } else if (sic[i] == 64) {
      sic[i] = ')';
    } else if (sic[i] == 65) {
      sic[i] = '+';
    } else if (sic[i] == 66) {
      sic[i] = ',';
    } else if (sic[i] == 67) {
      sic[i] = '-';
    } else if (sic[i] == 68) {
      sic[i] = '.';
    } else if (sic[i] == 69) {
      sic[i] = '/';
    } else if (sic[i] == 70) {
      sic[i] = ':';
    } else if (sic[i] == 71) {
      sic[i] = '=';
    } else if (sic[i] == 72) {
      sic[i] = '?';
    } else if (sic[i] == 73) {
      sic[i] = ' ';
    } else {
      sic[i] = '*';
      failure = TRUE;
    }
  }
  sic[i] = '\0';

  return failure;
}

static guint dmp_id_hash (gconstpointer k)
{
  dmp_id_key *dmpx=(dmp_id_key *)k;
  return dmpx->id;
}

static gint dmp_id_hash_equal (gconstpointer k1, gconstpointer k2)
{
  dmp_id_key *dmp1=(dmp_id_key *)k1;
  dmp_id_key *dmp2=(dmp_id_key *)k2;
  if (dmp1->id != dmp2->id)
    return 0;

  return (ADDRESSES_EQUAL (&dmp1->src, &dmp2->src) &&
          ADDRESSES_EQUAL (&dmp1->dst, &dmp2->dst));
}

static void register_dmp_id (packet_info *pinfo, guint8 reason)
{
  dmp_id_val *dmp_data = NULL, *pkg_data = NULL;
  dmp_id_key *dmp_key = NULL;
  nstime_t    msg_time;
  guint       msg_id = 0;

  if (pinfo->in_error_pkt) {
    /* No analysis of error packets */
    return;
  }

  nstime_set_zero(&msg_time);

  dmp_key = se_alloc (sizeof (dmp_id_key));

  if (!pinfo->fd->flags.visited &&
      (dmp.msg_type == REPORT || dmp.msg_type == NOTIF))
  {
    /* Try to match corresponding message */
    dmp_key->id = (guint) dmp.subj_id;
    SE_COPY_ADDRESS(&dmp_key->src, &(pinfo->dst));
    SE_COPY_ADDRESS(&dmp_key->dst, &(pinfo->src));

    dmp_data = (dmp_id_val *) g_hash_table_lookup (dmp_id_hash_table, dmp_key);

    if (dmp_data) {
      /* Found message */
      if (dmp_data->prev_msg_id > 0) {
        msg_id = dmp_data->prev_msg_id;
      } else {
        msg_id = dmp_data->msg_id;
      }
      msg_time = dmp_data->msg_time;
    }
  }

  if (dmp.msg_type == ACK) {
    dmp_key->id = (guint) dmp.subj_id;
    SE_COPY_ADDRESS(&dmp_key->src, &(pinfo->dst));
    SE_COPY_ADDRESS(&dmp_key->dst, &(pinfo->src));
  } else {
    dmp_key->id = (guint) dmp.msg_id;
    SE_COPY_ADDRESS(&dmp_key->src, &(pinfo->src));
    SE_COPY_ADDRESS(&dmp_key->dst, &(pinfo->dst));
  }

  dmp_data = (dmp_id_val *) g_hash_table_lookup (dmp_id_hash_table, dmp_key);

  if (!pinfo->fd->flags.visited) {
    if (dmp_data) {
      if (dmp.msg_type == ACK) {
        /* Only save this data if positive ack */
        if (reason == 0) {
          if (dmp_data->ack_id == 0) {
            /* Only save reference to first ACK */
            dmp_data->ack_id = pinfo->fd->num;
          } else {
            /* Only count when resending */
            dmp_data->ack_resend_count++;
          }
        }
      } else {
        /* Message resent */
        dmp_data->msg_resend_count++;
        dmp_data->prev_msg_id = pinfo->fd->num;
        dmp_data->prev_msg_time = dmp_data->msg_time;
        dmp_data->msg_time = pinfo->fd->abs_ts;
      }
    } else {
      /* New message */
      dmp_data = se_alloc0 (sizeof (dmp_id_val));
      dmp_data->msg_type = dmp.msg_type;

      if (dmp.msg_type == ACK) {
        /* No matching message for this ack */
        dmp_data->ack_id = pinfo->fd->num;
      } else {
        dmp_data->first_msg_time = pinfo->fd->abs_ts;
        dmp_data->msg_time = pinfo->fd->abs_ts;

        if (dmp.msg_type == REPORT) {
          dmp_data->rep_id = pinfo->fd->num;
          dmp_data->msg_id = msg_id;
          dmp_data->rep_not_msg_time = msg_time;
        } else if (dmp.msg_type == NOTIF) {
          dmp_data->not_id = pinfo->fd->num;
          dmp_data->msg_id = msg_id;
          dmp_data->rep_not_msg_time = msg_time;
        } else {
          dmp_data->msg_id = pinfo->fd->num;
        }

        g_hash_table_insert (dmp_id_hash_table, dmp_key, dmp_data);
      }
    }

    pkg_data = se_alloc (sizeof (dmp_id_val));
    *pkg_data = *dmp_data;
    p_add_proto_data (pinfo->fd, proto_dmp, pkg_data);
  } else {
    /* Fetch last values from data saved in packet */
    pkg_data = p_get_proto_data (pinfo->fd, proto_dmp);

    if (dmp_data && pkg_data && dmp.msg_type != ACK && pkg_data->ack_id == 0) {
      pkg_data->ack_id = dmp_data->ack_id;
    }
  }

  DISSECTOR_ASSERT (pkg_data);
  dmp.id_val = pkg_data;
}

static void dmp_add_seq_ack_analysis (tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *dmp_tree, gint offset)
{
  proto_tree *analysis_tree = NULL;
  proto_item *en = NULL, *eh = NULL;
  nstime_t    ns;

  if (dmp.msg_type > ACK || (dmp.msg_type < ACK && !dmp.checksum) ||
      dmp.id_val == NULL || pinfo->in_error_pkt)
  {
    /* No need for seq/ack analysis */
    return;
  }

  en = proto_tree_add_text (dmp_tree, tvb, 0, 0, "SEQ/ACK analysis");
  PROTO_ITEM_SET_GENERATED (en);
  analysis_tree = proto_item_add_subtree (en, ett_analysis);

  if ((dmp.msg_type == STANAG) || (dmp.msg_type == IPM) ||
      (dmp.msg_type == REPORT) || (dmp.msg_type == NOTIF)) {
    if (dmp.id_val->ack_id) {
      en = proto_tree_add_uint (analysis_tree, hf_analysis_ack_num, tvb,
                                0, 0, dmp.id_val->ack_id);
      PROTO_ITEM_SET_GENERATED (en);
      if (!dmp.checksum) {
        proto_item_append_text (en, " (unexpected)");
        expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                                "Unexpected ACK");
      }
    } else if (dmp.checksum && !dmp.id_val->msg_resend_count) {
      en = proto_tree_add_item (analysis_tree,
                                hf_analysis_ack_missing,
                                tvb, offset, 0, FALSE);
      if (pinfo->fd->flags.visited) {
        /* We do not know this on first visit and we do not want to
           add a entry in the "Expert Severity Info" for this note */
        expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                                "Acknowledgement missing");
        PROTO_ITEM_SET_GENERATED (en);
      }
    }

    if (dmp.msg_type == REPORT) {
      if (dmp.id_val->msg_id) {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_msg_num,
                                  tvb, 0, 0, dmp.id_val->msg_id);
        PROTO_ITEM_SET_GENERATED (en);

        nstime_delta (&ns, &pinfo->fd->abs_ts, &dmp.id_val->rep_not_msg_time);
        en = proto_tree_add_time (analysis_tree, hf_analysis_rep_time,
                                  tvb, 0, 0, &ns);
        PROTO_ITEM_SET_GENERATED (en);
      } else {
        en = proto_tree_add_item (analysis_tree, hf_analysis_msg_missing,
                                  tvb, 0, 0, FALSE);
        PROTO_ITEM_SET_GENERATED (en);

        expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                                "Message missing");
      }
    } else if (dmp.msg_type == NOTIF) {
      if (dmp.id_val->msg_id) {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_msg_num,
                                  tvb, 0, 0, dmp.id_val->msg_id);
        PROTO_ITEM_SET_GENERATED (en);

        nstime_delta (&ns, &pinfo->fd->abs_ts, &dmp.id_val->rep_not_msg_time);
        en = proto_tree_add_time (analysis_tree, hf_analysis_not_time,
                                  tvb, 0, 0, &ns);
        PROTO_ITEM_SET_GENERATED (en);
      } else {
        en = proto_tree_add_item (analysis_tree, hf_analysis_msg_missing,
                                  tvb, 0, 0, FALSE);
        PROTO_ITEM_SET_GENERATED (en);

        expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                                "Message missing");
      }
    }

    if (dmp.id_val->msg_resend_count) {
      en = proto_tree_add_uint (analysis_tree, hf_analysis_retrans_no,
                                tvb, 0, 0, dmp.id_val->msg_resend_count);
      PROTO_ITEM_SET_GENERATED (en);

      expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                              "Retransmission #%d",
                              dmp.id_val->msg_resend_count);

      if (dmp.msg_type == REPORT) {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_rep_resend_from,
                                  tvb, 0, 0, dmp.id_val->rep_id);
      } else if (dmp.msg_type == NOTIF) {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_not_resend_from,
                                  tvb, 0, 0, dmp.id_val->not_id);
      } else {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_msg_resend_from,
                                  tvb, 0, 0, dmp.id_val->msg_id);
      }
      PROTO_ITEM_SET_GENERATED (en);

      nstime_delta (&ns, &pinfo->fd->abs_ts, &dmp.id_val->prev_msg_time);
      en = proto_tree_add_time (analysis_tree, hf_analysis_retrans_time,
                                tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED (en);

      nstime_delta (&ns, &pinfo->fd->abs_ts, &dmp.id_val->first_msg_time);
      eh = proto_tree_add_time (analysis_tree, hf_analysis_total_retrans_time,
                                tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED (eh);

      if (dmp.id_val->first_msg_time.secs == dmp.id_val->prev_msg_time.secs &&
          dmp.id_val->first_msg_time.nsecs == dmp.id_val->prev_msg_time.nsecs) {
        /* Time values does not differ, hide the total time */
        PROTO_ITEM_SET_HIDDEN (eh);
      }
    }
  } else if (dmp.msg_type == ACK) {
    if (dmp.id_val->msg_type != ACK) {
      if (dmp.id_val->msg_type == REPORT) {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_rep_num,
                                  tvb, 0, 0, dmp.id_val->rep_id);
      } else if (dmp.id_val->msg_type == NOTIF) {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_not_num,
                                  tvb, 0, 0, dmp.id_val->not_id);
      } else {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_msg_num,
                                  tvb, 0, 0, dmp.id_val->msg_id);
      }
      PROTO_ITEM_SET_GENERATED (en);

      nstime_delta (&ns, &pinfo->fd->abs_ts, &dmp.id_val->msg_time);
      en = proto_tree_add_time (analysis_tree, hf_analysis_ack_time,
                                tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED (en);

      nstime_delta (&ns, &pinfo->fd->abs_ts, &dmp.id_val->first_msg_time);
      eh = proto_tree_add_time (analysis_tree, hf_analysis_total_time,
                                tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED (eh);

      if (dmp.id_val->first_msg_time.secs == dmp.id_val->msg_time.secs &&
          dmp.id_val->first_msg_time.nsecs == dmp.id_val->msg_time.nsecs) {
        /* Time values does not differ, hide the total time */
        PROTO_ITEM_SET_HIDDEN (eh);
      } else {
        /* Different times, add a reference to the message we have ack'ed */
        proto_item_append_text (en, " (from frame %d)",
                                dmp.id_val->prev_msg_id);
      }
    } else {
      en = proto_tree_add_item (analysis_tree, hf_analysis_msg_missing,
                                tvb, 0, 0, FALSE);
      PROTO_ITEM_SET_GENERATED (en);

      expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                              "Message missing");
    }

    if (dmp.id_val->ack_resend_count) {
      en = proto_tree_add_uint (analysis_tree, hf_analysis_ack_dup_no,
                                tvb, 0, 0, dmp.id_val->ack_resend_count);
      PROTO_ITEM_SET_GENERATED (en);

      expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                              "Dup ACK #%d", dmp.id_val->ack_resend_count);

      en = proto_tree_add_uint (analysis_tree, hf_analysis_ack_resend_from,
                                tvb, 0, 0, dmp.id_val->ack_id);
      PROTO_ITEM_SET_GENERATED (en);
    }
  }
}

/* Ref chapter 6.3.7.2.12 SIC */
static gint dissect_dmp_sic (tvbuff_t *tvb, packet_info *pinfo,
                             proto_tree *message_tree, gint offset)
{
  proto_tree *sic_tree = NULL, *bitmap_tree = NULL, *key_tree = NULL;
  proto_item *sf = NULL, *bf = NULL, *kf = NULL;
  guint64     value;
  guint8      key, bitmap, no, i, length = 0;
  gboolean    any, no_sic = FALSE, failure = FALSE;
  gint        bytes = 0, boffset = offset;
  gchar      *sic = NULL;

  key = tvb_get_guint8 (tvb, offset);
  sic = ep_alloc (MAX_SIC_LEN);

  if (key <= 0xB6) {
    /* 2 bytes, single 3-character SIC, characters [A-Z0-9] only */

    value = tvb_get_ntohs (tvb, offset);
    failure = dmp_dec_xbyte_sic (value, sic, 3, FALSE);
    sf = proto_tree_add_string_format (message_tree, hf_message_sic, tvb,
                                       offset, 2, sic,
                                       "SIC: %s [A-Z0-9 only]%s", sic,
                                       failure ? " (invalid)": "");
    if (failure) {
      expert_add_info_format (pinfo, sf, PI_UNDECODED, PI_NOTE, "Illegal SIC");
    }
    offset += 2;

  } else if (key <= 0xBD) {
    /* 3 bytes, single 3-character SIC, any valid character */

    value = tvb_get_ntohl (tvb, offset);
    value = (value >> 8) & 0x48FFFF;
    failure = dmp_dec_xbyte_sic (value, sic, 3, TRUE);
    sf = proto_tree_add_string_format (message_tree, hf_message_sic, tvb,
                                       offset, 3, sic,
                                       "SIC: %s [any character]%s", sic,
                                       failure ? " (invalid)": "");
    if (failure) {
      expert_add_info_format (pinfo, sf, PI_UNDECODED, PI_NOTE, "Illegal SIC");
    }
    offset += 3;

  } else if (key <= 0xBF) {
    /* Reserved (not used) */
    g_snprintf (sic, MAX_SIC_LEN, "Reserved");
    no_sic = TRUE;

  } else if (key <= 0xCF) {
    /* 2 or more 3-character SICs */

    sf = proto_tree_add_item (message_tree, hf_message_sic_key, tvb,
                              offset, 1, FALSE);
    sic_tree = proto_item_add_subtree (sf, ett_message_sic);

    kf = proto_tree_add_item (sic_tree, hf_message_sic_key_values, tvb, offset,
                              1, FALSE);
    key_tree = proto_item_add_subtree (kf, ett_message_sic_key);

    proto_tree_add_item (key_tree, hf_message_sic_key_type, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (key_tree, hf_message_sic_key_chars, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (key_tree, hf_message_sic_key_num, tvb, offset,
                         1, FALSE);
    offset += 1;

    any = (key & 0x08);
    no = (key & 0x07) + 1;
    for (i = 0; i < no; i++) {
      if (any) {
        value = tvb_get_ntohl (tvb, offset);
        value = (value >> 8) & 0x48FFFF;
        bytes = 3;
      } else {
        value = tvb_get_ntohs (tvb, offset);
        bytes = 2;
      }
      failure = dmp_dec_xbyte_sic (value, sic, 3, any);
      bf = proto_tree_add_string_format (sic_tree, hf_message_sic, tvb,
                                         offset, bytes, sic,
                                         "SIC %d: %s%s", i + 1, sic,
                                         failure ? " (invalid)": "");
      if (failure) {
        expert_add_info_format (pinfo, bf, PI_UNDECODED, PI_NOTE,
                                "Illegal SIC");
      }
      offset += bytes;
    }
    proto_item_append_text (sf, ": %d (3 %s character)", no,
                            any ? "any" : "[A-Z0-9]");

  } else if (key <= 0xDF) {
    /* 1 or more 3 to 8 character SICs */

    sf = proto_tree_add_item (message_tree, hf_message_sic_key, tvb,
                              offset, 1, FALSE);
    sic_tree = proto_item_add_subtree (sf, ett_message_sic);

    kf = proto_tree_add_item (sic_tree, hf_message_sic_key_values, tvb, offset,
                              1, FALSE);
    key_tree = proto_item_add_subtree (kf, ett_message_sic_key);

    proto_tree_add_item (key_tree, hf_message_sic_key_type, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (key_tree, hf_message_sic_key_chars, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (key_tree, hf_message_sic_key_num, tvb, offset,
                         1, FALSE);
    offset += 1;

    bitmap = tvb_get_guint8 (tvb, offset);
    bf = proto_tree_add_uint_format (sic_tree, hf_message_sic_bitmap, tvb,
                                     offset, 1, bitmap,
                                     "Length Bitmap: 0x%2.2x", bitmap);
    bitmap_tree = proto_item_add_subtree (bf, ett_message_sic_bitmap);
    proto_tree_add_item (bitmap_tree, hf_message_sic_bitmap, tvb, offset,
                         1, FALSE);

    any = (key & 0x08);
    no = (key & 0x07) + 1;
    offset += 1;

    for (i = 0; i < no; i++) {
      if (bitmap & (1 << (7 - i))) {
        /* 4 - 8 character */
        key = tvb_get_guint8 (tvb, offset);
        if (any) {
          /* Any valid characters */
          if ((key & 0xF0) == 0xA0) {        /* bit 7-4: 1010 */
            length = 4;
            bytes = 4;
            value = tvb_get_ntohl (tvb, offset) & 0x0FFFFFFF;
          } else if ((key & 0xC0) == 0xC0) { /* bit 7-4: 11xx */
            length = 6;
            bytes = 5;
            value = ((guint64)key & 0x3F)<<32|tvb_get_ntohl (tvb, offset + 1);
          } else if ((key & 0xF0) == 0xB0) { /* bit 7-4: 1011 */
            length = 7;
            bytes = 6;
            value = ((guint64)tvb_get_ntohs (tvb, offset) & 0x0FFF) << 32 |
              tvb_get_ntohl (tvb, offset + 2);
          } else if ((key & 0xF0) == 0x90) { /* bit 7-4: 1001 */
            length = 8;
            bytes = 7;
            value = ((guint64)(tvb_get_ntohl (tvb, offset)>>8) & 0x0FFF)<<32 |
              tvb_get_ntohl (tvb, offset + 3);
          } else {                           /* bit 7-4: 0xxx or 1000 */
            length = 5;
            bytes = 4;
            value = tvb_get_ntohl (tvb, offset);
          }
        } else {
          /* Characterts [A-Z0-9] only */
          if ((key & 0xE0) == 0xC0) {        /* bit 7-4: 110x */
            length = 4;
            bytes = 3;
            value = (tvb_get_ntohl (tvb, offset) >> 8) & 0x1FFFFF;
          } else if ((key & 0xF0) == 0xA0) { /* bit 7-4: 1010 */
            length = 5;
            bytes = 4;
            value = tvb_get_ntohl (tvb, offset) & 0x0FFFFFFF;
          } else if ((key & 0xE0) == 0xE0) { /* bit 7-4: 111x */
            length = 7;
            bytes = 5;
            value = ((guint64)key & 0x1F)<<32 | tvb_get_ntohl (tvb, offset +1);
          } else if ((key & 0xF0) == 0xB0) { /* bit 7-4: 1011 */
            length = 8;
            bytes = 6;
            value = ((guint64)tvb_get_ntohs (tvb, offset) & 0x0FFF) << 32 |
              tvb_get_ntohl (tvb, offset + 2);
          } else {                           /* bit 7-4: 0xxx or 1000 */
            length = 6;
            bytes = 4;
            value = tvb_get_ntohl (tvb, offset);
          }
        }
      } else {
        /* 3 character */
        if (any) {
          value = (tvb_get_ntohl (tvb, offset) >> 8) & 0x48FFFF;
          length = 3;
          bytes = 3;
        } else {
          value = tvb_get_ntohs (tvb, offset);
          length = 3;
          bytes = 2;
        }
      }
      failure = dmp_dec_xbyte_sic (value, sic, length, any);
      bf = proto_tree_add_string_format (sic_tree, hf_message_sic, tvb,
                                         offset, bytes, sic,
                                         "SIC %d: %s (%d bytes: %" G_GINT64_MODIFIER "x)%s",
                                         i + 1, sic, bytes, value,
                                         failure ? " (invalid)": "");
      if (bitmap & (1 << (7 - i))) {
        /* Only if 4 - 8 character */
        bitmap_tree = proto_item_add_subtree (bf, ett_message_sic_bits);
        if (any) {
          proto_tree_add_item (bitmap_tree, hf_message_sic_bits_any, tvb,
                               offset, 1, FALSE);
        } else {
          proto_tree_add_item (bitmap_tree, hf_message_sic_bits, tvb,
                               offset, 1, FALSE);
        }
      }
      if (failure) {
        expert_add_info_format (pinfo, bf, PI_UNDECODED, PI_NOTE,
                                "Illegal SIC");
      }
      offset += bytes;
    }
    proto_item_append_text (sf, ": %d (3-to-8 %s character)", no,
                            any ? "any" : "[A-Z0-9]");

  } else if (key == 0xFE) {
    /* No SIC */
    g_snprintf (sic, MAX_SIC_LEN, "Not present");
    no_sic = TRUE;

  } else {
    /* Resered (not used) */
    g_snprintf (sic, MAX_SIC_LEN, "Reserved");
    no_sic = TRUE;
  }

  if (no_sic) {
    /* Not added any SIC, dump text value */
    sf = proto_tree_add_string_format (message_tree, hf_message_sic, tvb,
                                       offset, 1, sic, "SIC: %s", sic);
    offset += 1;
  }

  proto_item_set_len (sf, offset - boffset);

  return offset;
}

/* Ref chapter 5.2.7.1 Direct Originator Encoding */
static gint dissect_dmp_direct_addr (tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *field_tree, proto_item *tf,
                                     gint offset, gint rec_no,
                                     gint rec_ofs, gint addr_type)
{
  proto_tree *addr_tree = NULL;
  proto_item *en = NULL;
  gint        dir_addr;
  guint8      value;

  value = tvb_get_guint8 (tvb, offset);
  dir_addr = (value & 0x7F);
  if (value & 0x80) {
    en = proto_tree_add_uint_format (field_tree, hf_addr_dir_address1, tvb,
                                     offset, 1, value,
                                     "%sDirect Address (bits 6-0): %d",
                                     val_to_str (addr_type, addr_type_str, ""),
                                     value & 0x7F);
    addr_tree = proto_item_add_subtree (en, ett_address_direct);
    proto_tree_add_item (addr_tree, hf_addr_dir_addr_ext, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (addr_tree, hf_addr_dir_address1, tvb, offset,
                         1, FALSE);
    offset += 1;

    /* Extended 1 */
    value = tvb_get_guint8 (tvb, offset);
    dir_addr |= ((value & 0x3F) << 7);
    en = proto_tree_add_uint_format (field_tree, hf_addr_dir_address2, tvb,
                                     offset, 1, value,
                                     "%sDirect Address (bits 12-7): %d",
                                     val_to_str (addr_type, addr_type_str, ""),
                                     value & 0x3F);
    addr_tree = proto_item_add_subtree (en, ett_address_direct);
    proto_tree_add_item (addr_tree, hf_addr_dir_addr_ext, tvb, offset,
                         1, FALSE);
    en = proto_tree_add_item (addr_tree, hf_reserved_0x40, tvb, offset,
                              1, FALSE);
    if (value & 0x40) {
      expert_add_info_format (pinfo, en, PI_UNDECODED, PI_WARN,
                              "Reserved value");
    }
    proto_tree_add_item (addr_tree, hf_addr_dir_address2, tvb, offset,
                         1, FALSE);
    offset += 1;

    if (value & 0x80) {
      /* Extended 2 */
      value = tvb_get_guint8 (tvb, offset);
      dir_addr |= ((value & 0x3F) << 13);
      en = proto_tree_add_uint_format (field_tree, hf_addr_dir_address3, tvb,
                                       offset, 1, value,
                                       "%sDirect Address (bits 18-13): %d",
                                       val_to_str (addr_type,addr_type_str,""),
                                       value & 0x3F);
      addr_tree = proto_item_add_subtree (en, ett_address_direct);
      en = proto_tree_add_item (addr_tree, hf_reserved_0xC0, tvb, offset,
                                1, FALSE);
      if (value & 0xC0) {
        expert_add_info_format (pinfo, en, PI_UNDECODED, PI_WARN,
                                "Reserved value");
      }
      proto_tree_add_item (addr_tree, hf_addr_dir_address3, tvb, offset,
                           1, FALSE);
      offset += 1;
    }

    en = proto_tree_add_uint_format (field_tree, hf_addr_dir_address_generated,
                                     tvb, offset, 0, dir_addr,
                                     "%sDirect Address: %d",
                                     val_to_str (addr_type, addr_type_str, ""),
                                     dir_addr);
    PROTO_ITEM_SET_GENERATED (en);
  } else {
    en = proto_tree_add_uint_format (field_tree, hf_addr_dir_address, tvb,
                                     offset, 1, value,
                                     "%sDirect Address: %d",
                                     val_to_str (addr_type, addr_type_str, ""),
                                     value & 0x7F);
    addr_tree = proto_item_add_subtree (en, ett_address_direct);
    proto_tree_add_item (addr_tree, hf_addr_dir_addr_ext, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (addr_tree, hf_addr_dir_address1, tvb, offset,
                         1, FALSE);
    offset += 1;
  }

  if (rec_no != -1) {
    proto_item_append_text (tf, " %d", rec_no);
    if (rec_ofs != -1) {
      proto_item_append_text (tf, " (offset from previous: %d)", rec_ofs);
    }
  }
  proto_item_append_text (tf, ", %sDirect Address: %d",
                          val_to_str (addr_type, addr_type_str, ""), dir_addr);

  return offset;
}

/* Ref 5.3.14 Extended Address */
static gint dissect_dmp_ext_addr (tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *field_tree, proto_item *tf,
                                  gint offset, gint rec_no, gint rec_ofs,
                                  gint addr_type)
{
  proto_tree *addr_tree = NULL, *ext_tree = NULL;
  proto_item *en = NULL, *ef = NULL;
  gint        type, length;
  guint8      value;
  gint        boffset = offset;
  gboolean    addr_length_extended = FALSE;
  asn1_ctx_t  asn1_ctx;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  value = tvb_get_guint8 (tvb, offset);
  type = (value & 0xE0) >> 5;
  length = (value & 0x1F);
  ef = proto_tree_add_none_format (field_tree, hf_addr_ext_address, tvb,
                                   offset, -1, "%sExtended Address",
                                   val_to_str (addr_type, addr_type_str, ""));
  ext_tree = proto_item_add_subtree (ef, ett_address_extended);

  en = proto_tree_add_uint_format (ext_tree, hf_addr_ext_type, tvb,
                                   offset, 1, value, "Address Type: %s",
                                   val_to_str (type, ext_addr_type,
                                               "Reserved"));
  addr_tree = proto_item_add_subtree (en, ett_address_ext_type);
  proto_tree_add_item (addr_tree, hf_addr_ext_type, tvb, offset,
                       1, FALSE);

  if (value & 0x80) {
    addr_length_extended = TRUE;
    en = proto_tree_add_uint_format (ext_tree, hf_addr_ext_length1, tvb,
                                     offset, 1, value,
                                     "Address Length (bits 4-0): %d", length);
    addr_tree = proto_item_add_subtree (en, ett_address_ext_length);
    proto_tree_add_item (addr_tree, hf_addr_ext_length1, tvb, offset,
                         1, FALSE);
    offset += 1;

    /* Extended */
    value = tvb_get_guint8 (tvb, offset);
    type = ((value & 0xE0) >> 5);
    length |= ((value & 0x1F) << 5);

    en = proto_tree_add_uint_format (ext_tree, hf_addr_ext_type_ext, tvb,
                                     offset, 1, value, "Address Type Ext: %s",
                                     val_to_str (type, ext_addr_type_ext,
                                                 "Reserved"));
    addr_tree = proto_item_add_subtree (en, ett_address_ext_type);
    proto_tree_add_item (addr_tree, hf_addr_ext_type, tvb, offset,
                         1, FALSE);

    en = proto_tree_add_uint_format (ext_tree, hf_addr_ext_length2, tvb,
                                     offset, 1, value,
                                     "Address Length (bits 9-5): %d",
                                     value & 0x1F);
    addr_tree = proto_item_add_subtree (en, ett_address_ext_length);
    proto_tree_add_item (addr_tree, hf_addr_ext_length2, tvb, offset,
                         1, FALSE);
    offset += 1;
  } else {
    en = proto_tree_add_uint_format (ext_tree, hf_addr_ext_length, tvb,
                                     offset, 1, value, "Address Length: %d",
                                     length);
    addr_tree = proto_item_add_subtree (en, ett_address_ext_length);
    proto_tree_add_item (addr_tree, hf_addr_ext_length1, tvb, offset,
                         1, FALSE);
    offset += 1;
  }

  if (type == ASN1_BER) {
    tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, length, length);

    dissect_p1_ORName (FALSE, next_tvb, 0, &asn1_ctx, ext_tree,
                         hf_addr_ext_asn1_ber);
  } else if (type == ASN1_PER) {
    proto_tree_add_item (ext_tree, hf_addr_ext_asn1_per, tvb, offset,
                         length, FALSE);
  } else {
    proto_tree_add_item (ext_tree, hf_addr_ext_unknown, tvb, offset,
                         length, FALSE);
  }
  offset += length;

  if (addr_length_extended) {
    en = proto_tree_add_uint_format (ext_tree, hf_addr_ext_length_generated,
                                     tvb, offset, 0, length,
                                     "Address Length: %d", length);
    PROTO_ITEM_SET_GENERATED (en);
  }

  proto_item_append_text (ef, ", Type: %s, Length: %d",
                          val_to_str (type, ext_addr_type, "Reserved"),
                          length);

  if (rec_no != -1) {
    proto_item_append_text (tf, " %d", rec_no);
    if (rec_ofs != -1) {
      proto_item_append_text (tf, " (offset from previous: %d)", rec_ofs);
    }
  }
  proto_item_append_text (tf, ", %sExtended Address Type: %s",
                          val_to_str (addr_type, addr_type_str, ""),
                          val_to_str (type, ext_addr_type_short, "Reserved"));

  proto_item_set_len (ef, offset - boffset);

  return offset;
}

/* Ref chapter 5.2.8.1 Extended Originator Encoding */
static gint dissect_dmp_originator (tvbuff_t *tvb, packet_info *pinfo,
                                    proto_tree *envelope_tree, gint offset)
{
  proto_tree *field_tree = NULL, *rec_tree = NULL;
  proto_item *en = NULL, *tf = NULL;
  guint8      value, dmp_addr_form;
  gint        boffset = offset;

  tf = proto_tree_add_item (envelope_tree, hf_addr_originator, tvb, offset,
                            -1, FALSE);
  field_tree = proto_item_add_subtree (tf, ett_address);

  if (dmp.addr_enc == DIRECT_ADDR) {
    offset = dissect_dmp_direct_addr (tvb, pinfo, field_tree, tf,
                                      offset, -1, -1, ORIGINATOR);
  } else {
    value = tvb_get_guint8 (tvb, offset);
    dmp_addr_form = (value & 0xE0) >> 5;

    en = proto_tree_add_uint_format (field_tree, hf_addr_ext_form_orig, tvb,
                                     offset, 1, value,
                                     "Address Form: %s",
                                     val_to_str (dmp_addr_form,
                                                 addr_form_orig, "Reserved"));
    rec_tree = proto_item_add_subtree (en, ett_address_ext_form);
    proto_tree_add_item (rec_tree, hf_addr_ext_form_orig, tvb, offset,
                         1, FALSE);
    en = proto_tree_add_item (rec_tree, hf_reserved_0x1F, tvb, offset,
                              1, FALSE);
    if (value & 0x1F) {
      expert_add_info_format (pinfo, en, PI_UNDECODED, PI_WARN,
                              "Reserved value");
    }
    offset += 1;

    if (dmp_addr_form == P1_DIRECT) {
      offset = dissect_dmp_direct_addr (tvb, pinfo, field_tree,
                                        tf, offset, -1, -1,
                                        ORIGINATOR);
    } else if (dmp_addr_form == P1_EXTENDED) {
      offset = dissect_dmp_ext_addr (tvb, pinfo, field_tree, tf, offset, -1,
                                     -1, ORIGINATOR);
    } else {
      proto_item_append_text (tf, " (invalid address form)");
    }
  }

  proto_item_set_len (tf, offset - boffset);

  return offset;
}

static void dmp_add_recipient_info (proto_item *tf, guint8 rep_req,
                                    guint8 not_req, gboolean action)
{
  if (rep_req || not_req) {
    proto_item_append_text (tf, ", Request:");
  }
  if (rep_req) {
    proto_item_append_text (tf, "%s",
                            val_to_str (rep_req, report_vals_short, ""));
  }
  if (not_req) {
    proto_item_append_text (tf, "%s",
                            val_to_str (not_req, notif_vals_short, ""));
  }
  if (action) {
    if (dmp.msg_type == STANAG) {
      proto_item_append_text (tf, " (Action)");
    } else if (dmp.msg_type == IPM) {
      proto_item_append_text (tf, " (To)");
    }
  } else {
    if (dmp.msg_type == STANAG) {
      proto_item_append_text (tf, " (Info)");
    } else if (dmp.msg_type == IPM) {
      proto_item_append_text (tf, " (Cc)");
    }
  }
}

/* Ref chapter 5.2.7 Direct Recipient Encoding */
static gint dissect_dmp_direct_encoding (tvbuff_t *tvb, packet_info *pinfo,
                                         proto_tree *field_tree, proto_item *tf,
                                         gint offset, guint *prev_rec_no)
{

  proto_tree *addr_tree = NULL, *rec_tree = NULL;
  proto_item *en = NULL;
  guint8      rep_req = 0, not_req = 0, value;
  gint        rec_no, rec_ofs = -1, dir_addr;
  gboolean    action = FALSE, dir_addr_extended = FALSE;

  value = tvb_get_guint8 (tvb, offset);
  rec_no = (value & 0xF0) >> 4;
  rep_req = (value & 0x0C) >> 2;
  not_req = (value & 0x03);

  if (rep_req == 0x03) {
    en = proto_tree_add_uint_format (field_tree, hf_addr_dir_rec_no1,
                                     tvb, offset, 1, value,
                                     "Recipient Number (bits 3-0): %d"
                                     " (offset from previous)",
                                     (value & 0xF0) >> 4);
  } else {
    en = proto_tree_add_uint_format (field_tree, hf_addr_dir_rec_no,
                                     tvb, offset, 1, value,
                                     "Recipient Number Offset: %d"
                                     " (offset from previous)",
                                     (value & 0xF0) >> 4);
  }
  rec_tree = proto_item_add_subtree (en, ett_address_rec_no);
  proto_tree_add_item (rec_tree, hf_addr_dir_rec_no1, tvb, offset,
                       1, FALSE);
  proto_tree_add_item (rec_tree, hf_addr_dir_rep_req1, tvb, offset,
                       1, FALSE);
  proto_tree_add_item (rec_tree, hf_addr_dir_not_req1, tvb, offset,
                       1, FALSE);
  offset += 1;

  value = tvb_get_guint8 (tvb, offset);
  dir_addr = (value & 0x7F);
  action = (value & 0x80);
  if (not_req == 0x03) {
    en = proto_tree_add_uint_format (field_tree, hf_addr_dir_address1,
                                     tvb, offset, 1, value,
                                     "Direct Address (bits 6-0): %d",
                                     value & 0x7F);
  } else {
    en = proto_tree_add_uint_format (field_tree, hf_addr_dir_address,
                                     tvb, offset, 1, value,
                                     "Direct Address: %d",
                                     value & 0x7F);
  }
  addr_tree = proto_item_add_subtree (en, ett_address_direct);
  proto_tree_add_item (addr_tree, hf_addr_dir_action, tvb, offset,
                       1, FALSE);
  proto_tree_add_item (addr_tree, hf_addr_dir_address1, tvb, offset,
                       1, FALSE);
  offset += 1;

  if (rep_req == 0x03) {
    /* Extended Recipient Number 1 */
    value = tvb_get_guint8 (tvb, offset);
    rec_no |= ((value & 0x3F) << 4);
    rec_ofs = rec_no;
    rep_req = (value & 0xC0) >> 6;

    en = proto_tree_add_uint_format (field_tree, hf_addr_dir_rec_no2,
                                     tvb, offset, 1, value,
                                     "Recipient Number (bits 9-4): %d"
                                     " (offset from previous)",
                                     value & 0x3F);
    rec_tree = proto_item_add_subtree (en, ett_address_rec_no);
    proto_tree_add_item (rec_tree, hf_addr_dir_rep_req2, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (rec_tree, hf_addr_dir_rec_no2, tvb, offset,
                         1, FALSE);
    offset += 1;

    if (rep_req == 0x03) {
      /* Extended Recipient Number 2 */
      value = tvb_get_guint8 (tvb, offset);
      rec_no |= ((value & 0x1F) << 10);
      rec_ofs = rec_no;
      rep_req = (value & 0xC0) >> 6;

      en = proto_tree_add_uint_format (field_tree, hf_addr_dir_rec_no3,
                                       tvb, offset, 1, value,
                                       "Recipient Number (bits 14-10): %d"
                                       " (offset from previous)",
                                       value & 0x1F);
      rec_tree = proto_item_add_subtree (en, ett_address_rec_no);
      proto_tree_add_item (rec_tree, hf_addr_dir_rep_req3, tvb, offset,
                           1, FALSE);
      en = proto_tree_add_item (rec_tree, hf_reserved_0x20, tvb, offset,
                                1, FALSE);
      if (value & 0x20) {
        expert_add_info_format (pinfo, en, PI_UNDECODED, PI_WARN,
                                "Reserved value");
      }
      proto_tree_add_item (rec_tree, hf_addr_dir_rec_no3, tvb, offset,
                           1, FALSE);
      offset += 1;
    }
  }

  if (not_req == 0x03) {
    /* Extended Direct Address 1 */
    dir_addr_extended = TRUE;
    value = tvb_get_guint8 (tvb, offset);
    dir_addr |= ((value & 0x3F) << 7);
    not_req = (value & 0xC0) >> 6;

    en = proto_tree_add_uint_format (field_tree, hf_addr_dir_address2, tvb,
                                     offset, 1, value,
                                     "Direct Address (bits 12-7): %d",
                                     value & 0x3F);
    addr_tree = proto_item_add_subtree (en, ett_address_direct);
    proto_tree_add_item (addr_tree, hf_addr_dir_not_req2, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (addr_tree, hf_addr_dir_address2, tvb, offset,
                         1, FALSE);
    offset += 1;

    if (not_req == 0x03) {
      /* Extended Direct Address 2 */
      value = tvb_get_guint8 (tvb, offset);
      dir_addr |= ((value & 0x3F) << 13);
      not_req = (value & 0xC0) >> 6;

      en = proto_tree_add_uint_format (field_tree, hf_addr_dir_address3, tvb,
                                       offset, 1, value,
                                       "Direct Address (bits 18-13): %d",
                                       value & 0x3F);
      addr_tree = proto_item_add_subtree (en, ett_address_direct);
      proto_tree_add_item (addr_tree, hf_addr_dir_not_req3, tvb, offset,
                           1, FALSE);
      proto_tree_add_item (addr_tree, hf_addr_dir_address3, tvb, offset,
                           1, FALSE);
      offset += 1;
    }
  }

  rec_no += (1 + *prev_rec_no);
  *prev_rec_no = rec_no;

  en = proto_tree_add_uint_format (field_tree, hf_addr_dir_rec_no_generated,
                                   tvb, offset, 0, rec_no,
                                   "Recipient Number: %d", rec_no);
  if (rec_no > 32767) {
    proto_item_append_text (en, " (maximum 32767)");
    expert_add_info_format (pinfo, en, PI_MALFORMED, PI_WARN,
                            "Recipient number too big");
  }
  PROTO_ITEM_SET_GENERATED (en);

  if (dir_addr_extended) {
    en = proto_tree_add_uint_format (field_tree, hf_addr_dir_address_generated,
                                     tvb, offset, 0, dir_addr,
                                     "Direct Address: %d", dir_addr);
    PROTO_ITEM_SET_GENERATED (en);
  }

  proto_item_append_text (tf, " %d", rec_no);
  if (rec_ofs != -1) {
    proto_item_append_text (tf, " (offset from previous: %d)", rec_ofs);
  }

  proto_item_append_text (tf, ", Direct Address: %d", dir_addr);
  dmp_add_recipient_info (tf, rep_req, not_req, action);

  return offset;
}

/* Ref 5.2.8.2 Extended Recipient Encoding */
static gint dissect_dmp_ext_encoding (tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *field_tree,
                                      proto_item *tf, gint offset,
                                      guint *prev_rec_no)
{
  proto_tree *addr_tree = NULL;
  proto_item *en = NULL;
  guint8      rep_req = 0, not_req = 0;
  guint8      value, dmp_addr_form;
  gboolean    action = FALSE;
  gint        rec_no, rec_ofs = -1;

  value = tvb_get_guint8 (tvb, offset);
  dmp_addr_form = (value & 0xE0) >> 5;
  action = (value & 0x10);
  en = proto_tree_add_uint_format (field_tree, hf_addr_ext_form, tvb,
                                   offset, 1, value,
                                   "Address Form: %s",
                                   val_to_str (dmp_addr_form,
                                               addr_form, "Reserved"));
  addr_tree = proto_item_add_subtree (en, ett_address_ext_form);
  proto_tree_add_item (addr_tree, hf_addr_ext_form, tvb, offset,
                       1, FALSE);

  en = proto_tree_add_boolean_format (field_tree, hf_addr_ext_action, tvb,
                                      offset, 1, value, "Action: %s",
                                      action ? "Yes" : "No");
  addr_tree = proto_item_add_subtree (en, ett_address_ext_action);
  proto_tree_add_item (addr_tree, hf_addr_ext_action, tvb, offset,
                       1, FALSE);

  rep_req = (value & 0x0C) >> 2;
  en = proto_tree_add_uint_format (field_tree, hf_addr_ext_rep_req, tvb,
                                   offset, 1, value,
                                   "Report Request: %s",
                                   val_to_str ((value & 0x0C) >> 2,
                                               report_vals, "Reserved"));
  addr_tree = proto_item_add_subtree (en, ett_address_ext_rep_req);
  proto_tree_add_item (addr_tree, hf_addr_ext_rep_req, tvb, offset,
                       1, FALSE);

  not_req = (value & 0x03);
  en = proto_tree_add_uint_format (field_tree, hf_addr_ext_not_req, tvb,
                                   offset, 1, value,
                                   "Notification Request: %s",
                                   val_to_str (value & 0x03,
                                               notif_vals, "Reserved"));
  addr_tree = proto_item_add_subtree (en, ett_address_ext_not_req);
  proto_tree_add_item (addr_tree, hf_addr_ext_not_req, tvb, offset,
                       1, FALSE);
  offset += 1;

  value = tvb_get_guint8 (tvb, offset);
  rec_no = (value & 0x7F);
  if (value & 0x80) {
    en = proto_tree_add_uint_format (field_tree, hf_addr_ext_rec_no1, tvb,
                                     offset, 1, value,
                                     "Recipient Number (bits 6-0): %d"
                                     " (offset from previous)",
                                     value & 0x7F);
    addr_tree = proto_item_add_subtree (en, ett_address_ext_rec_no);
    proto_tree_add_item (addr_tree, hf_addr_ext_rec_ext, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (addr_tree, hf_addr_ext_rec_no1, tvb, offset,
                         1, FALSE);
    offset += 1;

    /* Extended */
    value = tvb_get_guint8 (tvb, offset);
    rec_no |= (value << 7);
    rec_ofs = rec_no;
    en = proto_tree_add_uint_format (field_tree, hf_addr_ext_rec_no2, tvb,
                                     offset, 1, value,
                                     "Recipient Number (bits 14-7): %d"
                                     " (offset from previous)", value);
    addr_tree = proto_item_add_subtree (en, ett_address_ext_rec_no);
    proto_tree_add_item (addr_tree, hf_addr_ext_rec_no2, tvb, offset,
                         1, FALSE);
    offset += 1;

  } else {
    en = proto_tree_add_uint_format (field_tree, hf_addr_ext_rec_no, tvb,
                                     offset, 1, value,
                                     "Recipient Number Offset: %d"
                                     " (offset from previous)",
                                     value & 0x7F);
    addr_tree = proto_item_add_subtree (en, ett_address_ext_rec_no);
    proto_tree_add_item (addr_tree, hf_addr_ext_rec_ext, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (addr_tree, hf_addr_ext_rec_no1, tvb, offset,
                         1, FALSE);
    offset += 1;

  }

  rec_no += (1 + *prev_rec_no);
  *prev_rec_no = rec_no;

  en = proto_tree_add_uint_format (field_tree, hf_addr_ext_rec_no_generated,
                                   tvb, offset, 0, rec_no,
                                   "Recipient Number: %d", rec_no);
  if (rec_no > 32767) {
    proto_item_append_text (en, " (maximum 32767)");
    expert_add_info_format (pinfo, en, PI_MALFORMED, PI_WARN,
                            "Recipient number too big");
  }
  PROTO_ITEM_SET_GENERATED (en);


  switch (dmp_addr_form) {

  case P1_DIRECT:
  case P1_P2_DIRECT:
  case P1_DIRECT_P2_EXTENDED:
    offset = dissect_dmp_direct_addr (tvb, pinfo, field_tree, tf, offset,
                                      rec_no, rec_ofs, P1_ADDRESS);
    break;

  case P1_EXTENDED:
  case P1_EXTENDED_P2_DIRECT:
  case P1_P2_EXTENDED:
    offset = dissect_dmp_ext_addr (tvb, pinfo, field_tree, tf, offset,
                                   rec_no, rec_ofs, P1_ADDRESS);
    break;

  }

  switch (dmp_addr_form) {

  case P2_DIRECT:
  case P1_P2_DIRECT:
  case P1_EXTENDED_P2_DIRECT:
    offset = dissect_dmp_direct_addr (tvb, pinfo, field_tree, tf, offset,
                                      rec_no, rec_ofs, P2_ADDRESS);
    break;

  case P2_EXTENDED:
  case P1_DIRECT_P2_EXTENDED:
  case P1_P2_EXTENDED:
    offset = dissect_dmp_ext_addr (tvb, pinfo, field_tree, tf, offset,
                                   rec_no, rec_ofs, P2_ADDRESS);
    break;

  }

  dmp_add_recipient_info (tf, rep_req, not_req, action);

  return offset;
}

/* Ref chapter 5.2 Address encoding */
static gint dissect_dmp_address (tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *envelope_tree,
                                 gint offset, guint *prev_rec_no,
                                 gboolean reporting_name)
{
  proto_tree *field_tree = NULL;
  proto_item *tf = NULL;
  gint        boffset = offset;

  if (reporting_name) {
    tf = proto_tree_add_item (envelope_tree, hf_addr_reporting_name, tvb,
                              offset, -1, FALSE);
  } else {
    tf = proto_tree_add_none_format (envelope_tree, hf_addr_recipient, tvb,
                                     offset, -1, "Recipient Number");
  }
  field_tree = proto_item_add_subtree (tf, ett_address);

  if (dmp.addr_enc == DIRECT_ADDR) {
    offset = dissect_dmp_direct_encoding (tvb, pinfo, field_tree, tf,
                                          offset, prev_rec_no);
  } else {
    offset = dissect_dmp_ext_encoding (tvb, pinfo, field_tree, tf, offset,
                                       prev_rec_no);
  }

  proto_item_set_len (tf, offset - boffset);

  return offset;
}

/* Ref chapter 6.2.9 Acknowledgement */
static gint dissect_dmp_ack (tvbuff_t *tvb, packet_info *pinfo,
                             proto_tree *dmp_tree, gint offset)
{
  proto_tree *ack_tree = NULL, *recip_tree = NULL;
  proto_item *en = NULL, *rt = NULL;
  proto_item *hidden_item;
  guint       prev_rec_no = 0;
  gint        rec_len, rec_no = 0;
  gint        boffset = offset;

  en = proto_tree_add_item (dmp_tree, hf_ack, tvb, offset, 4, FALSE);
  ack_tree = proto_item_add_subtree (en, ett_ack);

  dmp.ack_reason = tvb_get_guint8 (tvb, offset);
  proto_item_append_text (en, ", Reason: %s",
                          val_to_str (dmp.ack_reason, ack_reason, "Reserved"));

  rt = proto_tree_add_item (ack_tree, hf_ack_reason, tvb, offset, 1, FALSE);
  if (dmp.ack_reason != 0) {
    expert_add_info_format (pinfo, rt, PI_RESPONSE_CODE, PI_NOTE, "ACK reason: %s",
                            val_to_str (dmp.ack_reason, ack_reason, "Reserved"));
  }
  offset += 1;

  proto_tree_add_item (ack_tree, hf_ack_diagnostic, tvb, offset, 1, FALSE);
  offset += 1;

  /* Subject Message Identifier */
  dmp.subj_id = tvb_get_ntohs (tvb, offset);
  proto_tree_add_item (ack_tree, hf_message_subj_id, tvb, offset, 2, FALSE);
  hidden_item = proto_tree_add_item (ack_tree, hf_dmp_id, tvb, offset, 2, FALSE);
  PROTO_ITEM_SET_HIDDEN (hidden_item);
  offset += 2;

  if (use_seq_ack_analysis) {
    register_dmp_id (pinfo, dmp.ack_reason);
  }

  if (dmp.ack_rec_present) {
    /* Recipient List */
    rec_len = tvb_length (tvb);
    if (dmp.checksum) {
      rec_len -= 2;
    }
    if (offset < rec_len) {
      rt = proto_tree_add_item (ack_tree, hf_ack_recips, tvb, offset, -1,
                                FALSE);
      recip_tree = proto_item_add_subtree (rt, ett_ack_recips);
      while (offset < rec_len) {
        offset = dissect_dmp_address (tvb, pinfo, recip_tree, offset,
                                      &prev_rec_no, FALSE);
        rec_no++;
      }
      proto_item_append_text (rt, ", No Recipients: %d", rec_no);
      proto_item_set_len (rt, offset - boffset - 4);
      proto_item_set_len (en, offset - boffset);
    }
  }

  return offset;
}

/* Ref chapter 6.2.7 Envelope structure */
static gint dissect_dmp_envelope (tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *dmp_tree, gint offset)
{
  proto_tree *envelope_tree = NULL;
  proto_tree *field_tree = NULL;
  proto_item *en = NULL, *tf = NULL, *vf = NULL;
  proto_item *hidden_item;
  guint8      envelope, time_diff;
  guint16     subm_time, no_rec, value16;
  gint32      secs = 0;
  gchar      *env_flags = NULL;
  guint       prev_rec_no = 0;
  gint        boffset = offset, i;

  en = proto_tree_add_item (dmp_tree, hf_envelope, tvb, offset, 10, FALSE);
  envelope_tree = proto_item_add_subtree (en, ett_envelope);

  envelope = tvb_get_guint8 (tvb, offset);
  dmp.prot_id = (envelope & 0xF8) >> 3;
  dmp.version = (envelope & 0x07) + 1;

  /* Protocol Version */
  tf = proto_tree_add_uint_format (envelope_tree, hf_envelope_version,
                                   tvb, offset, 1, dmp.version,
                                   "Protocol Version: %d", dmp.version);

  field_tree = proto_item_add_subtree (tf, ett_envelope_version);
  vf = proto_tree_add_item (field_tree, hf_envelope_protocol_id, tvb,
                            offset, 1, FALSE);
  if (dmp.prot_id == PROT_NAT) {
    proto_item_append_text (vf, " (national version of DMP)");
    proto_item_append_text (tf, " (national)");
  } else if (dmp.prot_id == PROT_DMP) {
    proto_item_append_text (vf, " (correct)");
  } else {
    proto_item_append_text (vf, " (incorrect, should be 0x1d)");
  }
  vf = proto_tree_add_item (field_tree, hf_envelope_version, tvb,
                            offset, 1, FALSE);
  offset += 1;

  if (dmp.version > DMP_VERSION_1) {
    /* Unsupported DMP Version */
    proto_item_append_text (vf, " (unsupported)");
    proto_item_append_text (tf, " (unsupported)");
    expert_add_info_format (pinfo, vf, PI_UNDECODED, PI_ERROR,
                            "Unsupported DMP Version: %d", dmp.version);
    return offset;
  }

  envelope = tvb_get_guint8 (tvb, offset);
  dmp.addr_enc = ((envelope & 0x10) >> 4);
  dmp.checksum = ((envelope & 0x08) >> 3);
  dmp.msg_type = (envelope & 0x07);

  if (dmp.msg_type != ACK) {
    /* Hop count */
    tf = proto_tree_add_uint_format (envelope_tree, hf_envelope_hop_count,
                                     tvb, offset, 1, envelope,
                                     "Hop Count: %d", (envelope & 0xE0) >> 5);
    field_tree = proto_item_add_subtree (tf, ett_envelope_hop_count);
    proto_tree_add_item (field_tree, hf_envelope_hop_count, tvb,
                         offset, 1, FALSE);
  } else {
    /* Recipient Present */
    dmp.ack_rec_present = (envelope & 0x20);
    tf = proto_tree_add_boolean_format (envelope_tree,hf_envelope_rec_present,
                                        tvb, offset, 1, envelope,
                                        "Recipient Present: %s",
                                        (envelope & 0x20) ? "Present" : "Absent");
    field_tree = proto_item_add_subtree (tf, ett_envelope_rec_present);
    proto_tree_add_item (field_tree, hf_envelope_rec_present, tvb,
                         offset, 1, FALSE);
  }

  /* Address Encoding */
  tf = proto_tree_add_boolean_format (envelope_tree, hf_envelope_addr_enc,
                                      tvb, offset, 1, envelope,
                                      "Address Encoding: %s",
                                      (envelope & 0x10) ?
                                      addr_enc.true_string :
                                      addr_enc.false_string);
  field_tree = proto_item_add_subtree (tf, ett_envelope_addr_enc);
  proto_tree_add_item (field_tree, hf_envelope_addr_enc, tvb,
                       offset, 1, FALSE);

  /* Checksum Present */
  tf = proto_tree_add_boolean_format (envelope_tree, hf_envelope_checksum,
                                      tvb, offset, 1, envelope,
                                      "Checksum: %s",
                                      (envelope & 0x08) ? "Used" : "Not used");
  field_tree = proto_item_add_subtree (tf, ett_envelope_checksum);
  proto_tree_add_item (field_tree, hf_envelope_checksum, tvb,
                       offset, 1, FALSE);

  /* Content Type */
  tf = proto_tree_add_uint_format (envelope_tree, hf_envelope_type,
                                   tvb, offset, 1, envelope,
                                   "Content Type: %s (%d)",
                                   val_to_str (envelope & 0x07,
                                               type_vals, "Unknown"),
                                   envelope & 0x07);
  field_tree = proto_item_add_subtree (tf, ett_envelope_cont_type);
  proto_tree_add_item (field_tree, hf_envelope_type, tvb,
                       offset, 1, FALSE);

  proto_item_append_text (en, ", Checksum %s", (envelope >> 3) & 0x01 ? "Used" : "Not used");
  offset += 1;

  if (dmp.msg_type >= ACK) {
    proto_item_set_len (en, offset - boffset);
    return offset;
  }

  /* Message Identifier */
  dmp.msg_id = tvb_get_ntohs (tvb, offset);
  proto_tree_add_item (envelope_tree, hf_envelope_msg_id, tvb, offset,
                       2, FALSE);
  hidden_item = proto_tree_add_item (envelope_tree, hf_dmp_id, tvb, offset,
                              2, FALSE);
  PROTO_ITEM_SET_HIDDEN (hidden_item);
  offset += 2;

  /* Submission Time */
  subm_time = tvb_get_ntohs (tvb, offset);
  dmp.subm_time = dmp_dec_subm_time ((guint16)(subm_time & 0x7FFF),
                                     (gint32) pinfo->fd->abs_ts.secs);
  tf = proto_tree_add_uint_format (envelope_tree, hf_envelope_subm_time, tvb,
                                   offset, 2, subm_time,
                                   "Submission time: %s",
                                   (subm_time & 0x7FFF) >= 0x7FF8 ?
                                   "Reserved" :
                                   abs_time_secs_to_str (dmp.subm_time, ABSOLUTE_TIME_LOCAL, TRUE));
  field_tree = proto_item_add_subtree (tf, ett_envelope_subm_time);
  proto_tree_add_item (field_tree, hf_envelope_time_diff_present, tvb,
                       offset, 2, FALSE);
  proto_tree_add_item (field_tree, hf_envelope_subm_time_value, tvb,
                       offset, 2, FALSE);
  offset += 2;

  if (subm_time & 0x8000) {
    /* Timed Difference */
    time_diff = tvb_get_guint8 (tvb, offset);
    tf = proto_tree_add_uint_format (envelope_tree, hf_envelope_time_diff,
                                     tvb, offset, 1, time_diff,
                                     "Time Difference: ");
    field_tree = proto_item_add_subtree (tf, ett_envelope_time_diff);
    proto_tree_add_item (field_tree, hf_envelope_time_diff_value, tvb,
                         offset, 1, FALSE);
    secs = dmp_dec_time_diff (time_diff);
    if (secs == -1 || secs == -2) {
      proto_item_append_text (tf, "Reserved (0x%2.2x)", time_diff);
    } else {
      proto_item_append_text (tf, "%s", time_secs_to_str (secs));
    }
    offset += 1;
  }

  /* Envelope Flags */
  envelope = tvb_get_guint8 (tvb, offset);
  tf = proto_tree_add_uint_format (envelope_tree, hf_envelope_flags,
                                   tvb, offset, 1, envelope,
                                   "Envelope Flags");

  field_tree = proto_item_add_subtree (tf, ett_envelope_flags);
  proto_tree_add_item (field_tree, hf_envelope_content_id_discarded, tvb,
                       offset, 1, FALSE);
  proto_tree_add_item (field_tree, hf_envelope_recip_reassign_prohib, tvb,
                       offset, 1, FALSE);
  proto_tree_add_item (field_tree, hf_envelope_dl_expansion_prohib, tvb,
                       offset, 1, FALSE);

  if (envelope & 0xE0) {
    env_flags = ep_strdup_printf ("%s%s%s",
                                  (envelope & 0x80) ? ", ContId discarded" : "",
                                  (envelope & 0x40) ? ", Reass prohibited" : "",
                                  (envelope & 0x20) ? ", DLE prohibited"   : "");
    proto_item_append_text (tf, ":%s", &env_flags[1]);
  } else {
    proto_item_append_text (tf, " (none)");
  }

  /* Recipient Count */
  no_rec = (envelope & 0x1F);
  tf = proto_tree_add_uint_format (envelope_tree, hf_envelope_recipients,
                                   tvb, offset, 1, envelope,
                                   "Recipient Count: %d", no_rec);

  field_tree = proto_item_add_subtree (tf, ett_envelope_recipients);
  proto_tree_add_item (field_tree, hf_envelope_recipients, tvb,
                       offset, 1, FALSE);
  offset += 1;

  if (no_rec == 0) {
    /* Extended Recipient Count */
    value16 = tvb_get_ntohs (tvb, offset);
    no_rec = value16 & 0x7FFF;
    tf = proto_tree_add_uint_format (envelope_tree,hf_envelope_ext_recipients,
                                     tvb, offset, 2, value16,
                                     "Extended Recipient Count: %d%s", no_rec,
                                     (no_rec < 32 ?
                                      " (incorrect, reserved value)" : ""));

    field_tree = proto_item_add_subtree (tf, ett_envelope_ext_recipients);
    en = proto_tree_add_item (field_tree, hf_reserved_0x8000, tvb,
                              offset, 2, FALSE);
    if (value16 & 0x8000) {
      expert_add_info_format (pinfo, en, PI_UNDECODED, PI_WARN,
                              "Reserved value");
    }
    proto_tree_add_item (field_tree, hf_envelope_ext_recipients, tvb,
                         offset, 2, FALSE);
    offset += 2;
  }

  if (dmp.msg_type != REPORT) {
    /* Originator - Not present for reports */
    offset = dissect_dmp_originator (tvb, pinfo, envelope_tree, offset);
  }

  for (i = 1; i <= no_rec; i++) {
    /* Recipient(s) */
    offset = dissect_dmp_address (tvb, pinfo, envelope_tree, offset,
                                  &prev_rec_no, FALSE);
  }
  proto_item_set_len (en, offset - boffset);

  return offset;
}

static void dissect_dmp_structured_id (tvbuff_t *tvb, proto_tree *body_tree,
                                       gint offset)
{
  gint        length;

  offset += dmp_struct_offset;
  switch (dmp_struct_format) {

  case STRUCT_ID_UINT8:
    dmp.struct_id = ep_strdup_printf ("%u", tvb_get_guint8 (tvb, offset));
    proto_tree_add_item (body_tree, hf_message_bodyid_uint8, tvb, offset, 1, FALSE);
    break;

  case STRUCT_ID_UINT16:
    dmp.struct_id = ep_strdup_printf ("%u", tvb_get_ntohs (tvb, offset));
    proto_tree_add_item (body_tree, hf_message_bodyid_uint16, tvb, offset, 2, FALSE);
    break;

  case STRUCT_ID_UINT32:
    dmp.struct_id = ep_strdup_printf ("%u", tvb_get_ntohl (tvb, offset));
    proto_tree_add_item (body_tree, hf_message_bodyid_uint32, tvb, offset, 4, FALSE);
    break;

  case STRUCT_ID_UINT64:
    dmp.struct_id = ep_strdup_printf ("%" G_GINT64_MODIFIER "u", tvb_get_ntoh64 (tvb, offset));
    proto_tree_add_item (body_tree, hf_message_bodyid_uint64, tvb, offset, 8, FALSE);
    break;

  case STRUCT_ID_STRING:
    dmp.struct_id = tvb_get_ephemeral_string (tvb, offset, (gint) dmp_struct_length);
    proto_tree_add_item (body_tree, hf_message_bodyid_string, tvb, offset, dmp_struct_length, FALSE);
    break;

  case STRUCT_ID_ZSTRING:
    dmp.struct_id = tvb_get_ephemeral_stringz (tvb, offset, &length);
    proto_tree_add_item (body_tree, hf_message_bodyid_zstring, tvb, offset, length, FALSE);
    break;

  }
}

/*
 * Ref chapter 6.3.7.1 STANAG 4406 message structure
 * and chapter 6.3.8.1 IPM 88 message structure
 */
static gint dissect_dmp_message (tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *dmp_tree, gint offset)
{
  tvbuff_t   *next_tvb = NULL;
  proto_tree *message_tree = NULL;
  proto_tree *field_tree = NULL;
  proto_item *en = NULL, *tf = NULL, *tr = NULL;
  guint8      message, eit = 0, compr_alg = ALGORITHM_NONE;
  gint        len, boffset = offset;

  en = proto_tree_add_item (dmp_tree, hf_message_body, tvb, offset, -1, FALSE);
  message_tree = proto_item_add_subtree (en, ett_message);

  if (dmp.body_format == FREE_TEXT_SUBJECT) {
    len = tvb_strsize (tvb, offset);
    if (dmp_subject_as_id) {
      dmp.struct_id = tvb_get_ephemeral_string (tvb, offset, len);
    }
    proto_tree_add_item (message_tree, hf_message_subject, tvb, offset,
                         len, FALSE);
    offset += len;
  }

  if (dmp.body_format == FREE_TEXT || dmp.body_format == FREE_TEXT_SUBJECT) {
    message = tvb_get_guint8 (tvb, offset);
    eit = (message & 0xE0) >> 5;
    compr_alg = (message & 0x18) >> 3;
    /* Encoded Information Type */
    tf = proto_tree_add_uint_format (message_tree, hf_message_eit,
                                     tvb, offset, 1, message, "EIT: %s (%d)",
                                     val_to_str (eit, eit_vals, "Unknown"),
                                     eit);
    field_tree = proto_item_add_subtree (tf, ett_message_eit);
    proto_tree_add_item (field_tree, hf_message_eit, tvb,
                         offset, 1, FALSE);
    proto_item_append_text (en, ", Type: %s",
                            val_to_str (eit, eit_vals, "Unknown"));

    /* Compression Algorithm */
    tf = proto_tree_add_uint_format (message_tree, hf_message_compr,
                                     tvb, offset, 1, message,
                                     "Compression Algorithm: %s (%d)",
                                     val_to_str (compr_alg, compression_vals,
                                                 "Unknown"), compr_alg);
    field_tree = proto_item_add_subtree (tf, ett_message_compr);
    tr = proto_tree_add_item (field_tree, hf_message_compr, tvb,
                              offset, 1, FALSE);
    if (compr_alg == ALGORITHM_ZLIB) {
      proto_item_append_text (en, " (compressed)");
    } else if (compr_alg != ALGORITHM_NONE) {
      expert_add_info_format (pinfo, tr, PI_UNDECODED, PI_WARN,
                              "Unknown compression algorithm");
    }

    if (message & 0x07) {
      /* Reserved */
      tf = proto_tree_add_uint_format (message_tree, hf_reserved_0x07,
                                       tvb, offset, 1, message,
                                       "Reserved: %d",  message & 0x07);
      field_tree = proto_item_add_subtree (tf, ett_message_body_reserved);
      tf = proto_tree_add_item (field_tree, hf_reserved_0x07, tvb,
                                offset, 1, FALSE);
      expert_add_info_format (pinfo, tf, PI_UNDECODED, PI_WARN,
                              "Reserved value");
    }
    offset += 1;
  }

  len = tvb_length_remaining (tvb, offset);
  if (dmp.checksum) {
    len -= 2;
  }

  tf = proto_tree_add_none_format (message_tree, hf_message_body_data, tvb,
                                   offset, len,
                                   "%sUser data, Length: %d",
                                   (compr_alg == ALGORITHM_ZLIB) ?
                                   "Compressed " : "", len);
  field_tree = proto_item_add_subtree (tf, ett_message_body);

  if (dmp.body_format == STRUCTURED) {
    /* Structured Message ID */
    dissect_dmp_structured_id (tvb, field_tree, offset);
    proto_tree_add_item (field_tree, hf_message_body_structured, tvb, offset,
                         len, FALSE);
  } else if (len > 0 && (dmp.body_format == FREE_TEXT ||
                         dmp.body_format == FREE_TEXT_SUBJECT)) {
    if (compr_alg == ALGORITHM_ZLIB) {
      if ((next_tvb = tvb_uncompress (tvb, offset, len)) != NULL) {
                gint zlen = tvb_length (next_tvb);
                add_new_data_source (pinfo, next_tvb, "Uncompressed User data");
                tf = proto_tree_add_none_format (message_tree,
                                                 hf_message_body_uncompr,
                                                 next_tvb, 0, zlen,
                                                 "Uncompressed User data, "
                                                 "Length: %d", zlen);
                field_tree = proto_item_add_subtree (tf, ett_message_body_uncompr);
                proto_tree_add_item (field_tree, hf_message_body_uncompressed,
                                         next_tvb, 0, -1, FALSE);
      } else {
                tf = proto_tree_add_text (message_tree, tvb, offset, -1,
                                          "Error: Unable to uncompress content");
                expert_add_info_format (pinfo, tf, PI_UNDECODED, PI_WARN,
                                        "Unable to uncompress content");
      }
    } else if (eit != EIT_BILATERAL) {
      proto_tree_add_item (field_tree, hf_message_body_plain, tvb,
                           offset, len, FALSE);
    }
  }
  offset += len;

  if (dmp.struct_id) {
    proto_item_append_text (en, ", Id: %s", dmp.struct_id);
  }

  proto_item_set_len (en, offset - boffset);

  return offset;
}

/* Ref chapter 6.3.9.1 Report structure */
static gint dissect_dmp_report (tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *dmp_tree, gint offset,
                                guint *prev_rec_no, gint num)
{
  proto_tree *report_tree = NULL;
  proto_tree *field_tree = NULL;
  proto_item *en = NULL, *ei = NULL, *tf = NULL;
  guint8      report;
  gboolean    info_present;
  gint32      secs = 0;
  gint        len, boffset = offset;
  gint        rep_type = 0;

  report = tvb_get_guint8 (tvb, offset);
  rep_type = (report & 0x80) >> 7;
  if (rep_type) {
    en = proto_tree_add_item (dmp_tree, hf_non_delivery_report, tvb,
                              offset, 4, FALSE);
  } else {
    en = proto_tree_add_item (dmp_tree, hf_delivery_report, tvb,
                              offset, 4, FALSE);
  }
  proto_item_append_text (en, " (#%d)", num);

  report_tree = proto_item_add_subtree (en, ett_report);

  /* Report Type */
  tf = proto_tree_add_boolean_format (report_tree, hf_report_type,
                                      tvb, offset, 1, report,
                                      "Report Type: %s", rep_type ?
                                      report_type.true_string :
                                      report_type.false_string);
  field_tree = proto_item_add_subtree (tf, ett_report_type);
  proto_tree_add_item (field_tree, hf_report_type, tvb, offset,
                       1, FALSE);

  if (rep_type == DR) {
    dmp.dr = TRUE;
    /* Info Present */
    info_present = (report & 0x40);
    tf = proto_tree_add_boolean_format (report_tree,hf_report_info_present_dr,
                                        tvb, offset, 1, report,
                                        "Info Present: %s", (report & 0x40) ? "Present" : "Absent");
    field_tree = proto_item_add_subtree (tf, ett_report_info_present_dr);
    proto_tree_add_item (field_tree, hf_report_info_present_dr, tvb,
                         offset, 1, FALSE);

    /* Address Encoding */
    dmp.addr_enc = ((report & 0x20) >> 5);
    tf = proto_tree_add_boolean_format (report_tree, hf_report_addr_enc_dr,
                                        tvb, offset, 1, report,
                                        "Address Encoding: %s",
                                        (report & 0x20) ?
                                        addr_enc.true_string :
                                        addr_enc.false_string);
    field_tree = proto_item_add_subtree (tf, ett_report_addr_enc_dr);
    proto_tree_add_item (field_tree, hf_report_addr_enc_dr, tvb,
                         offset, 1, FALSE);

    if (report & 0x1F) {
      /* Reserved */
      tf = proto_tree_add_uint_format (report_tree, hf_reserved_0x1F,
                                       tvb, offset, 1, report,
                                       "Reserved: %d", report & 0x1F);
      field_tree = proto_item_add_subtree (tf, ett_report_reserved);
      tf = proto_tree_add_item (field_tree, hf_reserved_0x1F, tvb, offset,
                                1, FALSE);
      expert_add_info_format (pinfo, tf, PI_UNDECODED, PI_WARN,
                              "Reserved value");

    }
    offset += 1;

    /* Delivery Time */
    report = tvb_get_guint8 (tvb, offset);
    secs = dmp_dec_del_time (report);
    tf = proto_tree_add_uint_format (report_tree, hf_report_del_time,
                                     tvb, offset, 1, report,
                                     "Delivery Time: ");
    field_tree = proto_item_add_subtree (tf, ett_report_del_time);
    ei = proto_tree_add_item (field_tree, hf_report_del_time, tvb,
                              offset, 1, FALSE);
    if (secs == -2) {
      proto_item_append_text (tf, "Reserved (0x%2.2x)", report);
      proto_item_append_text (ei, ", (Reserved)");
    } else if (secs == 0) {
      proto_item_append_text (tf, "0 seconds");
      proto_item_append_text (ei, " (0 seconds)");
    } else {
      proto_item_append_text (tf, "%s (offset from the original message"
                              " submission time)",
                              time_secs_to_str (secs));
      proto_item_append_text (ei, " (%s)", time_secs_to_str (secs));
    }
  } else {
    dmp.ndr = TRUE;
    /* Address Encoding */
    dmp.addr_enc = ((report & 0x40) >> 6);
    tf = proto_tree_add_boolean_format (report_tree, hf_report_addr_enc_ndr,
                                        tvb, offset, 1, report,
                                        "Address Encoding: %s",
                                        (report & 0x40) ?
                                        addr_enc.true_string :
                                        addr_enc.false_string);
    field_tree = proto_item_add_subtree (tf, ett_report_addr_enc_ndr);
    proto_tree_add_item (field_tree, hf_report_addr_enc_ndr, tvb,
                         offset, 1, FALSE);

    /* Reason */
    tf = proto_tree_add_uint_format (report_tree, hf_report_reason,
                                     tvb, offset, 1, report,
                                     "Reason%s: %s (%d)",
                                     ((report & 0x3F) < 0x3D) ? " (P1)":"",
                                     non_del_reason_str (report & 0x3F),
                                     report & 0x3F);
    field_tree = proto_item_add_subtree (tf, ett_report_reason);
    proto_tree_add_item (field_tree, hf_report_reason, tvb,
                         offset, 1, FALSE);
    offset += 1;

    /* Info Present */
    report = tvb_get_guint8 (tvb, offset);
    info_present = (report & 0x80);
    tf = proto_tree_add_boolean_format (report_tree,
                                        hf_report_info_present_ndr,
                                        tvb, offset, 1, report,
                                        "Info Present: %s", (report & 0x80) ? "Present" : "Absent");
    field_tree = proto_item_add_subtree (tf, ett_report_info_present_ndr);
    proto_tree_add_item (field_tree, hf_report_info_present_ndr, tvb,
                         offset, 1, FALSE);

    /* Diagnostic */
    tf = proto_tree_add_uint_format (report_tree, hf_report_diagn,
                                     tvb, offset, 1, report,
                                     "Diagnostic%s: %s (%d)",
                                     ((report & 0x7F) < 0x7C) ? " (P1)":"",
                                     non_del_diagn_str (report & 0x7F),
                                     report & 0x7F);
    field_tree = proto_item_add_subtree (tf, ett_report_diagn);
    proto_tree_add_item (field_tree, hf_report_diagn, tvb,
                         offset, 1, FALSE);
  }
  offset += 1;

  offset = dissect_dmp_address (tvb, pinfo, report_tree, offset,
                                prev_rec_no, TRUE);

  if (info_present) {
    /* Supplementary Information */
    len = tvb_strsize (tvb, offset);
    tf = proto_tree_add_uint_format (report_tree, hf_report_suppl_info_len,
                                     tvb, offset, len, len,
                                     "Supplementary Information, Length: %d",
                                     len - 1);
    if (len > 1) {
      if ((offset - boffset + len) > 128) {
        proto_item_append_text (tf, " (incorrect, should be less than %d)",
                                128 - (offset - boffset));
      }
      field_tree = proto_item_add_subtree (tf, ett_report_suppl_info);
      proto_tree_add_item (field_tree, hf_report_suppl_info, tvb,
                           offset, len, FALSE);
    }
    offset += len;
  }

  proto_item_set_len (en, offset - boffset);

  return offset;
}

/* Ref chapter 6.3.10.1 Notification structure */
static gint dissect_dmp_notification (tvbuff_t *tvb, packet_info *pinfo _U_,
                                      proto_tree *dmp_tree, gint offset)
{
  proto_tree *notif_tree = NULL;
  proto_tree *field_tree = NULL;
  proto_item *en = NULL, *tf = NULL;
  guint8      notif, rec_time, on_typex = 0xFF;
  gint        len, boffset = offset;
  gint32      secs = 0;

  if (dmp.notif_type == RN) {
    en = proto_tree_add_item (dmp_tree, hf_receipt_notif, tvb, offset, 4, FALSE);
  } else if (dmp.notif_type == NRN) {
    en = proto_tree_add_item (dmp_tree, hf_non_receipt_notif, tvb, offset, 4, FALSE);
  } else if (dmp.notif_type == ON) {
    en = proto_tree_add_item (dmp_tree, hf_other_notif, tvb, offset, 4, FALSE);
  } else {
    return offset;
  }
  notif_tree = proto_item_add_subtree (en, ett_notif);

  if (dmp.notif_type == RN || dmp.notif_type == ON) {
    /* Receipt Time */
    rec_time = tvb_get_guint8 (tvb, offset);
    tf = proto_tree_add_uint_format (notif_tree, hf_notif_rec_time,
                                     tvb, offset, 1, rec_time,
                                     "Receipt Time: ");
    field_tree = proto_item_add_subtree (tf, ett_notif_rec_time);
    proto_tree_add_item (field_tree, hf_notif_rec_time_val, tvb,
                         offset, 1, FALSE);
    secs = dmp_dec_exp_time (rec_time);
    if (rec_time == 0) {
      proto_item_append_text (tf, "Not present");
    } else if (secs == -1 || secs == -2) {
      proto_item_append_text (tf, "Reserved (0x%2.2x)", rec_time);
    } else {
      proto_item_append_text (tf, "%s (offset from the original message"
                              " submission time)", time_secs_to_str (secs));
    }
    offset += 1;

    if (dmp.notif_type == ON) {
      /* ON Type */
      on_typex = tvb_get_guint8 (tvb, offset);
      proto_tree_add_item (notif_tree, hf_notif_on_type, tvb, offset,
                           1, FALSE);
      offset += 1;
    }

    /* Supplementary Information */
    len = tvb_strsize (tvb, offset);
    tf = proto_tree_add_uint_format (notif_tree, hf_notif_suppl_info_len,
                                     tvb, offset, len, len,
                                     "Supplementary Information, Length: %d",
                                     len - 1);
    if (len > 1) {
      if ((offset - boffset + len) > 128) {
        proto_item_append_text (tf, " (incorrect, should be less than %d)",
                                128 - (offset - boffset));
      }
      field_tree = proto_item_add_subtree (tf, ett_notif_suppl_info);
      proto_tree_add_item (field_tree, hf_notif_suppl_info, tvb, offset,
                           len, FALSE);
    }
    offset += len;

    if ((dmp.notif_type == ON) && (on_typex < 0x03)) {
      /* ACP127 Receipient */
      len = tvb_strsize (tvb, offset);
      tf = proto_tree_add_uint_format (notif_tree, hf_notif_acp127,
                                       tvb, offset, len, len,
                                       "ACP127 Recipient, Length: %d",
                                       len - 1);
      if (len > 1) {
        if (len > 64) {
          proto_item_append_text (tf, " (incorrect, must be less than 64)");
        }
        field_tree = proto_item_add_subtree (tf, ett_notif_acp127recip);
        proto_tree_add_item (field_tree, hf_notif_acp127recip, tvb,
                             offset, len, FALSE);
      }
      offset += len;
    }
  } else if (dmp.notif_type == NRN) {
    /* Non-Recipient Reason */
    notif = tvb_get_guint8 (tvb, offset);
    proto_tree_add_uint_format (notif_tree, hf_notif_non_rec_reason,
                                tvb, offset, 1, notif,
                                "Non-Receipt Reason%s: %s (%d)",
                                (notif < 0x10) ? " (P22)" : "",
                                nrn_reason_str (notif), notif);
    offset += 1;

    /* Discard Reason */
    notif = tvb_get_guint8 (tvb, offset);
    proto_tree_add_uint_format (notif_tree, hf_notif_discard_reason,
                                tvb, offset, 1, notif,
                                "Discard Reason%s: %s (%d)",
                                (notif < 0x10) ? " (P22)" : "",
                                discard_reason_str (notif), notif);
    offset += 1;
  }

  proto_item_set_len (en, offset - boffset);

  return offset;
}

/*
 * Ref chapter 6.3.7.1 STANAG 4406 message structure
 * and chapter 6.3.8.1 IPM 88 message structure
 * and chapter 6.3.9.1 Report structure
 * and chapter 6.3.10.1 Notification structure
 */
static gint dissect_dmp_content (tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *dmp_tree, gint offset)
{
  proto_tree *message_tree = NULL;
  proto_tree *field_tree = NULL;
  proto_item *en = NULL, *tf = NULL, *tr = NULL;
  proto_item *hidden_item;
  guint8      message, dmp_sec_pol, dmp_sec_class, exp_time, dtg;
  gint32      secs = 0;
  gchar      *sec_cat = NULL;
  guint       prev_rec_no = 0;
  gint        rep_len, rep_no = 1;
  gint        boffset = offset;

  if (dmp.msg_type == REPORT) {
    en = proto_tree_add_item (dmp_tree, hf_report_content, tvb, offset,
                              7, FALSE);
  } else if (dmp.msg_type == NOTIF) {
    en = proto_tree_add_item (dmp_tree, hf_notif_content, tvb, offset,
                              7, FALSE);
  } else {
    en = proto_tree_add_item (dmp_tree, hf_message_content, tvb, offset, 7, FALSE);
  }
  message_tree = proto_item_add_subtree (en, ett_content);

  if (dmp.msg_type == STANAG || dmp.msg_type == IPM) {
    message = tvb_get_guint8 (tvb, offset);
    dmp.body_format = (message & 0x03);

    if (dmp.msg_type == STANAG) {
      /* Message Type */
      dmp.st_type = (message & 0xC0) >> 6;
      tf = proto_tree_add_uint_format (message_tree, hf_message_st_type,
                                       tvb, offset, 1, message,
                                       "Message Type: %s (%d)",
                                       val_to_str (dmp.st_type,
                                                   message_type_vals, ""),
                                       dmp.st_type);
      field_tree = proto_item_add_subtree (tf, ett_message_st_type);
      proto_tree_add_item (field_tree, hf_message_st_type, tvb, offset,
                           1, FALSE);

      if ((message & 0x20) >> 5) {
        /* Reserved */
        tf = proto_tree_add_uint_format (message_tree, hf_reserved_0x20,
                                         tvb, offset, 1, message,
                                         "Reserved: %d", (message & 0x20)>>5);
        field_tree = proto_item_add_subtree (tf, ett_message_reserved);
        tf = proto_tree_add_item (field_tree, hf_reserved_0x20, tvb, offset,
                                  1, FALSE);
        expert_add_info_format (pinfo, tf, PI_UNDECODED, PI_WARN,
                                "Reserved value");
      }

      /* Precedence */
      dmp.prec = (message & 0x1C) >> 2;
      tf = proto_tree_add_uint_format (message_tree, hf_message_precedence,
                                       tvb, offset, 1, message,
                                       "Precedence: %s (%d)",
                                       val_to_str (dmp.prec, precedence, ""),
                                       dmp.prec);
      field_tree = proto_item_add_subtree (tf, ett_message_precedence);
      proto_tree_add_item (field_tree, hf_message_precedence, tvb, offset,
                           1, FALSE);

    } else {
      if ((message & 0xE0) >> 5) {
        /* Reserved */
        tf = proto_tree_add_uint_format (message_tree, hf_reserved_0xE0,
                                         tvb, offset, 1, message,
                                         "Reserved: %d", (message & 0xE0)>>5);
        field_tree = proto_item_add_subtree (tf, ett_message_reserved);
        tf = proto_tree_add_item (field_tree, hf_reserved_0xE0, tvb, offset,
                                  1, FALSE);
        expert_add_info_format (pinfo, tf, PI_UNDECODED, PI_WARN,
                                "Reserved value");
      }

      /* Importance */
      dmp.prec = (message & 0x1C) >> 2;
      tf = proto_tree_add_uint_format (message_tree, hf_message_importance,
                                       tvb, offset, 1, message,
                                       "Importance: %s (%d)",
                                       val_to_str (dmp.prec, importance, ""),
                                       dmp.prec);
      field_tree = proto_item_add_subtree (tf, ett_message_importance);
      proto_tree_add_item (field_tree, hf_message_importance, tvb, offset,
                           1, FALSE);
    }

    /* Body Format */
    tf = proto_tree_add_uint_format (message_tree, hf_message_body_format,
                                     tvb, offset, 1, message,
                                     "Body Format: %s (%d)",
                                     val_to_str (message & 0x03,
                                                 body_format_vals, ""),
                                     message & 0x03);
    field_tree = proto_item_add_subtree (tf, ett_message_body_format);
    proto_tree_add_item (field_tree, hf_message_body_format, tvb, offset,
                         1, FALSE);
    offset += 1;
  }

  message = tvb_get_guint8 (tvb, offset);
  /* Security Classification */
  dmp_sec_class = (message & 0xE0) >> 5;
  dmp_sec_pol = (message & 0x1C) >> 2;

  if (dmp_sec_pol == NATO || dmp_sec_pol == NATIONAL) {
    /* NATO or National security policy */
    tf = proto_tree_add_uint_format (message_tree, hf_message_sec_class_nat,
                                     tvb, offset, 1, message,
                                     "Security Classification: %s (%d)",
                                     val_to_str (dmp_sec_class,
                                                 sec_class, "Unknown"),
                                     dmp_sec_class);
    field_tree = proto_item_add_subtree (tf, ett_message_sec_class);
    proto_tree_add_item (field_tree, hf_message_sec_class_nat, tvb, offset,
                         1, FALSE);

    proto_item_append_text (en, ", Security Label: %s",
                            val_to_str (dmp_sec_class, sec_class, "Unknown"));
  } else {
    tf = proto_tree_add_uint_format (message_tree, hf_message_sec_class_val,
                                     tvb, offset, 1, message,
                                     "Security Classification: %d",
                                     dmp_sec_class);
    field_tree = proto_item_add_subtree (tf, ett_message_sec_class);
    proto_tree_add_item (field_tree, hf_message_sec_class_val, tvb, offset,
                         1, FALSE);
  }

  /* Security Policy */
  tf = proto_tree_add_uint_format (message_tree, hf_message_sec_pol,
                                   tvb, offset, 1, message,
                                   "Security Policy: %s (%d)",
                                   val_to_str (dmp_sec_pol, sec_pol, ""),
                                   dmp_sec_pol);
  field_tree = proto_item_add_subtree (tf, ett_message_sec_pol);
  proto_tree_add_item (field_tree, hf_message_sec_pol, tvb, offset,
                       1, FALSE);

  if (dmp.msg_type == STANAG || dmp.msg_type == IPM) {
    /* Heading Flags */
    tf = proto_tree_add_item (message_tree, hf_message_heading_flags,
                              tvb, offset, 1, FALSE);
    field_tree = proto_item_add_subtree (tf, ett_message_heading_flags);
    proto_tree_add_item (field_tree, hf_message_auth_users, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (field_tree, hf_message_subject_disc, tvb, offset,
                         1, FALSE);
    if (message & 0x03) {
      proto_item_append_text (tf, ": %s%s%s discarded",
                              (message & 0x02) ? "Authorizing users" : "",
                              (message & 0x03) == 0x03 ? " and " : "",
                              (message & 0x01) ? "Subject" : "");
    } else {
      proto_item_append_text (tf, " (none)");
    }
  } else if (dmp.msg_type == NOTIF) {
    /* Notification Type */
    dmp.notif_type = (message & 0x03);
    tf = proto_tree_add_uint_format (message_tree, hf_notif_type,
                                     tvb, offset, 1, message,
                                     "Notification Type: %s",
                                     val_to_str (dmp.notif_type, notif_type,
                                                 "Reserved"));
    field_tree = proto_item_add_subtree (tf, ett_notif_type);
    proto_tree_add_item (field_tree, hf_notif_type, tvb, offset,
                         1, FALSE);
  } else if (message & 0x02) {
    /* Reserved */
    tf = proto_tree_add_uint_format (message_tree, hf_reserved_0x02,
                                     tvb, offset, 1, message,
                                     "Reserved: %d", message & 0x02);
    field_tree = proto_item_add_subtree (tf, ett_message_reserved);
    tf = proto_tree_add_item (field_tree, hf_reserved_0x02, tvb, offset,
                              1, FALSE);
    expert_add_info_format (pinfo, tf, PI_UNDECODED, PI_WARN,
                            "Reserved value");
  }
  offset += 1;

  if (dmp_sec_pol == EXTENDED_NATIONAL) {
    /* National Policy Identifier */
    proto_tree_add_item (message_tree, hf_message_national_policy_id,
                         tvb, offset, 1, FALSE);
    offset += 1;
  } else if (dmp_sec_pol == EXTENDED_MISSION) {
    /* Mission Policy Identifier */
    message = tvb_get_guint8 (tvb, offset);
    if (message == 0xFF) {
      proto_tree_add_uint_format (message_tree, hf_message_mission_policy_id,
                                  tvb, offset, 1, message,
                                  "Mission Policy Identifier: Reserved");
    } else {
      proto_tree_add_item (message_tree, hf_message_mission_policy_id,
                           tvb, offset, 1, FALSE);
    }
    offset += 1;
  }

  /* Security Categories */
  message = tvb_get_guint8 (tvb, offset);
  if (dmp_sec_pol == NATO || dmp_sec_pol == NATIONAL) {
    tf = proto_tree_add_uint_format (message_tree, hf_message_sec_cat_nat, tvb,
                                     offset, 1, message, "Security Categories");
    field_tree = proto_item_add_subtree (tf, ett_message_sec_cat);

    proto_tree_add_item (field_tree, hf_message_sec_cat_cl, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (field_tree, hf_message_sec_cat_cs, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (field_tree, hf_message_sec_cat_ex, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (field_tree, hf_message_sec_cat_ne, tvb, offset,
                         1, FALSE);
    tr = proto_tree_add_item (field_tree, hf_reserved_0x08, tvb, offset,
                              1, FALSE);
    if (message & 0x08) {
      expert_add_info_format (pinfo, tr, PI_UNDECODED, PI_WARN,
                              "Reserved value");
    }
    tr = proto_tree_add_item (field_tree, hf_reserved_0x04, tvb, offset,
                              1, FALSE);
    if (message & 0x04) {
      expert_add_info_format (pinfo, tr, PI_UNDECODED, PI_WARN,
                              "Reserved value");
    }
    tr = proto_tree_add_item (field_tree, hf_reserved_0x02, tvb, offset,
                              1, FALSE);
    if (message & 0x02) {
      expert_add_info_format (pinfo, tr, PI_UNDECODED, PI_WARN,
                              "Reserved value");
    }
    tr = proto_tree_add_item (field_tree, hf_reserved_0x01, tvb, offset,
                              1, FALSE);
    if (message & 0x01) {
      expert_add_info_format (pinfo, tr, PI_UNDECODED, PI_WARN,
                              "Reserved value");
    }

    if (message & 0xF0) {
      sec_cat = ep_strdup_printf ("%s%s%s%s",
                                  (message & 0x80) ? ",cl" : "",
                                  (message & 0x40) ? ",cs" : "",
                                  (message & 0x20) ? ",ex" : "",
                                  (message & 0x10) ? ",ne" : "");
      proto_item_append_text (tf, ": %s", &sec_cat[1]);
      proto_item_append_text (en, "%s", sec_cat);
    }
    proto_item_append_text (tf, " (0x%2.2x)", message);
  } else {
    tf = proto_tree_add_item (message_tree, hf_message_sec_cat_val, tvb,
                              offset, 1, FALSE);
    field_tree = proto_item_add_subtree (tf, ett_message_sec_cat);

    proto_tree_add_item (field_tree, hf_message_sec_cat_bit7, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (field_tree, hf_message_sec_cat_bit6, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (field_tree, hf_message_sec_cat_bit5, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (field_tree, hf_message_sec_cat_bit4, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (field_tree, hf_message_sec_cat_bit3, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (field_tree, hf_message_sec_cat_bit2, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (field_tree, hf_message_sec_cat_bit1, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (field_tree, hf_message_sec_cat_bit0, tvb, offset,
                         1, FALSE);
  }
  offset += 1;

  if (dmp.msg_type == STANAG || dmp.msg_type == IPM) {
    exp_time = tvb_get_guint8 (tvb, offset);
    tf = proto_tree_add_uint_format (message_tree, hf_message_exp_time,
                                     tvb, offset, 1, exp_time,
                                     "Expiry Time: ");
    field_tree = proto_item_add_subtree (tf, ett_message_exp_time);
    proto_tree_add_item (field_tree, hf_message_exp_time_val, tvb,
                         offset, 1, FALSE);
    secs = dmp_dec_exp_time (exp_time);
    if (exp_time == 0) {
      proto_item_append_text (tf, "Not present");
    } else if (secs == -1 || secs == -2) {
      proto_item_append_text (tf, "Reserved (0x%2.2x)", exp_time);
    } else {
      proto_item_append_text (tf, "%s (%s)", time_secs_to_str (secs),
                              abs_time_secs_to_str (dmp.subm_time + secs, ABSOLUTE_TIME_LOCAL, TRUE));
    }
    offset += 1;
  }

  if (dmp.msg_type == STANAG) {
    dtg = tvb_get_guint8 (tvb, offset);
    tf = proto_tree_add_uint_format (message_tree, hf_message_dtg, tvb,
                                     offset, 1, dtg, "DTG: ");
    field_tree = proto_item_add_subtree (tf, ett_message_dtg);
    proto_tree_add_item (field_tree, hf_message_dtg_sign, tvb, offset,
                         1, FALSE);
    proto_tree_add_item (field_tree, hf_message_dtg_val, tvb, offset,
                         1, FALSE);
    secs = dmp_dec_dtg (dtg & 0x7F);
    if (dtg == 0) {
      proto_item_append_text (tf, "Not present");
    } else if (secs == -1 || secs == -2) {
      proto_item_append_text (tf, "Reserved (0x%2.2x)", dtg & 0x7F);
    } else if (secs == 0) {
      proto_item_append_text (tf, "0 minutes in the %s (%s)",
                              (dtg & 0x80) ? dtg_sign.true_string :
                              dtg_sign.false_string,
                              abs_time_secs_to_str (dmp.subm_time, ABSOLUTE_TIME_LOCAL, TRUE));
    } else {
      proto_item_append_text (tf, "%s in the %s (%s)", time_secs_to_str(secs),
                              (dtg & 0x80) ? dtg_sign.true_string :
                              dtg_sign.false_string, (dtg & 0x80) ?
                              abs_time_secs_to_str (dmp.subm_time + secs, ABSOLUTE_TIME_LOCAL, TRUE) :
                              abs_time_secs_to_str (dmp.subm_time - secs, ABSOLUTE_TIME_LOCAL, TRUE));
    }
    offset += 1;
  }

  if (dmp.msg_type == STANAG) {
    /* SIC */
    offset = dissect_dmp_sic (tvb, pinfo, message_tree, offset);
  } else if (dmp.msg_type == REPORT || dmp.msg_type == NOTIF) {
    /* Subject Message Identifier */
    dmp.subj_id = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (message_tree, hf_message_subj_id, tvb, offset,
                         2, FALSE);
    hidden_item = proto_tree_add_item (message_tree, hf_dmp_id, tvb, offset,
                                2, FALSE);
    PROTO_ITEM_SET_HIDDEN (hidden_item);
    offset += 2;
  }

  if (use_seq_ack_analysis) {
    register_dmp_id (pinfo, 0);
  }

  proto_item_set_len (en, offset - boffset);

  if  (dmp.msg_type == STANAG || dmp.msg_type == IPM) {
    /* User Data */
    offset = dissect_dmp_message (tvb, pinfo, dmp_tree, offset);
  } else if (dmp.msg_type == REPORT) {
    /* One or more Delivery Report or Non-Delivery Report Data */
    rep_len = tvb_length (tvb);
    if (dmp.checksum) {
      rep_len -= 2;
    }
    while (offset < rep_len) {
      offset = dissect_dmp_report (tvb, pinfo, dmp_tree, offset,
                                   &prev_rec_no, rep_no++);
    }
  } else if (dmp.msg_type == NOTIF) {
    /* Notification Data */
    offset = dissect_dmp_notification (tvb, pinfo, dmp_tree, offset);
  }

  return offset;
}

static void dissect_dmp (tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree)
{
  proto_tree *dmp_tree = NULL, *checksum_tree = NULL;
  proto_item *ti = NULL, *en = NULL;
  guint16     checksum1 = 0, checksum2 = 1;
  gint        length, offset = 0;
  gboolean    retrans_or_dup_ack = FALSE;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "DMP");
  col_clear (pinfo->cinfo, COL_INFO);

  /* Initialize global data structure */
  memset (&dmp, 0, sizeof (dmp));

  ti = proto_tree_add_item (tree, proto_dmp, tvb, offset, -1, FALSE);
  dmp_tree = proto_item_add_subtree (ti, ett_dmp);

  offset = dissect_dmp_envelope (tvb, pinfo, dmp_tree, offset);

  if (dmp.version > DMP_VERSION_1) {
    /* Unsupported DMP Version, no point to continue */
    col_add_fstr (pinfo->cinfo, COL_INFO, "Unsupported Version: %d", dmp.version);
    return;
  }

  if ((dmp.msg_type == STANAG) || (dmp.msg_type == IPM) ||
      (dmp.msg_type == REPORT) || (dmp.msg_type == NOTIF))
  {
    offset = dissect_dmp_content (tvb, pinfo, dmp_tree, offset);
  } else if (dmp.msg_type == ACK) {
    offset = dissect_dmp_ack (tvb, pinfo, dmp_tree, offset);
  }

  if (dmp.checksum) {
    length = tvb_length (tvb);
    checksum1 = crc16_x25_ccitt_tvb (tvb, length - 2);
    checksum2 = tvb_get_ntohs (tvb, offset);

    en = proto_tree_add_item (dmp_tree, hf_checksum, tvb, offset,
                              2, FALSE);
    checksum_tree = proto_item_add_subtree (en, ett_checksum);
    if (checksum1 == checksum2) {
      proto_item_append_text (en, " (correct)");
      en = proto_tree_add_boolean (checksum_tree, hf_checksum_good, tvb,
                                   offset, 2, TRUE);
      PROTO_ITEM_SET_GENERATED (en);
      en = proto_tree_add_boolean (checksum_tree, hf_checksum_bad, tvb,
                                   offset, 2, FALSE);
      PROTO_ITEM_SET_GENERATED (en);
    } else {
      proto_item_append_text (en, " (incorrect, should be 0x%04x)",
                              checksum1);
      expert_add_info_format (pinfo, en, PI_CHECKSUM, PI_WARN, "Bad checksum");
      en = proto_tree_add_boolean (checksum_tree, hf_checksum_good, tvb,
                                   offset, 2, FALSE);
      PROTO_ITEM_SET_GENERATED (en);
      en = proto_tree_add_boolean (checksum_tree, hf_checksum_bad, tvb,
                                   offset, 2, TRUE);
      PROTO_ITEM_SET_GENERATED (en);
    }
  }

  if (use_seq_ack_analysis) {
    dmp_add_seq_ack_analysis (tvb, pinfo, dmp_tree, offset);
  }

  if (check_col (pinfo->cinfo, COL_INFO)) {
    if (((dmp.msg_type == STANAG) || (dmp.msg_type == IPM) ||
         (dmp.msg_type == REPORT) || (dmp.msg_type == NOTIF)) &&
        dmp.id_val && dmp.id_val->msg_resend_count)
    {
      guint retrans_num;
      if (dmp.msg_type == REPORT) {
        retrans_num = dmp.id_val->rep_id;
      } else if (dmp.msg_type == NOTIF) {
        retrans_num = dmp.id_val->not_id;
      } else {
        retrans_num = dmp.id_val->msg_id;
      }
      col_append_fstr (pinfo->cinfo, COL_INFO, "[Retrans %d#%d] ",
                       retrans_num, dmp.id_val->msg_resend_count);
      retrans_or_dup_ack = TRUE;
    } else if (dmp.msg_type == ACK && dmp.id_val && dmp.id_val->ack_resend_count) {
      col_append_fstr (pinfo->cinfo, COL_INFO, "[Dup ACK %d#%d] ",
                       dmp.id_val->ack_id, dmp.id_val->ack_resend_count);
      retrans_or_dup_ack = TRUE;
    }
    if (dmp_align && !retrans_or_dup_ack) {
      if (dmp.msg_type == ACK) {
        /* ACK does not have "Msg Id" */
        col_append_fstr (pinfo->cinfo, COL_INFO, "%-45.45s", msg_type_to_str ());
      } else {
        col_append_fstr (pinfo->cinfo, COL_INFO, "%-31.31s", msg_type_to_str ());
      }
    } else {
      col_append_str (pinfo->cinfo, COL_INFO, msg_type_to_str ());
    }
    if ((dmp.msg_type == STANAG) || (dmp.msg_type == IPM) ||
        (dmp.msg_type == REPORT) || (dmp.msg_type == NOTIF))
    {
      if (dmp_align && !retrans_or_dup_ack) {
        col_append_fstr (pinfo->cinfo, COL_INFO, " Msg Id: %5d", dmp.msg_id);
      } else {
        col_append_fstr (pinfo->cinfo, COL_INFO, ", Msg Id: %d", dmp.msg_id);
      }
    }
    if ((dmp.msg_type == REPORT) || (dmp.msg_type == NOTIF) ||
        (dmp.msg_type == ACK))
    {
      if (dmp_align && !retrans_or_dup_ack) {
        col_append_fstr (pinfo->cinfo, COL_INFO, "  Subj Id: %5d",
                         dmp.subj_id);
      } else {
        col_append_fstr (pinfo->cinfo, COL_INFO, ", Subj Id: %d",
                         dmp.subj_id);
      }
    } else if (dmp.struct_id) {
      if (dmp_align && !retrans_or_dup_ack) {
        col_append_fstr (pinfo->cinfo, COL_INFO, "  Body Id: %s",
                         dmp.struct_id);
      } else {
        col_append_fstr (pinfo->cinfo, COL_INFO, ", Body Id: %s",
                         dmp.struct_id);
      }
    }
    if (dmp.checksum && (checksum1 != checksum2)) {
      col_append_str (pinfo->cinfo, COL_INFO, ", Checksum incorrect");
    }
  }

  proto_item_append_text (ti, ", Version: %d%s, %s", dmp.version,
                          (dmp.prot_id == PROT_NAT ? " (national)" : ""),
                          msg_type_to_str());
}

static void dmp_init_routine (void)
{
  if (dmp_id_hash_table) {
    g_hash_table_destroy (dmp_id_hash_table);
  }

  dmp_id_hash_table = g_hash_table_new (dmp_id_hash, dmp_id_hash_equal);
}

void proto_register_dmp (void)
{
  static hf_register_info hf[] = {
    /*
    ** DMP Identifier
    */
    { &hf_dmp_id,
      { "DMP Identifier", "dmp.id", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},

    /*
    ** Envelope
    */
    { &hf_envelope,
      { "Envelope", "dmp.envelope", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

    /* Protocol data */
    { &hf_envelope_protocol_id,
      { "Protocol Identifier", "dmp.protocol_id", FT_UINT8,
        BASE_HEX, NULL, 0xF8, NULL, HFILL}},
    { &hf_envelope_version,
      { "Protocol Version", "dmp.version", FT_UINT8, BASE_DEC,
        VALS(version_vals), 0x07, NULL, HFILL } },

    /* Envelope elements (byte 1) */
    { &hf_envelope_hop_count,
      { "Hop Count", "dmp.hop_count", FT_UINT8, BASE_DEC,
        NULL, 0xE0, NULL, HFILL } },
    { &hf_envelope_rec_present,
      { "Recipient Present", "dmp.rec_present", FT_BOOLEAN, 8,
        TFS (&tfs_present_absent), 0x20, NULL, HFILL } },
    { &hf_envelope_addr_enc,
      { "Address Encoding", "dmp.addr_encoding", FT_BOOLEAN, 8,
        TFS (&addr_enc), 0x10, NULL, HFILL } },
    { &hf_envelope_checksum,
      { "Checksum", "dmp.checksum_used", FT_BOOLEAN, 8,
        TFS (&tfs_used_notused), 0x08, "Checksum Used", HFILL } },
    { &hf_envelope_type,
      { "Content Type", "dmp.content_type", FT_UINT8, BASE_DEC,
        VALS(type_vals), 0x07, NULL, HFILL } },

    /* Message identifier */
    { &hf_envelope_msg_id,
      { "Message Identifier", "dmp.msg_id", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},

    /* Submission time */
    { &hf_envelope_subm_time,
      { "Submission Time", "dmp.subm_time", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL } },
    { &hf_envelope_time_diff_present,
      { "Time Diff", "dmp.time_diff_present", FT_BOOLEAN, 16,
        TFS (&tfs_present_absent), 0x8000, "Time Diff Present", HFILL } },
    { &hf_envelope_subm_time_value,
      { "Submission Time Value", "dmp.subm_time_value", FT_UINT16,
        BASE_HEX, NULL, 0x7FFF, NULL, HFILL } },
    { &hf_envelope_time_diff,
      { "Time Difference", "dmp.time_diff", FT_UINT8, BASE_HEX,
        NULL, 0xFF, NULL, HFILL } },
    { &hf_envelope_time_diff_value,
      { "Time Difference Value", "dmp.time_diff_value", FT_UINT8,
        BASE_HEX, NULL, 0xFF, NULL, HFILL } },

    /* Envelope flags */
    { &hf_envelope_flags,
      { "Flags", "dmp.envelope_flags", FT_UINT8, BASE_DEC,
        NULL, 0x0, "Envelope Flags", HFILL}},
    { &hf_envelope_content_id_discarded,
      { "Content Identifier discarded", "dmp.cont_id_discarded",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
        NULL, HFILL } },
    { &hf_envelope_recip_reassign_prohib,
      { "Recipient reassign prohibited","dmp.recip_reassign_prohib",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
        NULL, HFILL }},
    { &hf_envelope_dl_expansion_prohib,
      { "DL expansion prohibited", "dmp.dl_expansion_prohib",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL,
        HFILL } },

    /* Recipient Count */
    { &hf_envelope_recipients,
      { "Recipient Count", "dmp.rec_count", FT_UINT8, BASE_DEC,
        NULL, 0x1F, NULL, HFILL}},
    { &hf_envelope_ext_recipients,
      { "Extended Recipient Count", "dmp.ext_rec_count", FT_UINT16,
        BASE_DEC, NULL, 0x7FFF, NULL, HFILL}},

    /*
    ** Address
    */
    { &hf_addr_recipient,
      { "Recipient Number", "dmp.recipient", FT_NONE, BASE_NONE,
        NULL, 0x0, "Recipient", HFILL } },
    { &hf_addr_originator,
      { "Originator", "dmp.originator", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_addr_reporting_name,
      { "Reporting Name Number", "dmp.reporting_name", FT_NONE,
        BASE_NONE, NULL, 0x0, "Reporting Name", HFILL } },

    /*
    ** Address Direct
    */
    { &hf_addr_dir_addr_ext,
      { "Address Extended", "dmp.addr_ext", FT_BOOLEAN, 8,
        NULL, 0x80, NULL, HFILL } },
    { &hf_addr_dir_rec_no,
      { "Recipient Number Offset", "dmp.rec_no_offset", FT_UINT8,
        BASE_DEC, NULL, 0xF0, NULL, HFILL } },
    { &hf_addr_dir_rec_no_generated,
      { "Recipient Number", "dmp.rec_no", FT_UINT32,
        BASE_DEC, NULL, 0x0, "Recipient Number Offset", HFILL } },
    { &hf_addr_dir_rec_no1,
      { "Recipient Number (bits 3-0)", "dmp.rec_no_offset1", FT_UINT8,
        BASE_DEC, NULL, 0xF0, "Recipient Number (bits 3-0) Offset", HFILL } },
    { &hf_addr_dir_rec_no2,
      { "Recipient Number (bits 9-4)", "dmp.rec_no_offset2", FT_UINT8,
        BASE_DEC, NULL, 0x3F, "Recipient Number (bits 9-4) Offset", HFILL } },
    { &hf_addr_dir_rec_no3,
      { "Recipient Number (bits 14-10)", "dmp.rec_no_offset3", FT_UINT8,
        BASE_DEC, NULL, 0x1F, "Recipient Number (bits 14-10) Offset",HFILL } },
    { &hf_addr_dir_rep_req1,
      { "Report Request", "dmp.rep_rec", FT_UINT8, BASE_HEX,
        VALS (report_vals_ext), 0x0C, NULL, HFILL } },
    { &hf_addr_dir_rep_req2,
      { "Report Request", "dmp.rep_rec", FT_UINT8, BASE_HEX,
        VALS (report_vals_ext), 0xC0, NULL, HFILL } },
    { &hf_addr_dir_rep_req3,
      { "Report Request", "dmp.rep_rec", FT_UINT8, BASE_HEX,
        VALS (report_vals), 0xC0, NULL, HFILL } },
    { &hf_addr_dir_not_req1,
      { "Notification Request", "dmp.not_req", FT_UINT8, BASE_HEX,
        VALS (notif_vals_ext), 0x03, NULL, HFILL } },
    { &hf_addr_dir_not_req2,
      { "Notification Request", "dmp.not_req", FT_UINT8, BASE_HEX,
        VALS (notif_vals_ext), 0xC0, NULL, HFILL } },
    { &hf_addr_dir_not_req3,
      { "Notification Request", "dmp.not_req", FT_UINT8, BASE_HEX,
        VALS (notif_vals), 0xC0, NULL, HFILL } },
    { &hf_addr_dir_action,
      { "Action", "dmp.action", FT_BOOLEAN, 8,
        TFS (&tfs_yes_no), 0x80, NULL, HFILL } },
    { &hf_addr_dir_address,
      { "Direct Address", "dmp.direct_addr", FT_UINT8,
        BASE_DEC, NULL, 0x7F, NULL, HFILL } },
    { &hf_addr_dir_address_generated,
      { "Direct Address", "dmp.direct_addr", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_addr_dir_address1,
      { "Direct Address (bits 6-0)", "dmp.direct_addr1", FT_UINT8,
        BASE_DEC, NULL, 0x7F, NULL, HFILL } },
    { &hf_addr_dir_address2,
      { "Direct Address (bits 12-7)", "dmp.direct_addr2", FT_UINT8,
        BASE_DEC, NULL, 0x3F, NULL, HFILL } },
    { &hf_addr_dir_address3,
      { "Direct Address (bits 18-13)", "dmp.direct_addr3", FT_UINT8,
        BASE_DEC, NULL, 0x3F, NULL, HFILL } },

    /*
    ** Address Extended
    */
    { &hf_addr_ext_form,
      { "Address Form", "dmp.addr_form", FT_UINT8, BASE_DEC,
        VALS (&addr_form), 0xE0, NULL, HFILL } },
    { &hf_addr_ext_form_orig,
      { "Address Form", "dmp.addr_form", FT_UINT8, BASE_DEC,
        VALS (&addr_form_orig), 0xE0, NULL, HFILL } },
    { &hf_addr_ext_action,
      { "Action", "dmp.action", FT_BOOLEAN, 8,
        TFS (&tfs_yes_no), 0x10, NULL, HFILL } },
    { &hf_addr_ext_rep_req,
      { "Report Request", "dmp.rep_rec", FT_UINT8, BASE_HEX,
        VALS (report_vals), 0x0C, NULL, HFILL } },
    { &hf_addr_ext_not_req,
      { "Notification Request", "dmp.not_req", FT_UINT8, BASE_HEX,
        VALS (notif_vals), 0x03, NULL, HFILL } },
    { &hf_addr_ext_rec_ext,
      { "Recipient Number Extended", "dmp.rec_no_ext", FT_BOOLEAN, 8,
        NULL, 0x80, NULL, HFILL } },
    { &hf_addr_ext_rec_no,
      { "Recipient Number Offset", "dmp.rec_no_offset", FT_UINT8,
        BASE_DEC, NULL, 0x7F, NULL, HFILL } },
    { &hf_addr_ext_rec_no_generated,
      { "Recipient Number", "dmp.rec_no", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_addr_ext_rec_no1,
      { "Recipient Number (bits 6-0)", "dmp.rec_no_offset1", FT_UINT8,
        BASE_DEC, NULL, 0x7F, "Recipient Number (bits 6-0) Offset", HFILL } },
    { &hf_addr_ext_rec_no2,
      { "Recipient Number (bits 14-7)", "dmp.rec_no_offset2", FT_UINT8,
        BASE_DEC, NULL, 0xFF, "Recipient Number (bits 14-7) Offset", HFILL } },
    { &hf_addr_ext_address,
      { "Extended Address", "dmp.addr_form", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_addr_ext_type,
      { "Address Type", "dmp.addr_type", FT_UINT8, BASE_DEC,
        VALS (&ext_addr_type), 0xE0, NULL, HFILL } },
    { &hf_addr_ext_type_ext,
      { "Address Type Extended", "dmp.addr_type_ext", FT_UINT8,
        BASE_DEC, VALS (&ext_addr_type_ext), 0xE0, NULL,
        HFILL } },
    { &hf_addr_ext_length,
      { "Address Length", "dmp.addr_length", FT_UINT8,
        BASE_DEC, NULL, 0x1F, NULL, HFILL } },
    { &hf_addr_ext_length_generated,
      { "Address Length", "dmp.addr_length", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_addr_ext_length1,
      { "Address Length (bits 4-0)", "dmp.addr_length1", FT_UINT8,
        BASE_DEC, NULL, 0x1F, NULL, HFILL } },
    { &hf_addr_ext_length2,
      { "Address Length (bits 9-5)", "dmp.addr_length2", FT_UINT8,
        BASE_DEC, NULL, 0x1F, NULL, HFILL } },
    { &hf_addr_ext_asn1_ber,
      { "ASN.1 BER-encoded OR-name", "dmp.or_name", FT_NONE,
        BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_addr_ext_asn1_per,
      { "ASN.1 PER-encoded OR-name", "dmp.asn1_per", FT_BYTES,
        BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_addr_ext_unknown,
      { "Unknown encoded address", "dmp.addr_unknown", FT_BYTES,
        BASE_NONE, NULL, 0x0, NULL, HFILL } },

    /*
    ** Message content
    */
    { &hf_message_content,
      { "Message Content", "dmp.message", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_report_content,
      { "Report Content", "dmp.report", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_notif_content,
      { "Notification Content", "dmp.notification", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },

    { &hf_message_st_type,
      { "Message type", "dmp.msg_type", FT_UINT8, BASE_DEC,
        VALS (message_type_vals), 0xC0, NULL, HFILL } },
    { &hf_message_precedence,
      { "Precedence", "dmp.precedence", FT_UINT8, BASE_DEC,
        VALS (precedence), 0x1C, NULL, HFILL } },
    { &hf_message_importance,
      { "Importance", "dmp.importance", FT_UINT8, BASE_DEC,
        VALS (importance), 0x1C, NULL, HFILL } },
    { &hf_message_body_format,
      { "Body format", "dmp.body_format", FT_UINT8, BASE_DEC,
        VALS (body_format_vals), 0x03, NULL, HFILL } },

    /* Security Values */
    { &hf_message_sec_class_nat,
      { "Security Classification", "dmp.sec_class", FT_UINT8,
        BASE_DEC, VALS (sec_class), 0xE0, NULL, HFILL}},
    { &hf_message_sec_class_val,
      { "Security Classification", "dmp.sec_class", FT_UINT8,
        BASE_DEC, NULL, 0xE0, NULL, HFILL}},
    { &hf_message_sec_pol,
      { "Security Policy", "dmp.sec_pol", FT_UINT8, BASE_DEC,
        VALS (sec_pol), 0x1C, NULL, HFILL } },
    { &hf_message_heading_flags,
      { "Heading Flags", "dmp.heading_flags", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_message_auth_users,
      { "Authorizing users discarded", "dmp.auth_discarded",
        FT_BOOLEAN, 8, TFS (&tfs_yes_no), 0x02,
        NULL, HFILL }},
    { &hf_message_subject_disc,
      { "Subject discarded", "dmp.subject_discarded", FT_BOOLEAN, 8,
        TFS (&tfs_yes_no), 0x01, NULL, HFILL } },

    /* National Policy Identifier */
    { &hf_message_national_policy_id,
      { "National Policy Identifier", "dmp.nat_pol_id", FT_UINT8,
        BASE_DEC, VALS(nat_pol_id), 0x0, NULL,
        HFILL } },

    /* Mission Policy Identifier */
    { &hf_message_mission_policy_id,
      { "Mission Policy Identifier", "dmp.mission_pol_id", FT_UINT8,
        BASE_DEC, NULL, 0x0, NULL,
        HFILL } },

    /* Security Categories */
    { &hf_message_sec_cat_nat,
      { "Security Categories", "dmp.sec_cat", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL } },
    { &hf_message_sec_cat_val,
      { "Security Categories", "dmp.sec_cat", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL } },
    { &hf_message_sec_cat_cl,
      { "Clear", "dmp.sec_cat.cl", FT_BOOLEAN, 8,
        TFS (&tfs_set_notset), 0x80, NULL, HFILL } },
    { &hf_message_sec_cat_cs,
      { "Crypto Security", "dmp.sec_cat.cs", FT_BOOLEAN, 8,
        TFS (&tfs_set_notset), 0x40, NULL, HFILL } },
    { &hf_message_sec_cat_ex,
      { "Exclusive", "dmp.sec_cat.ex", FT_BOOLEAN, 8,
        TFS (&tfs_set_notset), 0x20, NULL, HFILL } },
    { &hf_message_sec_cat_ne,
      { "National Eyes Only", "dmp.sec_cat.ne", FT_BOOLEAN, 8,
        TFS (&tfs_set_notset), 0x10, NULL, HFILL } },
    { &hf_message_sec_cat_bit0,
      { "Bit 0", "dmp.sec_cat.bit0", FT_BOOLEAN, 8,
        TFS (&tfs_set_notset), 0x01, NULL, HFILL } },
    { &hf_message_sec_cat_bit1,
      { "Bit 1", "dmp.sec_cat.bit1", FT_BOOLEAN, 8,
        TFS (&tfs_set_notset), 0x02, NULL, HFILL } },
    { &hf_message_sec_cat_bit2,
      { "Bit 2", "dmp.sec_cat.bit2", FT_BOOLEAN, 8,
        TFS (&tfs_set_notset), 0x04, NULL, HFILL } },
    { &hf_message_sec_cat_bit3,
      { "Bit 3", "dmp.sec_cat.bit3", FT_BOOLEAN, 8,
        TFS (&tfs_set_notset), 0x08, NULL, HFILL } },
    { &hf_message_sec_cat_bit4,
      { "Bit 4", "dmp.sec_cat.bit4", FT_BOOLEAN, 8,
        TFS (&tfs_set_notset), 0x10, NULL, HFILL } },
    { &hf_message_sec_cat_bit5,
      { "Bit 5", "dmp.sec_cat.bit5", FT_BOOLEAN, 8,
        TFS (&tfs_set_notset), 0x20, NULL, HFILL } },
    { &hf_message_sec_cat_bit6,
      { "Bit 6", "dmp.sec_cat.bit6", FT_BOOLEAN, 8,
        TFS (&tfs_set_notset), 0x40, NULL, HFILL } },
    { &hf_message_sec_cat_bit7,
      { "Bit 7", "dmp.sec_cat.bit7", FT_BOOLEAN, 8,
        TFS (&tfs_set_notset), 0x80, NULL, HFILL } },

    /* Expiry Time */
    { &hf_message_exp_time,
      { "Expiry Time", "dmp.expiry_time", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL } },
    { &hf_message_exp_time_val,
      { "Expiry Time Value", "dmp.expiry_time_val", FT_UINT8, BASE_HEX,
        NULL, 0xFF, NULL, HFILL } },

    /* DTG */
    { &hf_message_dtg,
      { "DTG", "dmp.dtg", FT_UINT8, BASE_HEX,
        NULL, 0xFF, NULL, HFILL } },
    { &hf_message_dtg_sign,
      { "DTG in the", "dmp.dtg.sign", FT_BOOLEAN, 8, TFS (&dtg_sign),
        0x80, "Sign", HFILL } },
    { &hf_message_dtg_val,
      { "DTG Value", "dmp.dtg.val", FT_UINT8, BASE_HEX, NULL,
        0x7F, NULL, HFILL } },

    /* SIC */
    { &hf_message_sic,
      { "SIC", "dmp.sic", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_message_sic_key,
      { "SICs", "dmp.sic_key", FT_NONE, BASE_NONE,
        NULL, 0x0, "SIC Content", HFILL } },
    { &hf_message_sic_key_values,
      { "Content Byte", "dmp.sic_key.values", FT_UINT8, BASE_HEX,
        NULL, 0x0, "SIC Content Byte", HFILL } },
    { &hf_message_sic_key_type,
      { "Type", "dmp.sic_key.type", FT_UINT8, BASE_HEX,
        VALS (sic_key_type), 0xF0, "SIC Content Type", HFILL } },
    { &hf_message_sic_key_chars,
      { "Valid Characters", "dmp.sic_key.chars", FT_BOOLEAN, 8,
        TFS (&sic_key_chars), 0x08, "SIC Valid Characters", HFILL } },
    { &hf_message_sic_key_num,
      { "Number of SICs", "dmp.sic_key.num", FT_UINT8, BASE_HEX,
        VALS (sic_key_num), 0x07, NULL, HFILL } },
    { &hf_message_sic_bitmap,
      { "Length Bitmap (0 = 3 bytes, 1 = 4-8 bytes)", "dmp.sic_bitmap",
        FT_UINT8, BASE_HEX, NULL, 0xFF, "SIC Length Bitmap", HFILL } },
    { &hf_message_sic_bits,
      { "Bit 7-4", "dmp.sic_bits", FT_UINT8, BASE_HEX,
        VALS(sic_bit_vals), 0xF0, "SIC Bit 7-4, Characters [A-Z0-9] only",
        HFILL } },
    { &hf_message_sic_bits_any,
      { "Bit 7-4", "dmp.sic_bits_any", FT_UINT8, BASE_HEX,
        VALS(sic_bit_any_vals), 0xF0, "SIC Bit 7-4, Any valid characters",
        HFILL } },

    /* Subject Message Id */
    { &hf_message_subj_id,
      { "Subject Message Identifier", "dmp.subj_id", FT_UINT16,
        BASE_DEC, NULL, 0x0, NULL, HFILL } },

    /*
    ** Message body
    */
    { &hf_message_body,
      { "Message Body", "dmp.body", FT_NONE, BASE_NONE, NULL,
        0x0, NULL, HFILL}},

    /* Body Id */
    { &hf_message_eit,
      { "EIT", "dmp.body.eit", FT_UINT8, BASE_DEC,
        VALS(eit_vals), 0xE0, "Encoded Information Type", HFILL } },
    { &hf_message_compr,
      { "Compression", "dmp.body.compression", FT_UINT8, BASE_DEC,
        VALS(compression_vals), 0x18, NULL, HFILL } },

    /* Subject */
    { &hf_message_subject,
      { "Subject", "dmp.subject", FT_STRINGZ, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },

    /* Message Body */
    { &hf_message_body_data,
      { "User data", "dmp.body.data", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_message_body_plain,
      { "Message Body", "dmp.body.plain", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_message_bodyid_uint8,
      { "Structured Id", "dmp.body.id", FT_UINT8, BASE_DEC,
        NULL, 0x0, "Structured Body Id (1 byte)", HFILL } },
    { &hf_message_bodyid_uint16,
      { "Structured Id", "dmp.body.id", FT_UINT16, BASE_DEC,
        NULL, 0x0, "Structured Body Id (2 bytes)", HFILL } },
    { &hf_message_bodyid_uint32,
      { "Structured Id", "dmp.body.id", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Structured Body Id (4 bytes)", HFILL } },
    { &hf_message_bodyid_uint64,
      { "Structured Id", "dmp.body.id", FT_UINT64, BASE_DEC,
        NULL, 0x0, "Structured Body Id (8 bytes)", HFILL } },
    { &hf_message_bodyid_string,
      { "Structured Id", "dmp.body.id", FT_STRING, BASE_NONE,
        NULL, 0x0, "Structured Body Id (fixed text string)", HFILL } },
    { &hf_message_bodyid_zstring,
      { "Structured Id", "dmp.body.id", FT_STRINGZ, BASE_NONE,
        NULL, 0x0, "Structured Body Id (zero terminated text string)",
        HFILL } },
    { &hf_message_body_structured,
      { "Structured Body", "dmp.body.structured", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_message_body_uncompr,
      { "Uncompressed User data", "dmp.body.uncompressed", FT_NONE,
        BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_message_body_uncompressed,
      { "Uncompressed Message Body", "dmp.body.uncompressed",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL,
        HFILL } },

    /*
    ** Report
    */
    { &hf_delivery_report,
      { "Delivery Report", "dmp.dr", FT_NONE, BASE_NONE, NULL,
        0x0, NULL, HFILL}},
    { &hf_non_delivery_report,
      { "Non-Delivery Report", "dmp.ndr", FT_NONE, BASE_NONE, NULL,
        0x0, NULL, HFILL}},

    { &hf_report_type,
      { "Report Type", "dmp.report_type", FT_BOOLEAN, 8,
        TFS (&report_type), 0x80, NULL, HFILL } },
    { &hf_report_info_present_dr,
      { "Info Present", "dmp.info_present", FT_BOOLEAN, 8,
        TFS (&tfs_present_absent), 0x40, NULL, HFILL } },
    { &hf_report_addr_enc_dr,
      { "Address Encoding", "dmp.addr_encoding", FT_BOOLEAN, 8,
        TFS (&addr_enc), 0x20, NULL, HFILL } },
    { &hf_report_del_time,
      { "Delivery Time", "dmp.delivery_time", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_report_addr_enc_ndr,
      { "Address Encoding", "dmp.addr_encoding", FT_BOOLEAN, 8,
        TFS (&addr_enc), 0x40, NULL, HFILL } },
    { &hf_report_reason,
      { "Reason (P1)", "dmp.report_reason", FT_UINT8, BASE_DEC,
        VALS (p1_NonDeliveryReasonCode_vals), 0x3F,
        "Reason", HFILL } },
    { &hf_report_info_present_ndr,
      { "Info Present", "dmp.info_present", FT_BOOLEAN, 8,
        TFS (&tfs_present_absent), 0x80, NULL, HFILL } },
    { &hf_report_diagn,
      { "Diagnostic (P1)", "dmp.report_diagnostic", FT_UINT8, BASE_DEC,
        VALS (p1_NonDeliveryDiagnosticCode_vals), 0x7F,
        "Diagnostic", HFILL } },
    { &hf_report_suppl_info_len,
      { "Supplementary Information", "dmp.suppl_info_len", FT_UINT8,
        BASE_DEC, NULL, 0x0, "Supplementary Information Length", HFILL } },
    { &hf_report_suppl_info,
      { "Supplementary Information", "dmp.suppl_info", FT_STRINGZ,
        BASE_NONE, NULL, 0x0, NULL, HFILL } },

    /*
    ** Notification
    */
    { &hf_receipt_notif,
      { "Receipt Notification (RN)", "dmp.rn", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL} },
    { &hf_non_receipt_notif,
      { "Non-Receipt Notification (NRN)", "dmp.nrn", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL} },
    { &hf_other_notif,
      { "Other Notification (ON)", "dmp.on", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL} },

    { &hf_notif_type,
      { "Notification Type", "dmp.notif_type", FT_UINT8, BASE_DEC,
        VALS (notif_type), 0x03, NULL, HFILL } },
    { &hf_notif_rec_time,
      { "Receipt Time", "dmp.receipt_time", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL } },
    { &hf_notif_rec_time_val,
      { "Receipt Time Value", "dmp.receipt_time_val", FT_UINT8,
        BASE_HEX, NULL, 0xFF, NULL, HFILL } },
    { &hf_notif_suppl_info_len,
      { "Supplementary Information", "dmp.suppl_info_len",
        FT_UINT8, BASE_DEC, NULL, 0x0, "Supplementary Information Length",
        HFILL } },
    { &hf_notif_suppl_info,
      { "Supplementary Information", "dmp.suppl_info",
        FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL,
        HFILL } },
    { &hf_notif_non_rec_reason,
      { "Non-Receipt Reason", "dmp.notif_non_rec_reason",
        FT_UINT8, BASE_DEC, VALS (p22_NonReceiptReasonField_vals), 0x0,
        NULL, HFILL } },
    { &hf_notif_discard_reason,
      { "Discard Reason", "dmp.notif_discard_reason", FT_UINT8,
        BASE_DEC, VALS (p22_DiscardReasonField_vals), 0x0,
        NULL, HFILL } },
    { &hf_notif_on_type,
      { "ON Type", "dmp.notif_on_type", FT_UINT8, BASE_DEC,
        VALS (on_type), 0x0, NULL, HFILL } },
    { &hf_notif_acp127,
      { "ACP127 Recipient", "dmp.acp127recip_len", FT_UINT8,
        BASE_DEC, NULL, 0x0, "ACP 127 Recipient Length", HFILL } },
    { &hf_notif_acp127recip,
      { "ACP127 Recipient", "dmp.acp127recip", FT_STRINGZ,
        BASE_NONE, NULL, 0x0, "ACP 127 Recipient", HFILL } },

    /*
    ** Acknowledgement
    */
    { &hf_ack,
      { "Acknowledgement", "dmp.ack", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_ack_reason,
      { "Ack Reason", "dmp.ack_reason", FT_UINT8, BASE_DEC,
        VALS (&ack_reason), 0x0, "Reason", HFILL } },
    { &hf_ack_diagnostic,
      { "Ack Diagnostic", "dmp.ack_diagnostic", FT_UINT8, BASE_DEC,
        NULL, 0x0, "Diagnostic", HFILL } },
    { &hf_ack_recips,
      { "Recipient List", "dmp.ack_rec_list", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },

    /*
    ** Checksum
    */
    { &hf_checksum,
      { "Checksum", "dmp.checksum", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL } },
    { &hf_checksum_good,
      { "Good", "dmp.checksum_good", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, "True: checksum matches packet content; False: doesn't match content or not checked", HFILL } },
    { &hf_checksum_bad,
      { "Bad", "dmp.checksum_bad", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, "True: checksum doesn't match packet content; False: matches content or not checked", HFILL } },

    /*
    ** Ack matching / Resend
    */
    { &hf_analysis_ack_time,
      { "Acknowledgement Time", "dmp.analysis.ack_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the Message and the Acknowledge", HFILL } },
    { &hf_analysis_rep_time,
      { "Report Reply Time", "dmp.analysis.report_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the Message and the Report", HFILL } },
    { &hf_analysis_not_time,
      { "Notification Reply Time", "dmp.analysis.notif_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the Message and the Notification", HFILL } },
    { &hf_analysis_total_time,
      { "Total Time", "dmp.analysis.total_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the first Message and the Acknowledge", HFILL } },
    { &hf_analysis_retrans_time,
      { "Retransmission Time", "dmp.analysis.retrans_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the last Message and this Message", HFILL } },
    { &hf_analysis_total_retrans_time,
      { "Total Retransmission Time", "dmp.analysis.total_retrans_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the first Message and this Message", HFILL } },
    { &hf_analysis_msg_num,
      { "Message in", "dmp.analysis.msg_in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This packet has a Message in this frame", HFILL } },
    { &hf_analysis_ack_num,
      { "Acknowledgement in", "dmp.analysis.ack_in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This packet has an Acknowledgement in this frame", HFILL } },
    { &hf_analysis_rep_num,
      { "Report in", "dmp.analysis.report_in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This packet has a Report in this frame", HFILL } },
    { &hf_analysis_not_num,
      { "Notification in", "dmp.analysis.notif_in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This packet has a Notification in this frame", HFILL } },
    { &hf_analysis_msg_missing,
      { "Message missing", "dmp.analysis.msg_missing", FT_NONE, BASE_NONE,
        NULL, 0x0, "The Message for this packet is missing", HFILL } },
    { &hf_analysis_ack_missing,
      { "Acknowledgement missing", "dmp.analysis.ack_missing", FT_NONE, BASE_NONE,
        NULL, 0x0, "The acknowledgement for this packet is missing", HFILL } },
    { &hf_analysis_retrans_no,
      { "Retransmission #", "dmp.analysis.retrans_no", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Retransmission count", HFILL } },
    { &hf_analysis_ack_dup_no,
      { "Duplicate ACK #", "dmp.analysis.dup_ack_no", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Duplicate Acknowledgement count", HFILL } },
    { &hf_analysis_msg_resend_from,
      { "Retransmission of Message sent in", "dmp.analysis.msg_first_sent_in",
        FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This Message was first sent in this frame", HFILL } },
    { &hf_analysis_rep_resend_from,
      { "Retransmission of Report sent in", "dmp.analysis.report_first_sent_in",
        FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This Report was first sent in this frame", HFILL } },
    { &hf_analysis_not_resend_from,
      { "Retransmission of Notification sent in", "dmp.analysis.notif_first_sent_in",
        FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This Notification was first sent in this frame", HFILL } },
    { &hf_analysis_ack_resend_from,
      { "Retransmission of Acknowledgement sent in", "dmp.analysis.ack_first_sent_in",
        FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This Acknowledgement was first sent in this frame", HFILL } },

    /*
    ** Reserved values
    */
    { &hf_reserved_0x01,
      { "Reserved", "dmp.reserved", FT_UINT8, BASE_DEC,
        NULL, 0x01, NULL, HFILL } },
    { &hf_reserved_0x02,
      { "Reserved", "dmp.reserved", FT_UINT8, BASE_DEC,
        NULL, 0x02, NULL, HFILL } },
    { &hf_reserved_0x04,
      { "Reserved", "dmp.reserved", FT_UINT8, BASE_DEC,
        NULL, 0x04, NULL, HFILL } },
    { &hf_reserved_0x07,
      { "Reserved", "dmp.reserved", FT_UINT8, BASE_DEC,
        NULL, 0x07, NULL, HFILL } },
    { &hf_reserved_0x08,
      { "Reserved", "dmp.reserved", FT_UINT8, BASE_DEC,
        NULL, 0x08, NULL, HFILL } },
    { &hf_reserved_0x1F,
      { "Reserved", "dmp.reserved", FT_UINT8, BASE_DEC,
        NULL, 0x1F, NULL, HFILL } },
    { &hf_reserved_0x20,
      { "Reserved", "dmp.reserved", FT_UINT8, BASE_DEC,
        NULL, 0x20, NULL, HFILL } },
    { &hf_reserved_0x40,
      { "Reserved", "dmp.reserved", FT_UINT8, BASE_DEC,
        NULL, 0x40, NULL, HFILL } },
    { &hf_reserved_0xC0,
      { "Reserved", "dmp.reserved", FT_UINT8, BASE_DEC,
        NULL, 0xC0, NULL, HFILL } },
    { &hf_reserved_0xE0,
      { "Reserved", "dmp.reserved", FT_UINT8, BASE_DEC,
        NULL, 0xE0, NULL, HFILL } },
    { &hf_reserved_0x8000,
      { "Reserved", "dmp.reserved", FT_UINT16, BASE_DEC,
        NULL, 0x8000, NULL, HFILL } },
  };

  static gint *ett[] = {
    &ett_dmp,
    &ett_envelope,
    &ett_envelope_version,
    &ett_envelope_hop_count,
    &ett_envelope_rec_present,
    &ett_envelope_addr_enc,
    &ett_envelope_checksum,
    &ett_envelope_cont_type,
    &ett_envelope_subm_time,
    &ett_envelope_time_diff,
    &ett_envelope_flags,
    &ett_envelope_recipients,
    &ett_envelope_ext_recipients,
    &ett_envelope_addresses,
    &ett_address,
    &ett_address_direct,
    &ett_address_rec_no,
    &ett_address_extended,
    &ett_address_ext_form,
    &ett_address_ext_rec_no,
    &ett_address_ext_action,
    &ett_address_ext_rep_req,
    &ett_address_ext_not_req,
    &ett_address_ext_type,
    &ett_address_ext_length,
    &ett_content,
    &ett_message,
    &ett_message_st_type,
    &ett_message_reserved,
    &ett_message_precedence,
    &ett_message_importance,
    &ett_message_body_format,
    &ett_message_sec_class,
    &ett_message_sec_pol,
    &ett_message_sec_cat,
    &ett_message_heading_flags,
    &ett_message_exp_time,
    &ett_message_dtg,
    &ett_message_sic,
    &ett_message_sic_key,
    &ett_message_sic_bitmap,
    &ett_message_sic_bits,
    &ett_message_eit,
    &ett_message_compr,
    &ett_message_body_reserved,
    &ett_message_body,
    &ett_message_body_uncompr,
    &ett_report,
    &ett_report_type,
    &ett_report_info_present_dr,
    &ett_report_info_present_ndr,
    &ett_report_addr_enc_dr,
    &ett_report_addr_enc_ndr,
    &ett_report_reserved,
    &ett_report_del_time,
    &ett_report_reason,
    &ett_report_suppl_info,
    &ett_report_diagn,
    &ett_notif,
    &ett_notif_type,
    &ett_notif_rec_time,
    &ett_notif_suppl_info,
    &ett_notif_acp127recip,
    &ett_ack,
    &ett_ack_recips,
    &ett_checksum,
    &ett_analysis
  };

  module_t *dmp_module;

  proto_dmp = proto_register_protocol (PNAME, PSNAME, PFNAME);
  register_dissector(PFNAME, dissect_dmp, proto_dmp);

  proto_register_field_array (proto_dmp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  register_init_routine (&dmp_init_routine);

  /* Set default UDP ports */
  range_convert_str (&global_dmp_port_range, DEFAULT_DMP_PORT_RANGE,
                     MAX_UDP_PORT);

  /* Register our configuration options */
  dmp_module = prefs_register_protocol (proto_dmp, proto_reg_handoff_dmp);

  prefs_register_obsolete_preference (dmp_module, "udp_port");
  prefs_register_obsolete_preference (dmp_module, "udp_port_second");

  prefs_register_range_preference (dmp_module, "udp_ports",
                                  "DMP port numbers",
                                  "Port numbers used for DMP traffic",
                                   &global_dmp_port_range, MAX_UDP_PORT);
  prefs_register_bool_preference (dmp_module, "seq_ack_analysis",
                                  "SEQ/ACK Analysis",
                                  "Calculate sequence/acknowledgement analysis",
                                  &use_seq_ack_analysis);
  prefs_register_bool_preference (dmp_module, "align_ids",
                                  "Align identifiers in info list",
                                  "Align identifiers in info list"
                                  " (does not align when retransmission or"
                                  " duplicate acknowledgement indication)",
                                  &dmp_align);
  prefs_register_bool_preference (dmp_module, "subject_as_id",
                                  "Print subject as body id",
                                  "Print subject as body id in free text "
                                  "messages with subject",
                                  &dmp_subject_as_id);
  prefs_register_enum_preference (dmp_module, "struct_print",
                                  "Structured message id format",
                                  "Format of the structured message id",
                                  &dmp_struct_format, struct_id_options,
                                  FALSE);
  prefs_register_uint_preference (dmp_module, "struct_offset",
                                  "Offset to structured message id",
                                  "Used to set where the structured message "
                                  "id starts in the User Data",
                                  10, &dmp_struct_offset);

  prefs_register_uint_preference (dmp_module, "struct_length",
                                  "Fixed text string length",
                                  "Used to set length of fixed text string "
                                  "in the structured message id format "
                                  "(maximum 128 characters)",
                                  10, &dmp_struct_length);
}

static void range_delete_callback (guint32 port)
{
    dissector_delete_uint ("udp.port", port, dmp_handle);
}

static void range_add_callback (guint32 port)
{
    dissector_add_uint ("udp.port", port, dmp_handle);
}

void proto_reg_handoff_dmp (void)
{
  static range_t *dmp_port_range;
  static gboolean dmp_prefs_initialized = FALSE;

  if (!dmp_prefs_initialized) {
    dmp_handle = find_dissector (PFNAME);
    dmp_prefs_initialized = TRUE;
  } else {
    range_foreach (dmp_port_range, range_delete_callback);
    g_free (dmp_port_range);
  }

  /* Save port number for later deletion */
  dmp_port_range = range_copy (global_dmp_port_range);

  range_foreach (dmp_port_range, range_add_callback);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 noexpandtab
 * :indentSize=2:tabSize=8:noTabs=false:
 */

