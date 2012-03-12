/* Routines for LTE PDCP/ROHC
 *
 * Martin Mathieson
 *
 * $Id: packet-pdcp-lte.c 36204 2011-03-16 23:18:59Z martinm $
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

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>

#include "packet-pdcp-lte.h"

/* Described in:
 * 3GPP TS 36.323 Evolved Universal Terrestrial Radio Access (E-UTRA)
 *                Packet Data Convergence Protocol (PDCP) specification
 *
 * RFC 3095       RObust Header Compression (ROHC):
 *                Framework and four profiles: RTP, UDP, ESP, and uncompressed
 */


/* TODO:
   - Complete ROHC support for RTP and extend to other profiles (including ROHCv2)
   - Support for deciphering
   - Verify MAC authentication bytes
*/


/* Initialize the protocol and registered fields. */
int proto_pdcp_lte = -1;

extern int proto_rlc_lte;

/* Configuration (info known outside of PDU) */
static int hf_pdcp_lte_configuration = -1;
static int hf_pdcp_lte_direction = -1;
static int hf_pdcp_lte_ueid = -1;
static int hf_pdcp_lte_channel_type = -1;
static int hf_pdcp_lte_channel_id = -1;
static int hf_pdcp_lte_rohc = -1;
static int hf_pdcp_lte_rohc_compression = -1;
static int hf_pdcp_lte_rohc_mode = -1;
static int hf_pdcp_lte_rohc_rnd = -1;
static int hf_pdcp_lte_rohc_udp_checksum_present = -1;
static int hf_pdcp_lte_rohc_profile = -1;
static int hf_pdcp_lte_no_header_pdu = -1;
static int hf_pdcp_lte_plane = -1;
static int hf_pdcp_lte_seqnum_length = -1;
static int hf_pdcp_lte_cid_inclusion_info = -1;
static int hf_pdcp_lte_large_cid_present = -1;

/* PDCP header fields */
static int hf_pdcp_lte_seq_num_5 = -1;
static int hf_pdcp_lte_seq_num_7 = -1;
static int hf_pdcp_lte_reserved3 = -1;
static int hf_pdcp_lte_seq_num_12 = -1;
static int hf_pdcp_lte_signalling_data = -1;
static int hf_pdcp_lte_mac = -1;
static int hf_pdcp_lte_data_control = -1;
static int hf_pdcp_lte_user_plane_data = -1;
static int hf_pdcp_lte_control_pdu_type = -1;
static int hf_pdcp_lte_fms = -1;
static int hf_pdcp_lte_bitmap = -1;
static int hf_pdcp_lte_bitmap_not_received = -1;

/* Robust Header Compression Fields */
static int hf_pdcp_lte_rohc_padding = -1;
static int hf_pdcp_lte_rohc_r_0_crc = -1;
static int hf_pdcp_lte_rohc_feedback = -1;

static int hf_pdcp_lte_rohc_type0_t = -1;
static int hf_pdcp_lte_rohc_type1_t = -1;
static int hf_pdcp_lte_rohc_type2_t = -1;

static int hf_pdcp_lte_rohc_d = -1;
static int hf_pdcp_lte_rohc_ir_crc = -1;

static int hf_pdcp_lte_rohc_static_ipv4 = -1;
static int hf_pdcp_lte_rohc_ip_version = -1;
static int hf_pdcp_lte_rohc_ip_protocol = -1;
static int hf_pdcp_lte_rohc_ip_src = -1;
static int hf_pdcp_lte_rohc_ip_dst = -1;

static int hf_pdcp_lte_rohc_static_udp = -1;
static int hf_pdcp_lte_rohc_static_udp_src_port = -1;
static int hf_pdcp_lte_rohc_static_udp_dst_port = -1;

static int hf_pdcp_lte_rohc_static_rtp = -1;
static int hf_pdcp_lte_rohc_static_rtp_ssrc = -1;

static int hf_pdcp_lte_rohc_dynamic_ipv4 = -1;
static int hf_pdcp_lte_rohc_dynamic_ipv4_tos = -1;
static int hf_pdcp_lte_rohc_dynamic_ipv4_ttl = -1;
static int hf_pdcp_lte_rohc_dynamic_ipv4_id = -1;
static int hf_pdcp_lte_rohc_dynamic_ipv4_df = -1;
static int hf_pdcp_lte_rohc_dynamic_ipv4_rnd = -1;
static int hf_pdcp_lte_rohc_dynamic_ipv4_nbo = -1;

static int hf_pdcp_lte_rohc_dynamic_udp = -1;
static int hf_pdcp_lte_rohc_dynamic_udp_checksum = -1;
static int hf_pdcp_lte_rohc_dynamic_udp_seqnum = -1;

static int hf_pdcp_lte_rohc_dynamic_rtp = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_rx = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_cc = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_seqnum = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_timestamp = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_reserved3 = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_x = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_mode = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_tis = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_tss = -1;
static int hf_pdcp_lte_rohc_dynamic_rtp_ts_stride = -1;

static int hf_pdcp_lte_rohc_ts = -1;
static int hf_pdcp_lte_rohc_m = -1;
static int hf_pdcp_lte_rohc_uor2_sn = -1;
static int hf_pdcp_lte_rohc_uor2_x = -1;

static int hf_pdcp_lte_rohc_add_cid = -1;
static int hf_pdcp_lte_rohc_large_cid = -1;

static int hf_pdcp_lte_rohc_uo0_sn = -1;
static int hf_pdcp_lte_rohc_uo0_crc = -1;

static int hf_pdcp_lte_rohc_r0_sn = -1;
static int hf_pdcp_lte_rohc_r0_crc_sn = -1;
static int hf_pdcp_lte_rohc_r0_crc_crc = -1;

static int hf_pdcp_lte_rohc_feedback_code = -1;
static int hf_pdcp_lte_rohc_feedback_size = -1;
static int hf_pdcp_lte_rohc_feedback_feedback1 = -1;
static int hf_pdcp_lte_rohc_feedback_feedback2 = -1;
static int hf_pdcp_lte_rohc_feedback_ack_type = -1;
static int hf_pdcp_lte_rohc_feedback_mode = -1;
static int hf_pdcp_lte_rohc_feedback_sn = -1;
static int hf_pdcp_lte_rohc_feedback_option = -1;
static int hf_pdcp_lte_rohc_feedback_length = -1;
static int hf_pdcp_lte_rohc_feedback_crc = -1;
static int hf_pdcp_lte_rohc_feedback_option_sn = -1;
static int hf_pdcp_lte_rohc_feedback_option_clock = -1;

static int hf_pdcp_lte_rohc_ip_id = -1;
static int hf_pdcp_lte_rohc_udp_checksum = -1;
static int hf_pdcp_lte_rohc_payload = -1;

/* Sequence Analysis */
static int hf_pdcp_lte_sequence_analysis = -1;
static int hf_pdcp_lte_sequence_analysis_ok = -1;
static int hf_pdcp_lte_sequence_analysis_previous_frame = -1;
static int hf_pdcp_lte_sequence_analysis_expected_sn = -1;

static int hf_pdcp_lte_sequence_analysis_repeated = -1;
static int hf_pdcp_lte_sequence_analysis_skipped = -1;




/* Protocol subtree. */
static int ett_pdcp = -1;
static int ett_pdcp_configuration = -1;
static int ett_pdcp_packet = -1;
static int ett_pdcp_lte_sequence_analysis = -1;
static int ett_pdcp_rohc = -1;
static int ett_pdcp_rohc_static_ipv4 = -1;
static int ett_pdcp_rohc_static_udp = -1;
static int ett_pdcp_rohc_static_rtp = -1;
static int ett_pdcp_rohc_dynamic_ipv4 = -1;
static int ett_pdcp_rohc_dynamic_udp = -1;
static int ett_pdcp_rohc_dynamic_rtp = -1;
static int ett_pdcp_rohc_report_bitmap = -1;


static const value_string direction_vals[] =
{
    { DIRECTION_UPLINK,      "Uplink"},
    { DIRECTION_DOWNLINK,    "Downlink"},
    { 0, NULL }
};


static const value_string pdcp_plane_vals[] = {
    { SIGNALING_PLANE,    "Signalling" },
    { USER_PLANE,         "User" },
    { 0,   NULL }
};

static const value_string logical_channel_vals[] = {
    { Channel_DCCH,  "DCCH"},
    { Channel_BCCH,  "BCCH"},
    { Channel_CCCH,  "CCCH"},
    { Channel_PCCH,  "PCCH"},
    { 0,             NULL}
};

static const value_string rohc_mode_vals[] = {
    { UNIDIRECTIONAL,            "Unidirectional" },
    { OPTIMISTIC_BIDIRECTIONAL,  "Optimistic Bidirectional" },
    { RELIABLE_BIDIRECTIONAL,    "Reliable Bidirectional" },
    { 0,   NULL }
};


/* Values taken from:
   http://www.iana.org/assignments/rohc-pro-ids/rohc-pro-ids.txt */
static const value_string rohc_profile_vals[] = {
         { 0x0000,   "ROHC uncompressed" },      /* [RFC5795] */
         { 0x0001,   "ROHC RTP" },               /* [RFC3095] */
         { 0x0101,   "ROHCv2 RTP" },             /* [RFC5225] */
         { 0x0002,   "ROHC UDP" },               /* [RFC3095] */
         { 0x0102,   "ROHCv2 UDP" },             /* [RFC5225] */
         { 0x0003,   "ROHC ESP" },               /* [RFC3095] */
         { 0x0103,   "ROHCv2 ESP" },             /* [RFC5225] */
         { 0x0004,   "ROHC IP" },                /* [RFC3843] */
         { 0x0104,   "ROHCv2 IP" },              /* [RFC5225] */
         { 0x0005,   "ROHC LLA" },               /* [RFC4362] */
         { 0x0105,   "ROHC LLA with R-mode" },   /* [RFC3408] */
         { 0x0006,   "ROHC TCP" },               /* [RFC4996] */
         { 0x0007,   "ROHC RTP/UDP-Lite" },      /* [RFC4019] */
         { 0x0107,   "ROHCv2 RTP/UDP-Lite" },    /* [RFC5225] */
         { 0x0008,   "ROHC UDP-Lite" },          /* [RFC4019] */
         { 0x0108,   "ROHCv2 UDP-Lite" },        /* [RFC5225] */
         { 0,   NULL }
};

static const value_string pdu_type_vals[] = {
    { 0,   "Control PDU" },
    { 1,   "Data PDU" },
    { 0,   NULL }
};

static const value_string feedback_ack_vals[] = {
    { 0,   "ACK" },
    { 1,   "NACK" },
    { 2,   "STATIC-NACK" },
    { 0,   NULL }
};

static const value_string feedback_option_vals[] = {
    { 1,   "CRC" },
    { 2,   "REJECT" },
    { 3,   "SN-Not-Valid" },
    { 4,   "SN" },
    { 5,   "Clock" },
    { 6,   "Jitter" },
    { 7,   "Loss" },
    { 0,   NULL }
};

static const value_string control_pdu_type_vals[] = {
    { 0,   "PDCP Status report" },
    { 1,   "Header Compression Feedback Information" },
    { 0,   NULL }
};

static const value_string t_vals[] = {
    { 0,   "ID message format" },
    { 1,   "TS message format" },
    { 0,   NULL }
};

static const value_string ip_protocol_vals[] = {
    { 6,   "TCP" },
    { 17,  "UDP" },
    { 0,   NULL }
};


static dissector_handle_t ip_handle;


/* Preference variables */
static gboolean global_pdcp_show_feedback_option_tag_length = FALSE;
static gboolean global_pdcp_dissect_user_plane_as_ip = FALSE;
static gboolean global_pdcp_dissect_signalling_plane_as_rrc = FALSE;
static gboolean global_pdcp_check_sequence_numbers = FALSE;
static gboolean global_pdcp_dissect_rohc = FALSE;


/**************************************************/
/* Sequence number analysis                       */

/* Channel key */
typedef struct
{
    guint16            ueId;
    LogicalChannelType channelType;
    guint16            channelId;
    guint8             direction;
} pdcp_channel_hash_key;

/* Channel state */
typedef struct
{
    guint16  previousSequenceNumber;
    guint32  previousFrameNum;
} pdcp_channel_status;

/* The sequence analysis channel hash table.
   Maps key -> status */
static GHashTable *pdcp_sequence_analysis_channel_hash = NULL;

/* Equal keys */
static gint pdcp_channel_equal(gconstpointer v, gconstpointer v2)
{
    const pdcp_channel_hash_key* val1 = v;
    const pdcp_channel_hash_key* val2 = v2;

    /* All fields must match */
    return (memcmp(val1, val2, sizeof(pdcp_channel_hash_key)) == 0);
}

/* Compute a hash value for a given key. */
static guint pdcp_channel_hash_func(gconstpointer v)
{
    const pdcp_channel_hash_key* val1 = v;

    /* TODO: use multipliers */
    return val1->ueId + val1->channelType + val1->channelId + val1->direction;
}

/* Hash table functions for frame reports */

/* TODO: copied from packet-rlc-lte.c.  extern, or add to lib? */
/* Equal keys */
static gint pdcp_frame_equal(gconstpointer v, gconstpointer v2)
{
    return (v == v2);
}

/* Compute a hash value for a given key. */
static guint pdcp_frame_hash_func(gconstpointer v)
{
    return GPOINTER_TO_UINT(v);
}


/* Info to attach to frame when first read, recording what to show about sequence */
typedef struct
{
    gboolean  sequenceExpectedCorrect;
    guint16   sequenceExpected;
    guint32   previousFrameNum;

    guint16   firstSN;
    guint16   lastSN;

    enum { SN_OK, SN_Repeated, SN_MAC_Retx, SN_Retx, SN_Missing} state;
} pdcp_sequence_report_in_frame;

/* The sequence analysis frame report hash table instance itself   */
static GHashTable *pdcp_lte_frame_sequence_analysis_report_hash = NULL;


/* Add to the tree values associated with sequence analysis for this frame */
static void addChannelSequenceInfo(pdcp_sequence_report_in_frame *p,
                                   pdcp_lte_info *p_pdcp_lte_info,
                                   guint16   sequenceNumber,
                                   packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    proto_tree *seqnum_tree;
    proto_item *seqnum_ti;
    proto_item *ti;

    /* Create subtree */
    seqnum_ti = proto_tree_add_string_format(tree,
                                             hf_pdcp_lte_sequence_analysis,
                                             tvb, 0, 0,
                                             "", "Sequence Analysis");
    seqnum_tree = proto_item_add_subtree(seqnum_ti,
                                         ett_pdcp_lte_sequence_analysis);
    PROTO_ITEM_SET_GENERATED(seqnum_ti);


    /* Previous channel frame */
    if (p->previousFrameNum != 0) {
        proto_tree_add_uint(seqnum_tree, hf_pdcp_lte_sequence_analysis_previous_frame,
                            tvb, 0, 0, p->previousFrameNum);
    }

    /* Expected sequence number */
    ti = proto_tree_add_uint(seqnum_tree, hf_pdcp_lte_sequence_analysis_expected_sn,
                            tvb, 0, 0, p->sequenceExpected);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Make sure we have recognised SN length */
    switch (p_pdcp_lte_info->seqnum_length) {
        case PDCP_SN_LENGTH_5_BITS:
        case PDCP_SN_LENGTH_7_BITS:
        case PDCP_SN_LENGTH_12_BITS:
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
    }

    switch (p->state) {
        case SN_OK:
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_ok,
                                        tvb, 0, 0, TRUE);
            PROTO_ITEM_SET_GENERATED(ti);
            proto_item_append_text(seqnum_ti, " - OK");
            break;

        case SN_Missing:
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_ok,
                                        tvb, 0, 0, FALSE);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_skipped,
                                        tvb, 0, 0, TRUE);
            PROTO_ITEM_SET_GENERATED(ti);
            if (p->lastSN != p->firstSN) {
                expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                       "PDCP SNs (%u to %u) missing for %s on UE %u",
                                       p->firstSN, p->lastSN,
                                       val_to_str_const(p_pdcp_lte_info->direction, direction_vals, "Unknown"),
                                       p_pdcp_lte_info->ueid);
                proto_item_append_text(seqnum_ti, " - SNs missing (%u to %u)",
                                       p->firstSN, p->lastSN);
            }
            else {
                expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                       "PDCP SN (%u) missing for %s on UE %u",
                                       p->firstSN,
                                       val_to_str_const(p_pdcp_lte_info->direction, direction_vals, "Unknown"),
                                       p_pdcp_lte_info->ueid);
                proto_item_append_text(seqnum_ti, " - SN missing (%u)",
                                       p->firstSN);
            }
            break;

        case SN_Repeated:
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_ok,
                                        tvb, 0, 0, FALSE);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_repeated,
                                        tvb, 0, 0, TRUE);
            PROTO_ITEM_SET_GENERATED(ti);
            expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                   "PDCP SN (%u) repeated for %s for UE %u",
                                   p->firstSN,
                                   val_to_str_const(p_pdcp_lte_info->direction, direction_vals, "Unknown"),
                                   p_pdcp_lte_info->ueid);
            proto_item_append_text(seqnum_ti, "- SN %u Repeated",
                                   p->firstSN);
            break;

        default:
            /* Incorrect sequence number */
            expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                   "Wrong Sequence Number for %s on UE %u - got %u, expected %u",
                                   val_to_str_const(p_pdcp_lte_info->direction, direction_vals, "Unknown"),
                                   p_pdcp_lte_info->ueid, sequenceNumber, p->sequenceExpected);
            break;
    }
}


/* Update the channel status and set report for this frame */
static void checkChannelSequenceInfo(packet_info *pinfo, tvbuff_t *tvb,
                                     pdcp_lte_info *p_pdcp_lte_info,
                                     guint16 sequenceNumber,
                                     proto_tree *tree)
{
    pdcp_channel_hash_key          channel_key;
    pdcp_channel_hash_key          *p_channel_key;
    pdcp_channel_status            *p_channel_status;
    pdcp_sequence_report_in_frame  *p_report_in_frame = NULL;
    gboolean               createdChannel = FALSE;
    guint16                expectedSequenceNumber = 0;
    guint16                snLimit = 0;

    /* If find stat_report_in_frame already, use that and get out */
    if (pinfo->fd->flags.visited) {
        p_report_in_frame = (pdcp_sequence_report_in_frame*)g_hash_table_lookup(pdcp_lte_frame_sequence_analysis_report_hash,
                                                                                &pinfo->fd->num);
        if (p_report_in_frame != NULL) {
            addChannelSequenceInfo(p_report_in_frame, p_pdcp_lte_info,
                                   sequenceNumber,
                                   pinfo, tree, tvb);
            return;
        }
        else {
            /* Give up - we must have tried already... */
            return;
        }
    }


    /**************************************************/
    /* Create or find an entry for this channel state */
    memset(&channel_key, 0, sizeof(channel_key));
    channel_key.ueId = p_pdcp_lte_info->ueid;
    channel_key.channelType = p_pdcp_lte_info->channelType;
    channel_key.channelId = p_pdcp_lte_info->channelId;
    channel_key.direction = p_pdcp_lte_info->direction;

    /* Do the table lookup */
    p_channel_status = (pdcp_channel_status*)g_hash_table_lookup(pdcp_sequence_analysis_channel_hash, &channel_key);

    /* Create table entry if necessary */
    if (p_channel_status == NULL) {
        createdChannel = TRUE;

        /* Allocate a new key and value */
        p_channel_key = se_alloc(sizeof(pdcp_channel_hash_key));
        p_channel_status = se_alloc0(sizeof(pdcp_channel_status));

        /* Copy key contents */
        memcpy(p_channel_key, &channel_key, sizeof(pdcp_channel_hash_key));

        /* Add entry */
        g_hash_table_insert(pdcp_sequence_analysis_channel_hash, p_channel_key, p_channel_status);
    }

    /* Create space for frame state_report */
    p_report_in_frame = se_alloc(sizeof(pdcp_sequence_report_in_frame));

    switch (p_pdcp_lte_info->seqnum_length) {
        case PDCP_SN_LENGTH_5_BITS:
            snLimit = 32;
            break;
        case PDCP_SN_LENGTH_7_BITS:
            snLimit = 128;
            break;
        case PDCP_SN_LENGTH_12_BITS:
            snLimit = 4096;
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
    }

    /* Work out expected sequence number */
    if (!createdChannel) {
        expectedSequenceNumber = (p_channel_status->previousSequenceNumber + 1) % snLimit;
    }

    /* Set report for this frame */
    /* For PDCP, sequence number is always expectedSequence number */
    p_report_in_frame->sequenceExpectedCorrect = (sequenceNumber == expectedSequenceNumber);

    /* For wrong sequence number... */
    if (!p_report_in_frame->sequenceExpectedCorrect) {

        /* Frames are not missing if we get an earlier sequence number again */
        if (((snLimit + expectedSequenceNumber - sequenceNumber) % snLimit) > 15) {
            p_report_in_frame->state = SN_Missing;
            p_report_in_frame->firstSN = expectedSequenceNumber;
            p_report_in_frame->lastSN = (snLimit + sequenceNumber - 1) % snLimit;

            p_report_in_frame->sequenceExpected = expectedSequenceNumber;
            p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;

            /* Update channel status to remember *this* frame */
            p_channel_status->previousFrameNum = pinfo->fd->num;
            p_channel_status->previousSequenceNumber = sequenceNumber;
        }
        else {
            /* An SN has been repeated */
            p_report_in_frame->state = SN_Repeated;
            p_report_in_frame->firstSN = sequenceNumber;

            p_report_in_frame->sequenceExpected = expectedSequenceNumber;
            p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;
        }
    }
    else {
        /* SN was OK */
        p_report_in_frame->state = SN_OK;
        p_report_in_frame->sequenceExpected = expectedSequenceNumber;
        p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;

        /* Update channel status to remember *this* frame */
        p_channel_status->previousFrameNum = pinfo->fd->num;
        p_channel_status->previousSequenceNumber = sequenceNumber;
    }

    /* Associate with this frame number */
    g_hash_table_insert(pdcp_lte_frame_sequence_analysis_report_hash, &pinfo->fd->num, p_report_in_frame);

    /* Add state report for this frame into tree */
    addChannelSequenceInfo(p_report_in_frame, p_pdcp_lte_info, sequenceNumber,
                           pinfo, tree, tvb);
}


/* Write the given formatted text to:
   - the info column
   - the top-level RLC PDU item */
static void write_pdu_label_and_info(proto_item *pdu_ti,
                                     packet_info *pinfo, const char *format, ...)
{
    #define MAX_INFO_BUFFER 256
    static char info_buffer[MAX_INFO_BUFFER];

    va_list ap;

    va_start(ap, format);
    g_vsnprintf(info_buffer, MAX_INFO_BUFFER, format, ap);
    va_end(ap);

    /* Add to indicated places */
    col_append_str(pinfo->cinfo, COL_INFO, info_buffer);
    proto_item_append_text(pdu_ti, "%s", info_buffer);
}



/***************************************************************/


/* Dissect a Large-CID field.
   Return following offset */
static int dissect_large_cid(proto_tree *tree,
                             tvbuff_t *tvb,
                             int offset)
{
    guint8 first_octet = tvb_get_guint8(tvb, offset);

    if ((first_octet & 0x80) == 0) {
        /* One byte */
        proto_tree_add_uint(tree, hf_pdcp_lte_rohc_large_cid, tvb, offset, 1,
                            first_octet);
        return offset+1;
    }
    else {
        /* Two bytes */
        guint16 bytes = tvb_get_ntohs(tvb, offset) & 0x7fff;
        proto_tree_add_uint(tree, hf_pdcp_lte_rohc_large_cid, tvb, offset, 2,
                            bytes);
        return offset+2;
    }

}

static int dissect_pdcp_dynamic_chain(proto_tree *tree,
                                      proto_item *root_item _U_,
                                      tvbuff_t *tvb,
                                      int offset,
                                      struct pdcp_lte_info *p_pdcp_info,
                                      packet_info *pinfo)
{
    /* IPv4 dynamic */
    if (p_pdcp_info->rohc_ip_version == 4) {
        proto_tree *dynamic_ipv4_tree;
        proto_item *root_ti;
        int tree_start_offset = offset;
        guint8 tos, ttl, id, rnd, nbo;

        /* Create dynamic IPv4 subtree */
        root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_dynamic_ipv4, tvb, offset, -1, FALSE);
        dynamic_ipv4_tree = proto_item_add_subtree(root_ti, ett_pdcp_rohc_dynamic_ipv4);

        /* ToS */
        tos = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(dynamic_ipv4_tree, hf_pdcp_lte_rohc_dynamic_ipv4_tos, tvb, offset, 1, FALSE);
        offset++;

        /* TTL */
        ttl = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(dynamic_ipv4_tree, hf_pdcp_lte_rohc_dynamic_ipv4_ttl, tvb, offset, 1, FALSE);
        offset++;

        /* IP-ID */
        id = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(dynamic_ipv4_tree, hf_pdcp_lte_rohc_dynamic_ipv4_id, tvb, offset, 1, FALSE);
        offset++;

        /* IP flags */
        rnd = (tvb_get_guint8(tvb, offset) & 0x40) >> 6;
        nbo = (tvb_get_guint8(tvb, offset) & 0x20) >> 5;
        proto_tree_add_item(dynamic_ipv4_tree, hf_pdcp_lte_rohc_dynamic_ipv4_df, tvb, offset, 1, FALSE);
        proto_tree_add_item(dynamic_ipv4_tree, hf_pdcp_lte_rohc_dynamic_ipv4_rnd, tvb, offset, 1, FALSE);
        proto_tree_add_item(dynamic_ipv4_tree, hf_pdcp_lte_rohc_dynamic_ipv4_nbo, tvb, offset, 1, FALSE);

        /* TODO: general extension header list... */
        offset += 3;

        /* Set proper length for subtree */
        proto_item_set_len(root_ti, offset-tree_start_offset);

        /* Add summary to root item */
        proto_item_append_text(root_ti, " (ToS=%u, TTL=%u, ID=%u, RND=%u, NBO=%u)",
                               tos, ttl, id, rnd, nbo);
    }

    /* UDP dynamic */
    if ((p_pdcp_info->profile == 1) ||
        (p_pdcp_info->profile == 2)) {

        proto_tree *dynamic_udp_tree;
        proto_item *root_ti;
        unsigned short checksum;

        /* Create dynamic UDP subtree */
        root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_dynamic_udp, tvb, offset, 2, FALSE);
        dynamic_udp_tree = proto_item_add_subtree(root_ti, ett_pdcp_rohc_dynamic_udp);

        /* 16-bit checksum */
        checksum = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(dynamic_udp_tree, hf_pdcp_lte_rohc_dynamic_udp_checksum, tvb, offset, 2, FALSE);
        offset +=2;

        if (p_pdcp_info->profile == 2) {
            guint16 seqnum;

            seqnum = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(dynamic_udp_tree, hf_pdcp_lte_rohc_dynamic_udp_seqnum, tvb, offset, 2, FALSE);
            offset +=2;

            /* Add summary to root item */
            proto_item_append_text(root_ti, " (checksum = %04x, seqnum = %u)", checksum, seqnum);
        }
        else {
            /* Add summary to root item */
            proto_item_append_text(root_ti, " (checksum = %04x)", checksum);
        }
    }

    /* RTP dynamic */
    if (p_pdcp_info->profile == 1) {
        proto_tree *dynamic_rtp_tree;
        proto_item *root_ti;
        int tree_start_offset = offset;
        guint8     rx;
        guint8     contributing_csrcs;
        guint16    sequence_number;
        guint32    timestamp;
        guint8     tis=0, tss=0;
        guint64    ts_stride=0;

        /* Create dynamic RTP subtree */
        root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_dynamic_rtp, tvb, offset, -1, FALSE);
        dynamic_rtp_tree = proto_item_add_subtree(root_ti, ett_pdcp_rohc_dynamic_rtp);

        /* TODO: */
        /* V | P | RX | CC */
        rx = tvb_get_guint8(tvb, offset) & 0x10;
        proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_rx, tvb, offset, 1, FALSE);
        contributing_csrcs = tvb_get_guint8(tvb, offset) & 0x0f;
        proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_cc, tvb, offset, 1, FALSE);
        offset += 1;

        /* TODO: */
        /* M | PT */
        offset += 1;

        /* Sequence number */
        sequence_number = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_seqnum, tvb, offset, 2, FALSE);
        offset += 2;

        /* Timestamp (4 octets) */
        timestamp = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_timestamp, tvb, offset, 4, FALSE);
        offset += 4;

        /* TODO: CSRC list */
        /*offset += (4 * contributing_csrcs); */
        offset++;

        /* TODO: Reserved | X | Mode | TIS | TIS */
        if (rx) {
            guint8 this_byte = tvb_get_guint8(tvb, offset);
            proto_item *reserved_ti = proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_reserved3,
                                                          tvb, offset, 1, FALSE);

            /* Check reserved bits are 0 */
            if ((this_byte & 0xe0) != 0) {
                expert_add_info_format(pinfo, reserved_ti, PI_MALFORMED, PI_ERROR,
                                       "Reserved bits have value 0x%x - should be 0x0",
                                       (this_byte & 0xe0));
            }
            proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_x, tvb, offset, 1, FALSE);
            proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_mode, tvb, offset, 1, FALSE);
            tss = (this_byte & 0x02);
            proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_tss, tvb, offset, 1, FALSE);
            tis = (this_byte & 0x01);
            proto_tree_add_item(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_tis, tvb, offset, 1, FALSE);
            offset++;
        }

        /* TODO: the length of these fields can be learned by looked at the leading bits, see
           RFC 3095, "4.5.6.  Self-describing variable-length values" */
        /* TODO: TS-Stride (1-4 bytes) */
        if (tis) {
            /* Assume encoded in two bytes for now... */
            proto_tree_add_bits_ret_val(dynamic_rtp_tree, hf_pdcp_lte_rohc_dynamic_rtp_ts_stride,
                                        tvb, offset*8 + 2, 14, &ts_stride, FALSE);
            offset += 2;
        }

        /* TODO: Time-stride (1-4 bytes) */
        if (tss) {
        }

        /* Set proper length for subtree */
        proto_item_set_len(root_ti, offset-tree_start_offset);

        /* Add summary to root item */
        proto_item_append_text(root_ti, " (seqnum = %u, timestamp = %u)",
                               sequence_number, timestamp);
    }

    return offset;
}



static int dissect_pdcp_irdyn_packet(proto_tree *tree,
                                     proto_item *root_item,
                                     tvbuff_t *tvb,
                                     int offset,
                                     struct pdcp_lte_info *p_pdcp_info,
                                     packet_info *pinfo)
{
    col_append_str(pinfo->cinfo, COL_INFO, " IRDYN");
    proto_item_append_text(root_item, " (IRDYN)");

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* Profile */
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_profile, tvb, offset, 1, FALSE);
    offset++;

    /* 8-bit CRC */
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_ir_crc, tvb, offset, 1, FALSE);
    offset++;

    /* Dissect dynamic chain */
    offset = dissect_pdcp_dynamic_chain(tree,
                                        root_item,
                                        tvb,
                                        offset,
                                        p_pdcp_info,
                                        pinfo);
    return offset;
}


static int dissect_pdcp_ir_packet(proto_tree *tree,
                                  proto_item *root_item,
                                  tvbuff_t *tvb,
                                  int offset,
                                  struct pdcp_lte_info *p_pdcp_info,
                                  packet_info *pinfo)
{
    unsigned char dynamic_chain_present;

    col_append_str(pinfo->cinfo, COL_INFO, " IR");
    proto_item_append_text(root_item, " (IR)");

    /* Is dynamic chain present? */
    dynamic_chain_present = tvb_get_guint8(tvb, offset) & 0x1;
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_d, tvb, offset, 1, FALSE);
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* Profile */
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_profile, tvb, offset, 1, FALSE);
    offset++;

    /* 8-bit CRC */
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_ir_crc, tvb, offset, 1, FALSE);
    offset++;

    /* IPv4 static part */
    if (p_pdcp_info->rohc_ip_version == 4) {
        proto_tree *static_ipv4_tree;
        proto_item *root_ti;
        int tree_start_offset = offset;
        guint8  protocol;
        guint32 source, dest;

        /* Create static IPv4 subtree */
        root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_static_ipv4, tvb, offset, -1, FALSE);
        static_ipv4_tree = proto_item_add_subtree(root_ti, ett_pdcp_rohc_static_ipv4);

        /* IP version (must be 4) */
        proto_tree_add_item(static_ipv4_tree, hf_pdcp_lte_rohc_ip_version, tvb, offset, 1, FALSE);
        offset++;

        /* Protocol */
        protocol = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(static_ipv4_tree, hf_pdcp_lte_rohc_ip_protocol, tvb, offset, 1, FALSE);
        offset++;

        /* Source address */
        source = tvb_get_ipv4(tvb, offset);
        proto_tree_add_item(static_ipv4_tree, hf_pdcp_lte_rohc_ip_src, tvb, offset, 4, FALSE);
        offset += 4;

        /* Dest address */
        dest = tvb_get_ipv4(tvb, offset);
        proto_tree_add_item(static_ipv4_tree, hf_pdcp_lte_rohc_ip_dst, tvb, offset, 4, FALSE);
        offset += 4;

        /* Set proper length for subtree */
        proto_item_set_len(root_ti, offset-tree_start_offset);

        /* Add summary to root item */
        proto_item_append_text(root_ti, " (prot=%s: %s -> %s)",
                               val_to_str(protocol, ip_protocol_vals, "Unknown"),
                               (char*)get_hostname(source),
                               (char*)get_hostname(dest));
    }

    /* UDP static part. TODO: also check protocol from last part!? */
    if ((p_pdcp_info->profile == 1) ||
        (p_pdcp_info->profile == 2)) {

        proto_tree *static_udp_tree;
        proto_item *root_ti;
        int tree_start_offset = offset;
        unsigned short source_port, dest_port;

        /* Create static UDP subtree */
        root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_static_udp, tvb, offset, -1, FALSE);
        static_udp_tree = proto_item_add_subtree(root_ti, ett_pdcp_rohc_static_udp);

        /* Source port */
        source_port = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(static_udp_tree, hf_pdcp_lte_rohc_static_udp_src_port, tvb, offset, 2, FALSE);
        offset += 2;

        /* Dest port */
        dest_port = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(static_udp_tree, hf_pdcp_lte_rohc_static_udp_src_port, tvb, offset, 2, FALSE);
        offset += 2;

        /* Set proper length for subtree */
        proto_item_set_len(root_ti, offset-tree_start_offset);

        /* Add summary to root item */
        proto_item_append_text(root_ti, " (%u -> %u)", source_port, dest_port);
    }

    /* RTP static */
    if (p_pdcp_info->profile == 1) {
        proto_tree *static_rtp_tree;
        proto_item *root_ti;
        guint32    ssrc;

        /* Create static RTP subtree */
        root_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_static_rtp, tvb, offset, 4, FALSE);
        static_rtp_tree = proto_item_add_subtree(root_ti, ett_pdcp_rohc_static_rtp);

        /* SSRC */
        ssrc = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(static_rtp_tree, hf_pdcp_lte_rohc_static_rtp_ssrc, tvb, offset, 4, FALSE);
        offset += 4;

        /* Add summary to root item */
        proto_item_append_text(root_ti, " (SSRC=%u)", ssrc);
    }


    /* Dynamic chain */
    if (dynamic_chain_present) {
        offset = dissect_pdcp_dynamic_chain(tree,
                                            root_item,
                                            tvb,
                                            offset,
                                            p_pdcp_info,
                                            pinfo);
    }

    return offset;
}



static int dissect_pdcp_feedback_feedback1(proto_tree *tree,
                                           proto_item *item,
                                           tvbuff_t *tvb,
                                           int offset,
                                           struct pdcp_lte_info *p_pdcp_info _U_,
                                           packet_info *pinfo)
{
    guint8 sn;

    proto_item_append_text(item, " (type 1)");

    /* TODO: profile-specific */
    sn = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_feedback_feedback1, tvb, offset, 1, FALSE);
    offset++;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);

    return offset;
}

/* Includes Large-CID, if present */
static int dissect_pdcp_feedback_feedback2(proto_tree *tree,
                                           proto_item *item,
                                           tvbuff_t *tvb,
                                           int offset,
                                           int size,
                                           struct pdcp_lte_info *p_pdcp_info,
                                           packet_info *pinfo)
{
    proto_item *ti;
    guint8  ack_type;
    guint8  mode;
    guint8  first_octet;
    guint16 sn;
    const char * full_mode_name;
    int size_remaining;

    proto_item_append_text(item, " (type 2)");

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* Feedback2 hidden filter */
    ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_feedback_feedback2, tvb, offset, -1, FALSE);
    PROTO_ITEM_SET_HIDDEN(ti);

    /* Ack-type */
    first_octet = tvb_get_guint8(tvb, offset);
    ack_type = (first_octet & 0xc0) >> 6;
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_feedback_ack_type, tvb, offset, 1, FALSE);

    /* TODO: expert info on NACK? */

    /* Mode */
    mode = (first_octet & 0x30) >> 4;
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_feedback_mode, tvb, offset, 1, FALSE);

    /* Show ACK-TYPE(Mode) in info column */
    full_mode_name = val_to_str(mode, rohc_mode_vals, "Error");

    col_append_fstr(pinfo->cinfo, COL_INFO, " %s(%c)",
                    val_to_str(ack_type, feedback_ack_vals, "Unknown"),
                    full_mode_name[0]);

    /* 11 bits of SN */
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_feedback_sn, tvb, offset, 2, FALSE);
    sn = tvb_get_ntohs(tvb, offset) & 0x7ff;
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);

    /* Loop over any remaining feedback options */
    size_remaining = size - 2;

    while (tvb_length_remaining(tvb, offset) > 0) {
        guint8 option = (tvb_get_guint8(tvb, offset) & 0xf0) >> 4;
        guint8 length = tvb_get_guint8(tvb, offset) & 0x0f;
        guint8 one_byte_value;

        /* Preference setting controls showing option and lengths */
        if (global_pdcp_show_feedback_option_tag_length) {
            proto_tree_add_item(tree, hf_pdcp_lte_rohc_feedback_option, tvb, offset, 1, FALSE);
            proto_tree_add_item(tree, hf_pdcp_lte_rohc_feedback_length, tvb, offset, 1, FALSE);
        }
        offset++;
        size_remaining--;

        /* TODO: switch including missing option types */
        switch (option) {
            case 1:
                /* CRC */
                one_byte_value = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_pdcp_lte_rohc_feedback_crc, tvb, offset, 1, FALSE);
                col_append_fstr(pinfo->cinfo, COL_INFO, " CRC=%u ", one_byte_value);
                break;
            case 2:
                /* REJECT: TODO */
                break;
            case 3:
                /* SN-Not-Valid: TODO */
                break;
            case 4:
                /* SN */
                one_byte_value = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_pdcp_lte_rohc_feedback_option_sn, tvb, offset, 1, FALSE);
                col_append_fstr(pinfo->cinfo, COL_INFO, " SN=%u ", one_byte_value);
                break;
            case 5:
                /* Clock */
                one_byte_value = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_pdcp_lte_rohc_feedback_option_clock, tvb, offset, 1, FALSE);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Clock=%u ", one_byte_value);
                break;
            case 6:
                /* Jitter: TODO */
                break;
            case 7:
                /* Loss: TODO */
                break;

            default:
                /* TODO: unhandled option */
                break;
        }

        /* Skip length */
        offset += length;
        size_remaining -= length;
    }

    return offset;
}


/* Dissect a feedback packet.
   Return following offset */
static int dissect_pdcp_feedback_packet(proto_tree *tree,
                                        proto_item *root_item,
                                        tvbuff_t *tvb,
                                        int offset,
                                        struct pdcp_lte_info *p_pdcp_info,
                                        packet_info *pinfo)
{
    guint8 code;
    guint8 size;
    proto_item *ti;
    proto_item *feedback_ti;
    proto_tree *feedback_tree;

    col_append_str(pinfo->cinfo, COL_INFO, " Feedback");
    proto_item_append_text(root_item, " (Feedback)");

    /* Create feedback tree root */
    feedback_ti = proto_tree_add_item(tree, hf_pdcp_lte_rohc_feedback, tvb, offset, -1, FALSE);
    feedback_tree = proto_item_add_subtree(feedback_ti, ett_pdcp_packet);

    /* Code */
    code = tvb_get_guint8(tvb, offset) & 0x07;
    ti = proto_tree_add_item(feedback_tree, hf_pdcp_lte_rohc_feedback_code, tvb, offset, 1, FALSE);
    offset++;

    /* Optional length field */
    if (code != 0) {
        proto_item_append_text(ti, " (length of feedback data)");
        size = code;
    }
    else {
        proto_tree_add_item(feedback_tree, hf_pdcp_lte_rohc_feedback_size, tvb, offset, 1, FALSE);
        size = tvb_get_guint8(tvb, offset);
        offset++;
    }

    /* Work out feedback type */
    if ((p_pdcp_info->cid_inclusion_info == CID_IN_ROHC_PACKET) &&
         !p_pdcp_info->large_cid_present) {

        /* Small CID */
        if (size == 1) {
            offset = dissect_pdcp_feedback_feedback1(feedback_tree, feedback_ti, tvb, offset, p_pdcp_info, pinfo);
        }
        else if ((size > 1) && ((tvb_get_guint8(tvb, offset) & 0xc0) == 0xc0)) {
            /* Add-CID here! */
            proto_tree_add_item(feedback_tree, hf_pdcp_lte_rohc_add_cid, tvb, offset, 1, FALSE);
            offset++;

            if (size == 2) {
                offset = dissect_pdcp_feedback_feedback1(feedback_tree, feedback_ti, tvb, offset, p_pdcp_info, pinfo);
            }
            else {
                offset = dissect_pdcp_feedback_feedback2(feedback_tree, feedback_ti, tvb, offset, size, p_pdcp_info, pinfo);
            }
        }
        else {
            offset = dissect_pdcp_feedback_feedback2(feedback_tree, feedback_ti, tvb, offset, size, p_pdcp_info, pinfo);
        }
    }
    else {
        offset = dissect_pdcp_feedback_feedback2(feedback_tree, feedback_ti, tvb, offset, size, p_pdcp_info, pinfo);
    }

    return offset;
}


/* Dissect R-0 packet.
   Return following offset */
static int dissect_pdcp_r_0_packet(proto_tree *tree,
                                   proto_item *root_item,
                                   tvbuff_t *tvb,
                                   int offset,
                                   struct pdcp_lte_info *p_pdcp_info,
                                   packet_info *pinfo)
{
    guint8 sn;

    col_append_str(pinfo->cinfo, COL_INFO, " R-0");
    proto_item_append_text(root_item, " (R-0)");

    /* 6 bits of sn */
    sn = tvb_get_guint8(tvb, offset) & 0x3f;
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_r0_sn, tvb, offset, 1, FALSE);
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);

    return offset;
}


/* Dissect R-0-CRC packet.
   Return following offset */
static int dissect_pdcp_r_0_crc_packet(proto_tree *tree,
                                       proto_item *root_item,
                                       tvbuff_t *tvb,
                                       int offset,
                                       struct pdcp_lte_info *p_pdcp_info,
                                       packet_info *pinfo)
{
    guint8 sn;

    col_append_str(pinfo->cinfo, COL_INFO, " R-0-CRC");
    proto_item_append_text(root_item, " (R-0-CRC)");

    proto_tree_add_item(tree, hf_pdcp_lte_rohc_r_0_crc, tvb, offset, -1, FALSE);

    /* 7 bits of sn */
    /* TODO: wrong!  Large-cid may be in-between!!!! */
    sn = tvb_get_guint8(tvb, offset) & 0x3f;
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* Conclude SN */
    sn = (sn << 1) + ((tvb_get_guint8(tvb, offset) & 0x80) >> 7);
    proto_tree_add_uint(tree, hf_pdcp_lte_rohc_r0_crc_sn, tvb, offset, 1, sn);

    /* 7 bit CRC */
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_r0_crc_crc, tvb, offset, 1, FALSE);
    offset++;

    /* Show SN in info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);

    return offset;
}


/* Dissect UO-0-CRC packet.
   Return following offset */
static int dissect_pdcp_uo_0_packet(proto_tree *tree,
                                    proto_item *root_item,
                                    tvbuff_t *tvb,
                                    int offset,
                                    struct pdcp_lte_info *p_pdcp_info,
                                    packet_info *pinfo)
{
    guint8 sn;

    col_append_str(pinfo->cinfo, COL_INFO, " U0-0");
    proto_item_append_text(root_item, " (UO-0)");

    /* SN */
    sn = (tvb_get_guint8(tvb, offset) & 0x78) >> 3;
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_uo0_sn, tvb, offset, 1, FALSE);

    /* CRC (3 bits) */
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_uo0_crc, tvb, offset, 1, FALSE);

    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* Show SN in info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);

    return offset;
}


/* Dissect R-1 packet.
   Return following offset */
static int  dissect_pdcp_r_1_packet(proto_tree *tree,
                                    proto_item *root_item,
                                    tvbuff_t *tvb,
                                    int offset,
                                    struct pdcp_lte_info *p_pdcp_info,
                                    packet_info *pinfo)
{
    col_append_str(pinfo->cinfo, COL_INFO, " R-1");
    proto_item_append_text(root_item, " (R-1)");

    /* TODO: octet before large-cid */
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    if (p_pdcp_info->profile == 1) {
        /* TODO: */
    }
    else if (p_pdcp_info->profile == 2) {
        /* TODO: */
    }

    return offset;
}


/* Dissect R-1-TS or R-1-ID packet.
   Return following offset */
static int  dissect_pdcp_r_1_ts_or_id_packet(proto_tree *tree,
                                             proto_item *root_item,
                                             tvbuff_t *tvb,
                                             int offset,
                                             struct pdcp_lte_info *p_pdcp_info,
                                             packet_info *pinfo)
{
    unsigned char T;

    /* TODO: octet before large-cid */
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* T determines frame type */
    T = tvb_get_guint8(tvb, ++offset) >> 7;
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_type1_t, tvb, offset, 1, FALSE);
    if (T) {
        col_append_str(pinfo->cinfo, COL_INFO, " R-1-TS");
        proto_item_append_text(root_item, " (R-1-TS)");
    }
    else {
        col_append_str(pinfo->cinfo, COL_INFO, " R-1-ID");
        proto_item_append_text(root_item, " (R-1-ID)");
    }

    if (p_pdcp_info->profile == 1) {
        /* TODO: */
    }
    else if (p_pdcp_info->profile == 2) {
        /* TODO: */
    }

    return offset;
}


/* Dissect UO-1 packet.
   Return following offset */
static int  dissect_pdcp_uo_1_packet(proto_tree *tree,
                                     proto_item *root_item,
                                     tvbuff_t *tvb,
                                     int offset,
                                     struct pdcp_lte_info *p_pdcp_info,
                                     packet_info *pinfo)
{
    col_append_str(pinfo->cinfo, COL_INFO, " UO-1");
    proto_item_append_text(root_item, " (UO-1)");

    /* TODO: octet before large-cid */
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    if (p_pdcp_info->profile == 1) {
        /* TODO: */
    }
    else if (p_pdcp_info->profile == 2) {
        /* TODO: */
    }

    return offset;
}


/* Dissect UO-1-TS or UO-1-ID packet.
   Return following offset */
static int  dissect_pdcp_uo_1_ts_or_id_packet(proto_tree *tree,
                                              proto_item *root_item,
                                              tvbuff_t *tvb,
                                              int offset,
                                              struct pdcp_lte_info *p_pdcp_info,
                                              packet_info *pinfo)
{
    unsigned char T;

    /* TODO: octet before large-cid */
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* T determines frame type */
    T = tvb_get_guint8(tvb, ++offset) >> 5;
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_type0_t, tvb, offset, 1, FALSE);
    if (T) {
        col_append_str(pinfo->cinfo, COL_INFO, " UO-1-TS");
        proto_item_append_text(root_item, " (UO-1-TS)");
    }
    else {
        col_append_str(pinfo->cinfo, COL_INFO, " UO-1-ID");
        proto_item_append_text(root_item, " (UO-1-ID)");
    }

    if (p_pdcp_info->profile == 1) {
        /* TODO: */
    }
    else if (p_pdcp_info->profile == 2) {
        /* TODO: */
    }

    return offset;
}





/* Dissect UOR-2 packet.
   Return following offset */
static int  dissect_pdcp_uor_2_packet(proto_tree *tree,
                                      proto_item *root_item,
                                      tvbuff_t *tvb,
                                      int offset,
                                      struct pdcp_lte_info *p_pdcp_info,
                                      packet_info *pinfo)
{
    guint8 ts;

    col_append_str(pinfo->cinfo, COL_INFO, " U0R-2");
    proto_item_append_text(root_item, " (UOR-2)");

    /* TS straddles CID */
    ts = tvb_get_guint8(tvb, offset) & 0x1f;
    offset++;

    /* Large CID */
    if (p_pdcp_info->large_cid_present) {
        offset = dissect_large_cid(tree, tvb, offset);
    }

    /* Last bit of TS is here */
    ts = (ts << 1) | (tvb_get_guint8(tvb, offset) >> 7);
    proto_tree_add_uint(tree, hf_pdcp_lte_rohc_ts, tvb, offset, 1, ts);

    if (p_pdcp_info->profile == 1) {
        /* M */
        proto_tree_add_item(tree, hf_pdcp_lte_rohc_m, tvb, offset, 1, FALSE);

        /* SN (6 bits) */
        proto_tree_add_item(tree, hf_pdcp_lte_rohc_uor2_sn, tvb, offset, 1, FALSE);
        offset++;

        /* X (one bit) */
        proto_tree_add_item(tree, hf_pdcp_lte_rohc_uor2_x, tvb, offset, 1, FALSE);

        /* TODO: CRC */
        offset++;
    }
    else if (p_pdcp_info->profile == 2) {
        /* TODO: */
        offset += 2;
    }

    return offset;
}


/* Dissect UOR-2-TS or UOR-2-ID packet.
   Return following offset */
static int  dissect_pdcp_uor_2_ts_or_id_packet(proto_tree *tree,
                                               proto_item *root_item,
                                               tvbuff_t *tvb,
                                               int offset,
                                               struct pdcp_lte_info *p_pdcp_info,
                                               packet_info *pinfo)
{
    unsigned char T;

    /* TODO: octet before large-cid.
       TODO: can't decode this until we know what T is,
             but T is after large-cid... */
    offset++;

    /* T determines frame type */
    T = tvb_get_guint8(tvb, offset) >> 7;
    proto_tree_add_item(tree, hf_pdcp_lte_rohc_type2_t, tvb, offset, 1, FALSE);

    if (T) {
        col_append_str(pinfo->cinfo, COL_INFO, " U0R-2-TS");
        proto_item_append_text(root_item, " (UOR-2-TS)");
    }
    else {
        col_append_str(pinfo->cinfo, COL_INFO, " U0R-2-ID");
        proto_item_append_text(root_item, " (UOR-2-ID)");
    }


    if (T) {
        /* UOR-2-TS format */

        /* TS */
        guint8 ts = tvb_get_guint8(tvb, offset) & 0x1f;
        proto_tree_add_uint(tree, hf_pdcp_lte_rohc_ts, tvb, offset, 1, ts);
        offset++;

        /* Large CID */
        if (p_pdcp_info->large_cid_present) {
            offset = dissect_large_cid(tree, tvb, offset);
        }

        /* m */
        proto_tree_add_item(tree, hf_pdcp_lte_rohc_m, tvb, offset, 1, ts);

        /* TODO: */
    }
    else {
        /* TODO: UOR-2-ID format */

        /* IP-ID */

        /* Large CID */
        if (p_pdcp_info->large_cid_present) {
            offset = dissect_large_cid(tree, tvb, offset);
        }

        /* TODO: */
    }

    if (p_pdcp_info->profile == 1) {
        /* TODO: */
    }
    else if (p_pdcp_info->profile == 2) {
        /* TODO: */
    }

    return offset;
}




/* Show in the tree the config info attached to this frame, as generated fields */
static void show_pdcp_config(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
                             pdcp_lte_info *p_pdcp_info)
{
    proto_item *ti;
    proto_tree *configuration_tree;
    proto_item *configuration_ti = proto_tree_add_item(tree,
                                                       hf_pdcp_lte_configuration,
                                                       tvb, 0, 0, FALSE);
    configuration_tree = proto_item_add_subtree(configuration_ti, ett_pdcp_configuration);

    /* Direction */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_direction, tvb, 0, 0,
                             p_pdcp_info->direction);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Plane */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_plane, tvb, 0, 0,
                             p_pdcp_info->plane);
    PROTO_ITEM_SET_GENERATED(ti);

    /* UEId */
    if (p_pdcp_info->ueid != 0) {
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_ueid, tvb, 0, 0,
                                 p_pdcp_info->ueid);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* Channel type */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_channel_type, tvb, 0, 0,
                             p_pdcp_info->channelType);
    PROTO_ITEM_SET_GENERATED(ti);
    if (p_pdcp_info->channelId != 0) {
        /* Channel type */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_channel_id, tvb, 0, 0,
                                 p_pdcp_info->channelId);
        PROTO_ITEM_SET_GENERATED(ti);
    }


    /* User-plane-specific fields */
    if (p_pdcp_info->plane == USER_PLANE) {

        /* No Header PDU */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_no_header_pdu, tvb, 0, 0,
                                 p_pdcp_info->no_header_pdu);
        PROTO_ITEM_SET_GENERATED(ti);

        if (!p_pdcp_info->no_header_pdu) {

            /* Seqnum length */
            ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_seqnum_length, tvb, 0, 0,
                                     p_pdcp_info->seqnum_length);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    /* ROHC compression */
    ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_lte_rohc_compression, tvb, 0, 0,
                                p_pdcp_info->rohc_compression);
    PROTO_ITEM_SET_GENERATED(ti);

    /* ROHC-specific settings */
    if (p_pdcp_info->rohc_compression) {

        /* Show ROHC mode */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_mode, tvb, 0, 0,
                                 p_pdcp_info->mode);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Show RND */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_rnd, tvb, 0, 0,
                                 p_pdcp_info->rnd);
        PROTO_ITEM_SET_GENERATED(ti);

        /* UDP Checksum */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_udp_checksum_present, tvb, 0, 0,
                                 p_pdcp_info->udp_checkum_present);
        PROTO_ITEM_SET_GENERATED(ti);

        /* ROHC profile */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_profile, tvb, 0, 0,
                                 p_pdcp_info->profile);
        PROTO_ITEM_SET_GENERATED(ti);

        /* CID Inclusion Info */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_cid_inclusion_info, tvb, 0, 0,
                                 p_pdcp_info->cid_inclusion_info);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Large CID */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_large_cid_present, tvb, 0, 0,
                                 p_pdcp_info->large_cid_present);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* Append summary to configuration root */
    proto_item_append_text(configuration_ti, "(direction=%s, plane=%s",
                           val_to_str(p_pdcp_info->direction, direction_vals, "Unknown"),
                           val_to_str(p_pdcp_info->plane, pdcp_plane_vals, "Unknown"));

    if (p_pdcp_info->rohc_compression) {
        const char *mode = val_to_str(p_pdcp_info->mode, rohc_mode_vals, "Error");
        proto_item_append_text(configuration_ti, ", mode=%c, profile=%s",
                               mode[0],
                               val_to_str(p_pdcp_info->profile, rohc_profile_vals, "Unknown"));
    }
    proto_item_append_text(configuration_ti, ")");
    PROTO_ITEM_SET_GENERATED(configuration_ti);

    /* Show plane in info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s: ",
                    val_to_str(p_pdcp_info->plane, pdcp_plane_vals, "Unknown"));

}


/* Look for an RRC dissector for signalling data (using channel type and direction) */
static dissector_handle_t lookup_rrc_dissector_handle(struct pdcp_lte_info  *p_pdcp_info)
{
    dissector_handle_t rrc_handle = 0;

    switch (p_pdcp_info->channelType)
    {
        case Channel_CCCH:
            if (p_pdcp_info->direction == DIRECTION_UPLINK) {
                rrc_handle = find_dissector("lte_rrc.ul_ccch");
            }
            else {
                rrc_handle = find_dissector("lte_rrc.dl_ccch");
            }
            break;
        case Channel_PCCH:
            rrc_handle = find_dissector("lte-rrc.pcch");
            break;
        case Channel_BCCH:
            switch (p_pdcp_info->BCCHTransport) {
                case BCH_TRANSPORT:
                    rrc_handle = find_dissector("lte-rrc.bcch.bch");
                    break;
                case DLSCH_TRANSPORT:
                    rrc_handle = find_dissector("lte-rrc.bcch.dl.sch");
                    break;
            }
            break;
        case Channel_DCCH:
            if (p_pdcp_info->direction == DIRECTION_UPLINK) {
                rrc_handle = find_dissector("lte_rrc.ul_dcch");
            }
            else {
                rrc_handle = find_dissector("lte_rrc.dl_dcch");
            }
            break;


        default:
            break;
    }

    return rrc_handle;
}


/* Forwad declarations */
static void dissect_pdcp_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Heuristic dissection */
static gboolean global_pdcp_lte_heur = FALSE;

/* Heuristic dissector looks for supported framing protocol (see wiki page)  */
static gboolean dissect_pdcp_lte_heur(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree)
{
    gint                 offset = 0;
    struct pdcp_lte_info *p_pdcp_lte_info;
    tvbuff_t             *pdcp_tvb;
    guint8               tag = 0;
    gboolean             infoAlreadySet = FALSE;
    gboolean             seqnumLengthTagPresent = FALSE;

    /* This is a heuristic dissector, which means we get all the UDP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */

    if (!global_pdcp_lte_heur) {
        return FALSE;
    }

    /* Do this again on re-dissection to re-discover offset of actual PDU */

    /* Needs to be at least as long as:
       - the signature string
       - fixed header bytes
       - tag for data
       - at least one byte of PDCP PDU payload */
    if ((size_t)tvb_length_remaining(tvb, offset) < (strlen(PDCP_LTE_START_STRING)+3+2)) {
        return FALSE;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, PDCP_LTE_START_STRING, strlen(PDCP_LTE_START_STRING)) != 0) {
        return FALSE;
    }
    offset += (gint)strlen(PDCP_LTE_START_STRING);


    /* If redissecting, use previous info struct (if available) */
    p_pdcp_lte_info = p_get_proto_data(pinfo->fd, proto_pdcp_lte);
    if (p_pdcp_lte_info == NULL) {
        /* Allocate new info struct for this frame */
        p_pdcp_lte_info = se_alloc0(sizeof(struct pdcp_lte_info));
        infoAlreadySet = FALSE;
    }
    else {
        infoAlreadySet = TRUE;
    }


    /* Read fixed fields */
    p_pdcp_lte_info->no_header_pdu = tvb_get_guint8(tvb, offset++);
    p_pdcp_lte_info->plane = tvb_get_guint8(tvb, offset++);
    p_pdcp_lte_info->rohc_compression = tvb_get_guint8(tvb, offset++);

    /* Read optional fields */
    while (tag != PDCP_LTE_PAYLOAD_TAG) {
        /* Process next tag */
        tag = tvb_get_guint8(tvb, offset++);
        switch (tag) {
            case PDCP_LTE_SEQNUM_LENGTH_TAG:
                p_pdcp_lte_info->seqnum_length = tvb_get_guint8(tvb, offset);
                offset++;
                seqnumLengthTagPresent = TRUE;
                break;
            case PDCP_LTE_DIRECTION_TAG:
                p_pdcp_lte_info->direction = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_LOG_CHAN_TYPE_TAG:
                p_pdcp_lte_info->channelType = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_BCCH_TRANSPORT_TYPE_TAG:
                p_pdcp_lte_info->BCCHTransport = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_IP_VERSION_TAG:
                p_pdcp_lte_info->rohc_ip_version = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case PDCP_LTE_ROHC_CID_INC_INFO_TAG:
                p_pdcp_lte_info->cid_inclusion_info = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_LARGE_CID_PRES_TAG:
                p_pdcp_lte_info->large_cid_present = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_MODE_TAG:
                p_pdcp_lte_info->mode = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_RND_TAG:
                p_pdcp_lte_info->rnd = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_UDP_CHECKSUM_PRES_TAG:
                p_pdcp_lte_info->udp_checkum_present = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_PROFILE_TAG:
                p_pdcp_lte_info->profile = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;

            case PDCP_LTE_PAYLOAD_TAG:
                /* Have reached data, so get out of loop */
                continue;

            default:
                /* It must be a recognised tag */
                return FALSE;
        }
    }

    if ((p_pdcp_lte_info->plane == USER_PLANE) && (seqnumLengthTagPresent == FALSE)) {
        /* Conditional field is not present */
        return FALSE;
    }

    if (!infoAlreadySet) {
        /* Store info in packet */
        p_add_proto_data(pinfo->fd, proto_pdcp_lte, p_pdcp_lte_info);
    }

    /**************************************/
    /* OK, now dissect as PDCP LTE        */

    /* Create tvb that starts at actual PDCP PDU */
    pdcp_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb)-offset);
    dissect_pdcp_lte(pdcp_tvb, pinfo, tree);
    return TRUE;
}


/******************************/
/* Main dissection function.  */
static void dissect_pdcp_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    const char         *mode;
    proto_tree         *pdcp_tree = NULL;
    proto_item         *root_ti = NULL;
    proto_tree         *rohc_tree = NULL;
    proto_item         *rohc_ti = NULL;
    gint               offset = 0;
    gint               rohc_offset;
    struct pdcp_lte_info  *p_pdcp_info;
    guint8             base_header_byte;
    gboolean           udp_checksum_needed = TRUE;
    gboolean           ip_id_needed = TRUE;

    /* Append this protocol name rather than replace. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PDCP-LTE");

    /* Create pdcp tree. */
    if (tree) {
        root_ti = proto_tree_add_item(tree, proto_pdcp_lte, tvb, offset, -1, FALSE);
        pdcp_tree = proto_item_add_subtree(root_ti, ett_pdcp);
    }


    /* Look for attached packet info! */
    p_pdcp_info = p_get_proto_data(pinfo->fd, proto_pdcp_lte);
    /* Can't dissect anything without it... */
    if (p_pdcp_info == NULL) {
        return;
    }


    /* Set mode string */
    mode = val_to_str(p_pdcp_info->mode, rohc_mode_vals, "Error");

    /* Show configuration (attached packet) info in tree */
    if (pdcp_tree) {
        show_pdcp_config(pinfo, tvb, pdcp_tree, p_pdcp_info);
    }

    /* Show ROHC mode */
    if (p_pdcp_info->rohc_compression) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (mode=%c)", mode[0]);
    }


    /* Handle PDCP header (if present) */
    if (!p_pdcp_info->no_header_pdu) {

        /* TODO: shouldn't need to initialise this one!! */
        guint16  seqnum = 0;
        gboolean seqnum_set = FALSE;

        /*****************************/
        /* Signalling plane messages */
        if (p_pdcp_info->plane == SIGNALING_PLANE) {
            guint32 mac;
            guint32 data_length;

            /* 5-bit sequence number */
            seqnum = tvb_get_guint8(tvb, offset) & 0x1f;
            seqnum_set = TRUE;
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_5, tvb, offset, 1, FALSE);
            write_pdu_label_and_info(root_ti, pinfo, " sn=%-2u ", seqnum);
            offset++;

            /* RRC data is all but last 4 bytes.
               Call lte-rrc dissector (according to direction and channel type) */
            if (global_pdcp_dissect_signalling_plane_as_rrc) {
                /* Get appropriate dissector handle */
                dissector_handle_t rrc_handle = lookup_rrc_dissector_handle(p_pdcp_info);

                if (rrc_handle != 0) {
                    /* Call RRC dissector if have one */
                    tvbuff_t *payload_tvb = tvb_new_subset(tvb, offset,
                                                           tvb_length_remaining(tvb, offset) - 4,
                                                           tvb_length_remaining(tvb, offset) - 4);
                    call_dissector_only(rrc_handle, payload_tvb, pinfo, pdcp_tree);
                }
                else {
                     /* Just show data */
                        proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, tvb, offset,
                                            tvb_length_remaining(tvb, offset) - 4, FALSE);
                }
            }
            else {
                /* Just show as unparsed data */
                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, tvb, offset,
                                    tvb_length_remaining(tvb, offset) - 4, FALSE);
            }

            data_length = tvb_length_remaining(tvb, offset) - 4;
            offset += data_length;

            /* Last 4 bytes are MAC */
            mac = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_mac, tvb, offset, 4, FALSE);
            offset += 4;

            col_append_fstr(pinfo->cinfo, COL_INFO, " MAC=0x%08x (%u bytes data)",
                            mac, data_length);

        }
        else if (p_pdcp_info->plane == USER_PLANE) {

            /**********************************/
            /* User-plane messages            */
            gboolean pdu_type = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;

            /* Data/Control flag */
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_data_control, tvb, offset, 1, FALSE);

            if (pdu_type == 1) {
                /*****************************/
                /* Use-plane Data            */

                /* Number of sequence number bits depends upon config */
                if (p_pdcp_info->seqnum_length == PDCP_SN_LENGTH_7_BITS) {
                    seqnum = tvb_get_guint8(tvb, offset) & 0x7f;
                    seqnum_set = TRUE;
                    proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_7, tvb, offset, 1, FALSE);
                    offset++;
                }
                else if (p_pdcp_info->seqnum_length == PDCP_SN_LENGTH_12_BITS) {
                    proto_item *ti;
                    guint8 reserved_value;

                    /* 3 reserved bits */
                    ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_reserved3, tvb, offset, 1, FALSE);
                    reserved_value = (tvb_get_guint8(tvb, offset) & 0x70) >> 4;

                    /* Complain if not 0 */
                    if (reserved_value != 0) {
                        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                               "Reserved bits have value 0x%x - should be 0x0",
                                               reserved_value);
                    }

                    /* 12-bit sequence number */
                    seqnum = tvb_get_ntohs(tvb, offset) & 0x0fff;
                    seqnum_set = TRUE;
                    proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_12, tvb, offset, 2, FALSE);
                    offset += 2;
                }
                else {
                    /* Not a recognised data format!!!!! */
                    return;
                }

                write_pdu_label_and_info(root_ti, pinfo, " (SN=%u)", seqnum);
            }
            else {
                /*******************************/
                /* User-plane Control messages */
                guint8 control_pdu_type = (tvb_get_guint8(tvb, offset) & 0x70) >> 4;
                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_control_pdu_type, tvb, offset, 1, FALSE);

                switch (control_pdu_type) {
                    case 0:    /* PDCP status report */
                        {
                            guint16 fms;
                            guint   not_received = 0;
                            guint   sn;
                            proto_tree *bitmap_tree;
                            proto_item *bitmap_ti = NULL;

                            /* First-Missing-Sequence SN */
                            fms = tvb_get_ntohs(tvb, offset) & 0x0fff;
                            sn = (fms + 1) % 4096;
                            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_fms, tvb,
                                                offset, 2, FALSE);
                            offset += 2;

                            /* Bitmap tree */
                            if (tvb_length_remaining(tvb, offset) > 0) {
                                bitmap_ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_bitmap, tvb,
                                                                offset, -1, FALSE);
                                bitmap_tree = proto_item_add_subtree(bitmap_ti, ett_pdcp_rohc_report_bitmap);


                                /* For each byte... */
                                for ( ; tvb_length_remaining(tvb, offset); offset++) {
                                    guint bit_offset = 0;
                                    /* .. look for error (0) in each bit */
                                    for ( ; bit_offset < 8; bit_offset++) {
                                        if ((tvb_get_guint8(tvb, offset) >> (7-bit_offset) & 0x1) == 0) {
                                            proto_tree_add_boolean_format_value(bitmap_tree, hf_pdcp_lte_bitmap_not_received, tvb, offset, 1, TRUE,
                                                                                " (SN=%u)", sn);
                                            not_received++;
                                        }
                                        sn = (sn + 1) % 4096;
                                    }
                                }
                            }

                            if (bitmap_ti != NULL) {
                                proto_item_append_text(bitmap_ti, " (not-received=%u)", not_received);
                            }
                            write_pdu_label_and_info(root_ti, pinfo, " Status Report (fms=%u) not-received=%u",
                                                    fms, not_received);
                        }
                        return;

                    case 1:     /* ROHC Feedback */
                        offset++;
                        break;  /* Drop-through to dissect feedback */

                    default:    /* Reserved */
                        return;
                }
            }
        }
        else {
            /* Invalid plane setting...! */
            write_pdu_label_and_info(root_ti, pinfo, " - INVALID PLANE (%u)",
                                     p_pdcp_info->plane);
            return;
        }

        /* For now, only do sequence analysis if RLC wasn't present in the frame */
        /* This can be fixed once RLC does re-assembly... */
        if (global_pdcp_check_sequence_numbers && seqnum_set &&
             (p_get_proto_data(pinfo->fd, proto_rlc_lte) == NULL)) {

            checkChannelSequenceInfo(pinfo, tvb, p_pdcp_info,
                                     (guint16)seqnum, pdcp_tree);
        }

    }
    else {
        /* Show that its a no-header PDU */
        write_pdu_label_and_info(root_ti, pinfo, " No-Header ");
    }


    /* If not compressed with ROHC, show as user-plane data */
    if (!p_pdcp_info->rohc_compression) {
        if (tvb_length_remaining(tvb, offset) > 0) {
            if (p_pdcp_info->plane == USER_PLANE) {
                if (global_pdcp_dissect_user_plane_as_ip) {
                    tvbuff_t *payload_tvb = tvb_new_subset_remaining(tvb, offset);
                    call_dissector_only(ip_handle, payload_tvb, pinfo, pdcp_tree);
                }
                else {
                    proto_tree_add_item(pdcp_tree, hf_pdcp_lte_user_plane_data, tvb, offset, -1, FALSE);
                }
            }
            else {
                if (global_pdcp_dissect_signalling_plane_as_rrc) {
                    /* Get appropriate dissector handle */
                    dissector_handle_t rrc_handle = lookup_rrc_dissector_handle(p_pdcp_info);

                    if (rrc_handle != 0) {
                        /* Call RRC dissector if have one */
                        tvbuff_t *payload_tvb = tvb_new_subset(tvb, offset,
                                                               tvb_length_remaining(tvb, offset),
                                                               tvb_length_remaining(tvb, offset));
                        call_dissector_only(rrc_handle, payload_tvb, pinfo, pdcp_tree);
                    }
                    else {
                         /* Just show data */
                         proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, tvb, offset,
                                             tvb_length_remaining(tvb, offset), FALSE);
                    }
                }
                else {
                    proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, tvb, offset, -1, FALSE);
                }
            }

            write_pdu_label_and_info(root_ti, pinfo, "(%u bytes data)",
                                     tvb_length_remaining(tvb, offset));
        }
        return;
    }


    /***************************/
    /* ROHC packets            */
    /***************************/

    col_append_fstr(pinfo->cinfo, COL_PROTOCOL, "|ROHC(%s)",
                    val_to_str(p_pdcp_info->profile, rohc_profile_vals, "Unkown"));

    /* Only attempt ROHC if configured to */
    if (!global_pdcp_dissect_rohc) {
        return;
    }

    /* Create pdcp tree. */
    if (pdcp_tree) {
        rohc_ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_rohc, tvb, offset, -1, FALSE);
        rohc_tree = proto_item_add_subtree(rohc_ti, ett_pdcp_rohc);
    }

    rohc_offset = offset;

    /* Skip any leading padding octets (11100000) */
    while (tvb_get_guint8(tvb, offset) == 0xe0) {
        offset++;
    }
    if (offset > rohc_offset) {
        proto_tree_add_item(rohc_tree, hf_pdcp_lte_rohc_padding, tvb, rohc_offset,
                            offset-rohc_offset, FALSE);
    }

    /* Add-CID octet */
    if ((p_pdcp_info->cid_inclusion_info == CID_IN_ROHC_PACKET) &&
        !p_pdcp_info->large_cid_present)
    {
        if (((tvb_get_guint8(tvb, offset) >> 4) & 0x0f) == 0x0e) {
            proto_tree_add_item(rohc_tree, hf_pdcp_lte_rohc_add_cid, tvb, offset, 1, FALSE);
            offset++;
        }
        else {
            /* Assume CID value of 0 if field absent */
            proto_item *ti = proto_tree_add_uint(rohc_tree, hf_pdcp_lte_rohc_add_cid, tvb, offset, 0, 0);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    /* Now look at first octet of base header and identify packet type */
    base_header_byte = tvb_get_guint8(tvb, offset);

    /* IR (1111110) */
    if ((base_header_byte & 0xfe) == 0xfc) {
        offset = dissect_pdcp_ir_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        udp_checksum_needed = FALSE;
        ip_id_needed = FALSE;
    }

    /* IRDYN (11111000) */
    else if (base_header_byte == 0xf8) {
        offset = dissect_pdcp_irdyn_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        udp_checksum_needed = FALSE;
        ip_id_needed = FALSE;
    }

    /* Feedback (begins with 11110) */
    else if (((base_header_byte & 0xf8) >> 3) == 0x1e) {
        offset = dissect_pdcp_feedback_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        return;
    }

    /* Packet type 0 (0) */
    else if ((base_header_byte & 0x80) == 0) {

        /* TODO: decide type based upon:
           - mode
           - 2nd bit
           - length remaining (taking into account large-cid) */

        /* R-0 begins with 00 */
        if (((base_header_byte & 0xc0) == 0) &&
             (p_pdcp_info->mode == RELIABLE_BIDIRECTIONAL)) {

            offset = dissect_pdcp_r_0_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        }

        /* R-0-CRC begins with 01 */
        else if ((((base_header_byte & 0x40) >> 6) == 1) &&
                  (p_pdcp_info->mode == RELIABLE_BIDIRECTIONAL)) {

            offset = dissect_pdcp_r_0_crc_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        }

        else {
            offset = dissect_pdcp_uo_0_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        }
    }

    /* Packet type 1 (10) */
    else if (((base_header_byte & 0xc0) >> 6) == 2) {

        switch (p_pdcp_info->mode) {

            case RELIABLE_BIDIRECTIONAL:
                 /* R-1 if !(ipv4 && rand) */
                 if (!((p_pdcp_info->rohc_ip_version == 4) &&
                      (!p_pdcp_info->rnd))) {
                    offset = dissect_pdcp_r_1_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
                    return;
                 }
                else {
                    /* Whether its R-1-ID or R-1-TS depends upon T bit */
                    dissect_pdcp_r_1_ts_or_id_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
                    return;
                }
                break;

            case UNIDIRECTIONAL:
            case OPTIMISTIC_BIDIRECTIONAL:
                 /* UO-1 if !(ipv4 && rand) */
                 if (!((p_pdcp_info->rohc_ip_version == 4) &&
                      (!p_pdcp_info->rnd))) {

                    dissect_pdcp_uo_1_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
                 } else {
                    /* Whether its UO-1-ID or UO-1-TS depends upon T bit */
                    dissect_pdcp_uo_1_ts_or_id_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
                 }

                return;

        }
    }

    /* Packet type 2 (110) */
    else if (((base_header_byte & 0xe0) >> 5) == 6) {

        /* UOR-2 if !(ipv4 && rand) */
        if (!((p_pdcp_info->rohc_ip_version == 4) &&
              (!p_pdcp_info->rnd))) {

            dissect_pdcp_uor_2_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
        }
        else {
            /* Whether its UOR-2-ID or UOR-2-TS depends upon T bit */
            dissect_pdcp_uor_2_ts_or_id_packet(rohc_tree, rohc_ti, tvb, offset, p_pdcp_info, pinfo);
            return;
        }
    }

    /* Segment (1111111) */
    else if ((base_header_byte & 0xfe) == 0xfe) {
        /* TODO: */
        return;
    }


    /* Fields beyond base header */

    /* These 2 fields not present for IR, IR-DYN frames */

    /* IP-ID */
    if (p_pdcp_info->rnd && ip_id_needed) {
        proto_tree_add_item(rohc_tree, hf_pdcp_lte_rohc_ip_id, tvb, offset, 2, FALSE);
        offset += 2;
    }

    /* UDP Checksum */
    if (p_pdcp_info->udp_checkum_present && udp_checksum_needed) {
        proto_tree_add_item(rohc_tree, hf_pdcp_lte_rohc_udp_checksum, tvb, offset, 2, FALSE);
        offset += 2;
    }

    /* Payload */
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(rohc_tree, hf_pdcp_lte_rohc_payload, tvb, offset, -1, FALSE);
    }
}

/* Initializes the hash table and the mem_chunk area each time a new
 * file is loaded or re-loaded in wireshark */
static void
pdcp_lte_init_protocol(void)
{
    /* Destroy any existing hashes. */
    if (pdcp_sequence_analysis_channel_hash) {
        g_hash_table_destroy(pdcp_sequence_analysis_channel_hash);
    }
    if (pdcp_lte_frame_sequence_analysis_report_hash) {
        g_hash_table_destroy(pdcp_lte_frame_sequence_analysis_report_hash);
    }


    /* Now create them over */
    pdcp_sequence_analysis_channel_hash = g_hash_table_new(pdcp_channel_hash_func, pdcp_channel_equal);
    pdcp_lte_frame_sequence_analysis_report_hash = g_hash_table_new(pdcp_frame_hash_func, pdcp_frame_equal);
}



void proto_register_pdcp(void)
{
    static hf_register_info hf[] =
    {
        { &hf_pdcp_lte_configuration,
            { "Configuration",
              "pdcp-lte.configuration", FT_STRING, BASE_NONE, NULL, 0x0,
              "Configuration info passed into dissector", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_compression,
            { "ROHC Compression",
              "pdcp-lte.rohc.compression", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_mode,
            { "ROHC Mode",
              "pdcp-lte.rohc.mode", FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_rnd,
            { "RND",  /* TODO: true/false vals? */
              "pdcp-lte.rohc.rnd", FT_UINT8, BASE_DEC, NULL, 0x0,
              "RND of outer ip header", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_udp_checksum_present,
            { "UDP Checksum",  /* TODO: true/false vals? */
              "pdcp-lte.rohc.checksum-present", FT_UINT8, BASE_DEC, NULL, 0x0,
              "UDP Checksum present", HFILL
            }
        },
        { &hf_pdcp_lte_direction,
            { "Direction",
              "pdcp-lte.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Direction of message", HFILL
            }
        },
        { &hf_pdcp_lte_ueid,
            { "UE",
              "pdcp-lte.ueid", FT_UINT16, BASE_DEC, 0, 0x0,
              "UE Identifier", HFILL
            }
        },
        { &hf_pdcp_lte_channel_type,
            { "Channel type",
              "pdcp-lte.channel-type", FT_UINT8, BASE_DEC, VALS(logical_channel_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_channel_id,
            { "Channel Id",
              "pdcp-lte.channel-id", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_profile,
            { "ROHC profile",
              "pdcp-lte.rohc.profile", FT_UINT8, BASE_DEC, VALS(rohc_profile_vals), 0x0,
              "ROHC Mode", HFILL
            }
        },
        { &hf_pdcp_lte_no_header_pdu,
            { "No Header PDU",
              "pdcp-lte.no-header_pdu", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_plane,
            { "Plane",
              "pdcp-lte.plane", FT_UINT8, BASE_DEC, VALS(pdcp_plane_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_seqnum_length,
            { "Seqnum length",
              "pdcp-lte.seqnum_length", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Sequence Number Length", HFILL
            }
        },


        { &hf_pdcp_lte_cid_inclusion_info,
            { "CID Inclusion Info",
              "pdcp-lte.cid-inclusion-info", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_large_cid_present,
            { "Large CID Present",
              "pdcp-lte.large-cid-present", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_pdcp_lte_seq_num_5,
            { "Seq Num",
              "pdcp-lte.seq-num", FT_UINT8, BASE_DEC, NULL, 0x1f,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_7,
            { "Seq Num",
              "pdcp-lte.seq-num", FT_UINT8, BASE_DEC, NULL, 0x7f,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_reserved3,
            { "Reserved",
              "pdcp-lte.reserved3", FT_UINT8, BASE_HEX, NULL, 0x70,
              "3 reserved bits", HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_12,
            { "Seq Num",
              "pdcp-lte.seq-num", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_signalling_data,
            { "Signalling Data",
              "pdcp-lte.signalling-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_mac,
            { "MAC",
              "pdcp-lte.mac", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_data_control,
            { "PDU Type",
              "pdcp-lte.pdu-type", FT_UINT8, BASE_HEX, VALS(pdu_type_vals), 0x80,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_user_plane_data,
            { "User-Plane Data",
              "pdcp-lte.user-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_control_pdu_type,
            { "Control PDU Type",
              "pdcp-lte.control-pdu-type", FT_UINT8, BASE_HEX, VALS(control_pdu_type_vals), 0x70,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_fms,
            { "First Missing Sequence Number",
              "pdcp-lte.fms", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "First Missing PDCP Sequence Number", HFILL
            }
        },
        { &hf_pdcp_lte_bitmap,
            { "Bitmap",
              "pdcp-lte.bitmap", FT_NONE, BASE_NONE, NULL, 0x0,
              "Status report bitmap (0=error, 1=OK)", HFILL
            }
        },
        { &hf_pdcp_lte_bitmap_not_received,
            { "Not Received",
              "pdcp-lte.bitmap.error", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              "Status report PDU error", HFILL
            }
        },


        { &hf_pdcp_lte_sequence_analysis,
            { "Sequence Analysis",
              "pdcp-lte.sequence-analysis", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_ok,
            { "OK",
              "pdcp-lte.sequence-analysis.ok", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_previous_frame,
            { "Previous frame for channel",
              "pdcp-lte.sequence-analysis.previous-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_expected_sn,
            { "Expected SN",
              "pdcp-lte.sequence-analysis.expected-sn", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_skipped,
            { "Skipped frames",
              "pdcp-lte.sequence-analysis.skipped-frames", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_repeated,
            { "Repeated frame",
              "pdcp-lte.sequence-analysis.repeated-frame", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },

        { &hf_pdcp_lte_rohc,
            { "ROHC Message",
              "pdcp-lte.rohc", FT_NONE, BASE_NONE, NULL, 0,
              NULL, HFILL
            }
        },

        { &hf_pdcp_lte_rohc_padding,
            { "Padding",
              "pdcp-lte.rohc.padding", FT_NONE, BASE_NONE, NULL, 0,
              "ROHC Padding", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_r_0_crc,
            { "R-0-CRC Packet",
              "pdcp-lte.r-0-crc", FT_NONE, BASE_NONE, NULL, 0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_feedback,
            { "Feedback",
              "pdcp-lte.rohc.feedback", FT_NONE, BASE_NONE, NULL, 0,
              "Feedback Packet", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_type0_t,
            { "T",
              "pdcp-lte.rohc.t0.t", FT_UINT8, BASE_HEX, VALS(t_vals), 0x20,
              "Indicates whether frame type is TS (1) or ID (0)", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_type1_t,
            { "T",
              "pdcp-lte.rohc.t1.t", FT_UINT8, BASE_HEX, VALS(t_vals), 0x80,
              "Indicates whether frame type is TS (1) or ID (0)", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_type2_t,
            { "T",
              "pdcp-lte.rohc.t2.t", FT_UINT8, BASE_HEX, VALS(t_vals), 0x80,
              "Indicates whether frame type is TS (1) or ID (0)", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_d,
            { "D",
              "pdcp-lte.rohc.d", FT_UINT8, BASE_HEX, NULL, 0x01,
              "Indicates whether Dynamic chain is present", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_ir_crc,
            { "CRC",
              "pdcp-lte.rohc.ir.crc", FT_UINT8, BASE_HEX, NULL, 0x0,
              "8-bit CRC", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_static_ipv4,
            { "Static IPv4 chain",
              "pdcp-lte.rohc.static.ipv4", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_ip_version,
            { "IP Version",
              "pdcp-lte.rohc.ip-version", FT_UINT8, BASE_HEX, NULL, 0xf0,
              NULL, HFILL
            }
        },
        /* TODO: create/use value_string */
        { &hf_pdcp_lte_rohc_ip_protocol,
            { "IP Protocol",
              "pdcp-lte.rohc.ip-protocol", FT_UINT8, BASE_DEC, VALS(ip_protocol_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_ip_src,
            { "IP Source address",
              "pdcp-lte.rohc.ip-src", FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_ip_dst,
            { "IP Destination address",
              "pdcp-lte.rohc.ip-dst", FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_pdcp_lte_rohc_static_udp,
            { "Static UDP chain",
              "pdcp-lte.rohc.static.udp", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_static_udp_src_port,
            { "Static UDP source port",
              "pdcp-lte.rohc.static.udp.src-port", FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_static_udp_dst_port,
            { "Static UDP destination port",
              "pdcp-lte.rohc.static.udp.dst-port", FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_static_rtp,
            { "Static RTP chain",
              "pdcp-lte.rohc.static.rtp", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_static_rtp_ssrc,
            { "SSRC",
              "pdcp-lte.rohc.static.rtp.ssrc", FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              "Static RTP chain SSRC", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_dynamic_ipv4,
            { "Dynamic IPv4 chain",
              "pdcp-lte.rohc.dynamic.ipv4", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_ipv4_tos,
            { "ToS",
              "pdcp-lte.rohc.ip.tos", FT_UINT8, BASE_HEX, NULL, 0x0,
              "IP Type of Service", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_ipv4_ttl,
            { "TTL",
              "pdcp-lte.rohc.ip.ttl", FT_UINT8, BASE_HEX, NULL, 0x0,
              "IP Time To Live", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_ipv4_id,
            { "IP-ID",
              "pdcp-lte.rohc.ip.id", FT_UINT8, BASE_HEX, NULL, 0x0,
              "IP ID", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_ipv4_df,
            { "Don't Fragment",
              "pdcp-lte.rohc.ip.df", FT_UINT8, BASE_HEX, NULL, 0x80,
              "IP Don't Fragment flag", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_ipv4_rnd,
            { "Random IP-ID field",
              "pdcp-lte.rohc.ip.rnd", FT_UINT8, BASE_HEX, NULL, 0x40,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_ipv4_nbo,
            { "Network Byte Order IP-ID field",
              "pdcp-lte.rohc.ip.nbo", FT_UINT8, BASE_HEX, NULL, 0x20,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_udp,
            { "Dynamic UDP chain",
              "pdcp-lte.rohc.dynamic.udp", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_udp_checksum,
            { "UDP Checksum",
              "pdcp-lte.rohc.dynamic.udp.checksum", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_udp_seqnum,
            { "UDP Sequence Number",
              "pdcp-lte.rohc.dynamic.udp.seqnum", FT_UINT16, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_pdcp_lte_rohc_dynamic_rtp,
            { "Dynamic RTP chain",
              "pdcp-lte.rohc.dynamic.rtp", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_rx,
            { "RX",
              "pdcp-lte.rohc.dynamic.rtp.rx", FT_UINT8, BASE_DEC, NULL, 0x10,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_cc,
            { "Contributing CSRCs",
              "pdcp-lte.rohc.dynamic.rtp.cc", FT_UINT8, BASE_DEC, NULL, 0x0f,
              "Dynamic RTP chain CCs", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_seqnum,
            { "RTP Sequence Number",
              "pdcp-lte.rohc.dynamic.rtp.seqnum", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Dynamic RTP chain Sequence Number", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_timestamp,
            { "RTP Timestamp",
              "pdcp-lte.rohc.dynamic.rtp.timestamp", FT_UINT32, BASE_DEC, NULL, 0x0,
              "Dynamic RTP chain Timestamp", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_reserved3,
            { "Reserved",
              "pdcp-lte.rohc.dynamic.rtp.reserved3", FT_UINT8, BASE_HEX, NULL, 0xc0,
              "Reserved bits", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_x,
            { "X",
              "pdcp-lte.rohc.dynamic.rtp.x", FT_UINT8, BASE_DEC, NULL, 0x10,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_mode,
            { "Mode",
              "pdcp-lte.rohc.dynamic.rtp.mode", FT_UINT8, BASE_HEX, VALS(rohc_mode_vals), 0x0c,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_tis,
            { "TIS",
              "pdcp-lte.rohc.dynamic.rtp.tis", FT_UINT8, BASE_HEX, NULL, 0x02,
              "Dynamic RTP chain TIS (indicates time_stride present)", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_tss,
            { "TSS",
              "pdcp-lte.rohc.dynamic.rtp.tss", FT_UINT8, BASE_HEX, NULL, 0x01,
              "Dynamic RTP chain TSS (indicates TS_stride present)", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_dynamic_rtp_ts_stride,
            { "TS Stride",
              "pdcp-lte.rohc.dynamic.rtp.ts-stride", FT_UINT32, BASE_DEC, NULL, 0x0,
              "Dynamic RTP chain TS Stride", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_ts,
            { "TS",
              "pdcp-lte.rohc.ts", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_m,
            { "M",
              "pdcp-lte.rohc.m", FT_UINT8, BASE_DEC, NULL, 0x40,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_uor2_sn,
            { "SN",
              "pdcp-lte.rohc.uor2.sn", FT_UINT8, BASE_DEC, NULL, 0x3f,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_uor2_x,
            { "X",
              "pdcp-lte.rohc.uor2.x", FT_UINT8, BASE_DEC, NULL, 0x80,
              NULL, HFILL
            }
        },

        { &hf_pdcp_lte_rohc_add_cid,
            { "Add-CID",
              "pdcp-lte.rohc.add-cid", FT_UINT8, BASE_DEC, NULL, 0x0f,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_large_cid,
            { "Large-CID",
              "pdcp-lte.rohc.large-cid", FT_UINT16, BASE_DEC, NULL, 0x07ff,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_uo0_sn,
            { "SN",
              "pdcp-lte.rohc.uo0.sn", FT_UINT8, BASE_DEC, NULL, 0x78,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_uo0_crc,
            { "CRC",
              "pdcp-lte.rohc.uo0.crc", FT_UINT8, BASE_DEC, NULL, 0x07,
              "3-bit CRC", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_r0_sn,
            { "SN",
              "pdcp-lte.rohc.r0.sn", FT_UINT8, BASE_DEC, NULL, 0x3f,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_r0_crc_sn,
            { "SN",
              "pdcp-lte.rohc.r0-crc.sn", FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_r0_crc_crc,
            { "CRC7",
              "pdcp-lte.rohc.r0-crc.crc", FT_UINT8, BASE_DEC, NULL, 0x7f,
              "CRC 7", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_feedback_code,
            { "Code",
              "pdcp-lte.rohc.feedback-code", FT_UINT8, BASE_DEC, NULL, 0x07,
              "Feedback options length (if > 0)", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_feedback_size,
            { "Size",
              "pdcp-lte.rohc.feedback-size", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Feedback options length", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_feedback_feedback1,
            { "FEEDBACK-1 (SN)",
              "pdcp-lte.rohc.feedback.feedback1", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Feedback-1", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_feedback_feedback2,
            { "FEEDBACK-2",
              "pdcp-lte.rohc.feedback.feedback2", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_pdcp_lte_rohc_feedback_ack_type,
            { "Acktype",
              "pdcp-lte.rohc.feedback-acktype", FT_UINT8, BASE_DEC, VALS(feedback_ack_vals), 0xc0,
              "Feedback-2 ack type", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_feedback_mode,
            { "mode",
              "pdcp-lte.rohc.feedback-mode", FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), 0x30,
              "Feedback mode", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_feedback_sn,
            { "SN",
              "pdcp-lte.rohc.feedback-sn", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "Feedback sequence number", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_feedback_option,
            { "Option",
              "pdcp-lte.rohc.feedback-option", FT_UINT8, BASE_DEC, VALS(feedback_option_vals), 0xf0,
              "Feedback option", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_feedback_length,
            { "Length",
              "pdcp-lte.rohc.feedback-length", FT_UINT8, BASE_DEC, NULL, 0x0f,
              "Feedback length", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_feedback_crc,
            { "CRC",
              "pdcp-lte.rohc.feedback-crc", FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
              "Feedback CRC", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_feedback_option_sn,
            { "SN",
              "pdcp-lte.rohc.feedback-option-sn", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Feedback Option SN", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_feedback_option_clock,
            { "Clock",
              "pdcp-lte.rohc.feedback-option-clock", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Feedback Option Clock", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_ip_id,
            { "IP-ID",
              "pdcp-lte.rohc.ip-id", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_udp_checksum,
            { "UDP Checksum",
              "pdcp-lte.rohc.udp-checksum", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_payload,
            { "Payload",
              "pdcp-lte.rohc.payload", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },

    };

    static gint *ett[] =
    {
        &ett_pdcp,
        &ett_pdcp_configuration,
        &ett_pdcp_packet,
        &ett_pdcp_lte_sequence_analysis,
        &ett_pdcp_rohc,
        &ett_pdcp_rohc_static_ipv4,
        &ett_pdcp_rohc_static_udp,
        &ett_pdcp_rohc_static_rtp,
        &ett_pdcp_rohc_dynamic_ipv4,
        &ett_pdcp_rohc_dynamic_udp,
        &ett_pdcp_rohc_dynamic_rtp,
        &ett_pdcp_rohc_report_bitmap
    };

    module_t *pdcp_lte_module;

    /* Register protocol. */
    proto_pdcp_lte = proto_register_protocol("PDCP-LTE", "PDCP-LTE", "pdcp-lte");
    proto_register_field_array(proto_pdcp_lte, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow other dissectors to find this one by name. */
    register_dissector("pdcp-lte", dissect_pdcp_lte, proto_pdcp_lte);

    pdcp_lte_module = prefs_register_protocol(proto_pdcp_lte, NULL);

    /* Dissect uncompressed user-plane data as IP */
    prefs_register_bool_preference(pdcp_lte_module, "show_user_plane_as_ip",
        "Show uncompressed User-Plane data as IP",
        "Show uncompressed User-Plane data as IP",
        &global_pdcp_dissect_user_plane_as_ip);

    /* Dissect unciphered signalling data as RRC */
    prefs_register_bool_preference(pdcp_lte_module, "show_signalling_plane_as_rrc",
        "Show unciphered Signalling-Plane data as RRC",
        "Show unciphered Signalling-Plane data as RRC",
        &global_pdcp_dissect_signalling_plane_as_rrc);

    /* Check for missing sequence numbers */
    prefs_register_bool_preference(pdcp_lte_module, "check_sequence_numbers",
        "Do sequence number analysis",
        "Do sequence number analysis",
        &global_pdcp_check_sequence_numbers);

    /* Attempt to dissect ROHC headers */
    prefs_register_bool_preference(pdcp_lte_module, "dissect_rohc",
        "Attempt to decode ROHC data",
        "Attempt to decode ROHC data",
        &global_pdcp_dissect_rohc);

    prefs_register_bool_preference(pdcp_lte_module, "show_feedback_option_tag_length",
        "Show ROHC feedback option tag & length",
        "Show ROHC feedback option tag & length",
        &global_pdcp_show_feedback_option_tag_length);

    prefs_register_bool_preference(pdcp_lte_module, "heuristic_pdcp_lte_over_udp",
        "Try Heuristic LTE-PDCP over UDP framing",
        "When enabled, use heuristic dissector to find PDCP-LTE frames sent with "
        "UDP framing",
        &global_pdcp_lte_heur);

    register_init_routine(&pdcp_lte_init_protocol);
}

void proto_reg_handoff_pdcp_lte(void)
{
    /* Add as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_pdcp_lte_heur, proto_pdcp_lte);

    ip_handle = find_dissector("ip");
}

