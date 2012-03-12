/* packet-tlv.c
 * Routines to Dissect Appendix C TLV's
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
 *
 * $Id: packet-tlv.c 35869 2011-02-08 00:24:10Z wmeier $
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

#include <epan/packet.h>
#include "packet-tlv.h"

/* This module will dissect the Appendix C TLV's.  Please see:
 * http://www.cablemodem.com/specifications/specifications.html
 *
 * The main dissector is dissect_tlv.  This routine will dissect
 * top level TLV's and call sub-dissectors for the sub-TLV's.
 */

/* Initialize the protocol and registered fields */
static dissector_handle_t docsis_vsif_handle;
static dissector_handle_t docsis_ucd_handle;


static int proto_docsis_tlv = -1;
static int hf_docsis_tlv_down_freq = -1;
static int hf_docsis_tlv_upstream_chid = -1;
static int hf_docsis_tlv_net_access = -1;
static int hf_docsis_tlv_cos = -1;
static int hf_docsis_tlv_mcap = -1;
static int hf_docsis_tlv_privacy_enable = -1;
static int hf_docsis_tlv_max_cpe = -1;
static int hf_docsis_tlv_max_classifiers = -1;
static int hf_docsis_tlv_snmp_access = -1;
static int hf_docsis_tlv_snmp_obj = -1;
static int hf_docsis_tlv_svc_unavail = -1;
static int hf_docsis_tlv_svc_unavail_classid = -1;
static int hf_docsis_tlv_svc_unavail_type = -1;
static int hf_docsis_tlv_svc_unavail_code = -1;
static int hf_docsis_tlv_bpi = -1;
static int hf_docsis_tlv_phs = -1;
static int hf_docsis_tlv_hmac_digest = -1;
static int hf_docsis_tlv_tftp_server_timestamp = -1;
static int hf_docsis_tlv_tftp_prov_modem_address = -1;
static int hf_docsis_tlv_upclsfr = -1;
static int hf_docsis_tlv_downclsfr = -1;
static int hf_docsis_tlv_upsflow = -1;
static int hf_docsis_tlv_downsflow = -1;
static int hf_docsis_tlv_vendor_spec = -1;
static int hf_docsis_tlv_cm_mic = -1;
static int hf_docsis_tlv_cmts_mic = -1;
static int hf_docsis_tlv_auth_block = -1;
static int hf_docsis_tlv_key_seq_num = -1;
static int hf_docsis_tlv_snmpv3_kick = -1;
static int hf_docsis_tlv_snmpv3_kick_name = -1;
static int hf_docsis_tlv_snmpv3_kick_publicnum = -1;
static int hf_docsis_tlv_mfgr_cvc = -1;
static int hf_docsis_tlv_cosign_cvc = -1;
static int hf_docsis_tlv_vendor_id = -1;
static int hf_docsis_tlv_sw_file = -1;
static int hf_docsis_tlv_sw_upg_srvr = -1;
static int hf_docsis_tlv_cpe_ethernet = -1;
static int hf_docsis_tlv_modem_addr = -1;
static int hf_docsis_tlv_rng_tech = -1;
static int hf_docsis_tlv_subs_mgmt_ctrl = -1;
static int hf_docsis_tlv_subs_mgmt_ip_table = -1;
static int hf_docsis_tlv_subs_mgmt_ip_entry = -1;
static int hf_docsis_tlv_subs_mgmt_filter_grps = -1;
static int hf_docsis_tlv_snmpv3_ntfy_rcvr = -1;
static int hf_docsis_tlv_enable_20_mode = -1;
static int hf_docsis_tlv_enable_test_modes = -1;
static int hf_docsis_tlv_ds_ch_list = -1;
static int hf_docsis_tlv_mc_mac_address = -1;
static int hf_docsis_tlv_dut_filter = -1;
static int hf_docsis_tlv_tcc = -1;
static int hf_docsis_tlv_sid_cl = -1;
static int hf_docsis_tlv_rcp = -1;
static int hf_docsis_tlv_rcc = -1;
static int hf_docsis_tlv_dsid = -1;
static int hf_docsis_tlv_sec_assoc = -1;
static int hf_docsis_tlv_init_ch_timeout = -1;
static int hf_docsis_tlv_ch_asgn = -1;
static int hf_docsis_tlv_cm_init_reason = -1;
static int hf_docsis_tlv_sw_upg_srvr_ipv6 = -1;
static int hf_docsis_tlv_tftp_prov_cm_ipv6_addr = -1;
static int hf_docsis_tlv_us_drop_clfy = -1;
static int hf_docsis_tlv_subs_mgmt_ipv6_lst = -1;
static int hf_docsis_tlv_us_drop_clfy_group_id = -1;
static int hf_docsis_tlv_subs_mgmt_ctrl_max_cpe_ipv6 = -1;
static int hf_docsis_tlv_cmts_mc_sess_enc = -1;

static int hf_docsis_tlv_cos_id = -1;
static int hf_docsis_tlv_cos_sid = -1;
static int hf_docsis_tlv_cos_max_down = -1;
static int hf_docsis_tlv_cos_max_up = -1;
static int hf_docsis_tlv_cos_up_chnl_pri = -1;
static int hf_docsis_tlv_cos_min_grntd_up = -1;
static int hf_docsis_tlv_cos_max_up_burst = -1;
static int hf_docsis_tlv_cos_privacy_enable = -1;

static int hf_docsis_tlv_mcap_concat = -1;
static int hf_docsis_tlv_mcap_docs_ver = -1;
static int hf_docsis_tlv_mcap_frag = -1;
static int hf_docsis_tlv_mcap_phs = -1;
static int hf_docsis_tlv_mcap_igmp = -1;
static int hf_docsis_tlv_mcap_down_said = -1;
static int hf_docsis_tlv_mcap_up_sid = -1;
static int hf_docsis_tlv_mcap_privacy = -1;
static int hf_docsis_tlv_mcap_8021P_filter = -1;
static int hf_docsis_tlv_mcap_8021Q_filter = -1;
static int hf_docsis_tlv_mcap_xmit_eq_taps_per_sym = -1;
static int hf_docsis_tlv_mcap_xmit_eq_taps = -1;
static int hf_docsis_tlv_mcap_dcc = -1;

static int hf_docsis_tlv_clsfr_ref = -1;
static int hf_docsis_tlv_clsfr_id = -1;
static int hf_docsis_tlv_clsfr_sflow_ref = -1;
static int hf_docsis_tlv_clsfr_sflow_id = -1;
static int hf_docsis_tlv_clsfr_rule_pri = -1;
static int hf_docsis_tlv_clsfr_act_state = -1;
static int hf_docsis_tlv_clsfr_dsc_act = -1;
static int hf_docsis_tlv_clsfr_err = -1;
static int hf_docsis_tlv_ipclsfr = -1;
static int hf_docsis_tlv_ethclsfr = -1;
static int hf_docsis_tlv_dot1qclsfr = -1;

static int hf_docsis_tlv_clsfr_vendor_spc = -1;

static int hf_docsis_tlv_clsfr_err_param = -1;
static int hf_docsis_tlv_clsfr_err_code = -1;
static int hf_docsis_tlv_clsfr_err_msg = -1;

static int hf_docsis_tlv_ipclsfr_tosmask = -1;
static int hf_docsis_tlv_ipclsfr_ipproto = -1;
static int hf_docsis_tlv_ipclsfr_src = -1;
static int hf_docsis_tlv_ipclsfr_dst = -1;
static int hf_docsis_tlv_ipclsfr_srcmask = -1;
static int hf_docsis_tlv_ipclsfr_dstmask = -1;
static int hf_docsis_tlv_ipclsfr_sport_start = -1;
static int hf_docsis_tlv_ipclsfr_sport_end = -1;
static int hf_docsis_tlv_ipclsfr_dport_start = -1;
static int hf_docsis_tlv_ipclsfr_dport_end = -1;

static int hf_docsis_tlv_ethclsfr_dmac = -1;
static int hf_docsis_tlv_ethclsfr_smac = -1;
static int hf_docsis_tlv_ethclsfr_ethertype = -1;

static int hf_docsis_tlv_dot1qclsfr_user_pri = -1;
static int hf_docsis_tlv_dot1qclsfr_vlanid = -1;
static int hf_docsis_tlv_dot1qclsfr_vendorspec = -1;

static int hf_docsis_tlv_sflow_ref = -1;
static int hf_docsis_tlv_sflow_id = -1;
static int hf_docsis_tlv_sflow_sid = -1;
static int hf_docsis_tlv_sflow_classname = -1;
static int hf_docsis_tlv_sflow_qos_param = -1;
static int hf_docsis_tlv_sflow_err = -1;
static int hf_docsis_tlv_sflow_traf_pri = -1;
static int hf_docsis_tlv_sflow_max_sus = -1;
static int hf_docsis_tlv_sflow_max_burst = -1;
static int hf_docsis_tlv_sflow_min_traf = -1;
static int hf_docsis_tlv_sflow_ass_min_pkt_size = -1;
static int hf_docsis_tlv_sflow_timeout_active = -1;
static int hf_docsis_tlv_sflow_timeout_admitted = -1;
static int hf_docsis_tlv_sflow_vendor_spec = -1;
static int hf_docsis_tlv_sflow_max_concat_burst = -1;
static int hf_docsis_tlv_sflow_sched_type = -1;
static int hf_docsis_tlv_sflow_reqxmit_pol = -1;
static int hf_docsis_tlv_sflow_nominal_polling = -1;
static int hf_docsis_tlv_sflow_tolerated_jitter = -1;
static int hf_docsis_tlv_sflow_ugs_size = -1;
static int hf_docsis_tlv_sflow_nom_grant_intvl = -1;
static int hf_docsis_tlv_sflow_tol_grant_jitter = -1;
static int hf_docsis_tlv_sflow_grants_per_intvl = -1;
static int hf_docsis_tlv_sflow_ip_tos_overwrite = -1;
static int hf_docsis_tlv_sflow_ugs_timeref = -1;
static int hf_docsis_tlv_sflow_max_down_latency = -1;

static int hf_docsis_tlv_sflow_err_param = -1;
static int hf_docsis_tlv_sflow_err_code = -1;
static int hf_docsis_tlv_sflow_err_msg = -1;

static int hf_docsis_tlv_phs_class_ref = -1;
static int hf_docsis_tlv_phs_class_id = -1;
static int hf_docsis_tlv_phs_sflow_ref = -1;
static int hf_docsis_tlv_phs_sflow_id = -1;
static int hf_docsis_tlv_phs_dsc_action = -1;
static int hf_docsis_tlv_phs_err = -1;
static int hf_docsis_tlv_phs_phsf = -1;
static int hf_docsis_tlv_phs_phsm = -1;
static int hf_docsis_tlv_phs_phsv = -1;
static int hf_docsis_tlv_phs_phsi = -1;
static int hf_docsis_tlv_phs_phss = -1;
static int hf_docsis_tlv_phs_vendorspec = -1;

static int hf_docsis_tlv_phs_err_param = -1;
static int hf_docsis_tlv_phs_err_code = -1;
static int hf_docsis_tlv_phs_err_msg = -1;

static int hf_docsis_tlv_ds_ch_list_single = -1;
static int hf_docsis_tlv_ds_ch_list_range = -1;
static int hf_docsis_tlv_ds_ch_list_default_timeout = -1;

static int hf_docsis_tlv_single_ch_timeout = -1;
static int hf_docsis_tlv_single_ch_freq = -1;

static int hf_docsis_tlv_freq_rng_timeout = -1;
static int hf_docsis_tlv_freq_rng_start = -1;
static int hf_docsis_tlv_freq_rng_end = -1;
static int hf_docsis_tlv_freq_rng_step = -1;

static int hf_docsis_tlv_dut_filter_control = -1;
static int hf_docsis_tlv_dut_filter_cmim = -1;

static int hf_docsis_tlv_tcc_refid = -1;
static int hf_docsis_tlv_tcc_us_ch_action= -1;
static int hf_docsis_tlv_tcc_us_ch_id= -1;
static int hf_docsis_tlv_tcc_new_us_ch_id= -1;
static int hf_docsis_tlv_tcc_ucd = -1;
static int hf_docsis_tlv_tcc_rng_sid= -1;
static int hf_docsis_tlv_tcc_init_tech= -1;
static int hf_docsis_tlv_tcc_rng_parms= -1;
static int hf_docsis_tlv_tcc_dyn_rng_win= -1;
static int hf_docsis_tlv_tcc_err = -1;

static int hf_docsis_rng_parms_us_ch_id = -1;
static int hf_docsis_rng_parms_time_off_int = -1;
static int hf_docsis_rng_parms_time_off_frac = -1;
static int hf_docsis_rng_parms_power_off = -1;
static int hf_docsis_rng_parms_freq_off = -1;

static int hf_docsis_tcc_err_subtype = -1;
static int hf_docsis_tcc_err_code = -1;
static int hf_docsis_tcc_err_msg = -1;

static int hf_docsis_sid_cl_sf_id = -1;
static int hf_docsis_sid_cl_enc = -1;
static int hf_docsis_sid_cl_so_crit = -1;

static int hf_docsis_sid_cl_enc_id = -1;
static int hf_docsis_sid_cl_enc_map = -1;

static int hf_docsis_sid_cl_map_us_ch_id = -1;
static int hf_docsis_sid_cl_map_sid = -1;
static int hf_docsis_sid_cl_map_action = -1;

static int hf_docsis_sid_cl_so_max_req = -1;
static int hf_docsis_sid_cl_so_max_out_bytes = -1;
static int hf_docsis_sid_cl_so_max_req_bytes = -1;
static int hf_docsis_sid_cl_so_max_time = -1;

static int hf_docsis_tlv_rcp_id = -1;
static int hf_docsis_tlv_rcp_name = -1;
static int hf_docsis_tlv_rcp_freq_spc = -1;
static int hf_docsis_tlv_rcp_rcv_mod_enc = -1;
static int hf_docsis_tlv_rcp_rcv_ch = -1;
static int hf_docsis_tlv_rcp_ven_spec = -1;

static int hf_docsis_rcv_mod_enc_idx = -1;
static int hf_docsis_rcv_mod_enc_adj_ch = -1;
static int hf_docsis_rcv_mod_enc_ch_bl_rng = -1;
static int hf_docsis_rcv_mod_enc_ctr_freq_asgn = -1;
static int hf_docsis_rcv_mod_enc_rsq_ch_subs_cap = -1;
static int hf_docsis_rcv_mod_enc_conn = -1;
static int hf_docsis_rcv_mod_enc_phy_layr_parms = -1;

static int hf_docsis_rcc_rcv_mod_enc_idx = -1;
static int hf_docsis_rcc_rcv_mod_enc_ctr_freq_asgn = -1;
static int hf_docsis_rcc_rcv_mod_enc_conn = -1;

static int hf_docsis_ch_bl_rng_min_ctr_freq = -1;
static int hf_docsis_ch_bl_rng_max_ctr_freq = -1;

static int hf_docsis_rcv_ch_idx = -1;
static int hf_docsis_rcv_ch_conn = -1;
static int hf_docsis_rcv_ch_conn_off = -1;
static int hf_docsis_rcv_ch_prim_ds_ch_ind = -1;

static int hf_docsis_rcc_rcv_ch_idx = -1;
static int hf_docsis_rcc_rcv_ch_conn = -1;
static int hf_docsis_rcc_rcv_ch_ctr_freq_asgn = -1;
static int hf_docsis_rcc_rcv_ch_prim_ds_ch_ind = -1;

static int hf_docsis_tlv_rcc_id = -1;
static int hf_docsis_tlv_rcc_rcv_mod_enc = -1;
static int hf_docsis_tlv_rcc_rcv_ch = -1;
static int hf_docsis_tlv_rcc_part_serv_ds_ch = -1;
static int hf_docsis_tlv_rcc_ven_spec = -1;
static int hf_docsis_tlv_rcc_err = -1;

static int hf_docsis_tlv_rcc_err_mod_or_ch = -1;
static int hf_docsis_tlv_rcc_err_idx = -1;
static int hf_docsis_tlv_rcc_err_param = -1;
static int hf_docsis_tlv_rcc_err_code = -1;
static int hf_docsis_tlv_rcc_err_msg = -1;

static int hf_docsis_tlv_dsid_id = -1;
static int hf_docsis_tlv_dsid_action = -1;
static int hf_docsis_tlv_dsid_ds_reseq = -1;
static int hf_docsis_tlv_dsid_mc = -1;

static int hf_docsis_ds_reseq_dsid = -1;
static int hf_docsis_ds_reseq_ch_lst = -1;
static int hf_docsis_ds_reseq_wait_time = -1;
static int hf_docsis_ds_reseq_warn_thresh = -1;
static int hf_docsis_ds_reseq_ho_timer = -1;

static int hf_docsis_tlv_dsid_mc_addr = -1;
static int hf_docsis_tlv_dsid_mc_cmim = -1;
static int hf_docsis_tlv_dsid_mc_group = -1;
static int hf_docsis_tlv_dsid_mc_phs = -1;

static int hf_docsis_mc_addr_action = -1;
static int hf_docsis_mc_addr_addr = -1;

static int hf_docsis_tlv_sec_assoc_action = -1;
static int hf_docsis_tlv_sec_assoc_desc = -1;

static int hf_docsis_ch_asgn_us_ch_id = -1;
static int hf_docsis_ch_asgn_rx_freq = -1;

static int hf_docsis_cmts_mc_sess_enc_grp = -1;
static int hf_docsis_cmts_mc_sess_enc_src = -1;

/* Initialize the subtree pointers */
static gint ett_docsis_tlv = -1;
static gint ett_docsis_tlv_cos = -1;
static gint ett_docsis_tlv_mcap = -1;
static gint ett_docsis_tlv_clsfr = -1;
static gint ett_docsis_tlv_clsfr_ip = -1;
static gint ett_docsis_tlv_clsfr_eth = -1;
static gint ett_docsis_tlv_clsfr_err = -1;
static gint ett_docsis_tlv_phs = -1;
static gint ett_docsis_tlv_phs_err = -1;
static gint ett_docsis_tlv_clsfr_dot1q = -1;
static gint ett_docsis_tlv_reqxmitpol = -1;
static gint ett_docsis_tlv_sflow_err = -1;
static gint ett_docsis_tlv_svc_unavail = -1;
static gint ett_docsis_tlv_snmpv3_kick = -1;
static gint ett_docsis_tlv_ds_ch_list = -1;
static gint ett_docsis_tlv_ds_ch_list_single = -1;
static gint ett_docsis_tlv_ds_ch_list_range = -1;
static gint ett_docsis_tlv_dut_filter = -1;
static gint ett_docsis_tlv_tcc = -1;
static gint ett_docsis_tlv_tcc_ucd = -1;
static gint ett_docsis_tlv_tcc_rng_parms = -1;
static gint ett_docsis_tlv_tcc_err = -1;
static gint ett_docsis_tlv_sid_cl = -1;
static gint ett_docsis_tlv_sid_cl_enc = -1;
static gint ett_docsis_tlv_sid_cl_enc_map = -1;
static gint ett_docsis_tlv_sid_cl_so = -1;
static gint ett_docsis_tlv_rcp = -1;
static gint ett_docsis_tlv_rcp_rcv_mod_enc = -1;
static gint ett_docsis_tlv_rcp_ch_bl_rng = -1;
static gint ett_docsis_tlv_rcp_rcv_ch = -1;
static gint ett_docsis_tlv_rcc = -1;
static gint ett_docsis_tlv_rcc_rcv_mod_enc = -1;
static gint ett_docsis_tlv_rcc_rcv_ch = -1;
static gint ett_docsis_tlv_rcc_err = -1;
static gint ett_docsis_tlv_dsid = -1;
static gint ett_docsis_tlv_dsid_ds_reseq = -1;
static gint ett_docsis_tlv_dsid_mc = -1;
static gint ett_docsis_tlv_dsid_mc_addr = -1;
static gint ett_docsis_tlv_sec_assoc = -1;
static gint ett_docsis_tlv_ch_asgn = -1;
static gint ett_docsis_cmts_mc_sess_enc = -1;

static const true_false_string on_off_tfs = {
  "On",
  "Off"
};

static const value_string on_off_vals[] = {
  {0, "Off"},
  {1, "On"},
  {0, NULL},
};

static const true_false_string ena_dis_tfs = {
  "Enable",
  "Disable"
};

static const value_string docs_ver_vals[] = {
  {0, "v1.0"},
  {1, "v1.1"},
  {0, NULL},
};

static const true_false_string activation_tfs = {
  "Active",
  "Inactive"
};

static const value_string dsc_act_vals[] = {
  {0, "DSC Add Classifier"},
  {1, "DSC Replace Classifier"},
  {2, "DSC Delete Classifier"},
  {0, NULL},
};

static const value_string qos_param_vals[] = {
  {0x01, "Apply to provisioned set only"},
  {0x02, "Perform admission control add apply to admitted set"},
  {0x03, "Apply to provisioned and admitted set; Perform admission control"},
  {0x04, "Perform admission control if needed and apply to active set"},
  {0x05,
   "Apply to provisioned and active sets; Admission control on admitted set in separate service flow, and activate service flow"},
  {0x06,
   "Perform admission control and activate; Apply to admitted and active sets"},
  {0x07,
   "Apply to Provisioned, Active and Admitted Sets; Admission Control and Activate Service Flow"},
  {0, NULL},
};

static const value_string sched_type_vals[] = {
  {0, "Reserved"},
  {1, "Undefined (CMTS Dependent)"},
  {2, "Best Effort Service"},
  {3, "Non-Real-Time Polling Service"},
  {4, "Real-Time Polling Service"},
  {5, "Unsolicited Grant Service w/Activity Detection"},
  {6, "Unsolicited Grant Service"},
  {0, NULL},
};

static const value_string action_vals[] = {
  {0, "Add PHS Rule"},
  {1, "Set PHS Rule"},
  {2, "Delete PHS Rule"},
  {3, "Delete all PHS Rules"},
  {0, NULL},
};

static const true_false_string verify_tfs = {
  "Don't Verify",
  "Verify"
};

static const value_string rng_tech_vals[] = {
  {0, "Perform initial maintenance on new channel"},
  {1, "Perform only station maintenance on new channel"},
  {2, "Perform either initial maintenance or station maintenance on new channel"},
  {3, "Use the new channel directly without performing initial or station maintenance"},
  {0, NULL},
};


const value_string docsis_conf_code[] = {
  {0, "okay/success"},
  {1, "Reject: Other/Auth failure (1.0)"},
  {2, "Reject: Unrecognized configuration setting/COS failure (1.0)"},
  {3, "Reject: Temporary/Reject resource"},
  {4, "Reject: Permanent/Reject admin"},
  {5, "Reject: Not owner"},
  {6, "Reject: Service flow not found"},
  {7, "Reject: Service flow exists"},
  {8, "Reject: Required parameter not present"},
  {9, "Reject: Header suppression"},
  {10, "Reject: Unknown transaction id"},
  {11, "Reject: Authentication failure"},
  {12, "Reject: Add aborted"},
  {13, "Reject: Multiple errors"},
  {14, "Reject: Classifier not found"},
  {15, "Reject: Classifier exists"},
  {16, "Reject: PHS rule not found"},
  {17, "Reject: PHS rule exists"},
  {18, "Reject: Duplicate reference ID or index in message"},
  {19, "Reject: Multiple upstream service flows"},
  {20, "Reject: Multiple downstream service flows"},
  {21, "Reject: Classifier for another service flow "},
  {22, "Reject: PHS for another service flow "},
  {23, "Reject: Parameter invalid for context"},
  {24, "Reject: Authorization failure"},
  {25, "Reject: Temporary DCC"},
  {180, "Depart"},
  {181, "Arrive"},
  {182, "Reject: Already There"},
  {200, "Reject: Major Service Flow Error"},
  {201, "Reject: Major Classifier Error"},
  {202, "Reject: Major PHS Rule Error"},
  {203, "Reject: Multiple Major Errors"},
  {204, "Reject: Message Syntax Error"},
  {205, "Reject: Primary Service Flow Error"},
  {206, "Reject: Message Too Big"},
  {207, "Reject: Invalid Modem Capabilities"},
  {0, NULL}
};

static const value_string us_ch_action_vals[] = {
  {0, "No Action"},
  {1, "Add"},
  {2, "Change"},
  {3, "Delete"},
  {4, "Replace"},
  {5, "Re-range"},
  {0, NULL},
};

static const value_string init_tech_vals[] = {
  {0, "reserved"},
  {1, "Perform broadcast initial ranging before normal ops"},
  {2, "Perform unicast ranging before normal ops"},
  {3, "Perform either broadcast or unicast ranging before normal ops"},
  {4, "Use new channel directly without reinitializing or ranging"},
  {0, NULL},
};

static const value_string sid_ch_map_vals[] = {
  {0, "reserved"},
  {1, "Add"},
  {2, "Delete"},
  {0, NULL},
};

static const value_string mod_or_ch_vals[] = {
  {0, "reserved"},
  {1, "reserved"},
  {2, "reserved"},
  {3, "reserved"},
  {4, "Receive Module"},
  {5, "Receive Channel"},
  {0, NULL},
};

static const value_string dsid_action_vals[] = {
  {0, "Add"},
  {1, "Change"},
  {2, "Delete"},
  {0, NULL},
};

static const value_string add_del_vals[] = {
  {0, "Add"},
  {1, "Delete"},
  {0, NULL},
};

static const value_string init_reason_vals[] = {
  {0, "reserved"},
  {1, "Power On"},
  {2, "T17 Lost Sync"},
  {3, "All Upstream Failed"},
  {4, "Bad DHCP Ack"},
  {5, "Link Local Address in use"},
  {6, "T6 Expired"},
  {7, "REG-RSP not ok"},
  {8, "BAD RCC/TCC"},
  {9, "Failed Primary Downstream"},
  {10, "TCS failed on all upstreams"},
  {11, "reserved"},
  {12, "reserved"},
  {13, "reserved"},
  {14, "reserved"},
  {15, "MTCM Change"},
  {16, "T4 Expired"},
  {17, "No Primary SF on US Channel"},
  {18, "CM Control Init"},
  {19, "Dynamic Range Window Violation"},
  {0, NULL},
};

/* Code to actually dissect the packets */
static void
dissect_phs_err (tvbuff_t * tvb, proto_tree * tree, int start,
                 guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *err_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "5 Service Flow Error Encodings (Length = %u)", len);
  err_tree = proto_item_add_subtree (it, ett_docsis_tlv_sflow_err);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case PHS_ERR_PARAM:
          if (length == 1)
            {
              proto_tree_add_item (err_tree, hf_docsis_tlv_phs_err_param, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case PHS_ERR_CODE:
          if (length == 1)
            {
              proto_tree_add_item (err_tree, hf_docsis_tlv_phs_err_code, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case PHS_ERR_MSG:
          proto_tree_add_item (err_tree, hf_docsis_tlv_phs_err_msg, tvb, pos,
                               length, FALSE);
          break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_phs (tvbuff_t * tvb, proto_tree * tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *phs_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "26 PHS Encodings (Length = %u)", len);
  phs_tree = proto_item_add_subtree (it, ett_docsis_tlv_phs);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case PHS_CLSFR_REF:
          if (length == 1)
            {
              proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_class_ref, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case PHS_CLSFR_ID:
          if (length == 2)
            {
              proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_class_id, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case PHS_SFLOW_REF:
          if (length == 2)
            {
              proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_sflow_ref, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case PHS_SFLOW_ID:
          if (length == 4)
            {
              proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_sflow_id, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case PHS_DSC_ACTION:
          if (length == 1)
            {
              proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_dsc_action,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case PHS_ERRORS:
          dissect_phs_err (tvb, phs_tree, pos, length);
        case PHS_FIELD:
          proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_phsf, tvb, pos,
                               length, FALSE);
          break;
        case PHS_INDEX:
          if (length == 1)
            {
              proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_phsi, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case PHS_MASK:
          proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_phsm, tvb, pos,
                               length, FALSE);
          break;
        case PHS_SUP_SIZE:
          if (length == 1)
            {
              proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_phss, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case PHS_VERIFICATION:
          if (length == 1)
            {
              proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_phsf, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case PHS_VENDOR_SPEC:
          proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_vendorspec, tvb,
                               pos, length, FALSE);
          break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}


static void
dissect_reqxmit_policy (tvbuff_t * tvb, proto_tree * tree, int start)
{
  guint32 value;
  proto_item *it;
  proto_tree *pol_tree;

  value = tvb_get_ntohl (tvb, start);
  it =
    proto_tree_add_item (tree, hf_docsis_tlv_sflow_reqxmit_pol, tvb, start, 4,
                         FALSE);
  pol_tree = proto_item_add_subtree (it, ett_docsis_tlv_reqxmitpol);

  if (value & 0x01)
    proto_tree_add_text (pol_tree, tvb, start, 4,
                         "Service flow MUST NOT use \"all CMs\" broadcast request opportunities");
  if (value & 0x02)
    proto_tree_add_text (pol_tree, tvb, start, 4,
                         "Service flow MUST NOT use priority multicast request opportunities");
  if (value & 0x04)
    proto_tree_add_text (pol_tree, tvb, start, 4,
                         "Service flow MUST NOT use Request/Data opportunities for requests");
  if (value & 0x08)
    proto_tree_add_text (pol_tree, tvb, start, 4,
                         "Service flow MUST NOT use Request/Data opportunities for data");
  if (value & 0x10)
    proto_tree_add_text (pol_tree, tvb, start, 4,
                         "Service flow MUST NOT use piggy back requests with data");
  if (value & 0x20)
    proto_tree_add_text (pol_tree, tvb, start, 4,
                         "Service flow MUST NOT concatenate data");
  if (value & 0x40)
    proto_tree_add_text (pol_tree, tvb, start, 4,
                         "Service flow MUST NOT fragment data");
  if (value & 0x80)
    proto_tree_add_text (pol_tree, tvb, start, 4,
                         "Service flow MUST NOT suppress payload headers");
  if (value & 0x100)
    proto_tree_add_text (pol_tree, tvb, start, 4,
                         "Service flow MUST drop packets that do not fit in the UGS size");
}

static void
dissect_sflow_err (tvbuff_t * tvb, proto_tree * tree, int start,
                   guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *err_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "5 Service Flow Error Encodings (Length = %u)", len);
  err_tree = proto_item_add_subtree (it, ett_docsis_tlv_sflow_err);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case SFW_ERR_PARAM:
          if (length == 1)
            {
              proto_tree_add_item (err_tree, hf_docsis_tlv_sflow_err_param,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_ERR_CODE:
          if (length == 1)
            {
              proto_tree_add_item (err_tree, hf_docsis_tlv_sflow_err_code,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_ERR_MSG:
          proto_tree_add_item (err_tree, hf_docsis_tlv_sflow_err_msg, tvb,
                               pos, length, FALSE);
          break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_downstream_sflow (tvbuff_t * tvb, proto_tree * sflow_tree,
                          int start, guint16 len)
{
  guint8 type, length;
  int pos = start;
  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case SFW_MAX_DOWN_LAT:
          if (length == 4)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_max_down_latency, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);

            }
          break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_upstream_sflow (tvbuff_t * tvb, proto_tree * sflow_tree,
                        int start, guint16 len)
{
  guint8 type, length;
  int pos = start;
  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case SFW_MAX_CONCAT_BURST:
          if (length == 2)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_max_concat_burst, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);

            }
          break;
        case SFW_SCHEDULING_TYPE:
          if (length == 1)
            {
              proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_sched_type,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_REQ_XMIT_POL:
          dissect_reqxmit_policy (tvb, sflow_tree, pos);
          break;
        case SFW_NOM_POLL_INT:
          if (length == 4)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_nominal_polling, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_POLL_JTTR_TOL:
          if (length == 4)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_tolerated_jitter, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_UG_SIZE:
          if (length == 2)
            {
              proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_ugs_size,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_NOM_GRNT_INTV:
          if (length == 4)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_nom_grant_intvl, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_GRNT_JTTR_TOL:
          if (length == 4)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_tol_grant_jitter, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_GRNTS_PER_INTV:
          if (length == 1)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_grants_per_intvl, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_IP_TOS_OVERWRITE:
          if (length == 2)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_ip_tos_overwrite, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_UG_TIME_REF:
          if (length == 4)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_ugs_timeref, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;

        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_sflow (tvbuff_t * tvb, proto_tree * tree, int start, guint16 len,
               guint8 direction)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *sflow_tree;
  int pos = start;
  if (direction == 24)
    it =
      proto_tree_add_text (tree, tvb, start, len,
                           "24 Upstream Service Flow (Length = %u)", len);
  else if (direction == 25)
    it =
      proto_tree_add_text (tree, tvb, start, len,
                           "25 Downstream Service Flow (Length = %u)", len);
  else
    return;
  sflow_tree = proto_item_add_subtree (it, ett_docsis_tlv_clsfr);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case SFW_REF:
          if (length == 2)
            {
              proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_ref, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_ID:
          if (length == 4)
            {
              proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_id, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_SID:
          if (length == 2)
            {
              proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_sid, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_SERVICE_CLASS_NAME:
          proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_classname, tvb,
                               pos, length, FALSE);
          break;
        case SFW_ERRORS:
          dissect_sflow_err (tvb, sflow_tree, pos, length);
          break;
        case SFW_QOS_SET_TYPE:
          if (length == 1)
            {
              proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_qos_param,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_TRAF_PRI:
          if (length == 1)
            {
              proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_traf_pri,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_MAX_SUSTAINED:
          if (length == 4)
            {
              proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_max_sus,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_MAX_BURST:
          if (length == 4)
            {
              proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_max_burst,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_MIN_RSVD_TRAF:
          if (length == 4)
            {
              proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_min_traf,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_MIN_RSVD_PACKETSIZE:
          if (length == 2)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_ass_min_pkt_size, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_ACTIVE_QOS_TIMEOUT:
          if (length == 2)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_timeout_active, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_ADMITT_QOS_TIMEOUT:
          if (length == 2)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_timeout_admitted, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SFW_VENDOR_SPEC:
          proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_vendor_spec,
                               tvb, pos, length, FALSE);
          break;
        default:
          if (direction == 24)
            dissect_upstream_sflow (tvb, sflow_tree, pos - 2, length);
          else
            dissect_downstream_sflow (tvb, sflow_tree, pos - 2, length);
          break;

        }                       /* switch (type) */
      pos = pos + length;
    }                           /* while(pos < start + len) */

}

static void
dissect_dot1q_clsfr (tvbuff_t * tvb, proto_tree * tree, int start,
                     guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *dot1qclsfr_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "11 801.1P/Q Classifiers (Length = %u)", len);
  dot1qclsfr_tree = proto_item_add_subtree (it, ett_docsis_tlv_cos);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case CFR_D1Q_USER_PRI:
          if (length == 2)
            {
              proto_tree_add_item (dot1qclsfr_tree,
                                   hf_docsis_tlv_dot1qclsfr_user_pri, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_D1Q_VLAN_ID:
          if (length == 2)
            {
              proto_tree_add_item (dot1qclsfr_tree,
                                   hf_docsis_tlv_dot1qclsfr_vlanid, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_D1Q_VENDOR_SPEC:
          proto_tree_add_item (dot1qclsfr_tree,
                               hf_docsis_tlv_dot1qclsfr_vendorspec, tvb, pos,
                               length, FALSE);
          break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_eth_clsfr (tvbuff_t * tvb, proto_tree * tree, int start,
                   guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *ethclsfr_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "10 Ethernet Classifiers (Length = %u)", len);
  ethclsfr_tree = proto_item_add_subtree (it, ett_docsis_tlv_clsfr_eth);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case CFR_ETH_DST_MAC:
          if (length == 6)
            {
              proto_tree_add_item (ethclsfr_tree, hf_docsis_tlv_ethclsfr_dmac,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_ETH_SRC_MAC:
          if (length == 6)
            {
              proto_tree_add_item (ethclsfr_tree, hf_docsis_tlv_ethclsfr_smac,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_ETH_DSAP:
          if (length == 3)
            {
              proto_tree_add_item (ethclsfr_tree,
                                   hf_docsis_tlv_ethclsfr_ethertype, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */



}

static void
dissect_clsfr_err (tvbuff_t * tvb, proto_tree * tree, int start,
                   guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *err_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "8 Classifier Error Encodings (Length = %u)", len);
  err_tree = proto_item_add_subtree (it, ett_docsis_tlv_clsfr_err);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case CFR_ERR_PARAM:
          if (length == 1)
            proto_tree_add_item (err_tree, hf_docsis_tlv_clsfr_err_param, tvb,
                                 pos, length, FALSE);
          else if (length == 2)
            {
              proto_tree_add_item (err_tree, hf_docsis_tlv_clsfr_err_param,
                                   tvb, pos, 1, FALSE);
              proto_tree_add_item (err_tree, hf_docsis_tlv_clsfr_err_param,
                                   tvb, pos + 1, 1, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_ERR_CODE:
          if (length == 1)
            {
              proto_tree_add_item (err_tree, hf_docsis_tlv_clsfr_err_code,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_ERR_MSG:
          proto_tree_add_item (err_tree, hf_docsis_tlv_clsfr_err_msg, tvb,
                               pos, length, FALSE);
          break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */



}

static void
dissect_ip_classifier (tvbuff_t * tvb, proto_tree * tree, int start,
                       guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *ipclsfr_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "9 IP Classifier (Length = %u)", len);
  ipclsfr_tree = proto_item_add_subtree (it, ett_docsis_tlv_clsfr_ip);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case CFR_IP_TOS_RANGE_MASK:
          if (length == 3)
            {
              proto_tree_add_item (ipclsfr_tree,
                                   hf_docsis_tlv_ipclsfr_tosmask, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_IP_PROTO:
          if (length == 2)
            {
              proto_tree_add_item (ipclsfr_tree,
                                   hf_docsis_tlv_ipclsfr_ipproto, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_IP_SOURCE_ADDR:
          if (length == 4)
            {
              proto_tree_add_item (ipclsfr_tree, hf_docsis_tlv_ipclsfr_src,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_IP_SOURCE_MASK:
          if (length == 4)
            {
              proto_tree_add_item (ipclsfr_tree,
                                   hf_docsis_tlv_ipclsfr_srcmask, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_IP_DEST_ADDR:
          if (length == 4)
            {
              proto_tree_add_item (ipclsfr_tree, hf_docsis_tlv_ipclsfr_dst,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_IP_DEST_MASK:
          if (length == 4)
            {
              proto_tree_add_item (ipclsfr_tree,
                                   hf_docsis_tlv_ipclsfr_dstmask, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_IP_SRCPORT_START:
          if (length == 2)
            {
              proto_tree_add_item (ipclsfr_tree,
                                   hf_docsis_tlv_ipclsfr_sport_start, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_IP_SRCPORT_END:
          if (length == 2)
            {
              proto_tree_add_item (ipclsfr_tree,
                                   hf_docsis_tlv_ipclsfr_sport_end, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_IP_DSTPORT_START:
          if (length == 2)
            {
              proto_tree_add_item (ipclsfr_tree,
                                   hf_docsis_tlv_ipclsfr_dport_start, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_IP_DSTPORT_END:
          if (length == 2)
            {
              proto_tree_add_item (ipclsfr_tree,
                                   hf_docsis_tlv_ipclsfr_dport_end, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */

}
static void
dissect_classifiers (tvbuff_t * tvb, proto_tree * tree, int start,
                     guint16 len, guint8 direction)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *clsfr_tree;
  int pos = start;
  if (direction == 22)
    it =
      proto_tree_add_text (tree, tvb, start, len,
                           "22 Upstream Packet Classifier (Length = %u)",
                           len);
  else if (direction == 23)
    it =
      proto_tree_add_text (tree, tvb, start, len,
                           "23 Downstream Packet Classifier (Length = %u)",
                           len);
  else
    return;
  clsfr_tree = proto_item_add_subtree (it, ett_docsis_tlv_clsfr);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case CFR_REF:
          if (length == 1)
            {
              proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_ref, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_ID:
          if (length == 2)
            {
              proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_id, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_SFLOW_REF:
          if (length == 2)
            {
              proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_sflow_ref,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_SFLOW_ID:
          if (length == 4)
            {
              proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_sflow_id,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_RULE_PRI:
          if (length == 1)
            {
              proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_rule_pri,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_ACT_STATE:
          if (length == 1)
            {
              proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_act_state,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_DSA_ACTION:
          if (length == 1)
            {
              proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_dsc_act,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CFR_ERROR:
          dissect_clsfr_err (tvb, clsfr_tree, pos, length);
          break;
        case CFR_IP_CLASSIFIER:
          dissect_ip_classifier (tvb, clsfr_tree, pos, length);
          break;
        case CFR_ETH_CLASSIFIER:
          dissect_eth_clsfr (tvb, clsfr_tree, pos, length);
          break;
        case CFR_8021Q_CLASSIFIER:
          dissect_dot1q_clsfr (tvb, clsfr_tree, pos, length);
          break;
        case CFR_VENDOR_SPEC:
          proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_vendor_spc,
                               tvb, pos, length, FALSE);
          break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */



}

static void
dissect_doc10cos (tvbuff_t * tvb, proto_tree * tree, int start,
                  guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *doc10cos_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "1 Docsis 1.0 Class of Service (Length = %u)", len);
  doc10cos_tree = proto_item_add_subtree (it, ett_docsis_tlv_cos);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case 1:
          if (length == 1)
            {
              proto_tree_add_item (doc10cos_tree, hf_docsis_tlv_cos_id, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case 2:
          if (length == 2)
            {
              proto_tree_add_item (doc10cos_tree, hf_docsis_tlv_cos_sid, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_modemcap (tvbuff_t * tvb, proto_tree * tree, int start,
                  guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *mcap_tree;
  int pos = start;

  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "5 Modem Capabilities Type (Length = %u)", len);

  mcap_tree = proto_item_add_subtree (it, ett_docsis_tlv_mcap);
  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case CAP_CONCAT:
          if (length == 1)
            {
              proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_concat, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CAP_DOCSIS_VER:
          if (length == 1)
            {
              proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_docs_ver,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CAP_FRAG:
          if (length == 1)
            {
              proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_frag, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CAP_PHS:
          if (length == 1)
            {
              proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_phs, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CAP_IGMP:
          if (length == 1)
            {
              proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_igmp, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CAP_PRIVACY:
          if (length == 1)
            {
              proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_privacy, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CAP_DOWN_SAID:
          if (length == 1)
            {
              proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_down_said,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CAP_UP_SID:
          if (length == 1)
            {
              proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_up_sid, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CAP_OPT_FILT:
          if (length == 1)
            {
              proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_8021P_filter,
                                   tvb, pos, length, FALSE);
              proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_8021Q_filter,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CAP_XMIT_EQPERSYM:
          if (length == 1)
            {
              proto_tree_add_item (mcap_tree,
                                   hf_docsis_tlv_mcap_xmit_eq_taps_per_sym,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CAP_NUM_XMIT_EQ_TAPS:
          if (length == 1)
            {
              proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_xmit_eq_taps,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CAP_DCC:
          if (length == 1)
            {
              proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_dcc, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch (type) */
      pos = pos + length;
    }                           /* while (pos < pos+len) */

}

static void
dissect_cos (tvbuff_t * tvb, proto_tree * tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *cos_tree;
  int pos = start;

  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "4 Class of Service Type (Length = %u)", len);
  cos_tree = proto_item_add_subtree (it, ett_docsis_tlv_cos);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case COS_CLASSID:
          if (length == 1)
            {
              proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_id, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case COS_MAX_DOWN:
          if (length == 4)
            {
              proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_max_down, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case COS_MAX_UP:
          if (length == 4)
            {
              proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_max_up, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case COS_UP_CH_PRIO:
          if (length == 1)
            {
              proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_up_chnl_pri,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case COS_MIN_UP_RATE:
          if (length == 4)
            {
              proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_min_grntd_up,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case COS_MAX_UP_BURST:
          if (length == 2)
            {
              proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_max_up_burst,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case COS_BP_ENABLE:
          if (length == 1)
            {
              proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_privacy_enable,
                                   tvb, pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);

            }
          break;
        }                       /* switch (type) */
      pos = pos + length;
    }                           /* while (pos < pos+len) */

}

static void
dissect_svc_unavail(tvbuff_t * tvb, proto_tree * tree, int pos, guint16 length) {

  proto_item *svc_unavail_it;
  proto_tree *svc_unavail_tree;
  svc_unavail_it = proto_tree_add_item (tree,
                                        hf_docsis_tlv_svc_unavail,
                                        tvb, pos, length, FALSE);
  svc_unavail_tree = proto_item_add_subtree(svc_unavail_it, ett_docsis_tlv_svc_unavail );
  proto_tree_add_item (svc_unavail_tree,
                       hf_docsis_tlv_svc_unavail_classid, tvb,
                       pos, 1, FALSE);
  proto_tree_add_item (svc_unavail_tree,
                       hf_docsis_tlv_svc_unavail_type, tvb,
                       pos+1, 1, FALSE);
  proto_tree_add_item (svc_unavail_tree,
                       hf_docsis_tlv_svc_unavail_code, tvb,
                       pos+2, 1, FALSE);

}

static void
dissect_snmpv3_kickstart(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len) {
  proto_item *snmpv3_it;
  proto_tree *snmpv3_tree;
  guint8 type, length;
  int pos = start;

  snmpv3_it = proto_tree_add_item (tree,
                                   hf_docsis_tlv_snmpv3_kick,
                                   tvb, start, len, FALSE);
  snmpv3_tree = proto_item_add_subtree(snmpv3_it, ett_docsis_tlv_snmpv3_kick);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case SNMPV3_SEC_NAME:
          proto_tree_add_item (snmpv3_tree,
                               hf_docsis_tlv_snmpv3_kick_name, tvb,
                               pos, length, FALSE);
          break;
        case SNMPV3_MGR_PUB_NUM:
          proto_tree_add_item (snmpv3_tree,
                               hf_docsis_tlv_snmpv3_kick_publicnum, tvb,
                               pos, length, FALSE);
          break;
        }  /* switch */
      pos += length;
    }   /* while */
}

static void
dissect_ds_ch_list_single (tvbuff_t * tvb, proto_tree * tree,
                           int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *single_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "1 Single Downstream Channel (Length = %u)", len);
  single_tree = proto_item_add_subtree (it, ett_docsis_tlv_ds_ch_list_single);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case SINGLE_CH_TIMEOUT:
          if (length == 2)
            {
              proto_tree_add_item (single_tree, hf_docsis_tlv_single_ch_timeout, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SINGLE_CH_FREQ:
          if (length == 4)
            {
              proto_tree_add_item (single_tree, hf_docsis_tlv_single_ch_freq, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }  /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_ds_ch_list_range (tvbuff_t * tvb, proto_tree * tree,
                          int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *range_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "2 Downstream Frequency Range (Length = %u)", len);
  range_tree = proto_item_add_subtree (it, ett_docsis_tlv_ds_ch_list_range);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case FREQ_RNG_TIMEOUT:
          if (length == 2)
            {
              proto_tree_add_item (range_tree, hf_docsis_tlv_freq_rng_timeout, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case FREQ_RNG_START:
          if (length == 4)
            {
              proto_tree_add_item (range_tree, hf_docsis_tlv_freq_rng_start, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case FREQ_RNG_END:
          if (length == 4)
            {
              proto_tree_add_item (range_tree, hf_docsis_tlv_freq_rng_end, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case FREQ_RNG_STEP:
          if (length == 4)
            {
              proto_tree_add_item (range_tree, hf_docsis_tlv_freq_rng_step, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                           /* switch */
      pos = pos + length;
    }                             /* while */
}

static void
dissect_dut_filter (tvbuff_t * tvb, proto_tree * tree,
                    int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *dut_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "Downstream Unencrypted Traffic (Length = %u)", len);
  dut_tree = proto_item_add_subtree (it, ett_docsis_tlv_dut_filter);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case DUT_CONTROL:
          if (length == 1)
            {
              proto_tree_add_item (dut_tree, hf_docsis_tlv_dut_filter_control, tvb,
                                   pos, length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case DUT_CMIM:
          proto_tree_add_item (dut_tree, hf_docsis_tlv_dut_filter_cmim, tvb,
                                   pos, length, FALSE);
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_ds_ch_list(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *dschlst_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "41 Downstream Channel List (Length = %u)", len);
  dschlst_tree = proto_item_add_subtree (it, ett_docsis_tlv_ds_ch_list);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case DS_CH_LIST_SINGLE:
      dissect_ds_ch_list_single(tvb, dschlst_tree, pos, length);
          break;
        case DS_CH_LIST_RANGE:
      dissect_ds_ch_list_range(tvb, dschlst_tree, pos, length);
          break;
        case DS_CH_LIST_DEFAULT_TIMEOUT:
          if (length == 2)
            {
              proto_tree_add_item (dschlst_tree,
                                   hf_docsis_tlv_ds_ch_list_default_timeout, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_tcc_err(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *tccerr_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "TCC Error Encodings (Length = %u)", len);
  tccerr_tree = proto_item_add_subtree (it, ett_docsis_tlv_tcc_err);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case TCC_ERR_SUBTYPE:
          proto_tree_add_item (tccerr_tree,
                               hf_docsis_tcc_err_subtype, tvb,
                               pos, length, FALSE);
          break;
        case TCC_ERR_CODE:
          if (length == 1)
            {
              proto_tree_add_item (tccerr_tree,
                                   hf_docsis_tcc_err_code, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TCC_ERR_MSG:
          proto_tree_add_item (tccerr_tree,
                               hf_docsis_tcc_err_msg, tvb,
                               pos, length, FALSE);
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_tcc_rng_parms(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *rngparm_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "Ranging Parameters (Length = %u)", len);
  rngparm_tree = proto_item_add_subtree (it, ett_docsis_tlv_tcc_rng_parms);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case RNG_PARMS_US_CH_ID:
          if (length == 1)
            {
              proto_tree_add_item (rngparm_tree,
                                   hf_docsis_rng_parms_us_ch_id, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RNG_PARMS_TIME_OFF_INT:
          if (length == 4)
            {
              proto_tree_add_item (rngparm_tree,
                                   hf_docsis_rng_parms_time_off_int, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RNG_PARMS_TIME_OFF_FRAC:
          if (length == 1)
            {
              proto_tree_add_item (rngparm_tree,
                                   hf_docsis_rng_parms_time_off_frac, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RNG_PARMS_POWER_OFF:
          if (length == 1)
            {
              proto_tree_add_item (rngparm_tree,
                                   hf_docsis_rng_parms_power_off, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RNG_PARMS_FREQ_OFF:
          if (length == 1)
            {
              proto_tree_add_item (rngparm_tree,
                                   hf_docsis_rng_parms_freq_off, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_sid_cl_so_crit(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *crit_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "SID Cluster Switchover Criteria (Length = %u)", len);
  crit_tree = proto_item_add_subtree (it, ett_docsis_tlv_sid_cl_so);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case SID_CL_SO_MAX_REQ:
          if (length == 1)
            {
              proto_tree_add_item (crit_tree,
                                   hf_docsis_sid_cl_so_max_req, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SID_CL_SO_MAX_OUT_BYTES:
          if (length == 4)
            {
              proto_tree_add_item (crit_tree,
                                   hf_docsis_sid_cl_so_max_out_bytes, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SID_CL_SO_MAX_REQ_BYTES:
          if (length == 4)
            {
              proto_tree_add_item (crit_tree,
                                   hf_docsis_sid_cl_so_max_req_bytes, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SID_CL_SO_MAX_TIME:
          if (length == 2)
            {
              proto_tree_add_item (crit_tree,
                                   hf_docsis_sid_cl_so_max_time, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_sid_cl_enc_map(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *map_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "SID-to-Channel Mapping (Length = %u)", len);
  map_tree = proto_item_add_subtree (it, ett_docsis_tlv_sid_cl_enc_map);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case SID_CL_MAP_US_CH_ID:
          if (length == 1)
            {
              proto_tree_add_item (map_tree,
                                   hf_docsis_sid_cl_map_us_ch_id, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SID_CL_MAP_SID:
          if (length == 2)
            {
              proto_tree_add_item (map_tree,
                                   hf_docsis_sid_cl_map_sid, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SID_CL_MAP_ACTION:
          if (length == 1)
            {
              proto_tree_add_item (map_tree,
                                   hf_docsis_sid_cl_map_action, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_sid_cl_enc(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *enc_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "SID Cluster Encoding (Length = %u)", len);
  enc_tree = proto_item_add_subtree (it, ett_docsis_tlv_sid_cl_enc);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case SID_CL_ENC_ID:
          if (length == 1)
            {
              proto_tree_add_item (enc_tree,
                                   hf_docsis_sid_cl_enc_id, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SID_CL_ENC_MAP:
          if (length == 10)
             dissect_sid_cl_enc_map(tvb, enc_tree, pos, length);
          else
              THROW (ReportedBoundsError);
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_sid_cl(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *sid_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "47 Service Flow SID Cluster Assignments (Length = %u)", len);
  sid_tree = proto_item_add_subtree (it, ett_docsis_tlv_sid_cl);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case SID_CL_SF_ID:
          if (length == 4)
            {
              proto_tree_add_item (sid_tree,
                                   hf_docsis_sid_cl_sf_id, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case SID_CL_ENC:
          dissect_sid_cl_enc(tvb, sid_tree, pos, length);
          break;
        case SID_CL_SO_CRIT:
          dissect_sid_cl_so_crit(tvb, sid_tree, pos, length);
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_tcc(tvbuff_t * tvb, packet_info * pinfo _U_,
            proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *tcc_tree;
  int pos = start;
  tvbuff_t *ucd_tvb;

  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "46 Transmit Channel Configuration (Length = %u)", len);
  tcc_tree = proto_item_add_subtree (it, ett_docsis_tlv_tcc);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case TLV_TCC_REFID:
          if (length == 1)
            {
              proto_tree_add_item (tcc_tree,
                                   hf_docsis_tlv_tcc_refid, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_TCC_US_CH_ACTION:
          if (length == 1)
            {
              proto_tree_add_item (tcc_tree,
                                   hf_docsis_tlv_tcc_us_ch_action, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_TCC_US_CH_ID:
          if (length == 1)
            {
              proto_tree_add_item (tcc_tree,
                                   hf_docsis_tlv_tcc_us_ch_id, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_TCC_NEW_US_CH_ID:
          if (length == 1)
            {
              proto_tree_add_item (tcc_tree,
                                   hf_docsis_tlv_tcc_new_us_ch_id, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_TCC_UCD:
          ucd_tvb = tvb_new_subset (tvb, pos, length, length);
          call_dissector (docsis_ucd_handle, ucd_tvb, pinfo, tcc_tree);
          break;
        case TLV_TCC_RNG_SID:
          if (length == 2)
            {
              proto_tree_add_item (tcc_tree,
                                   hf_docsis_tlv_tcc_rng_sid, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_TCC_INIT_TECH:
          if (length == 1)
            {
              proto_tree_add_item (tcc_tree,
                                   hf_docsis_tlv_tcc_init_tech, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_TCC_RNG_PARMS:
          dissect_tcc_rng_parms(tvb, tcc_tree, pos, length);
          break;
        case TLV_TCC_DYN_RNG_WIN:
          if (length == 1)
            {
              proto_tree_add_item (tcc_tree,
                                   hf_docsis_tlv_tcc_dyn_rng_win, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_TCC_ERR:
          dissect_tcc_err(tvb, tcc_tree, pos, length);
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_ch_bl_rng(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *chblrng_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "Receive Module Channel Block Range (Length = %u)", len);
  chblrng_tree = proto_item_add_subtree (it, ett_docsis_tlv_rcp_ch_bl_rng);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case CH_BL_RNG_MIN_CTR_FREQ:
          if (length == 4)
            {
              proto_tree_add_item (chblrng_tree,
                                   hf_docsis_ch_bl_rng_min_ctr_freq, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CH_BL_RNG_MAX_CTR_FREQ:
          if (length == 4)
            {
              proto_tree_add_item (chblrng_tree,
                                   hf_docsis_ch_bl_rng_max_ctr_freq, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcp_rcv_mod(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *rcvmod_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "Receive Module Capability (Length = %u)", len);
  rcvmod_tree = proto_item_add_subtree (it, ett_docsis_tlv_rcp_rcv_mod_enc);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case RCV_MOD_ENC_IDX:
          if (length == 1)
            {
              proto_tree_add_item (rcvmod_tree,
                                   hf_docsis_rcv_mod_enc_idx, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RCV_MOD_ENC_CH_BL_RNG:
          dissect_ch_bl_rng(tvb, rcvmod_tree, pos, length);
          break;
        case RCV_MOD_ENC_CTR_FREQ_ASGN:
          if (length == 4)
            {
              proto_tree_add_item (rcvmod_tree,
                                   hf_docsis_rcv_mod_enc_ctr_freq_asgn, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RCV_MOD_ENC_RSQ_CH_SUBS_CAP:
          proto_tree_add_item (rcvmod_tree,
                   hf_docsis_rcv_mod_enc_rsq_ch_subs_cap, tvb, pos,
                   length, FALSE);
          break;
        case RCV_MOD_ENC_CONN:
          proto_tree_add_item (rcvmod_tree,
                   hf_docsis_rcv_mod_enc_conn, tvb, pos,
                   length, FALSE);
          break;
        case RCV_MOD_ENC_PHY_LAYR_PARMS:
          proto_tree_add_item (rcvmod_tree,
                   hf_docsis_rcv_mod_enc_phy_layr_parms, tvb, pos,
                   length, FALSE);
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcp_rcv_ch(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *rcvch_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "Receive Channels (Length = %u)", len);
  rcvch_tree = proto_item_add_subtree (it, ett_docsis_tlv_rcp_rcv_ch);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case RCV_CH_IDX:
          if (length == 1)
            {
              proto_tree_add_item (rcvch_tree,
                                   hf_docsis_rcv_ch_idx, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RCV_CH_CONN:
          proto_tree_add_item (rcvch_tree,
                           hf_docsis_rcv_ch_conn, tvb, pos,
                           length, FALSE);
          break;
        case RCV_CH_CONN_OFF:
          if (length == 1)
            {
              proto_tree_add_item (rcvch_tree,
                                   hf_docsis_rcv_ch_conn_off, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RCV_CH_PRIM_DS_CH_IND:
          if (length == 1)
            {
              proto_tree_add_item (rcvch_tree,
                                   hf_docsis_rcv_ch_prim_ds_ch_ind, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}


static void
dissect_rcp(tvbuff_t * tvb, packet_info * pinfo _U_,
            proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *rcp_tree;
  int pos = start;
  tvbuff_t *vsif_tvb;

  it =
    proto_tree_add_text (tree, tvb, start, len,
                          "48 Receive Channel Profile (Length = %u)", len);
  rcp_tree = proto_item_add_subtree (it, ett_docsis_tlv_rcp);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case TLV_RCP_ID:
          if (length == 5)
            {
              proto_tree_add_item (rcp_tree,
                                   hf_docsis_tlv_rcp_id, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_RCP_NAME:
          if (length <= 15)
            {
              proto_tree_add_item (rcp_tree,
                                   hf_docsis_tlv_rcp_name, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_RCP_FREQ_SPC:
          if (length == 1)
            {
              proto_tree_add_item (rcp_tree,
                                   hf_docsis_tlv_rcp_freq_spc, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_RCP_RCV_MOD_ENC:
          dissect_rcp_rcv_mod(tvb, rcp_tree, pos, length);
          break;
        case TLV_RCP_RCV_CH:
          dissect_rcp_rcv_ch(tvb, rcp_tree, pos, length);
          break;
        case TLV_RCP_VEN_SPEC:
          vsif_tvb = tvb_new_subset (tvb, pos, length, length);
          call_dissector (docsis_vsif_handle, vsif_tvb, pinfo, rcp_tree);
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcc_rcv_mod(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *rcvmod_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "Receive Module Assignment (Length = %u)", len);
  rcvmod_tree = proto_item_add_subtree (it, ett_docsis_tlv_rcc_rcv_mod_enc);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case RCV_MOD_ENC_IDX:
          if (length == 1)
            {
              proto_tree_add_item (rcvmod_tree,
                                   hf_docsis_rcc_rcv_mod_enc_idx, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RCV_MOD_ENC_CTR_FREQ_ASGN:
          if (length == 4)
            {
              proto_tree_add_item (rcvmod_tree,
                                   hf_docsis_rcc_rcv_mod_enc_ctr_freq_asgn, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RCV_MOD_ENC_CONN:
          proto_tree_add_item (rcvmod_tree,
                   hf_docsis_rcc_rcv_mod_enc_conn, tvb, pos,
                   length, FALSE);
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcc_rcv_ch(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *rcvch_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "Receive Channels (Length = %u)", len);
  rcvch_tree = proto_item_add_subtree (it, ett_docsis_tlv_rcc_rcv_ch);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case RCV_CH_IDX:
          if (length == 1)
            {
              proto_tree_add_item (rcvch_tree,
                                   hf_docsis_rcc_rcv_ch_idx, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RCV_CH_CONN:
          proto_tree_add_item (rcvch_tree,
                           hf_docsis_rcc_rcv_ch_conn, tvb, pos,
                           length, FALSE);
          break;
        case RCV_CH_CTR_FREQ_ASGN:
          if (length == 4)
            {
              proto_tree_add_item (rcvch_tree,
                                   hf_docsis_rcc_rcv_ch_ctr_freq_asgn, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RCV_CH_PRIM_DS_CH_IND:
          if (length == 1)
            {
              proto_tree_add_item (rcvch_tree,
                                   hf_docsis_rcc_rcv_ch_prim_ds_ch_ind, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcc_err(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *err_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "RCC Error Encodings (Length = %u)", len);
  err_tree = proto_item_add_subtree (it, ett_docsis_tlv_rcc_rcv_ch);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case RCC_ERR_MOD_OR_CH:
          if (length == 1)
            {
              proto_tree_add_item (err_tree,
                                   hf_docsis_tlv_rcc_err_mod_or_ch, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RCC_ERR_IDX:
          if (length == 1)
            {
              proto_tree_add_item (err_tree,
                                   hf_docsis_tlv_rcc_err_idx, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RCC_ERR_PARAM:
          if (length == 1)
            {
              proto_tree_add_item (err_tree,
                                   hf_docsis_tlv_rcc_err_param, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RCC_ERR_CODE:
          if (length == 1)
            {
              proto_tree_add_item (err_tree,
                                   hf_docsis_tlv_rcc_err_code, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case RCC_ERR_MSG:
          proto_tree_add_item (err_tree,
                               hf_docsis_tlv_rcc_err_msg, tvb, pos,
                               length, FALSE);
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcc(tvbuff_t * tvb, packet_info * pinfo _U_,
            proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *rcc_tree;
  int pos = start;
  tvbuff_t *vsif_tvb;

  it =
    proto_tree_add_text (tree, tvb, start, len,
                          "49 Receive Channel Configuration (Length = %u)", len);
  rcc_tree = proto_item_add_subtree (it, ett_docsis_tlv_rcc);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case TLV_RCP_ID:
          if (length == 5)
            {
              proto_tree_add_item (rcc_tree,
                                   hf_docsis_tlv_rcc_id, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_RCP_RCV_MOD_ENC:
          dissect_rcc_rcv_mod(tvb, rcc_tree, pos, length);
          break;
        case TLV_RCP_RCV_CH:
          dissect_rcc_rcv_ch(tvb, rcc_tree, pos, length);
          break;
        case TLV_RCP_VEN_SPEC:
          vsif_tvb = tvb_new_subset (tvb, pos, length, length);
          call_dissector (docsis_vsif_handle, vsif_tvb, pinfo, rcc_tree);
          break;
        case TLV_RCC_ERR:
          dissect_rcc_err(tvb, rcc_tree, pos, length);
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_dsid_ds_reseq(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *dsid_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "Resequencing DSID (Length = %u)", len);
  dsid_tree = proto_item_add_subtree (it, ett_docsis_tlv_dsid_ds_reseq);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case DS_RESEQ_DSID:
          if (length == 1)
            {
              proto_tree_add_item (dsid_tree,
                                   hf_docsis_ds_reseq_dsid, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case DS_RESEQ_CH_LST:
          proto_tree_add_item (dsid_tree,
                           hf_docsis_ds_reseq_ch_lst, tvb, pos,
                           length, FALSE);
          break;
        case DS_RESEQ_WAIT_TIME:
          if (length == 1)
            {
              proto_tree_add_item (dsid_tree,
                                   hf_docsis_ds_reseq_wait_time, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case DS_RESEQ_WARN_THRESH:
          if (length == 1)
            {
              proto_tree_add_item (dsid_tree,
                                   hf_docsis_ds_reseq_warn_thresh, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case DS_RESEQ_HO_TIMER:
          if (length == 2)
            {
              proto_tree_add_item (dsid_tree,
                                   hf_docsis_ds_reseq_ho_timer, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_dsid_mc_addr(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *dsid_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "Client MAC Address Encodings (Length = %u)", len);
  dsid_tree = proto_item_add_subtree (it, ett_docsis_tlv_dsid_mc_addr);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case MC_ADDR_ACTION:
          if (length == 1)
            {
              proto_tree_add_item (dsid_tree,
                                   hf_docsis_mc_addr_action, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case MC_ADDR_ADDR:
          if (length == 6)
            {
              proto_tree_add_item (dsid_tree,
                                   hf_docsis_mc_addr_addr, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_dsid_mc(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *dsid_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "Multicast Encodings (Length = %u)", len);
  dsid_tree = proto_item_add_subtree (it, ett_docsis_tlv_dsid_mc);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case TLV_DSID_MC_ADDR:
          dissect_dsid_mc_addr(tvb, dsid_tree, pos, length);
          break;
        case TLV_DSID_MC_CMIM:
          proto_tree_add_item (dsid_tree,
                               hf_docsis_tlv_dsid_mc_cmim, tvb, pos,
                               length, FALSE);
          break;
        case TLV_DSID_MC_GROUP:
          proto_tree_add_item (dsid_tree,
                               hf_docsis_tlv_dsid_mc_group, tvb, pos,
                               length, FALSE);
          break;
    case TLV_DSID_MC_PHS:
          dissect_phs(tvb, dsid_tree, pos, length);
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_dsid(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *dsid_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "50 DSID Encodings (Length = %u)", len);
  dsid_tree = proto_item_add_subtree (it, ett_docsis_tlv_dsid);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case TLV_DSID_ID:
          if (length == 3)
            {
              proto_tree_add_item (dsid_tree,
                                   hf_docsis_tlv_dsid_id, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_DSID_ACTION:
          if (length == 1)
            {
              proto_tree_add_item (dsid_tree,
                                   hf_docsis_tlv_dsid_action, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_DSID_DS_RESEQ:
          dissect_dsid_ds_reseq(tvb, dsid_tree, pos, length);
          break;
        case TLV_DSID_MC:
          dissect_dsid_mc(tvb, dsid_tree, pos, length);
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_sec_assoc(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *sec_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "51 Security Association Encodings (Length = %u)", len);
  sec_tree = proto_item_add_subtree (it, ett_docsis_tlv_dsid);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case TLV_SEC_ASSOC_ACTION:
          if (length == 1)
            {
              proto_tree_add_item (sec_tree,
                                   hf_docsis_tlv_sec_assoc_action, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_SEC_ASSOC_DESC:
          if (length == 14)
            {
              proto_tree_add_item (sec_tree,
                                   hf_docsis_tlv_sec_assoc_desc, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_ch_asgn(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *asgn_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "56 Channel Assignment Configuration Settings (Length = %u)", len);
  asgn_tree = proto_item_add_subtree (it, ett_docsis_tlv_ch_asgn);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case TLV_CH_ASGN_US_CH_ID:
          if (length == 1)
            {
              proto_tree_add_item (asgn_tree,
                                   hf_docsis_ch_asgn_us_ch_id, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case TLV_CH_ASGN_RX_FREQ:
          if (length == 4)
            {
              proto_tree_add_item (asgn_tree,
                                   hf_docsis_ch_asgn_rx_freq, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_cmts_mc_sess_enc(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *it;
  proto_tree *mc_tree;
  int pos = start;
  it =
    proto_tree_add_text (tree, tvb, start, len,
                         "64 CMTS Static Multicast Session Encoding (Length = %u)", len);
  mc_tree = proto_item_add_subtree (it, ett_docsis_cmts_mc_sess_enc);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case CMTS_MC_SESS_ENC_GRP:
          if (length == 4 || length == 16)
            {
              proto_tree_add_item (mc_tree,
                                   hf_docsis_cmts_mc_sess_enc_grp, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CMTS_MC_SESS_ENC_SRC:
          if (length == 4 || length == 16)
            {
              proto_tree_add_item (mc_tree,
                                   hf_docsis_cmts_mc_sess_enc_src, tvb, pos,
                                   length, FALSE);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}


static void
dissect_tlv (tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree)
{

  proto_item *it;
  proto_tree *tlv_tree;
  int pos = 0;
  gint total_len;
  guint8 type, length;
  guint16 x;
  tvbuff_t *vsif_tvb;

  total_len = tvb_reported_length_remaining (tvb, 0);

  {
    it =
      proto_tree_add_protocol_format (tree, proto_docsis_tlv, tvb, 0,
                                      total_len, "TLV Data");
    tlv_tree = proto_item_add_subtree (it, ett_docsis_tlv);
    while (pos < total_len)
      {
        type = tvb_get_guint8 (tvb, pos++);
        length = tvb_get_guint8 (tvb, pos++);
        switch (type)
          {
          case TLV_DOWN_FREQ:
            /* This is ugly.  There are multiple type 1 TLV's that may appear
             * in the TLV data, the problem is that they are dependent on
             * message type.  */
            if (length == 4)
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_down_freq, tvb,
                                   pos, length, FALSE);
            else if (length == 1)
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_rng_tech, tvb,
                                   pos, length, FALSE);
            else
              dissect_doc10cos (tvb, tlv_tree, pos, length);
            break;
          case TLV_CHNL_ID:
            if (length == 1)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_upstream_chid,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_NET_ACCESS:
            if (length == 1)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_net_access,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_COS:
            dissect_cos (tvb, tlv_tree, pos, length);
            break;
          case TLV_MODEM_CAP:
            dissect_modemcap (tvb, tlv_tree, pos, length);
            break;
          case TLV_CM_MIC:
            if (length == 16)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_cm_mic, tvb,
                                     pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_CMTS_MIC:
            if (length == 16)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_cmts_mic, tvb,
                                     pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_VENDOR_ID:
            if (length == 3)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_vendor_id, tvb,
                                     pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_SW_UPG_FILE:
            proto_tree_add_item (tlv_tree, hf_docsis_tlv_sw_file, tvb, pos,
                                 length, FALSE);
            break;
          case TLV_SNMP_WRITE_CTRL:
            proto_tree_add_item (tlv_tree, hf_docsis_tlv_snmp_access, tvb,
                                 pos, length, FALSE);
            break;
          case TLV_SNMP_OBJECT:
            proto_tree_add_item (tlv_tree, hf_docsis_tlv_snmp_obj, tvb,
                                 pos, length, FALSE);
            break;
          case TLV_MODEM_IP:
            if (length == 4)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_modem_addr,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_SVC_UNAVAIL:
            if (length == 3)
              {
                dissect_svc_unavail(tvb, tlv_tree, pos, length);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_ETHERNET_MAC:
            if (length == 6)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_cpe_ethernet,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_TEL_SETTINGS:
            break;
          case TLV_BPI_CONFIG:
            proto_tree_add_item (tlv_tree, hf_docsis_tlv_bpi, tvb,
                                 pos, length, FALSE);
            break;
          case TLV_MAX_CPES:
            if (length == 1)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_max_cpe, tvb,
                                     pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_TFTP_TIME:
            if (length == 4)
              {
                proto_tree_add_item (tlv_tree,
                                     hf_docsis_tlv_tftp_server_timestamp,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_TFTP_MODEM_ADDRESS:
            if (length == 4)
              {
                proto_tree_add_item (tlv_tree,
                                     hf_docsis_tlv_tftp_prov_modem_address,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_SW_UPG_SRVR:
            if (length == 4)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_sw_upg_srvr,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_UPSTREAM_CLASSIFIER:
          case TLV_DOWN_CLASSIFIER:
            dissect_classifiers (tvb, tlv_tree, pos, length, type);
            break;
          case TLV_UPSTREAM_SERVICE_FLOW:
          case TLV_DOWN_SERVICE_FLOW:
            dissect_sflow (tvb, tlv_tree, pos, length, type);
            break;
          case TLV_PHS:
            dissect_phs (tvb, tlv_tree, pos, length);
            break;
          case TLV_HMAC_DIGEST:
            if (length == 20)
              {
                proto_tree_add_item (tlv_tree,
                                     hf_docsis_tlv_hmac_digest, tvb,
                                     pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_MAX_CLASSIFIERS:
            if (length == 2)
              {
                proto_tree_add_item (tlv_tree,
                                     hf_docsis_tlv_max_classifiers, tvb,
                                     pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_PRIVACY_ENABLE:
            if (length == 1)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_privacy_enable,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_AUTH_BLOCK:
            proto_tree_add_item (tlv_tree, hf_docsis_tlv_auth_block,
                                 tvb, pos, length, FALSE);
            break;
          case TLV_KEY_SEQ_NUM:
            if (length == 1)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_key_seq_num, tvb,
                                     pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_MFGR_CVC:
            proto_tree_add_item (tlv_tree, hf_docsis_tlv_mfgr_cvc,
                                 tvb, pos, length, FALSE);
            break;
          case TLV_COSIGN_CVC:
            proto_tree_add_item (tlv_tree, hf_docsis_tlv_cosign_cvc,
                                 tvb, pos, length, FALSE);
            break;
          case TLV_SNMPV3_KICKSTART:
            dissect_snmpv3_kickstart(tvb, tlv_tree, pos, length);
            break;
          case TLV_SUBS_MGMT_CTRL:
            proto_tree_add_item (tlv_tree, hf_docsis_tlv_subs_mgmt_ctrl,
                                 tvb, pos, length, FALSE);
            break;
          case TLV_SUBS_MGMT_CPE:
            if ((length % 4) == 0)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_subs_mgmt_ip_table,
                                     tvb, pos, length, FALSE);
                for (x = 0; x < length; x+=4)
                  {
                    proto_tree_add_item (tlv_tree,
                                         hf_docsis_tlv_subs_mgmt_ip_entry,
                                         tvb, pos + x, 4, FALSE);
                  }
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_SUBS_MGMT_FLTR:
            proto_tree_add_item (tlv_tree,
                                 hf_docsis_tlv_subs_mgmt_filter_grps,
                                 tvb, pos, length, FALSE);
            break;
          case TLV_SNMPV3_NTFY_RCVR:
            proto_tree_add_item(tlv_tree,
                                hf_docsis_tlv_snmpv3_ntfy_rcvr,
                                tvb, pos, length, FALSE);
            break;
          case TLV_ENABLE_20_MODE:
            if (length == 1)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_enable_20_mode,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_ENABLE_TEST_MODES:
            if (length == 1)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_enable_test_modes,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_DS_CH_LIST:
            dissect_ds_ch_list(tvb, tlv_tree, pos, length);
            break;
          case TLV_MC_MAC_ADDRESS:
            if (length == 6)
              {
                proto_tree_add_item(tlv_tree, hf_docsis_tlv_mc_mac_address,
                                    tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_VENDOR_SPEC:
            vsif_tvb = tvb_new_subset (tvb, pos, length, length);
            call_dissector (docsis_vsif_handle, vsif_tvb, pinfo, tlv_tree);
            break;
          case TLV_DUT_FILTER:
            dissect_dut_filter(tvb, tlv_tree, pos, length);
            break;
          case TLV_TCC:
            dissect_tcc(tvb, pinfo, tlv_tree, pos, length);
            break;
          case TLV_SID_CL:
            dissect_sid_cl(tvb, tlv_tree, pos, length);
            break;
          case TLV_RCP:
            dissect_rcp(tvb, pinfo, tlv_tree, pos, length);
            break;
          case TLV_RCC:
            dissect_rcc(tvb, pinfo, tlv_tree, pos, length);
            break;
          case TLV_DSID:
            dissect_dsid(tvb, tlv_tree, pos, length);
            break;
          case TLV_SEC_ASSOC:
            dissect_sec_assoc(tvb, tlv_tree, pos, length);
            break;
          case TLV_INIT_CH_TIMEOUT:
            if (length == 2)
              {
                proto_tree_add_item(tlv_tree, hf_docsis_tlv_init_ch_timeout,
                                    tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_CH_ASGN:
            dissect_ch_asgn(tvb, tlv_tree, pos, length);
            break;
          case TLV_CM_INIT_REASON:
            if (length == 1)
              {
                proto_tree_add_item(tlv_tree, hf_docsis_tlv_cm_init_reason,
                                    tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_SW_UPG_SRVR_IPV6:
            if (length == 16)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_sw_upg_srvr_ipv6,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_TFTP_PROV_CM_IPV6_ADDR:
            if (length == 16)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_tftp_prov_cm_ipv6_addr,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_US_DROP_CLFY:
            proto_tree_add_item (tlv_tree, hf_docsis_tlv_us_drop_clfy,
                                 tvb, pos, length, FALSE);
            break;
          case TLV_SUBS_MGMT_IPV6_LST:
            proto_tree_add_item (tlv_tree, hf_docsis_tlv_subs_mgmt_ipv6_lst,
                                 tvb, pos, length, FALSE);
            break;
          case TLV_US_DROP_CLFY_GROUP_ID:
            proto_tree_add_item (tlv_tree, hf_docsis_tlv_us_drop_clfy_group_id,
                                 tvb, pos, length, FALSE);
            break;
          case TLV_SUBS_MGMT_CTRL_MAX_CPE_IPV6:
            if (length == 2)
              {
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_subs_mgmt_ctrl_max_cpe_ipv6,
                                     tvb, pos, length, FALSE);
              }
            else
              {
                THROW (ReportedBoundsError);
              }
            break;
          case TLV_CMTS_MC_SESS_ENC:
            dissect_cmts_mc_sess_enc(tvb, tlv_tree, pos, length);
            break;
          case TLV_END:
            break;
          }                     /* switch(type) */

        pos = pos + length;
      }                         /* while (pos < total_len) */
  }                             /*if (tree) */

}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_tlv (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_tlv_down_freq,
     {"1 Downstream Frequency", "docsis_tlv.downfreq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Downstream Frequency", HFILL}
     },
    {&hf_docsis_tlv_upstream_chid,
     {"2 Upstream Channel ID", "docsis_tlv.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Service Identifier", HFILL}
     },
    {&hf_docsis_tlv_net_access,
     {"3 Network Access", "docsis_tlv.netaccess",
      FT_BOOLEAN, BASE_NONE, TFS (&on_off_tfs), 0x0,
      "Network Access TLV", HFILL}
     },
    {&hf_docsis_tlv_cos,
     {"4 COS Encodings", "docsis_tlv.cos",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_tlv_cos_id,
     {".1 Class ID", "docsis_tlv.cos.id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Class ID", HFILL}
     },
    {&hf_docsis_tlv_cos_sid,
     {".2 Service ID", "docsis_tlv.cos.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service ID", HFILL}
     },
    {&hf_docsis_tlv_cos_max_down,
     {".2 Max Downstream Rate (bps)", "docsis_tlv.cos.maxdown",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Max Downstream Rate", HFILL}
     },
    {&hf_docsis_tlv_cos_max_up,
     {".3 Max Upstream Rate (bps)", "docsis_tlv.cos.maxup",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Max Upstream Rate", HFILL}
     },
    {&hf_docsis_tlv_cos_up_chnl_pri,
     {".4 Upstream Channel Priority", "docsis_tlv.cos.upchnlpri",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel Priority", HFILL}
     },
    {&hf_docsis_tlv_cos_min_grntd_up,
     {".5 Guaranteed Upstream Rate", "docsis_tlv.cos.mingrntdup",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Guaranteed Minimum Upstream Data Rate", HFILL}
     },
    {&hf_docsis_tlv_cos_max_up_burst,
     {".6 Maximum Upstream Burst", "docsis_tlv.cos.maxupburst",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Maximum Upstream Burst", HFILL}
     },
    {&hf_docsis_tlv_cos_privacy_enable,
     {".7 COS Privacy Enable", "docsis_tlv.cos.privacy_enable",
      FT_BOOLEAN, BASE_NONE, TFS (&ena_dis_tfs), 0x0,
      "Class of Service Privacy Enable", HFILL}
     },
    {&hf_docsis_tlv_mcap,
     {"5 Modem Capabilities", "docsis_tlv.mcap",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Modem Capabilities", HFILL}
     },
    {&hf_docsis_tlv_mcap_concat,
     {".1 Concatenation Support", "docsis_tlv.mcap.concat",
      FT_BOOLEAN, BASE_NONE, TFS (&on_off_tfs), 0x0,
      "Concatenation Support", HFILL}
     },
    {&hf_docsis_tlv_mcap_docs_ver,
     {".2 Docsis Version", "docsis_tlv.map.docsver",
      FT_UINT8, BASE_DEC, VALS (docs_ver_vals), 0x0,
      "DOCSIS Version", HFILL}
     },
    {&hf_docsis_tlv_mcap_frag,
     {".3 Fragmentation Support", "docsis_tlv.mcap.frag",
      FT_BOOLEAN, BASE_NONE, TFS (&on_off_tfs), 0x0,
      "Fragmentation Support", HFILL}
     },
    {&hf_docsis_tlv_mcap_phs,
     {".4 PHS Support", "docsis_tlv.mcap.phs",
      FT_BOOLEAN, BASE_NONE, TFS (&on_off_tfs), 0x0,
      "PHS Support", HFILL}
     },
    {&hf_docsis_tlv_mcap_igmp,
     {".5 IGMP Support", "docsis_tlv.mcap.igmp",
      FT_BOOLEAN, BASE_NONE, TFS (&on_off_tfs), 0x0,
      "IGMP Support", HFILL}
     },
    {&hf_docsis_tlv_mcap_privacy,
     {".6 Privacy Support", "docsis_tlv.mcap.privacy",
      FT_BOOLEAN, BASE_NONE, TFS (&on_off_tfs), 0x0,
      "Privacy Support", HFILL}
     },
    {&hf_docsis_tlv_mcap_down_said,
     {".7 # Downstream SAIDs Supported", "docsis_tlv.mcap.downsaid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Downstream Said Support", HFILL}
     },
    {&hf_docsis_tlv_mcap_up_sid,
     {".8 # Upstream SAIDs Supported", "docsis_tlv.mcap.upsid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream SID Support", HFILL}
     },
    {&hf_docsis_tlv_mcap_8021P_filter,
     {".9 802.1P Filtering Support", "docsis_tlv.mcap.dot1pfiltering",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x80,
      "802.1P Filtering Support", HFILL}
     },
    {&hf_docsis_tlv_mcap_8021Q_filter,
     {".9 802.1Q Filtering Support", "docsis_tlv.mcap.dot1qfilt",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x40,
      "802.1Q Filtering Support", HFILL}
     },
    {&hf_docsis_tlv_mcap_xmit_eq_taps_per_sym,
     {".10 Xmit Equalizer Taps/Sym", "docsis_tlv.mcap.tapspersym",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Transmit Equalizer Taps per Symbol", HFILL}
     },
    {&hf_docsis_tlv_mcap_xmit_eq_taps,
     {".11 # Xmit Equalizer Taps", "docsis_tlv.mcap.numtaps",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Number of Transmit Equalizer Taps", HFILL}
     },
    {&hf_docsis_tlv_mcap_dcc,
     {".12 DCC Support", "docsis_tlv.mcap.dcc",
      FT_BOOLEAN, BASE_NONE, TFS (&on_off_tfs), 0x0,
      "DCC Support", HFILL}
     },
    {&hf_docsis_tlv_cm_mic,
     {"6 CM MIC", "docsis_tlv.cmmic",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Cable Modem Message Integrity Check", HFILL}
     },
    {&hf_docsis_tlv_cmts_mic,
     {"7 CMTS MIC", "docsis_tlv.cmtsmic",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "CMTS Message Integrity Check", HFILL}
     },
    {&hf_docsis_tlv_vendor_id,
     {"8 Vendor ID", "docsis_tlv.vendorid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Vendor Identifier", HFILL}
     },
    {&hf_docsis_tlv_sw_file,
     {"9 Software Upgrade File", "docsis_tlv.sw_upg_file",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Software Upgrade File", HFILL}
     },
    {&hf_docsis_tlv_snmp_access,
     {"10 SNMP Write Access", "docsis_tlv.snmp_access",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SNMP Write Access", HFILL}
     },
    {&hf_docsis_tlv_snmp_obj,
     {"11 SNMP Object", "docsis_tlv.snmp_obj",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SNMP Object", HFILL}
     },
    {&hf_docsis_tlv_modem_addr,
     {"12 Modem IP Address", "docsis_tlv.modemaddr",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "Modem IP Address", HFILL}
     },
    {&hf_docsis_tlv_svc_unavail,
     {"13 Service Not Available Response", "docsis_tlv.svcunavail",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Service Not Available Response", HFILL}
     },
    {&hf_docsis_tlv_svc_unavail_classid,
     {"Service Not Available: (Class ID)", "docsis_tlv.svcunavail.classid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Service Not Available (Class ID)", HFILL}
     },
    {&hf_docsis_tlv_svc_unavail_type,
     {"Service Not Available (Type)", "docsis_tlv.svcunavail.type",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_tlv_svc_unavail_code,
     {"Service Not Available (Code)", "docsis_tlv.svcunavail.code",
      FT_UINT8, BASE_DEC, VALS(docsis_conf_code), 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_tlv_cpe_ethernet,
     {"14 CPE Ethernet Addr", "docsis_tlv.cpe_ether",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      "CPE Ethernet Addr", HFILL}
     },
    {&hf_docsis_tlv_bpi,
     {"17 Baseline Privacy Encoding", "docsis_tlv.bpi",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Baseline Privacy Encoding", HFILL}
     },
    {&hf_docsis_tlv_max_cpe,
     {"18 Max # of CPE's", "docsis_tlv.maxcpe",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Max Number of CPE's", HFILL}
     },
    {&hf_docsis_tlv_tftp_server_timestamp,
     {"19 TFTP Server Timestamp", "docsis_tlv.tftp_time",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "TFTP Server TimeStamp", HFILL}
     },
    {&hf_docsis_tlv_tftp_prov_modem_address,
     {"20 TFTP Server Provisioned Modem Addr", "docsis_tlv.tftpmodemaddr",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "TFTP Server Provisioned Modem Addr", HFILL}
     },
    {&hf_docsis_tlv_sw_upg_srvr,
     {"21 Software Upgrade Server", "docsis_tlv.sw_upg_srvr",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "Software Upgrade Server", HFILL}
     },
    {&hf_docsis_tlv_upclsfr,
     {"22 Upstream Classifier", "docsis_tlv.upclsfr",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_tlv_downclsfr,
     {"23 Downstream Classifier", "docsis_tlv.downclsfr",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_tlv_clsfr_ref,
     {".1 Classifier Ref", "docsis_tlv.clsfr.ref",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Classifier Reference", HFILL}
     },
    {&hf_docsis_tlv_clsfr_id,
     {".2 Classifier ID", "docsis_tlv.clsfr.id",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Classifier ID", HFILL}
     },
    {&hf_docsis_tlv_clsfr_sflow_ref,
     {".3 Service Flow Ref", "docsis_tlv.clsfr.sflowref",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Flow Reference", HFILL}
     },
    {&hf_docsis_tlv_clsfr_sflow_id,
     {".4 Service Flow ID", "docsis_tlv.clsfr.sflowid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Flow ID", HFILL}
     },
    {&hf_docsis_tlv_clsfr_rule_pri,
     {".5 Rule Priority", "docsis_tlv.clsfr.rulepri",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Rule Priority", HFILL}
     },
    {&hf_docsis_tlv_clsfr_act_state,
     {".6 Activation State", "docsis_tlv.clsfr.actstate",
      FT_BOOLEAN, BASE_NONE, TFS (&activation_tfs), 0x0,
      "Classifier Activation State", HFILL}
     },
    {&hf_docsis_tlv_clsfr_dsc_act,
     {".7 DSC Action", "docsis_tlv.clsfr.dscact",
      FT_UINT8, BASE_DEC, VALS (dsc_act_vals), 0x0,
      "Dynamic Service Change Action", HFILL}
     },
    {&hf_docsis_tlv_clsfr_err,
     {".8 Error Encodings", "docsis_tlv.clsfr.err",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Error Encodings", HFILL}
     },
    {&hf_docsis_tlv_clsfr_err_param,
     {"..1 Param Subtype", "docsis_tlv.clsfr.err.param",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Parameter Subtype", HFILL}
     },
    {&hf_docsis_tlv_clsfr_err_code,
     {"..2 Error Code", "docsis_tlv.clsfr.err.code",
      FT_UINT8, BASE_DEC, VALS(docsis_conf_code), 0x0,
      "TCP/UDP Destination Port End", HFILL}
     },
    {&hf_docsis_tlv_clsfr_err_msg,
     {"..3 Error Message", "docsis_tlv.clsfr.err.msg",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Error Message", HFILL}
     },
    {&hf_docsis_tlv_ipclsfr,
     {".9 IP Classifier Encodings", "docsis_tlv.clsfr.ip",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "IP Classifier Encodings", HFILL}
     },
    {&hf_docsis_tlv_ipclsfr_tosmask,
     {"..1 Type Of Service Mask", "docsis_tlv.clsfr.ip.tosmask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Type Of Service Mask", HFILL}
     },
    {&hf_docsis_tlv_ipclsfr_ipproto,
     {"..2 IP Protocol", "docsis_tlv.clsfr.ip.ipproto",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "IP Protocol", HFILL}
     },
    {&hf_docsis_tlv_ipclsfr_src,
     {"..3 Source Address", "docsis_tlv.clsfr.ip.src",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "Source Address", HFILL}
     },
    {&hf_docsis_tlv_ipclsfr_dst,
     {"..4 Destination Address", "docsis_tlv.clsfr.ip.dst",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "Destination Address", HFILL}
     },
    {&hf_docsis_tlv_ipclsfr_srcmask,
     {"..5 Source Mask", "docsis_tlv.clsfr.ip.smask",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "Source Mask", HFILL}
     },
    {&hf_docsis_tlv_ipclsfr_dstmask,
     {"..6 Destination Mask", "docsis_tlv.clsfr.ip.dmask",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "Destination Mask", HFILL}
     },
    {&hf_docsis_tlv_ipclsfr_sport_start,
     {"..7 Source Port Start", "docsis_tlv.clsfr.ip.sportstart",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "TCP/UDP Source Port Start", HFILL}
     },
    {&hf_docsis_tlv_ipclsfr_sport_end,
     {"..8 Source Port End", "docsis_tlv.clsfr.ip.sportend",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "TCP/UDP Source Port End", HFILL}
     },
    {&hf_docsis_tlv_ipclsfr_dport_start,
     {"..9 Dest Port Start", "docsis_tlv.clsfr.ip.dportstart",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "TCP/UDP Destination Port Start", HFILL}
     },
    {&hf_docsis_tlv_ipclsfr_dport_end,
     {"..10 Dest Port End", "docsis_tlv.clsfr.ip.dportend",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "TCP/UDP Destination Port End", HFILL}
     },
    {&hf_docsis_tlv_ethclsfr,
     {".10 Ethernet Classifier Encodings", "docsis_tlv.clsfr.eth",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Ethernet Classifier Encodings", HFILL}
     },
    {&hf_docsis_tlv_ethclsfr_dmac,
     {"..1 Dest Mac Address", "docsis_tlv.clsfr.eth.dmac",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      "Destination Mac Address", HFILL}
     },
    {&hf_docsis_tlv_ethclsfr_smac,
     {"..2 Source Mac Address", "docsis_tlv.clsfr.eth.smac",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      "Source Mac Address", HFILL}
     },
    {&hf_docsis_tlv_ethclsfr_ethertype,
     {"..3 Ethertype", "docsis_tlv.clsfr.eth.ethertype",
      FT_UINT24, BASE_HEX, NULL, 0x0,
      "Ethertype", HFILL}
     },
    {&hf_docsis_tlv_dot1qclsfr,
     {".11 802.1Q Classifier Encodings", "docsis_tlv.clsfr.dot1q",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "802.1Q Classifier Encodings", HFILL}
     },
    {&hf_docsis_tlv_dot1qclsfr_user_pri,
     {"..1 User Priority", "docsis_tlv.clsfr.dot1q.userpri",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "User Priority", HFILL}
     },
    {&hf_docsis_tlv_dot1qclsfr_vlanid,
     {"..2 VLAN id", "docsis_tlv.clsfr.dot1q.ethertype",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "VLAN Id", HFILL}
     },
    {&hf_docsis_tlv_dot1qclsfr_vendorspec,
     {"..43 Vendor Specific Encodings", "docsis_tlv.clsfr.dot1q.vendorspec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Vendor Specific Encodings", HFILL}
     },
    {&hf_docsis_tlv_clsfr_vendor_spc,
     {".43 Vendor Specific Encodings", "docsis_tlv.clsfr.vendor",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Vendor Specific Encodings", HFILL}
     },
    {&hf_docsis_tlv_upsflow,
     {"24 Upstream Service Flow", "docsis_tlv.upsflow",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_tlv_downsflow,
     {"25 Downstream Service Flow", "docsis_tlv.downsflow",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_tlv_sflow_ref,
     {".1 Service Flow Ref", "docsis_tlv.sflow.ref",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Flow Reference", HFILL}
     },
    {&hf_docsis_tlv_sflow_id,
     {".2 Service Flow Id", "docsis_tlv.sflow.id",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Service Flow Id", HFILL}
     },
    {&hf_docsis_tlv_sflow_sid,
     {".3 Service Identifier", "docsis_tlv.sflow.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Identifier", HFILL}
     },
    {&hf_docsis_tlv_sflow_classname,
     {".4 Service Class Name", "docsis_tlv.sflow.cname",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Service Class Name", HFILL}
     },
    {&hf_docsis_tlv_sflow_err,
     {".5 Error Encodings", "docsis_tlv.sflow.err",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Error Encodings", HFILL}
     },
    {&hf_docsis_tlv_sflow_err_param,
     {"..1 Param Subtype", "docsis_tlv.sflow.err.param",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Parameter Subtype", HFILL}
     },
    {&hf_docsis_tlv_sflow_err_code,
     {"..2 Error Code", "docsis_tlv.sflow.err.code",
      FT_UINT8, BASE_DEC, VALS(docsis_conf_code), 0x0,
      "Error Code", HFILL}
     },
    {&hf_docsis_tlv_sflow_err_msg,
     {"..3 Error Message", "docsis_tlv.sflow.err.msg",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Error Message", HFILL}
     },
    {&hf_docsis_tlv_sflow_qos_param,
     {".6 QOS Parameter Set", "docsis_tlv.sflow.qos",
      FT_UINT8, BASE_HEX, VALS (qos_param_vals), 0x0,
      "QOS Parameter Set", HFILL}
     },
    {&hf_docsis_tlv_sflow_traf_pri,
     {".7 Traffic Priority", "docsis_tlv.sflow.trafpri",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Traffic Priority", HFILL}
     },
    {&hf_docsis_tlv_sflow_max_sus,
     {".8 Maximum Sustained Traffic Rate (bps)", "docsis_tlv.sflow.maxtrafrate",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Maximum Sustained Traffic Rate (bps)", HFILL}
     },
    {&hf_docsis_tlv_sflow_max_burst,
     {".9 Maximum Burst (bps)", "docsis_tlv.sflow.maxburst",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Maximum Burst (bps)", HFILL}
     },
    {&hf_docsis_tlv_sflow_min_traf,
     {".10 Minimum Traffic Rate (bps)", "docsis_tlv.sflow.mintrafrate",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Minimum Traffic Rate (bps)", HFILL}
     },
    {&hf_docsis_tlv_sflow_ass_min_pkt_size,
     {".11 Assumed Min Reserved Packet Size", "docsis_tlv.sflow.assumed_min_pkt_size",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Assumed Minimum Reserved Packet Size", HFILL}
     },
    {&hf_docsis_tlv_sflow_timeout_active,
     {".12 Timeout for Active Params (secs)", "docsis_tlv.sflow.act_timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Timeout for Active Params (secs)", HFILL}
     },
    {&hf_docsis_tlv_sflow_timeout_admitted,
     {".13 Timeout for Admitted Params (secs)", "docsis_tlv.sflow.adm_timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Timeout for Admitted Params (secs)", HFILL}
     },
    {&hf_docsis_tlv_sflow_max_down_latency,
     {".14 Maximum Downstream Latency (usec)", "docsis_tlv.sflow.max_down_lat",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Maximum Downstream Latency (usec)", HFILL}
     },
    {&hf_docsis_tlv_sflow_max_concat_burst,
     {".14 Max Concat Burst", "docsis_tlv.sflow.maxconcat",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Max Concatenated Burst", HFILL}
     },
    {&hf_docsis_tlv_sflow_sched_type,
     {".15 Scheduling Type", "docsis_tlv.sflow.schedtype",
      FT_UINT32, BASE_HEX, VALS (sched_type_vals), 0x0,
      "Scheduling Type", HFILL}
     },
    {&hf_docsis_tlv_sflow_reqxmit_pol,
     {".16 Request/Transmission Policy", "docsis_tlv.sflow.reqxmitpol",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "Request/Transmission Policy", HFILL}
     },
    {&hf_docsis_tlv_sflow_nominal_polling,
     {".17 Nominal Polling Interval(usec)", "docsis_tlv.sflow.nominal_polling",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Nominal Polling Interval(usec)", HFILL}
     },
    {&hf_docsis_tlv_sflow_tolerated_jitter,
     {".18 Tolerated Poll Jitter (usec)", "docsis_tlv.sflow.toler_jitter",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Tolerated Poll Jitter (usec)", HFILL}
     },
    {&hf_docsis_tlv_sflow_ugs_size,
     {".19 Unsolicited Grant Size (bytes)", "docsis_tlv.sflow.ugs_size",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Unsolicited Grant Size (bytes)", HFILL}
     },
    {&hf_docsis_tlv_sflow_nom_grant_intvl,
     {".20 Nominal Grant Interval (usec)", "docsis_tlv.sflow.nom_grant_intvl",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Nominal Grant Interval (usec)", HFILL}
     },
    {&hf_docsis_tlv_sflow_tol_grant_jitter,
     {".21 Tolerated Grant Jitter (usec)", "docsis_tlv.sflow.tol_grant_jitter",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Tolerated Grant Jitter (usec)", HFILL}
     },
    {&hf_docsis_tlv_sflow_grants_per_intvl,
     {".22 Grants Per Interval", "docsis_tlv.sflow.grnts_per_intvl",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Grants Per Interval", HFILL}
     },
    {&hf_docsis_tlv_sflow_ip_tos_overwrite,
     {".23 IP TOS Overwrite", "docsis_tlv.sflow.iptos_overwrite",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "IP TOS Overwrite", HFILL}
     },
    {&hf_docsis_tlv_sflow_ugs_timeref,
     {".24 UGS Time Reference", "docsis_tlv.sflow.ugs_timeref",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "UGS Time Reference", HFILL}
     },
    {&hf_docsis_tlv_sflow_vendor_spec,
     {".43 Vendor Specific Encodings", "docsis_tlv.sflow.vendorspec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Vendor Specific Encodings", HFILL}
     },
    {&hf_docsis_tlv_phs,
     {"26 PHS Rules", "docsis_tlv.phs",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "PHS Rules", HFILL}
     },
    {&hf_docsis_tlv_phs_class_ref,
     {".1 Classifier Reference", "docsis_tlv.phs.classref",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Classifier Reference", HFILL}
     },
    {&hf_docsis_tlv_phs_class_id,
     {".2 Classifier Id", "docsis_tlv.phs.classid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Classifier Id", HFILL}
     },
    {&hf_docsis_tlv_phs_sflow_ref,
     {".3 Service flow reference", "docsis_tlv.phs.sflowref",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Flow Reference", HFILL}
     },
    {&hf_docsis_tlv_phs_sflow_id,
     {".4 Service flow Id", "docsis_tlv.phs.sflowid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Flow Id", HFILL}
     },
    {&hf_docsis_tlv_phs_dsc_action,
     {".5 DSC Action", "docsis_tlv.phs.dscaction",
      FT_UINT8, BASE_DEC, VALS (action_vals), 0x0,
      "Dynamic Service Change Action", HFILL}
     },
    {&hf_docsis_tlv_phs_err,
     {".6 Error Encodings", "docsis_tlv.phs.err",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Error Encodings", HFILL}
     },
    {&hf_docsis_tlv_phs_err_param,
     {"..1 Param Subtype", "docsis_tlv.phs.err.param",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Parameter Subtype", HFILL}
     },
    {&hf_docsis_tlv_phs_err_code,
     {"..2 Error Code", "docsis_tlv.phs.err.code",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Error Code", HFILL}
     },
    {&hf_docsis_tlv_phs_err_msg,
     {"..3 Error Message", "docsis_tlv.phs.err.msg",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Error Message", HFILL}
     },
    {&hf_docsis_tlv_phs_phsf,
     {".7 PHS Field", "docsis_tlv.phs.phsf",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "PHS Field", HFILL}
     },
    {&hf_docsis_tlv_phs_phsi,
     {".8 PHS Index", "docsis_tlv.phs.phsi",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "PHS Index", HFILL}
     },
    {&hf_docsis_tlv_phs_phsm,
     {".9 PHS Mask", "docsis_tlv.phs.phsm",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "PHS Mask", HFILL}
     },
    {&hf_docsis_tlv_phs_phss,
     {".10 PHS Size", "docsis_tlv.phs.phss",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "PHS Size", HFILL}
     },
    {&hf_docsis_tlv_phs_phsv,
     {".11 PHS Verify", "docsis_tlv.phs.phsv",
      FT_BOOLEAN, BASE_NONE, TFS (&verify_tfs), 0x0,
      "PHS Verify", HFILL}
     },
    {&hf_docsis_tlv_phs_vendorspec,
     {".43 PHS Vendor Specific", "docsis_tlv.phs.vendorspec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "PHS Vendor Specific", HFILL}
     },
    {&hf_docsis_tlv_hmac_digest,
     {"27 HMAC Digest", "docsis_tlv.hmac_digest",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "HMAC Digest", HFILL}
     },
    {&hf_docsis_tlv_max_classifiers,
     {"28 Max # of Classifiers", "docsis_tlv.maxclass",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Max # of Classifiers", HFILL}
     },
    {&hf_docsis_tlv_privacy_enable,
     {"29 Privacy Enable", "docsis_tlv.bpi_en",
      FT_BOOLEAN, BASE_NONE, TFS (&ena_dis_tfs), 0x0,
      "Privacy Enable", HFILL}
     },
    {&hf_docsis_tlv_auth_block,
     {"30 Auth Block", "docsis_tlv.auth_block",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Auth Block", HFILL}
     },
    {&hf_docsis_tlv_key_seq_num,
     {"31 Key Sequence Number", "docsis_tlv.key_seq",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Key Sequence Number", HFILL}
     },
    {&hf_docsis_tlv_mfgr_cvc,
     {"32 Manufacturer CVC", "docsis_tlv.mfgr_cvc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Manufacturer CVC", HFILL}
     },
    {&hf_docsis_tlv_cosign_cvc,
     {"33 Co-Signer CVC", "docsis_tlv.cosign_cvc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Co-Signer CVC", HFILL}
     },
    {&hf_docsis_tlv_snmpv3_kick,
     {"34 SNMPv3 Kickstart Value", "docsis_tlv.snmpv3",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SNMPv3 Kickstart Value", HFILL}
     },
    {&hf_docsis_tlv_snmpv3_kick_name,
     {".1 SNMPv3 Kickstart Security Name", "docsis_tlv.snmpv3.secname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "SNMPv3 Kickstart Security Name", HFILL}
     },
    {&hf_docsis_tlv_snmpv3_kick_publicnum,
     {".2 SNMPv3 Kickstart Manager Public Number", "docsis_tlv.snmpv3.publicnum",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SNMPv3 Kickstart Value Manager Public Number", HFILL}
     },
    {&hf_docsis_tlv_subs_mgmt_ctrl,
     {"35 Subscriber Management Control", "docsis_tlv.subsmgmtctrl",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Subscriber Management Control", HFILL}
     },
    {&hf_docsis_tlv_subs_mgmt_ip_table,
     {"36 Subscriber Management CPE IP Table", "docsis_tlv.subsiptable",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Subscriber Management CPE IP Table", HFILL}
     },
    {&hf_docsis_tlv_subs_mgmt_ip_entry,
     {"Subscriber Management CPE IP Entry", "docsis_tlv.subsipentry",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_tlv_subs_mgmt_filter_grps,
     {"37 Subscriber Management Filter Groups", "docsis_tlv.subsfltrgrps",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Subscriber Management Filter Groups", HFILL}
     },
    {&hf_docsis_tlv_snmpv3_ntfy_rcvr,
     {"38 SNMPv3 Notification Receiver", "docsis_tlv.snmpv3ntfy",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SNMPv3 Notification Receiver", HFILL}
     },
    {&hf_docsis_tlv_enable_20_mode,
     {"39 Enable 2.0 Mode", "docsis_tlv.enable20mode",
      FT_BOOLEAN, BASE_NONE, TFS (&ena_dis_tfs), 0x0,
      "Enable 2.0 Mode", HFILL}
     },
    {&hf_docsis_tlv_enable_test_modes,
     {"40 Enable Test Modes", "docsis_tlv.enabletestmodes",
      FT_BOOLEAN, BASE_NONE, TFS (&ena_dis_tfs), 0x0,
      "Enable Test Modes", HFILL}
     },
    {&hf_docsis_tlv_ds_ch_list,
     {"41 Downstream Channel List", "docsis_tlv.dschlist",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_tlv_ds_ch_list_single,
     {".1 Single Downstream Channel", "docsis_tlv.dschlist.single",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_tlv_single_ch_timeout,
     {"..1 Timeout", "docsis_tlv.dschlist.single.timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Timeout", HFILL}
     },
    {&hf_docsis_tlv_single_ch_freq,
     {"..2 Timeout", "docsis_tlv.dschlist.single.freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Timeout", HFILL}
     },
    {&hf_docsis_tlv_ds_ch_list_range,
     {".2 Downstream Frequency Range", "docsis_tlv.dschlist.range",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_tlv_freq_rng_timeout,
     {"..1 Timeout", "docsis_tlv.dschlist.range.timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Timeout", HFILL}
     },
    {&hf_docsis_tlv_freq_rng_start,
     {"..2 Frequency Start", "docsis_tlv.dschlist.range.start",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Frequency Start", HFILL}
     },
    {&hf_docsis_tlv_freq_rng_end,
     {"..3 Frequency Start", "docsis_tlv.dschlist.range.end",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Frequency End", HFILL}
     },
    {&hf_docsis_tlv_freq_rng_step,
     {"..4 Frequency Step Size", "docsis_tlv.dschlist.range.step",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Frequency Step Size", HFILL}
     },
    {&hf_docsis_tlv_ds_ch_list_default_timeout,
     {".3 Default Scanning Timeout", "docsis_tlv.dschlist.defaulttimeout",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Default Scanning Timeout", HFILL}
     },
    {&hf_docsis_tlv_mc_mac_address,
     {"42 Static Multicast MAC Address", "docsis_tlv.mcmac",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      "Static Multicast MAC Address", HFILL}
     },
    {&hf_docsis_tlv_vendor_spec,
     {"43 Vendor Specific Encodings", "docsis_tlv.vendorspec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Vendor Specific Encodings", HFILL}
     },
    {&hf_docsis_tlv_rng_tech,
     {"Ranging Technique", "docsis_tlv.rng_tech",
      FT_UINT8, BASE_DEC, VALS (rng_tech_vals), 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_tlv_dut_filter,
     {"45 Downstream Unencrypted Traffic Filtering Encoding", "docsis_tlv.dut",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Downstream Unencrypted Traffic Filtering Encoding", HFILL}
     },
    {&hf_docsis_tlv_dut_filter_control,
     {".1 DUT Control", "docsis_tlv.dut.control",
      FT_BOOLEAN, BASE_NONE, TFS (&ena_dis_tfs), 0x0,
      "DUT Control", HFILL}
     },
    {&hf_docsis_tlv_dut_filter_cmim,
     {".2 DUT CMIM", "docsis_tlv.dut.cmim",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "DUT CMIM", HFILL}
     },
    {&hf_docsis_tlv_tcc,
     {"46 Transmit Channel Configuration", "docsis_tlv.tcc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Transmit Channel Configuration", HFILL}
     },
    {&hf_docsis_tlv_tcc_refid,
     {".1 TCC Reference ID", "docsis_tlv.tcc.refid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "TCC Reference ID", HFILL}
     },
    {&hf_docsis_tlv_tcc_us_ch_action,
     {".2 Upstream Channel Action", "docsis_tlv.tcc.uschact",
      FT_UINT8, BASE_DEC, VALS (us_ch_action_vals), 0x0,
      "Upstream Channel Action", HFILL}
     },
    {&hf_docsis_tlv_tcc_us_ch_id,
     {".3 Upstream Channel ID", "docsis_tlv.tcc.uschid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel ID", HFILL}
     },
    {&hf_docsis_tlv_tcc_new_us_ch_id,
     {".4 New Upstream Channel ID", "docsis_tlv.tcc.newuschid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "New Upstream Channel ID", HFILL}
     },
    {&hf_docsis_tlv_tcc_ucd,
     {".5 Upstream Channel Decsriptor", "docsis_tlv.tcc.ucd",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Upstream Channel Descriptor", HFILL}
     },
    {&hf_docsis_tlv_tcc_rng_sid,
     {".6 Ranging SID", "docsis_tlv.tcc.rngsid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Ranging SID", HFILL}
     },
    {&hf_docsis_tlv_tcc_init_tech,
     {".7 Initialization Technique", "docsis_tlv.tcc.inittech",
      FT_UINT8, BASE_DEC, VALS (init_tech_vals), 0x0,
      "Initialization Technique", HFILL}
     },
    {&hf_docsis_tlv_tcc_rng_parms,
     {".8 Ranging Parameters", "docsis_tlv.tcc.rngparms",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Ranging Parameters", HFILL}
     },
    {&hf_docsis_rng_parms_us_ch_id,
     {"..1 Ranging Reference Channel ID", "docsis_tlv.tcc.rngparms.uschid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel ID", HFILL}
     },
    {&hf_docsis_rng_parms_time_off_int,
     {"..2 Timing Offset, Integer Part", "docsis_tlv.tcc.rngparms.timeoffint",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Timing Offset, Integer Part", HFILL}
     },
    {&hf_docsis_rng_parms_time_off_frac,
     {"..3 Timing Offset, Fractional Part", "docsis_tlv.tcc.rngparms.timeofffrac",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Timing Offset, Fractional Part", HFILL}
     },
    {&hf_docsis_rng_parms_power_off,
     {"..4 Power Offset", "docsis_tlv.tcc.rngparms.poweroff",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Power Offset", HFILL}
     },
    {&hf_docsis_rng_parms_freq_off,
     {"..5 Frequency Offset", "docsis_tlv.tcc.rngparms.freqoff",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Frequency Offset", HFILL}
     },
    {&hf_docsis_tlv_tcc_dyn_rng_win,
     {".9 Dynamic Range Window", "docsis_tlv.tcc.dynrngwin",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Dynamic Range Window", HFILL}
     },
    {&hf_docsis_tlv_tcc_err,
     {".10 TCC Error Encodings", "docsis_tlv.tcc.err",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "TCC Error Encodings", HFILL}
     },
    {&hf_docsis_tcc_err_subtype,
     {"..1 TCC Subtype", "docsis_tlv.tcc.err.subtype",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "TCC Subtype", HFILL}
     },
    {&hf_docsis_tcc_err_code,
     {"..2 Error Code", "docsis_tlv.tcc.err.code",
      FT_UINT8, BASE_DEC, VALS(docsis_conf_code), 0x0,
      "Error Code", HFILL}
     },
    {&hf_docsis_tcc_err_msg,
     {"..3 Error Message", "docsis_tlv.tcc.err.msg",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Error Message", HFILL}
     },
    {&hf_docsis_tlv_sid_cl,
     {"47 Service Flow SID Cluster Assignments", "docsis_tlv.sid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Service Flow SID Cluster Assignments", HFILL}
     },
    {&hf_docsis_sid_cl_sf_id,
     {".1 Service Flow ID", "docsis_tlv.sid.sfid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Upstream Channel ID", HFILL}
     },
    {&hf_docsis_sid_cl_enc,
     {".2 SID Cluster Encodings", "docsis_tlv.sid.enc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SID Cluster Encodings", HFILL}
     },
    {&hf_docsis_sid_cl_enc_id,
     {"..1 SID Cluster ID", "docsis_tlv.sid.enc.id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "SID Cluster ID", HFILL}
     },
    {&hf_docsis_sid_cl_enc_map,
     {"..2 SID-to-Channel Mapping", "docsis_tlv.sid.enc.map",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SID Cluster ID", HFILL}
     },
    {&hf_docsis_sid_cl_map_us_ch_id,
     {"...1 Upstraem Channel ID", "docsis_tlv.sid.enc.map.uschid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel ID", HFILL}
     },
    {&hf_docsis_sid_cl_map_sid,
     {"...2 SID", "docsis_tlv.sid.enc.map.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "SID", HFILL}
     },
    {&hf_docsis_sid_cl_map_action,
     {"...3 SID-to-Channel Mapping Action", "docsis_tlv.sid.enc.map.action",
      FT_UINT8, BASE_DEC, VALS (sid_ch_map_vals), 0x0,
      "SID-to-Channel Mapping Action", HFILL}
     },
    {&hf_docsis_sid_cl_so_crit,
     {".3 SID Cluster Switchover Criteria", "docsis_tlv.sid.socrit",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SID Cluster Switchover Criteria", HFILL}
     },
    {&hf_docsis_sid_cl_so_max_req,
     {"..1 Maximum Requests per SID Cluster", "docsis_tlv.sid.socrit.maxreq",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Maximum Requests per SID Cluster", HFILL}
     },
    {&hf_docsis_sid_cl_so_max_out_bytes,
     {"..2 Maximum Outstanding Bytes per SID Cluster", "docsis_tlv.sid.socrit.maxoutbytes",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Maximum Outstanding Bytes per SID Cluster", HFILL}
     },
    {&hf_docsis_sid_cl_so_max_req_bytes,
     {"..3 Maximum Total Bytes Requested per SID Cluster", "docsis_tlv.sid.socrit.maxreqbytes",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Maximum Total Bytes Requested per SID Cluster", HFILL}
     },
    {&hf_docsis_sid_cl_so_max_time,
     {"..4 Maximum Time in the SID Cluster", "docsis_tlv.sid.socrit.maxtime",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Maximum Time in the SID Cluster", HFILL}
     },
    {&hf_docsis_tlv_rcp,
     {"48 Receive Channel Profile", "docsis_tlv.rcp",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Receive Channel Profile", HFILL}
     },
    {&hf_docsis_tlv_rcp_id,
     {".1 RCP-ID", "docsis_tlv.rcp.id",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "RCP-ID", HFILL}
     },
    {&hf_docsis_tlv_rcp_name,
     {".2 RCP Name", "docsis_tlv.rcp.name",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "RCP Name", HFILL}
     },
    {&hf_docsis_tlv_rcp_freq_spc,
     {".3 RCP Center Frequency Spacing", "docsis_tlv.rcp.freq_spc",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "RCP Center Frequency Spacing", HFILL}
     },
    {&hf_docsis_tlv_rcp_rcv_mod_enc,
     {".4 Receive Module Capability", "docsis_tlv.rcp.rcv_mod_enc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Receive Module Encoding", HFILL}
     },
    {&hf_docsis_rcv_mod_enc_idx,
     {"..1 Receive Module Index", "docsis_tlv.rcp.rcv_mod_enc.idx",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Receive Module Index", HFILL}
     },
    {&hf_docsis_rcv_mod_enc_adj_ch,
     {"..2 Adjacent Channels", "docsis_tlv.rcp.rcv_mod_enc.adj_ch",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Adjacent Channels", HFILL}
     },
    {&hf_docsis_rcv_mod_enc_ch_bl_rng,
     {"..3 Channel Block Range", "docsis_tlv.rcp.rcv_mod_enc.ch_bl_rng",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Channel Block Range", HFILL}
     },
    {&hf_docsis_ch_bl_rng_min_ctr_freq,
     {"...1 Minimum Center Frequency", "docsis_tlv.rcp.rcv_mod_enc.ch_bl_rng.min_ctr_freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Minimum Center Frequency", HFILL}
     },
    {&hf_docsis_ch_bl_rng_max_ctr_freq,
     {"...2 Maximum Center Frequency", "docsis_tlv.rcp.rcv_mod_enc.ch_bl_rng.max_ctr_freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Maximum Center Frequency", HFILL}
     },
    {&hf_docsis_rcv_mod_enc_rsq_ch_subs_cap ,
     {"..5 Resequencing Channel Subset Capability", "docsis_tlv.rcp.rcv_mod_enc.rsq_ch_subs_cap",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Resequencing Channel Subset Capability", HFILL}
     },
    {&hf_docsis_rcv_mod_enc_conn ,
     {"..6 Receive Module Connectivity", "docsis_tlv.rcp.rcv_mod_enc.conn",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Receive Module Connectivity", HFILL}
     },
    {&hf_docsis_rcv_mod_enc_phy_layr_parms,
     {"..7 Physical Layer Parameter", "docsis_tlv.rcp.rcv_mod_enc.phy_layr_parms",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Physical Layer Parameter", HFILL}
     },
    {&hf_docsis_tlv_rcp_rcv_ch,
     {".5 Receive Channel", "docsis_tlv.rcp.rcv_ch",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Receive Channel", HFILL}
     },
    {&hf_docsis_rcv_ch_idx,
     {"..1 Receive Channel Index", "docsis_tlv.rcp.rcv_ch.idx",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Receive Channel Index", HFILL}
     },
    {&hf_docsis_rcv_ch_conn,
     {"..2 Receive Channel Connectivity", "docsis_tlv.rcp.rcv_ch.conn",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Receive Channel Connectivity", HFILL}
     },
    {&hf_docsis_rcv_ch_conn_off,
     {"..3 Receive Channel Connected Offset", "docsis_tlv.rcp.rcv_ch.conn_off",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Receive Channel Connected Offset", HFILL}
     },
    {&hf_docsis_rcv_ch_prim_ds_ch_ind,
     {"..5 Primary Downstream Channel Indicator", "docsis_tlv.rcp.rcv_ch.prim_ds_ch_ind",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Primary Downstream Channel Indicator", HFILL}
     },
    {&hf_docsis_tlv_rcp_ven_spec,
     {".43 Vendor Specific Encodings", "docsis_tlv.rcp.vendorspec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Vendor Specific Encodings", HFILL}
     },
    {&hf_docsis_tlv_rcc,
     {"49 Receive Channel Configuration", "docsis_tlv.rcc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Receive Channel Configuration", HFILL}
     },
    {&hf_docsis_tlv_rcc_id,
     {".1 Assigned RCP-ID", "docsis_tlv.rcc.id",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Assigned RCP-ID", HFILL}
     },
    {&hf_docsis_tlv_rcc_rcv_mod_enc,
     {".4 Receive Module Assignment", "docsis_tlv.rcc.rcv_mod_enc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Receive Module Assignment", HFILL}
     },
    {&hf_docsis_rcc_rcv_mod_enc_idx,
     {"..1 Receive Module Index", "docsis_tlv.rcc.rcc_rcv_mod_enc.idx",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Receive Module Index", HFILL}
     },
    {&hf_docsis_rcc_rcv_mod_enc_ctr_freq_asgn,
     {"..4 First Channel Center Frequency Assignment", "docsis_tlv.rcc.rcv_mod_enc.ctr_freq_asgn",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "First Channel Center Frequency Assignment", HFILL}
     },
    {&hf_docsis_rcc_rcv_mod_enc_conn ,
     {"..6 Receive Module Connectivity", "docsis_tlv.rcc.rcv_mod_enc.conn",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Receive Module Connectivity", HFILL}
     },
    {&hf_docsis_tlv_rcc_rcv_ch,
     {".5 Receive Channel", "docsis_tlv.rcc.rcv_ch",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Receive Channel", HFILL}
     },
    {&hf_docsis_rcc_rcv_ch_idx,
     {"..1 Receive Channel Index", "docsis_tlv.rcc.rcv_ch.idx",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Receive Channel Index", HFILL}
     },
    {&hf_docsis_rcc_rcv_ch_conn,
     {"..2 Receive Channel Connectivity", "docsis_tlv.rcc.rcv_ch.conn",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Receive Channel Connectivity", HFILL}
     },
    {&hf_docsis_rcc_rcv_ch_ctr_freq_asgn,
     {"..4 Receive Channel Center Frequency Assignment", "docsis_tlv.rcc.rcv_ch.ctr_freq_asgn",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Receive Channel Center Frequency Assignment", HFILL}
     },
    {&hf_docsis_rcc_rcv_ch_prim_ds_ch_ind,
     {"..5 Primary Downstream Channel Indicator", "docsis_tlv.rcc.rcv_ch.prim_ds_ch_ind",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Primary Downstream Channel Indicator", HFILL}
     },
    {&hf_docsis_tlv_rcc_part_serv_ds_ch,
     {".6 Partial Service Downstream Channels", "docsis_tlv.rcc.part_serv_ds_ch",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Partial Service Downstream Channels", HFILL}
     },
    {&hf_docsis_tlv_rcc_ven_spec,
     {".43 Vendor Specific Encodings", "docsis_tlv.rcc.vendorspec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Vendor Specific Encodings", HFILL}
     },
    {&hf_docsis_tlv_rcc_err,
     {".254 RCC Error Encodings", "docsis_tlv.rcc.err",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "RCC Error Encodings", HFILL}
     },
    {&hf_docsis_tlv_rcc_err_mod_or_ch,
     {".1 Receive Modul or Receive Channel", "docsis_tlv.rcc.err.mod_or_ch",
      FT_UINT8, BASE_DEC, VALS (mod_or_ch_vals), 0x0,
      "Receive Modul or Receive Channel", HFILL}
     },
    {&hf_docsis_tlv_rcc_err_idx,
     {".2 Receive Modul/Channel Index", "docsis_tlv.rcc.err.idx",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Receive Modul/Channel Index", HFILL}
     },
    {&hf_docsis_tlv_rcc_err_param,
     {".3 Reported Parameter", "docsis_tlv.rcc.err.param",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reported Parameter", HFILL}
     },
    {&hf_docsis_tlv_rcc_err_code,
     {".4 Error Code", "docsis_tlv.rcc.err.code",
      FT_UINT8, BASE_DEC, VALS (docsis_conf_code), 0x0,
      "Error Code", HFILL}
     },
    {&hf_docsis_tlv_rcc_err_msg,
     {".5 Error Message", "docsis_tlv.rcc.err.msg",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Error Message", HFILL}
     },
    {&hf_docsis_tlv_dsid,
     {"50 DSID Encodings", "docsis_tlv.dsid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "DSID Encodings", HFILL}
     },
    {&hf_docsis_tlv_dsid_id,
     {".1 Downstream Service Identifier (DSID)", "docsis_tlv.dsid.id",
      FT_UINT24, BASE_DEC, NULL, 0x0,
      "Downstream Service Identifier (DSID)", HFILL}
     },
    {&hf_docsis_tlv_dsid_action,
     {".2 DSID Action", "docsis_tlv.dsid.action",
      FT_UINT8, BASE_DEC, VALS (dsid_action_vals), 0x0,
      "DSID Action", HFILL}
     },
    {&hf_docsis_tlv_dsid_ds_reseq,
     {".3 Downstream Resequencing Encodings", "docsis_tlv.dsid.ds_reseq",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Downstream Resequencing Encodings", HFILL}
     },
    {&hf_docsis_ds_reseq_dsid,
     {"..1 Resequencing DSID", "docsis_tlv.dsid.ds_reseq.dsid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Resequencing DSID", HFILL}
     },
    {&hf_docsis_ds_reseq_ch_lst,
     {"..2 Downstream Resequencing Channel List", "docsis_tlv.dsid.ds_reseq.ch_lst",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Downstream Resequencing Channel List", HFILL}
     },
    {&hf_docsis_ds_reseq_wait_time,
     {"..3 Downstream Resequencing Wait Time", "docsis_tlv.dsid.ds_reseq.wait_time",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Downstream Resequencing Wait Time", HFILL}
     },
    {&hf_docsis_ds_reseq_warn_thresh,
     {"..4 Resequencing Warn Threshold", "docsis_tlv.dsid.ds_reseq.warn_thresh",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Resequencing Warn Threshold", HFILL}
     },
    {&hf_docsis_ds_reseq_ho_timer,
     {"..5 CM-Status max. Event Hold-Off Timer (Out-of-Range Events)", "docsis_tlv.dsid.ds_reseq.ho_timer",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "CM-Status max. Event Hold-Off Timer (Out-of-Range Events)", HFILL}
     },
    {&hf_docsis_tlv_dsid_mc,
     {".4 Multicast Encodings", "docsis_tlv.dsid.mc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Multicast Encodings", HFILL}
     },
    {&hf_docsis_tlv_dsid_mc_addr,
     {"..1 Client MAC Address Encodings", "docsis_tlv.dsid.mc.addr",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Client MAC Address Encodings", HFILL}
     },
    {&hf_docsis_mc_addr_action,
     {"...1 Client MAC Address Action", "docsis_tlv.dsid.mc.addr.action",
      FT_UINT8, BASE_DEC, VALS (add_del_vals), 0x0,
      "Client MAC Address Action", HFILL}
     },
    {&hf_docsis_mc_addr_addr,
     {"...2 Client MAC Address", "docsis_tlv.dsid.mc.addr.addr",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Client MAC Address", HFILL}
     },
    {&hf_docsis_tlv_dsid_mc_cmim,
     {"..2 Multicast CM Interface Mask", "docsis_tlv.dsid.mc.cmim",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Multicast CM Interface Mask", HFILL}
     },
    {&hf_docsis_tlv_dsid_mc_group,
     {"..3 Multicast Group MAC Addresses", "docsis_tlv.dsid.mc.group",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Multicast Group MAC Addresses", HFILL}
     },
    {&hf_docsis_tlv_dsid_mc_phs,
     {"..26 Payload Header Suppression Encodings", "docsis_tlv.dsid.mc.phs",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Payload Header Suppression Encodings", HFILL}
     },
    {&hf_docsis_tlv_sec_assoc,
     {"51 Security Association Encodings", "docsis_tlv.sec_assoc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Security Association Encodings", HFILL}
     },
    {&hf_docsis_tlv_sec_assoc_action,
     {".1 SA Action", "docsis_tlv.sec_assoc.action",
      FT_UINT8, BASE_DEC, VALS (add_del_vals), 0x0,
      "SA Action", HFILL}
     },
    {&hf_docsis_tlv_sec_assoc_desc,
     {".23 SA Descriptor", "docsis_tlv.sec_assoc.desc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SA Descriptor", HFILL}
     },
    {&hf_docsis_tlv_init_ch_timeout,
     {"52 Intializing Channel Timeout", "docsis_tlv.init_ch_timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Intializing Channel Timeout", HFILL}
     },
    {&hf_docsis_tlv_ch_asgn,
     {"56 Channel Assignment Configuration Settings", "docsis_tlv.ch_asgn",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Channel Assignment Configuration Settings", HFILL}
     },
    {&hf_docsis_ch_asgn_us_ch_id,
     {".1 Upstream Channel ID", "docsis_tlv.ch_asgn.us_ch_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel ID", HFILL}
     },
    {&hf_docsis_ch_asgn_rx_freq,
     {".2 Rx Frequency", "docsis_tlv.ch_asgn.rx_freq",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Rx Frequency", HFILL}
     },
    {&hf_docsis_tlv_cm_init_reason,
     {"57 CM Initialization Reason", "docsis_tlv.cm_init_reason",
      FT_UINT16, BASE_DEC, VALS (init_reason_vals), 0x0,
      "CM Initialization Reason", HFILL}
     },
    {&hf_docsis_tlv_sw_upg_srvr_ipv6,
     {"58 Software Upgrade Server IPv6", "docsis_tlv.sw_upg_srvr_ipv6",
      FT_IPv6, BASE_NONE, NULL, 0x0,
      "Software Upgrade Server IPv6", HFILL}
     },
    {&hf_docsis_tlv_tftp_prov_cm_ipv6_addr,
     {"59 TFTP Server Provisioned Modem IPv6 Address", "docsis_tlv.tftp_prov_cm_ipv6_addr",
      FT_IPv6, BASE_NONE, NULL, 0x0,
      "TFTP Server Provisioned Modem IPv6 Address", HFILL}
     },
    {&hf_docsis_tlv_us_drop_clfy,
     {"60 Upstream Drop Packet Classification Encoding", "docsis_tlv.us_drop_clfy",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Upstream Drop Packet Classification Encoding", HFILL}
     },
    {&hf_docsis_tlv_subs_mgmt_ipv6_lst,
     {"61 Subscriber Management CPE IPv6 Prefix List", "docsis_tlv.subs_mgmt_ipv6_lst",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Subscriber Management CPE IPv6 Prefix List", HFILL}
     },
    {&hf_docsis_tlv_us_drop_clfy_group_id,
     {"62 Upstream Drop Classifier Group ID", "docsis_tlv.us_drop_clfy_group_id",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Upstream Drop Classifier Group ID", HFILL}
     },
    {&hf_docsis_tlv_subs_mgmt_ctrl_max_cpe_ipv6,
     {"63 Subscriber Management Control Max CPE IPv6 Prefix", "docsis_tlv.subs_mgmt_ctrl_max_cpe_ipv6",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Subscriber Management Control Max CPE IPv6 Prefix", HFILL}
     },
    {&hf_docsis_tlv_cmts_mc_sess_enc,
     {"64 CMTS Static Multicast Session Encoding", "docsis_tlv.cmts_mc_sess_enc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "CMTS Static Multicast Session Encoding", HFILL}
     },
    {&hf_docsis_cmts_mc_sess_enc_grp,
     {".1 Multicast Group Address", "docsis_tlv.cmts_mc_sess_enc.grp",
      FT_IPXNET, BASE_NONE, NULL, 0x0,
      "Multicast Group Address", HFILL}
     },
    {&hf_docsis_cmts_mc_sess_enc_src,
     {".2 Source IP Address", "docsis_tlv.cmts_mc_sess_enc.src",
      FT_IPXNET, BASE_NONE, NULL, 0x0,
      "Source IP Address", HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_tlv,
    &ett_docsis_tlv_cos,
    &ett_docsis_tlv_mcap,
    &ett_docsis_tlv_clsfr,
    &ett_docsis_tlv_clsfr_ip,
    &ett_docsis_tlv_clsfr_eth,
    &ett_docsis_tlv_clsfr_err,
    &ett_docsis_tlv_clsfr_dot1q,
    &ett_docsis_tlv_reqxmitpol,
    &ett_docsis_tlv_sflow_err,
    &ett_docsis_tlv_phs,
    &ett_docsis_tlv_phs_err,
    &ett_docsis_tlv_svc_unavail,
    &ett_docsis_tlv_snmpv3_kick,
    &ett_docsis_tlv_ds_ch_list,
    &ett_docsis_tlv_ds_ch_list_single,
    &ett_docsis_tlv_ds_ch_list_range,
    &ett_docsis_tlv_tcc,
    &ett_docsis_tlv_tcc_ucd,
    &ett_docsis_tlv_tcc_rng_parms,
    &ett_docsis_tlv_tcc_err,
    &ett_docsis_tlv_sid_cl,
    &ett_docsis_tlv_sid_cl_enc,
    &ett_docsis_tlv_sid_cl_enc_map,
    &ett_docsis_tlv_sid_cl_so,
    &ett_docsis_tlv_rcp,
    &ett_docsis_tlv_rcp_rcv_mod_enc,
    &ett_docsis_tlv_rcp_ch_bl_rng,
    &ett_docsis_tlv_rcp_rcv_ch,
    &ett_docsis_tlv_rcc,
    &ett_docsis_tlv_rcc_rcv_mod_enc,
    &ett_docsis_tlv_rcc_rcv_ch,
    &ett_docsis_tlv_rcc_err,
    &ett_docsis_tlv_dsid,
    &ett_docsis_tlv_dsid_ds_reseq,
    &ett_docsis_tlv_dsid_mc,
    &ett_docsis_tlv_dsid_mc_addr,
    &ett_docsis_tlv_sec_assoc,
    &ett_docsis_tlv_ch_asgn,
    &ett_docsis_cmts_mc_sess_enc,
  };

/* Register the protocol name and description */
  proto_docsis_tlv = proto_register_protocol ("DOCSIS Appendix C TLV's",
                                              "DOCSIS TLVs", "docsis_tlv");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_tlv, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_tlv", dissect_tlv, proto_docsis_tlv);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_tlv (void)
{
#if 0
  dissector_handle_t docsis_tlv_handle;

  docsis_tlv_handle = find_dissector ("docsis_tlv");
  dissector_add_uint ("docsis", 0xFF, docsis_tlv_handle);
#endif

  docsis_vsif_handle = find_dissector("docsis_vsif");
  docsis_ucd_handle = find_dissector("docsis_ucd");

}
