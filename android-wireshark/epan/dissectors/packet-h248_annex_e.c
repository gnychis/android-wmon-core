/*
 *  packet-h248-annex_e.c
 *  H.248 Annex E
 *
 *  (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * $Id: packet-h248_annex_e.c 35922 2011-02-11 21:27:46Z morriss $
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

#include "packet-h248.h"
#define PNAME  "H.248 Annex E"
#define PSNAME "H248E"
#define PFNAME "h248e"
/*
#include <epan/dissectors/packet-alcap.h>
*/
static int proto_h248_annex_E = -1;

static gboolean implicit = TRUE;

/* H.248.1 E.1  Generic Package */
static int hf_h248_pkg_generic = -1;
static int hf_h248_pkg_generic_cause_evt = -1;
static int hf_h248_pkg_generic_cause_gencause = -1;
static int hf_h248_pkg_generic_cause_failurecause = -1;
static int hf_h248_pkg_generic_sc_evt = -1;
static int hf_h248_pkg_generic_sc_sig_id = -1;
static int hf_h248_pkg_generic_sc_meth = -1;
static int hf_h248_pkg_generic_sc_slid = -1;
static int hf_h248_pkg_generic_sc_rid = -1;

static gint ett_h248_pkg_generic_cause_evt = -1;
static gint ett_h248_pkg_generic = -1;
static gint ett_h248_pkg_generic_sc_evt = -1;

static const value_string h248_pkg_generic_cause_vals[] _U_ = {
	{1, "gencause"},
	{2, "failurecause"},
	{ 0, NULL }
};

static const value_string h248_pkg_generic_evt_vals[] = {
	{1, "Cause"},
	{2, "Signal Completion"},
	{ 0, NULL }
};

static const value_string h248_pkg_generic_cause_gencause_vals[] = {
	{ 1, "NR (Normal Release)"},
	{ 2, "UR (Unavailable Resources)"},
	{ 3, "FT (Failure, Temporary)"},
	{ 4, "FP (Failure, Permanent)"},
	{ 5, "IW (Interworking Error)"},
	{ 6, "UN (Unsupported)"},
	{ 0, NULL }
};

static h248_pkg_param_t h248_pkg_generic_cause_evt_params[] = {
	{ 0x0001, &hf_h248_pkg_generic_cause_gencause, h248_param_ber_integer, &implicit },
	{ 0x0002, &hf_h248_pkg_generic_cause_failurecause, h248_param_ber_octetstring, &implicit },
	{ 0, NULL, NULL, NULL}
};

static const value_string h248_pkg_generic_sc_meth_vals[] _U_ = {
	{0x0001,"SigID"},
	{0x0002,"Meth"},
	{0x0003,"SLID"},
	{0x0004,"RID"},
	{0,NULL}
};

static const value_string h248_pkg_generic_sc_vals[] = {
	{0x0001,"TO - Signal timed out or otherwise completed on its own"},
	{0x0002,"EV - Interrupted by event"},
	{0x0003,"SD - Halted by new Signals Descriptor"},
	{0x0004,"NC - Not completed, other cause"},
	{0x0005,"PI - First to penultimate iteration"},
	{0,NULL}
};

static h248_pkg_param_t h248_pkg_generic_sc_evt_params[] = {
	{ 0x0001, &hf_h248_pkg_generic_sc_sig_id, h248_param_PkgdName, NULL },
	{ 0x0002, &hf_h248_pkg_generic_sc_meth, h248_param_ber_integer, NULL },
	{ 0x0003, &hf_h248_pkg_generic_sc_slid, h248_param_ber_integer, NULL },
	{ 0x0004, &hf_h248_pkg_generic_sc_rid, h248_param_ber_integer, NULL },
	{ 0, NULL, NULL, NULL}
};

static h248_pkg_evt_t h248_pkg_generic_cause_evts[] = {
	{ 0x0001, &hf_h248_pkg_generic_cause_evt, &ett_h248_pkg_generic_cause_evt, h248_pkg_generic_cause_evt_params, h248_pkg_generic_cause_gencause_vals},
	{ 0x0002, &hf_h248_pkg_generic_sc_evt, &ett_h248_pkg_generic_sc_evt, h248_pkg_generic_sc_evt_params, h248_pkg_generic_sc_vals},
	{ 0, NULL, NULL, NULL, NULL}
};

static h248_package_t h248_pkg_generic = {
	0x0001,
	&hf_h248_pkg_generic,
	&ett_h248_pkg_generic,
	NULL,
	NULL,
	h248_pkg_generic_evt_vals,
	NULL,
	NULL,
	NULL,
	h248_pkg_generic_cause_evts,
	NULL
};


/* H.248.1 E.2  Base Root Package
static int hf_h248_pkg_root = -1;
static int hf_h248_pkg_root_params = -1;
static int hf_h248_pkg_root_maxnrofctx = -1;
static int hf_h248_pkg_root_maxtermsperctx = -1;
static int hf_h248_pkg_root_normalmgexectime = -1;
static int hf_h248_pkg_root_normalmgcexecutiontime = -1;
static int hf_h248_pkg_root_provisionalresponsetimervalue = -1;

static gint ett_h248_pkg_root = -1;

static h248_pkg_param_t h248_pkg_root_properties[] = {
	{ 0x0001, &hf_h248_pkg_root_maxnrofctx, h248_param_ber_integer, &implicit },
	{ 0x0002, &hf_h248_pkg_root_maxtermsperctx, h248_param_ber_integer, &implicit },
	{ 0x0003, &hf_h248_pkg_root_normalmgexectime, h248_param_ber_integer, &implicit },
	{ 0x0004, &hf_h248_pkg_root_normalmgcexecutiontime, h248_param_ber_integer, &implicit },
	{ 0x0005, &hf_h248_pkg_root_provisionalresponsetimervalue, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL}
};

static h248_package_t h248_pkg_root = {
	0x0002,
	&hf_h248_pkg_root,
	&hf_h248_pkg_root_params,
	&ett_h248_pkg_root,
	NULL,
	NULL,
	NULL,
	NULL,
	h248_pkg_root_properties,
	NULL,
	NULL,
	NULL,
	NULL
};
*/

/* H.248.1 E.3  Tone Generator Package
static int hf_h248_pkg_tonegen = -1;
static int hf_h248_pkg_tonegen_params = -1;
static int hf_h248_pkg_tonegen_sig_pt = -1;
static int hf_h248_pkg_tonegen_sig_pt_tl = -1;
static int hf_h248_pkg_tonegen_sig_pt_ind = -1;

static gint ett_h248_pkg_tonegen = -1;

static h248_pkg_param_t hf_h248_pkg_tonegen_properties[] = {
	{ 0x0001, &hf_h248_pkg_tonegen_sig_pt_tl, h248_param_ber_integer, &implicit },
	{ 0x0002, &hf_h248_pkg_tonegen_sig_pt_ind, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL}
};

static h248_package_t h248_pkg_tonegen = {
	0x0002,
	&hf_h248_pkg_tonegen,
	&hf_h248_pkg_tonegen_params,
	&ett_h248_pkg_tonegen,
	h248_pkg_root_properties,
	NULL,
	NULL,
	NULL
};
*/


/* H.248.1 E.4  Tone Detector Package
static int hf_h248_pkg_tonedet = -1;
static int hf_h248_pkg_tonedet_evt_std = -1;
static int hf_h248_pkg_tonedet_evt_etd = -1;
static int hf_h248_pkg_tonedet_evt_ltd = -1;
*/

/* E.5 Basic DTMF Generator Package */
static int hf_h248_pkg_dg = -1;
static int hf_h248_pkg_dg_sig_d0 = -1;
static int hf_h248_pkg_dg_sig_d1 = -1;
static int hf_h248_pkg_dg_sig_d2 = -1;
static int hf_h248_pkg_dg_sig_d3 = -1;

static gint ett_h248_pkg_dg = -1;
static gint ett_h248_pkg_dg_sig_d0 = -1;
static gint ett_h248_pkg_dg_sig_d1 = -1;
static gint ett_h248_pkg_dg_sig_d2 = -1;
static gint ett_h248_pkg_dg_sig_d3 = -1;

static const value_string  h248_pkg_dg_signals_vals[] = {
	{ 0x0010, "d0"},
	{ 0x0011, "d1"},
	{ 0x0012, "d2"},
	{ 0x0013, "d3"},
	{0,NULL}
};

/* Signals defenitions */
static h248_pkg_sig_t h248_pkg_dg_signals[] = {
	{ 0x0010, &hf_h248_pkg_dg_sig_d0, &ett_h248_pkg_dg_sig_d0, NULL, NULL },
	{ 0x0011, &hf_h248_pkg_dg_sig_d1, &ett_h248_pkg_dg_sig_d1, NULL, NULL },
	{ 0x0012, &hf_h248_pkg_dg_sig_d2, &ett_h248_pkg_dg_sig_d2, NULL, NULL },
	{ 0x0013, &hf_h248_pkg_dg_sig_d3, &ett_h248_pkg_dg_sig_d3, NULL, NULL },
	/* TODO add the rest of the signals */

	{ 0, NULL, NULL, NULL, NULL}
};

/* Packet defenitions */
static h248_package_t h248_pkg_dg = {
	0x0005,
	&hf_h248_pkg_dg,
	&ett_h248_pkg_dg,
	NULL,
	h248_pkg_dg_signals_vals,
	NULL,
	NULL,
	NULL,					/* Properties	*/
	h248_pkg_dg_signals,	/* signals		*/
	NULL,					/* events		*/
	NULL					/* statistics	*/
};


/* H.248.1 E.9 Analog Line Supervision Package */
static int hf_h248_pkg_al = -1;
static int hf_h248_pkg_al_evt_onhook = -1;
static int hf_h248_pkg_al_evt_offhook = -1;
static int hf_h248_pkg_al_evt_flashhook = -1;
static int hf_h248_pkg_al_evt_onhook_par_strict = -1;
static int hf_h248_pkg_al_evt_offhook_par_strict = -1;
static int hf_h248_pkg_al_evt_onhook_par_init = -1;
static int hf_h248_pkg_al_evt_offhook_par_init = -1;
static int hf_h248_pkg_al_evt_flashhook_par_mindur = -1;

static gint ett_h248_pkg_al = -1;
static gint ett_h248_pkg_al_evt_onhook = -1;
static gint ett_h248_pkg_al_evt_offhook = -1;
static gint ett_h248_pkg_al_evt_flashhook = -1;


static const value_string  h248_pkg_al_evt_onhook_params_vals[] = {
	{ 0x0001, "strict"},
	{ 0x0002, "init"},
	{ 0, NULL}
};

static const value_string  h248_pkg_al_evt_flashhook_params_vals[] = {
	{ 0x0001, "mindur"},
	{ 0, NULL}
};

static const value_string  h248_pkg_al_evts_vals[] = {
	{ 0x0004, "onhook"},
	{ 0x0005, "offhook"},
	{ 0x0006, "flashhook"},
	{ 0, NULL}
};



/* Events defenitions */
static const value_string h248_pkg_al_evt_onhook_strict_vals[] = {
	{ 0, "exact"},
	{ 1, "state"},
	{ 2, "failWrong"},
	{ 0, NULL }
};

static const true_false_string h248_pkg_al_evt_onhook_par_init_vals = {
	"already on-hook",
	"actual state transition to on-hook"
};

static const true_false_string h248_pkg_al_evt_offhook_par_init_vals = {
	"already off-hook",
	"actual state transition to off-hook"
};

static h248_pkg_param_t  h248_pkg_al_evt_onhook_params[] = {
	{ 0x0001, &hf_h248_pkg_al_evt_onhook_par_strict, h248_param_ber_integer, &implicit },
	{ 0x0002, &hf_h248_pkg_al_evt_onhook_par_init, h248_param_ber_boolean, &implicit },
	{ 0, NULL, NULL, NULL}
};

static h248_pkg_param_t  h248_pkg_al_evt_offhook_params[] = {
	{ 0x0001, &hf_h248_pkg_al_evt_offhook_par_strict, h248_param_ber_integer, &implicit },
	{ 0x0002, &hf_h248_pkg_al_evt_offhook_par_init, h248_param_ber_boolean, &implicit },
	{ 0, NULL, NULL, NULL}
};

static h248_pkg_param_t  h248_pkg_al_evt_flashhook_params[] = {
	{ 0x0001, &hf_h248_pkg_al_evt_flashhook_par_mindur, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL}
};

static h248_pkg_evt_t h248_pkg_al_evts[] = {
	{ 0x0004, &hf_h248_pkg_al_evt_onhook, &ett_h248_pkg_al_evt_onhook, h248_pkg_al_evt_onhook_params, h248_pkg_al_evt_onhook_params_vals},
	{ 0x0005, &hf_h248_pkg_al_evt_offhook, &ett_h248_pkg_al_evt_offhook, h248_pkg_al_evt_offhook_params, h248_pkg_al_evt_onhook_params_vals },
	{ 0x0006, &hf_h248_pkg_al_evt_flashhook, &ett_h248_pkg_al_evt_flashhook, h248_pkg_al_evt_flashhook_params, h248_pkg_al_evt_flashhook_params_vals },

	{ 0, NULL, NULL, NULL, NULL}
};

/* Packet defenitions */
static const value_string h248_pkg_al_parameters[] _U_ = {
	/* Signals */
	{   0x0002, "ri (Ring)" },
	/* Events */
	{   0x0004, "on (On-hook)" },
	{   0x0005, "off (Off-hook)" },
	{   0x0006, "fl (Flashhook)" },

	{0,     NULL},
};

static h248_package_t h248_pkg_al = {
	0x0009,
	&hf_h248_pkg_al,
	&ett_h248_pkg_al,
	NULL,
	NULL,
	h248_pkg_al_evts_vals,
	NULL,
	NULL,						/* Properties */
	NULL,						/* signals */
	h248_pkg_al_evts,			/* events */
	NULL						/* statistics */
};

/* H.248.1 E.12 RTP package */
static int hf_h248_pkg_rtp = -1;
static int hf_h248_pkg_rtp_stat_ps = -1;

static gint ett_h248_pkg_rtp = -1;

static const value_string h248_pkg_rtp_stat_vals[] _U_ = {
	{ 0x0004, "ps"},
	{ 0, NULL}
};

static const value_string h248_pkg_rtp_parameters[] = {
	{   0x0001, "pltrans (Payload Transition)" },
	{   0x0004, "ps (Packets Sent)" },
	{   0x0005, "pr (Packets Received)" },
	{   0x0006, "pl (Packet Loss)" },
	{   0x0007, "jit (Jitter)" },
	{   0x0008, "delay (Delay)" },
	{0,     NULL},
};

static h248_pkg_stat_t h248_pkg_rtp_stat[] = {
	{ 0x0004, &hf_h248_pkg_rtp_stat_ps, &ett_h248_pkg_rtp, NULL,NULL},
};

/* Packet defenitions */
static h248_package_t h248_pkg_rtp = {
	0x000c,
	&hf_h248_pkg_rtp,
	&ett_h248_pkg_rtp,
	h248_pkg_rtp_parameters,
	NULL,
	NULL,
	NULL,
	NULL,						/* Properties */
	NULL,						/* signals */
	NULL,						/* events */
	h248_pkg_rtp_stat			/* statistics */
};

/* H.248.1 E.13 TDM Circuit Package */
static int hf_h248_pkg_tdmc = -1;
static int hf_h248_pkg_tdmc_ec = -1;
static int hf_h248_pkg_tdmc_gain = -1;

static gint ett_h248_pkg_tdmc = -1;

static const true_false_string h248_tdmc_ec_vals = {
	"On",
	"Off"
};
static const value_string h248_pkg_tdmc_props_vals[] = {
	{ 0x0008, "ec"},
	{ 0x000a, "gain"},
	{ 0, NULL}
};


static h248_pkg_param_t h248_pkg_tdmc_props[] = {
	{ 0x0008, &hf_h248_pkg_tdmc_ec, h248_param_ber_boolean, &implicit },
	{ 0x000a, &hf_h248_pkg_tdmc_gain, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL}
};

static h248_package_t h248_pkg_tdmc = {
	0x000d,
	&hf_h248_pkg_tdmc,
	&ett_h248_pkg_tdmc,
	h248_pkg_tdmc_props_vals,
	NULL,
	NULL,
	NULL,
	h248_pkg_tdmc_props,		/* Properties */
	NULL,						/* signals */
	NULL,						/* events */
	NULL						/* statistics */
};



void proto_register_h248_annex_e(void) {
	static hf_register_info hf[] = {
		/* H.248.1 E.1  Generic Package */
		{ &hf_h248_pkg_generic, { "Generic Package", "h248.pkg.generic", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_cause_evt, { "Cause Event", "h248.pkg.generic.cause", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_cause_gencause, { "Generic Cause", "h248.pkg.generic.cause.gencause", FT_UINT32, BASE_HEX, VALS(h248_pkg_generic_cause_gencause_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_cause_failurecause, { "Generic Cause", "h248.pkg.generic.cause.failurecause", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{&hf_h248_pkg_generic_sc_evt, {"Signal Completion","h248.pkg.generic.sc",FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},
		{ &hf_h248_pkg_generic_sc_sig_id, { "Signal Identity", "h248.pkg.generic.sc.sig_id", FT_BYTES, BASE_NONE, NULL , 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_sc_meth, { "Termination Method", "h248.pkg.generic.sc.meth", FT_UINT32, BASE_DEC, VALS(h248_pkg_generic_sc_vals) , 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_sc_slid, { "Signal List ID", "h248.pkg.generic.sc.slid", FT_UINT32, BASE_DEC, NULL , 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_sc_rid, { "Request ID", "h248.pkg.generic.sc.rid", FT_UINT32, BASE_DEC,  NULL, 0, NULL, HFILL }},
		/* H.248.1 E.9 Analog Line Supervision Package */
		{ &hf_h248_pkg_al, { "Analog Line Supervision Package", "h248.pkg.al", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_onhook, { "onhook", "h248.pkg.al.onhook", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_offhook, { "offhook", "h248.pkg.al.offhook", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_flashhook, { "flashhook", "h248.pkg.al.flashhook", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_onhook_par_strict, { "strict", "h248.pkg.al.ev.onhook.strict", FT_UINT8, BASE_DEC, VALS(h248_pkg_al_evt_onhook_strict_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_onhook_par_init, { "init", "h248.pkg.al.ev.onhook.init", FT_BOOLEAN, BASE_NONE, TFS(&h248_pkg_al_evt_onhook_par_init_vals), 0x0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_offhook_par_strict, { "strict", "h248.pkg.al.ev.offhook.strict", FT_UINT8, BASE_DEC, VALS(h248_pkg_al_evt_onhook_strict_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_offhook_par_init, { "init", "h248.pkg.al.ev.onhook.init", FT_BOOLEAN, BASE_NONE, TFS(&h248_pkg_al_evt_offhook_par_init_vals), 0x0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_flashhook_par_mindur, { "Minimum duration in ms", "h248.pkg.al.ev.flashhook.mindur", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		/* H.248.1 E.12 RTP package */
		{ &hf_h248_pkg_rtp, { "RTP package", "h248.pkg.rtp", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_rtp_stat_ps, { "Packets Sent", "h248.pkg.rtp.stat.ps", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
		/* H.248.1 E.13 TDM Circuit Package */
		{ &hf_h248_pkg_tdmc, { "TDM Circuit Package", "h248.pkg.tdmc", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_tdmc_ec, { "Echo Cancellation", "h248.pkg.tdmc.ec", FT_BOOLEAN, BASE_NONE, TFS(&h248_tdmc_ec_vals), 0x0, NULL, HFILL }},
		{ &hf_h248_pkg_tdmc_gain, { "Gain", "h248.pkg.tdmc.gain", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_h248_pkg_generic_cause_evt,
		&ett_h248_pkg_generic,
		&ett_h248_pkg_generic_sc_evt,

		&ett_h248_pkg_dg,
		&ett_h248_pkg_dg_sig_d0,
		&ett_h248_pkg_dg_sig_d1,
		&ett_h248_pkg_dg_sig_d2,
		&ett_h248_pkg_dg_sig_d3,

		&ett_h248_pkg_al,
		&ett_h248_pkg_al_evt_onhook,
		&ett_h248_pkg_al_evt_offhook,
		&ett_h248_pkg_al_evt_flashhook,

		&ett_h248_pkg_rtp,

		&ett_h248_pkg_tdmc
	};

	proto_h248_annex_E = proto_register_protocol(PNAME, PSNAME, PFNAME);

	proto_register_field_array(proto_h248_annex_E, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	h248_register_package(&h248_pkg_generic);
	h248_register_package(&h248_pkg_dg);
	h248_register_package(&h248_pkg_al);
	h248_register_package(&h248_pkg_rtp);
	h248_register_package(&h248_pkg_tdmc);
}


