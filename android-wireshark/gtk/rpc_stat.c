/* rpc_stat.c
 * rpc_stat   2002 Ronnie Sahlberg
 *
 * $Id: rpc_stat.c 34017 2010-08-30 16:10:01Z morriss $
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

/* This module provides rpc call/reply SRT (Server Response Time) statistics
 * to Wireshark.
 *
 * It serves as an example on how to use the tap api.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-rpc.h>

#include "../stat_menu.h"
#include "../simple_dialog.h"

#include "gtk/gui_stat_menu.h"
#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/main.h"
#include "gtk/filter_dlg.h"
#include "gtk/stock_icons.h"
#include "gtk/service_response_time_table.h"
#include "gtk/gtkglobals.h"
#include "gtk/filter_autocomplete.h"


/* used to keep track of the statistics for an entire program interface */
typedef struct _rpcstat_t {
	GtkWidget *win;
	srt_stat_table srt_table;
	const char *prog;
	guint32 program;
	guint32 version;
	guint32 num_procedures;
} rpcstat_t;

static char *
rpcstat_gen_title(rpcstat_t *rs)
{
	char *title;

	title = g_strdup_printf("ONC-RPC Service Response Time statistics for %s version %d: %s",
	    rs->prog, rs->version, cf_get_display_name(&cfile));
	return title;
}

static void
rpcstat_set_title(rpcstat_t *rs)
{
	char *title;

	title = rpcstat_gen_title(rs);
	gtk_window_set_title(GTK_WINDOW(rs->win), title);
	g_free(title);
}

static void
rpcstat_reset(void *arg)
{
	rpcstat_t *rs = arg;

	reset_srt_table_data(&rs->srt_table);
	rpcstat_set_title(rs);
}


static gboolean
rpcstat_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *arg2)
{
	rpcstat_t *rs = arg;
	const rpc_call_info_value *ri = arg2;

	/* we are only interested in reply packets */
	if(ri->request){
		return FALSE;
	}
	/* we are only interested in certain program/versions */
	if( (ri->prog!=rs->program) || (ri->vers!=rs->version) ){
		return FALSE;
	}
	/* maybe we have discovered a new procedure?
	 * then we might need to extend our tables
	 */
	if(ri->proc>=rs->num_procedures){
		guint32 i;
		if(ri->proc>256){
			/* no program have probably ever more than this many
			 * procedures anyway and it prevents us from allocating
			 * infinite memory if passed a garbage procedure id
			 */
			return FALSE;
		}
		for(i=rs->num_procedures;i<=ri->proc;i++){
			init_srt_table_row(&rs->srt_table, i, rpc_proc_name(rs->program, rs->version, i));
		}
		rs->num_procedures=ri->proc+1;
	}
	add_srt_table_data(&rs->srt_table, ri->proc, &ri->req_time, pinfo);

	return TRUE;
}

static void
rpcstat_draw(void *arg)
{
	rpcstat_t *rs = arg;

	draw_srt_table_data(&rs->srt_table);
}



static guint32 rpc_program=0;
static guint32 rpc_version=0;
static gint32 rpc_min_vers=-1;
static gint32 rpc_max_vers=-1;
static gint32 rpc_min_proc=-1;
static gint32 rpc_max_proc=-1;

static void
rpcstat_find_procs(gpointer *key, gpointer *value _U_, gpointer *user_data _U_)
{
	rpc_proc_info_key *k=(rpc_proc_info_key *)key;

	if(k->prog!=rpc_program){
		return;
	}
	if(k->vers!=rpc_version){
		return;
	}
	if(rpc_min_proc==-1){
		rpc_min_proc=k->proc;
		rpc_max_proc=k->proc;
	}
	if((gint32)k->proc<rpc_min_proc){
		rpc_min_proc=k->proc;
	}
	if((gint32)k->proc>rpc_max_proc){
		rpc_max_proc=k->proc;
	}

	return;
}

static void
rpcstat_find_vers(gpointer *key, gpointer *value _U_, gpointer *user_data _U_)
{
	rpc_proc_info_key *k=(rpc_proc_info_key *)key;

	if(k->prog!=rpc_program){
		return;
	}
	if(rpc_min_vers==-1){
		rpc_min_vers=k->vers;
		rpc_max_vers=k->vers;
	}
	if((gint32)k->vers<rpc_min_vers){
		rpc_min_vers=k->vers;
	}
	if((gint32)k->vers>rpc_max_vers){
		rpc_max_vers=k->vers;
	}

	return;
}

/* since the gtk2 implementation of tap is multithreaded we must protect
 * remove_tap_listener() from modifying the list while draw_tap_listener()
 * is running.  the other protected block is in main.c
 *
 * there should not be any other critical regions in gtk2
 */
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	rpcstat_t *rs=(rpcstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(rs);
	unprotect_thread_critical_region();

	free_srt_table_data(&rs->srt_table);
	g_free(rs);
}

/* When called, this function will create a new instance of gtk2-rpcstat.
 */
static void
gtk_rpcstat_init(const char *optarg, void* userdata _U_)
{
	rpcstat_t *rs;
	guint32 i;
	char *title_string;
	char *filter_string;
	GtkWidget *vbox;
	GtkWidget *stat_label;
	GtkWidget *filter_label;
	GtkWidget *bbox;
	GtkWidget *close_bt;
	int program, version, pos;
	const char *filter=NULL;
	GString *error_string;
	int hf_index;
	header_field_info *hfi;

	pos=0;
	if(sscanf(optarg,"rpc,srt,%d,%d,%n",&program,&version,&pos)==2){
		if(pos){
			filter=optarg+pos;
		} else {
			filter=NULL;
		}
	} else {
		fprintf(stderr, "wireshark: invalid \"-z rpc,srt,<program>,<version>[,<filter>]\" argument\n");
		exit(1);
	}

	rpc_program=program;
	rpc_version=version;
	rs=g_malloc(sizeof(rpcstat_t));
	rs->prog=rpc_prog_name(rpc_program);
	rs->program=rpc_program;
	rs->version=rpc_version;
	hf_index=rpc_prog_hf(rpc_program, rpc_version);
	hfi=proto_registrar_get_nth(hf_index);

	rs->win = dlg_window_new("rpc-stat");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(rs->win), TRUE);
	gtk_window_set_default_size(GTK_WINDOW(rs->win), 550, 400);
	rpcstat_set_title(rs);

	vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(rs->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	title_string = rpcstat_gen_title(rs);
	stat_label=gtk_label_new(title_string);
	g_free(title_string);
	gtk_box_pack_start(GTK_BOX(vbox), stat_label, FALSE, FALSE, 0);

	filter_string = g_strdup_printf("Filter: %s", filter ? filter : "");
	filter_label=gtk_label_new(filter_string);
	g_free(filter_string);
	gtk_label_set_line_wrap(GTK_LABEL(filter_label), TRUE);
	gtk_box_pack_start(GTK_BOX(vbox), filter_label, FALSE, FALSE, 0);

	rpc_min_proc=-1;
	rpc_max_proc=-1;
	g_hash_table_foreach(rpc_procs, (GHFunc)rpcstat_find_procs, NULL);
	rs->num_procedures=rpc_max_proc+1;

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show_all(rs->win);

	init_srt_table(&rs->srt_table, rpc_max_proc+1, vbox, hfi->abbrev);

	for(i=0;i<rs->num_procedures;i++){
		init_srt_table_row(&rs->srt_table, i, rpc_proc_name(rpc_program, rpc_version, i));
	}


	error_string=register_tap_listener("rpc", rs, filter, 0, rpcstat_reset, rpcstat_packet, rpcstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		free_srt_table_data(&rs->srt_table);
		g_free(rs);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(rs->win, close_bt, window_cancel_button_cb);

	g_signal_connect(rs->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(rs->win, "destroy", G_CALLBACK(win_destroy_cb), rs);

	gtk_widget_show_all(rs->win);
	window_present(rs->win);

	cf_retap_packets(&cfile);
	gdk_window_raise(rs->win->window);
}




static GtkWidget *dlg=NULL;
static GtkWidget *filter_entry;

static void
rpcstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	GString *str;
	const char *filter;

	str = g_string_new("rpc,srt");
	g_string_append_printf(str, ",%d,%d", rpc_program, rpc_version);
	filter=gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]!=0){
		g_string_append_printf(str, ",%s", filter);
	}

	gtk_rpcstat_init(str->str,NULL);
	g_string_free(str, TRUE);
}


static void
rpcstat_version_select(GtkWidget *vers_combo_box, gpointer user_data _U_)
{
	gpointer ptr;

	if (! ws_combo_box_get_active_pointer(GTK_COMBO_BOX(vers_combo_box), &ptr)) {
		g_assert_not_reached();  /* Programming error: somehow no active item */
	}

	rpc_version=GPOINTER_TO_INT(ptr);
}


static void
rpcstat_program_select(GtkWidget *prog_combo_box, gpointer user_data)
{
	rpc_prog_info_key *k;
	GtkWidget *vers_combo_box;
	int i;

	vers_combo_box = user_data;

	if (! ws_combo_box_get_active_pointer(GTK_COMBO_BOX(prog_combo_box), (gpointer)&k)) {
		g_assert_not_reached();  /* Programming error: somehow no active item */
	}
	rpc_program=k->prog;

	/* re-create version menu */
	rpc_version=0;
	g_signal_handlers_disconnect_by_func(vers_combo_box, G_CALLBACK(rpcstat_version_select), NULL );
	ws_combo_box_clear_text_and_pointer(GTK_COMBO_BOX(vers_combo_box));
	rpc_min_vers=-1;
	rpc_max_vers=-1;
	g_hash_table_foreach(rpc_procs, (GHFunc)rpcstat_find_vers, NULL);
	for(i=rpc_min_vers;i<=rpc_max_vers;i++){
		char vs[5];
		g_snprintf(vs, sizeof(vs), "%d",i);
		ws_combo_box_append_text_and_pointer(GTK_COMBO_BOX(vers_combo_box),
						     vs, GINT_TO_POINTER(i));
	}
	g_signal_connect(vers_combo_box, "changed", G_CALLBACK(rpcstat_version_select), NULL);
	ws_combo_box_set_active(GTK_COMBO_BOX(vers_combo_box), 0); /* default: will trigger rpcstat_version_select callback */
}



static void
rpcstat_list_programs(gpointer *key, gpointer *value, gpointer user_data)
{
	rpc_prog_info_key *k=(rpc_prog_info_key *)key;
	rpc_prog_info_value *v=(rpc_prog_info_value *)value;
	GtkComboBox *prog_combo_box = user_data;

	ws_combo_box_append_text_and_pointer(prog_combo_box, v->progname, k);

	if(!rpc_program){
		rpc_program=k->prog;
	}
}

static void
dlg_destroy_cb(GtkWidget *w _U_, gpointer user_data _U_)
{
	dlg=NULL;
}

static void
gtk_rpcstat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	GtkWidget *dlg_box;
	GtkWidget *prog_box, *prog_label;
	GtkWidget *vers_label;
	GtkWidget *prog_combo_box, *vers_combo_box;
	GtkWidget *filter_box, *filter_bt;
	GtkWidget *bbox, *start_button, *cancel_button;
	const char *filter;
	static construct_args_t args = {
	  "Service Response Time Statistics Filter",
	  TRUE,
	  FALSE,
	  FALSE
	};

	/* if the window is already open, bring it to front */
	if(dlg){
		gdk_window_raise(dlg->window);
		return;
	}

	dlg=dlg_window_new("Wireshark: Compute ONC-RPC SRT statistics");
	gtk_window_set_default_size(GTK_WINDOW(dlg), 300, -1);

	dlg_box=gtk_vbox_new(FALSE, 10);
	gtk_container_set_border_width(GTK_CONTAINER(dlg_box), 10);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);

	/* Program box */
	prog_box=gtk_hbox_new(FALSE, 10);

	/* Program label */
	gtk_container_set_border_width(GTK_CONTAINER(prog_box), 10);
	prog_label=gtk_label_new("Program:");
	gtk_box_pack_start(GTK_BOX(prog_box), prog_label, FALSE, FALSE, 0);
	gtk_widget_show(prog_label);

	/* Program menu */
	prog_combo_box=ws_combo_box_new_text_and_pointer();
	g_hash_table_foreach(rpc_progs, (GHFunc)rpcstat_list_programs, prog_combo_box);
	gtk_box_pack_start(GTK_BOX(prog_box), prog_combo_box, TRUE, TRUE, 0);
	gtk_widget_show(prog_combo_box);

	/* Version label */
	gtk_container_set_border_width(GTK_CONTAINER(prog_box), 10);
	vers_label=gtk_label_new("Version:");
	gtk_box_pack_start(GTK_BOX(prog_box), vers_label, FALSE, FALSE, 0);
	gtk_widget_show(vers_label);

	/* Note: version combo box rows set when rpcstat_program_select callback invoked below */
	vers_combo_box=ws_combo_box_new_text_and_pointer();
	gtk_box_pack_start(GTK_BOX(prog_box), vers_combo_box, TRUE, TRUE, 0);
	gtk_widget_show(vers_combo_box);

	gtk_box_pack_start(GTK_BOX(dlg_box), prog_box, TRUE, TRUE, 0);

	g_signal_connect(prog_combo_box, "changed", G_CALLBACK(rpcstat_program_select), vers_combo_box);
	ws_combo_box_set_active(GTK_COMBO_BOX(prog_combo_box), 0); /* invokes rpcstat_program_select callback */

	gtk_widget_show(prog_box);

	/* Filter box */
	filter_box=gtk_hbox_new(FALSE, 3);

	/* Filter label */
	filter_bt=gtk_button_new_from_stock(WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY);
	g_signal_connect(filter_bt, "clicked", G_CALLBACK(display_filter_construct_cb), &args);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_bt, FALSE, FALSE, 0);
	gtk_widget_show(filter_bt);

	/* Filter entry */
	filter_entry=gtk_entry_new();
	g_signal_connect(filter_entry, "changed", G_CALLBACK(filter_te_syntax_check_cb), NULL);
	g_object_set_data(G_OBJECT(filter_box), E_FILT_AUTOCOMP_PTR_KEY, NULL);
	g_signal_connect(filter_entry, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
	g_signal_connect(dlg, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);

	/* filter prefs dialog */
	g_object_set_data(G_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_entry);
	/* filter prefs dialog */

	gtk_box_pack_start(GTK_BOX(filter_box), filter_entry, TRUE, TRUE, 0);
	filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	if(filter){
		gtk_entry_set_text(GTK_ENTRY(filter_entry), filter);
	} else {
		colorize_filter_te_as_empty(filter_entry);
	}
	gtk_widget_show(filter_entry);

	gtk_box_pack_start(GTK_BOX(dlg_box), filter_box, TRUE, TRUE, 0);
	gtk_widget_show(filter_box);

	/* button box */
	bbox = dlg_button_row_new(WIRESHARK_STOCK_CREATE_STAT, GTK_STOCK_CANCEL, NULL);
	gtk_box_pack_start(GTK_BOX(dlg_box), bbox, FALSE, FALSE, 0);
	gtk_widget_show(bbox);

	start_button = g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_CREATE_STAT);
	g_signal_connect_swapped(start_button, "clicked",
				 G_CALLBACK(rpcstat_start_button_clicked), NULL);

	cancel_button = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
	window_set_cancel_button(dlg, cancel_button, window_cancel_button_cb);

	/* Give the initial focus to the "Filter" entry box. */
	gtk_widget_grab_focus(filter_entry);

	gtk_widget_grab_default(start_button );

	g_signal_connect(dlg, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(dlg, "destroy", G_CALLBACK(dlg_destroy_cb), NULL);

	gtk_widget_show_all(dlg);
	window_present(dlg);
}


void
register_tap_listener_gtkrpcstat(void)
{
	register_stat_cmd_arg("rpc,srt,", gtk_rpcstat_init, NULL);

	register_stat_menu_item("ONC-RPC...", REGISTER_STAT_GROUP_RESPONSE_TIME,
	    gtk_rpcstat_cb, NULL, NULL, NULL);
}
