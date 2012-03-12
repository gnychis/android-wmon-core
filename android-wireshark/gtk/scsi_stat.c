/* scsi_stat.c
 * scsi_stat   2006 Ronnie Sahlberg
 *
 * $Id: scsi_stat.c 34017 2010-08-30 16:10:01Z morriss $
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
#include <epan/conversation.h>
#include <epan/dissectors/packet-scsi.h>
#include <epan/dissectors/packet-fc.h>
#include <epan/dissectors/packet-scsi-sbc.h>
#include <epan/dissectors/packet-scsi-ssc.h>
#include <epan/dissectors/packet-scsi-smc.h>
#include <epan/dissectors/packet-scsi-osd.h>

#include "../simple_dialog.h"
#include "../globals.h"
#include "../stat_menu.h"

#include "gtk/gui_stat_menu.h"
#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/main.h"
#include "gtk/filter_dlg.h"
#include "gtk/stock_icons.h"
#include "gtk/service_response_time_table.h"
#include "gtk/gtkglobals.h"
#include "gtk/filter_autocomplete.h"


static GtkWidget *dlg=NULL;

/* used to keep track of the statistics for an entire scsi command set */
typedef struct _scsistat_t {
	GtkWidget *win;
	srt_stat_table srt_table;
	guint8 cmdset;
	const value_string *cdbnames;
	const char *prog;
} scsistat_t;

static guint8 scsi_program=0;
static GtkWidget *filter_entry;

enum
{
   SCSI_STAT_PROG_LABEL_SBC,
   SCSI_STAT_PROG_LABEL_SSC,
   SCSI_STAT_PROG_LABEL_MMC
};


static char *
scsistat_gen_title(scsistat_t *rs)
{
	char *title;

	title = g_strdup_printf("SCSI Service Response Time statistics for %s: %s",
	    rs->prog, cf_get_display_name(&cfile));
	return title;
}

static void
scsistat_set_title(scsistat_t *rs)
{
	char *title;

	title = scsistat_gen_title(rs);
	gtk_window_set_title(GTK_WINDOW(rs->win), title);
	g_free(title);
}

static void
scsistat_reset(void *arg)
{
	scsistat_t *rs = (scsistat_t *)arg;

	reset_srt_table_data(&rs->srt_table);
	scsistat_set_title(rs);
}


static void
dlg_destroy_cb(GtkWidget *w _U_, gpointer user_data _U_)
{
	dlg=NULL;
}

static void
scsistat_program_select(GtkWidget *w, gpointer key _U_)
{
	int i;

	i = gtk_combo_box_get_active (GTK_COMBO_BOX(w));
	switch(i){
		case SCSI_STAT_PROG_LABEL_SBC:
			scsi_program = SCSI_DEV_SBC;
			break;
		case SCSI_STAT_PROG_LABEL_SSC:
			scsi_program = SCSI_DEV_SSC;
			break;
		case SCSI_STAT_PROG_LABEL_MMC:
			scsi_program = SCSI_DEV_CDROM;
			break;
		default:
			scsi_program = SCSI_DEV_SBC;
			break;
	}
}

static int
scsistat_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *arg2)
{
	scsistat_t *rs = (scsistat_t *)arg;
	const scsi_task_data_t *ri = (const scsi_task_data_t *)arg2;

	/* we are only interested in response packets */
	if(ri->type!=SCSI_PDU_TYPE_RSP){
		return 0;
	}
	/* we are only interested in a specific commandset */
	if( (!ri->itl) || ((ri->itl->cmdset&SCSI_CMDSET_MASK)!=rs->cmdset) ){
		return 0;
	}
	/* check that the opcode looks sane */
	if( (!ri->itlq) || (ri->itlq->scsi_opcode>255) ){
		return 0;
	}

	add_srt_table_data(&rs->srt_table, ri->itlq->scsi_opcode, &ri->itlq->fc_time, pinfo);

	return 1;
}

static void
scsistat_draw(void *arg)
{
	scsistat_t *rs = (scsistat_t *)arg;

	draw_srt_table_data(&rs->srt_table);
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
	scsistat_t *rs=(scsistat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(rs);
	unprotect_thread_critical_region();

	free_srt_table_data(&rs->srt_table);
	g_free(rs);
}


/* When called, this function will create a new instance of gtk2-scsistat.
 */
static void
gtk_scsistat_init(const char *optarg, void* userdata _U_)
{
	scsistat_t *rs;
	guint32 i;
	char *title_string;
	char *filter_string;
	GtkWidget *vbox;
	GtkWidget *stat_label;
	GtkWidget *filter_label;
	GtkWidget *bbox;
	GtkWidget *close_bt;
	int program, pos;
	const char *filter=NULL;
	GString *error_string;
	const char *hf_name=NULL;

	pos=0;
	if(sscanf(optarg,"scsi,srt,%d,%n",&program,&pos)==1){
		if(pos){
			filter=optarg+pos;
		} else {
			filter=NULL;
		}
	} else {
		fprintf(stderr, "wireshark: invalid \"-z scsi,srt,<cmdset>[,<filter>]\" argument\n");
		exit(1);
	}

	scsi_program=program;
	rs=(scsistat_t *)g_malloc(sizeof(scsistat_t));
        rs->cmdset=program;
        switch(program){
	case SCSI_DEV_SBC:
		rs->prog="SBC (disk)";
		rs->cdbnames=scsi_sbc_vals;
		hf_name="scsi.sbc.opcode";
		break;
	case SCSI_DEV_SSC:
		rs->prog="SSC (tape)";
		rs->cdbnames=scsi_ssc_vals;
		hf_name="scsi.ssc.opcode";
		break;
	case SCSI_DEV_CDROM:
		rs->prog="MMC (cd/dvd)";
		rs->cdbnames=scsi_mmc_vals;
		hf_name="scsi.mmc.opcode";
		break;
	case SCSI_DEV_SMC:
		rs->prog="SMC (tape robot)";
		rs->cdbnames=scsi_smc_vals;
		hf_name="scsi.smc.opcode";
		break;
	case SCSI_DEV_OSD:
		rs->prog="OSD (object based)";
		rs->cdbnames=scsi_osd_vals;
		hf_name="scsi.osd.opcode";
		break;
	}

	rs->win = dlg_window_new("scsi-stat");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(rs->win), TRUE);
	gtk_window_set_default_size(GTK_WINDOW(rs->win), 550, 400);
	scsistat_set_title(rs);

	vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(rs->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	title_string = scsistat_gen_title(rs);
	stat_label=gtk_label_new(title_string);
	g_free(title_string);
	gtk_box_pack_start(GTK_BOX(vbox), stat_label, FALSE, FALSE, 0);

	filter_string = g_strdup_printf("Filter: %s", filter ? filter : "");
	filter_label=gtk_label_new(filter_string);
	g_free(filter_string);
	gtk_label_set_line_wrap(GTK_LABEL(filter_label), TRUE);
	gtk_box_pack_start(GTK_BOX(vbox), filter_label, FALSE, FALSE, 0);

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show_all(rs->win);

	init_srt_table(&rs->srt_table, 256, vbox, hf_name);

	for(i=0;i<256;i++){
		init_srt_table_row(&rs->srt_table, i, val_to_str(i, rs->cdbnames, "Unknown-0x%02x"));
	}


	error_string=register_tap_listener("scsi", rs, filter, 0, scsistat_reset, scsistat_packet, scsistat_draw);
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

	close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(rs->win, close_bt, window_cancel_button_cb);

	g_signal_connect(rs->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(rs->win, "destroy", G_CALLBACK(win_destroy_cb), rs);

	gtk_widget_show_all(rs->win);
	window_present(rs->win);

	cf_retap_packets(&cfile);
	gdk_window_raise(rs->win->window);
}



static void
scsistat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	GString *str;
	const char *filter;

	str = g_string_new("scsi,srt");
	g_string_append_printf(str, ",%d", scsi_program);
	filter=gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]!=0){
		g_string_append_printf(str, ",%s", filter);
	}

	gtk_scsistat_init(str->str,NULL);
	g_string_free(str, TRUE);
}

static void
gtk_scsistat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	GtkWidget *prog_combo_box;
	GtkWidget *dlg_box;
	GtkWidget *prog_box, *prog_label;
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

	dlg=dlg_window_new("Wireshark: Compute SCSI SRT statistics");
	gtk_window_set_default_size(GTK_WINDOW(dlg), 300, -1);

	dlg_box=gtk_vbox_new(FALSE, 10);
	gtk_container_set_border_width(GTK_CONTAINER(dlg_box), 10);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);

	/* Program box */
	prog_box=gtk_hbox_new(FALSE, 10);

	/* Program label */
	gtk_container_set_border_width(GTK_CONTAINER(prog_box), 10);
	prog_label=gtk_label_new("Commandset:");
	gtk_box_pack_start(GTK_BOX(prog_box), prog_label, FALSE, FALSE, 0);
	gtk_widget_show(prog_label);

	/* Program menu */
	prog_combo_box = gtk_combo_box_new_text ();

	/* SBC */
	gtk_combo_box_append_text (GTK_COMBO_BOX (prog_combo_box), "SBC (disk)");
	/* SSC */
	gtk_combo_box_append_text (GTK_COMBO_BOX (prog_combo_box), "SSC (tape)");
	/* MMC */
	gtk_combo_box_append_text (GTK_COMBO_BOX (prog_combo_box), "MMC (cd/dvd)");

	gtk_box_pack_start(GTK_BOX(prog_box), prog_combo_box, TRUE, TRUE, 0);
	gtk_combo_box_set_active(GTK_COMBO_BOX(prog_combo_box), SCSI_DEV_SBC);
	g_signal_connect(prog_combo_box, "changed", G_CALLBACK(scsistat_program_select), NULL);
	gtk_widget_show(prog_combo_box);

	gtk_box_pack_start(GTK_BOX(dlg_box), prog_box, TRUE, TRUE, 0);
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

        start_button = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_CREATE_STAT);
        g_signal_connect_swapped(start_button, "clicked",
			     G_CALLBACK(scsistat_start_button_clicked), NULL);

        cancel_button = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
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
register_tap_listener_gtkscsistat(void)
{
	register_stat_cmd_arg("scsi,srt,", gtk_scsistat_init, NULL);

	register_stat_menu_item("SCSI...", REGISTER_STAT_GROUP_RESPONSE_TIME,
	    gtk_scsistat_cb, NULL, NULL, NULL);

}

