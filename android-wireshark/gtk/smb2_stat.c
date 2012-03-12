/* smb2_stat.c
 * smb2_stat   2005 Ronnie Sahlberg
 *
 * $Id: smb2_stat.c 34692 2010-10-29 20:22:02Z wmeier $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/value_string.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-smb2.h>

#include "../timestats.h"
#include "../simple_dialog.h"
#include "../file.h"
#include "../globals.h"
#include "../stat_menu.h"

#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/filter_dlg.h"
#include "gtk/service_response_time_table.h"
#include "gtk/tap_dfilter_dlg.h"
#include "gtk/gtkglobals.h"
#include "gtk/main.h"


/* used to keep track of the statistics for an entire program interface */
typedef struct _smb2stat_t {
	GtkWidget *win;
	srt_stat_table smb2_srt_table;
} smb2stat_t;

static void
smb2stat_set_title(smb2stat_t *ss)
{
	char *title;

	title = g_strdup_printf("SMB2 Service Response Time statistics: %s",
	    cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(ss->win), title);
	g_free(title);
}

static void
smb2stat_reset(void *pss)
{
	smb2stat_t *ss=(smb2stat_t *)pss;

	reset_srt_table_data(&ss->smb2_srt_table);
	smb2stat_set_title(ss);
}

static int
smb2stat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi)
{
	smb2stat_t *ss=(smb2stat_t *)pss;
	const smb2_info_t *si=psi;

	/* we are only interested in response packets */
	if(!(si->flags&SMB2_FLAGS_RESPONSE)){
		return 0;
	}
	/* if we havnt seen the request, just ignore it */
	if(!si->saved){
		return 0;
	}

	add_srt_table_data(&ss->smb2_srt_table, si->opcode, &si->saved->req_time, pinfo);

	return 1;
}



static void
smb2stat_draw(void *pss)
{
	smb2stat_t *ss=(smb2stat_t *)pss;

	draw_srt_table_data(&ss->smb2_srt_table);
}


static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	smb2stat_t *ss=(smb2stat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(ss);
	unprotect_thread_critical_region();

	free_srt_table_data(&ss->smb2_srt_table);
	g_free(ss);
}


static void
gtk_smb2stat_init(const char *optarg, void *userdata _U_)
{
	smb2stat_t *ss;
	const char *filter=NULL;
	GtkWidget *label;
	char *filter_string;
	GString *error_string;
	int i;
	GtkWidget *vbox;
	GtkWidget *bbox;
	GtkWidget *close_bt;

	if(!strncmp(optarg,"smb2,srt,",9)){
		filter=optarg+9;
	} else {
		filter=NULL;
	}

	ss=g_malloc(sizeof(smb2stat_t));

	ss->win = dlg_window_new("smb2-stat");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(ss->win), TRUE);
	gtk_window_set_default_size(GTK_WINDOW(ss->win), 550, 400);
	smb2stat_set_title(ss);

	vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(ss->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	label=gtk_label_new("SMB2 Service Response Time statistics");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	filter_string = g_strdup_printf("Filter: %s", filter ? filter : "");
	label=gtk_label_new(filter_string);
	g_free(filter_string);
	gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	label=gtk_label_new("SMB2 Commands");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show_all(ss->win);

	init_srt_table(&ss->smb2_srt_table, 256, vbox, "smb2.cmd");
	for(i=0;i<256;i++){
		init_srt_table_row(&ss->smb2_srt_table, i, val_to_str_ext(i, &smb2_cmd_vals_ext, "Unknown(0x%02x)"));
	}


	error_string=register_tap_listener("smb2", ss, filter, 0, smb2stat_reset, smb2stat_packet, smb2stat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		g_free(ss);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(ss->win, close_bt, window_cancel_button_cb);

	g_signal_connect(ss->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(ss->win, "destroy", G_CALLBACK(win_destroy_cb), ss);

	gtk_widget_show_all(ss->win);
	window_present(ss->win);

	cf_retap_packets(&cfile);
	gdk_window_raise(ss->win->window);
}

static tap_dfilter_dlg smb2_stat_dlg = {
	"SMB2 SRT Statistics",
	"smb2,srt",
	gtk_smb2stat_init,
	-1
};

void
register_tap_listener_gtksmb2stat(void)
{
	register_dfilter_stat(&smb2_stat_dlg, "SMB2",
	    REGISTER_STAT_GROUP_RESPONSE_TIME);
}
