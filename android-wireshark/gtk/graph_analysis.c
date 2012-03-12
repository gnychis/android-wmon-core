 /* graph_analysis.c
 * Graphic Analysis addition for Wireshark
 *
 * $Id: graph_analysis.c 35877 2011-02-08 04:12:09Z sfisher $
 *
 * Copyright 2004, Verso Technologies Inc.
 * By Alejandro Vaquero <alejandrovaquero@yahoo.com>
 *
 * based on rtp_analysis.c and io_stat
 *
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-rtp.h>
#include <epan/addr_resolv.h>
#include "epan/filesystem.h"

#include "../util.h"
#include "../color.h"
#include "../simple_dialog.h"
#include "../alert_box.h"
#include <wsutil/file_util.h>

#include "gtk/gtkglobals.h"
#include "gtk/file_dlg.h"
#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/main.h"
#include "gtk/graph_analysis.h"
#include "../image/voip_select.xpm"
#include "../image/voip_bg.xpm"

/****************************************************************************/


#define OK_TEXT "[ Ok ]"
#define PT_UNDEFINED -1


static GtkWidget *save_to_file_w = NULL;

#define MAX_LABEL 50
#define MAX_COMMENT 100
#define ITEM_HEIGHT 20
#define NODE_WIDTH 100
#define TOP_Y_BORDER 40
#define BOTTOM_Y_BORDER 2
#define COMMENT_WIDTH 400
#define TIME_WIDTH 50

#define NODE_CHARS_WIDTH 20
#define CONV_TIME_HEADER       "Conv.| Time    "
#define TIME_HEADER "|Time     "
#define CONV_TIME_EMPTY_HEADER "     |         "
#define TIME_EMPTY_HEADER      "|         "
#define CONV_TIME_HEADER_LENGTH 16
#define TIME_HEADER_LENGTH 10

/****************************************************************************/
/* Reset the user_data structure */
static void graph_analysis_reset(graph_analysis_data_t *user_data)
{
	int i;

	user_data->num_nodes = 0;
	user_data->num_items = 0;
	for (i=0; i<MAX_NUM_NODES; i++){
		user_data->nodes[i].type = AT_NONE;
		user_data->nodes[i].len = 0;
		g_free((void *)user_data->nodes[i].data);
		user_data->nodes[i].data = NULL;
	}

	user_data->dlg.first_node=0;
	user_data->dlg.first_item=0;
	user_data->dlg.left_x_border=0;
	user_data->dlg.selected_item=0xFFFFFFFF;    /*not item selected */
}

/****************************************************************************/
/* Init the user_data structure */
static void graph_analysis_init_dlg(graph_analysis_data_t *user_data)
{
	int i;
	user_data->num_nodes = 0;
	user_data->num_items = 0;
	user_data->on_destroy_user_data = NULL;
	user_data->data = NULL;
	for (i=0; i<MAX_NUM_NODES; i++){
		user_data->nodes[i].type = AT_NONE;
		user_data->nodes[i].len = 0;
		user_data->nodes[i].data = NULL;
	}

	user_data->dlg.first_node=0;
	user_data->dlg.first_item=0;
	user_data->dlg.left_x_border=0;
	user_data->dlg.selected_item=0xFFFFFFFF;    /*not item selected */
	/* init dialog_graph */
	user_data->dlg.needs_redraw=TRUE;
	user_data->dlg.draw_area_time=NULL;
	user_data->dlg.draw_area=NULL;
	user_data->dlg.pixmap_main=NULL;
	user_data->dlg.pixmap_time=NULL;
	user_data->dlg.draw_area_comments=NULL;
	user_data->dlg.pixmap_comments=NULL;
	user_data->dlg.v_scrollbar=NULL;
	user_data->dlg.v_scrollbar_adjustment=NULL;
	user_data->dlg.hpane=NULL;
	user_data->dlg.pixmap_width = 350;
	user_data->dlg.pixmap_height=400;
	user_data->dlg.first_node=0;
	user_data->dlg.first_item=0;
	user_data->dlg.left_x_border=0;
	user_data->dlg.selected_item=0xFFFFFFFF;    /*not item selected */
	user_data->dlg.window=NULL;
	user_data->dlg.parent_w=NULL;
	user_data->dlg.inverse = FALSE;
	user_data->dlg.title=NULL;
}

/****************************************************************************/
/* CALLBACKS */

/****************************************************************************/
/* close the dialog window */
static void on_destroy(GtkWidget *win _U_, graph_analysis_data_t *user_data)
{
	int i;

	for (i=0; i<MAX_NUM_NODES; i++){
		user_data->nodes[i].type = AT_NONE;
		user_data->nodes[i].len = 0;
		g_free((void *)user_data->nodes[i].data);
		user_data->nodes[i].data = NULL;
	}
	user_data->dlg.window = NULL;
	g_free(user_data->dlg.title);
	user_data->dlg.title = NULL;

	if(user_data->on_destroy_user_data){
		user_data->on_destroy_user_data(user_data->data);
	}
}

#define RIGHT_ARROW 1
#define LEFT_ARROW 0
#define WIDTH_ARROW 8
#define HEIGHT_ARROW 6

/****************************************************************************/
static void draw_arrow(GdkDrawable *pixmap, GdkGC *gc, gint x, gint y, gboolean direction)
{
	GdkPoint arrow_point[3];

	arrow_point[0].x = x;
	arrow_point[0].y = y-HEIGHT_ARROW/2;
	if (direction == RIGHT_ARROW)
		arrow_point[1].x = x+WIDTH_ARROW;
	else
		arrow_point[1].x = x-WIDTH_ARROW;
	arrow_point[1].y = y;
	arrow_point[2].x = x;
	arrow_point[2].y = y+HEIGHT_ARROW/2;;

	if (GDK_IS_DRAWABLE(pixmap)) {
		gdk_draw_polygon(pixmap, gc, TRUE, arrow_point, 3);
	}
}

/****************************************************************************/
/* Adds trailing characters to complete the requested length.               */
/****************************************************************************/

static void enlarge_string(GString *gstr, guint32 length, char pad){

	gsize i;

	for (i = gstr->len; i < length; i++){
		g_string_append_c(gstr, pad);
	}
}

/****************************************************************************/
/* overwrites the characters in a string, between positions p1 and p2, with */
/*   the characters of text_to_insert                                       */
/*   NB: it does not check that p1 and p2 fit into string                   */
/****************************************************************************/

static void overwrite (GString *gstr, char *text_to_insert, guint32 p1, guint32 p2){

	gsize len;
	gsize pos;

	if (p1 == p2)
		return;

	if (p1 > p2){
		pos = p2;
		len = p1 - p2;
	}
	else{
		pos = p1;
		len = p2 - p1;
	}

	if (len > strlen(text_to_insert)){
		len = strlen(text_to_insert);
	}

	if (pos > gstr->len)
		pos = gstr->len;

	/* ouch this is ugly but gtk1 needs it */
	if ((pos + len) > gstr->len)
		g_string_truncate(gstr, pos);
	else
		g_string_erase(gstr, pos, len);

	g_string_insert(gstr, pos, text_to_insert);
}

/****************************************************************************/
static gboolean dialog_graph_dump_to_file(graph_analysis_data_t *user_data)
{
	guint32 i, first_node, display_items, display_nodes;
	guint32 start_position, end_position, item_width, header_length;
	graph_analysis_item_t *gai;
	guint16  first_conv_num = 0;
	gboolean several_convs = FALSE;
	gboolean first_packet  = TRUE;

	GString *label_string, *empty_line,*separator_line, *tmp_str, *tmp_str2;
	char    *empty_header;
	char     src_port[8],dst_port[8];

	GList *list;

	FILE  *of;

	of = ws_fopen(user_data->dlg.save_file,"w");
	if (of==NULL){
		open_failure_alert_box(user_data->dlg.save_file, errno, TRUE);
		return FALSE;
	}

	label_string   = g_string_new("");
	empty_line     = g_string_new("");
	separator_line = g_string_new("");
	tmp_str        = g_string_new("");
	tmp_str2       = g_string_new("");

	display_items = 0;
	list = g_list_first(user_data->graph_info->list);
	while (list)
	{
		gai = list->data;
		list = g_list_next(list);

		if (!gai->display)
			continue;

		display_items += 1;
		if (first_packet){
			first_conv_num = gai->conv_num;
			first_packet=FALSE;
		}
		else if (gai->conv_num != first_conv_num){
			several_convs = TRUE;
		}
	}

	/* if not items to display */
	if (display_items == 0)
		goto exit;

	display_nodes = user_data->num_nodes;

	first_node = user_data->dlg.first_node;

	/* Write the conv. and time headers */
	if (several_convs){
		fprintf(of, CONV_TIME_HEADER);
		empty_header = CONV_TIME_EMPTY_HEADER;
		header_length = CONV_TIME_HEADER_LENGTH;
	}
	else{
		fprintf(of, TIME_HEADER);
		empty_header = TIME_EMPTY_HEADER;
		header_length = TIME_HEADER_LENGTH;
	}

	/* Write the node names on top */
	for (i=0; i<display_nodes; i+=2){
		/* print the node identifiers */
		g_string_printf(label_string, "| %s",
			get_addr_name(&(user_data->nodes[i+first_node])));
		enlarge_string(label_string, NODE_CHARS_WIDTH*2, ' ');
		fprintf(of, "%s", label_string->str);
		g_string_printf(label_string, "| ");
		enlarge_string(label_string, NODE_CHARS_WIDTH, ' ');
		g_string_append(empty_line, label_string->str);
	}

	fprintf(of, "|\n%s", empty_header);
	g_string_printf(label_string, "| ");
	enlarge_string(label_string, NODE_CHARS_WIDTH, ' ');
	fprintf(of, "%s", label_string->str);

	/* Write the node names on top */
	for (i=1; i<display_nodes; i+=2){
		/* print the node identifiers */
		g_string_printf(label_string, "| %s",
			get_addr_name(&(user_data->nodes[i+first_node])));
		if (label_string->len < NODE_CHARS_WIDTH)
		{
			enlarge_string(label_string, NODE_CHARS_WIDTH, ' ');
			g_string_append(label_string, "| ");
		}
		enlarge_string(label_string, NODE_CHARS_WIDTH*2, ' ');
		fprintf(of, "%s", label_string->str);
		g_string_printf(label_string, "| ");
		enlarge_string(label_string, NODE_CHARS_WIDTH, ' ');
		g_string_append(empty_line, label_string->str);
	}

	fprintf(of, "\n");

	g_string_append_c(empty_line, '|');

	enlarge_string(separator_line, (guint32) empty_line->len + header_length, '-');

	/*
	 * Draw the items
	 */

	list = g_list_first(user_data->graph_info->list);
	while (list)
	{
		gai = list->data;
		list = g_list_next(list);

		if (!gai->display)
			continue;

		start_position = (gai->src_node-first_node)*NODE_CHARS_WIDTH+NODE_CHARS_WIDTH/2;

		end_position = (gai->dst_node-first_node)*NODE_CHARS_WIDTH+NODE_CHARS_WIDTH/2;

		if (start_position > end_position){
			item_width=start_position-end_position;
		}
		else if (start_position < end_position){
			item_width=end_position-start_position;
		}
		else{ /* same origin and destination address */
			end_position = start_position+NODE_CHARS_WIDTH;
			item_width = NODE_CHARS_WIDTH;
		}

		/* separator between conversations */
		if (gai->conv_num != first_conv_num){
			fprintf(of, "%s\n", separator_line->str);
			first_conv_num=gai->conv_num;
		}

		/* write the conversation number */
		if (several_convs){
			g_string_printf(label_string, "%i", gai->conv_num);
			enlarge_string(label_string, 5, ' ');
			fprintf(of, "%s", label_string->str);
		}

		/* write the time */
		g_string_printf(label_string, "|%.3f", gai->time);
		enlarge_string(label_string, 10, ' ');
		fprintf(of, "%s", label_string->str);

		/* write the frame label */

		g_string_printf(tmp_str, "%s", empty_line->str);
		overwrite(tmp_str,gai->frame_label,
			start_position,
			end_position
			);
		fprintf(of, "%s", tmp_str->str);

		/* write the comments */
		fprintf(of, "%s\n", gai->comment);

		/* write the arrow and frame label*/
		fprintf(of, "%s", empty_header);

		g_string_printf(tmp_str, "%s", empty_line->str);

		g_string_truncate(tmp_str2, 0);

		if (start_position<end_position){
			enlarge_string(tmp_str2, item_width-2, '-');
			g_string_append_c(tmp_str2, '>');
		}
		else{
			g_string_printf(tmp_str2, "<");
			enlarge_string(tmp_str2, item_width-1, '-');
		}

		overwrite(tmp_str,tmp_str2->str,
			start_position,
			end_position
			);

		g_snprintf(src_port,sizeof(src_port),"(%i)", gai->port_src);
		g_snprintf(dst_port,sizeof(dst_port),"(%i)", gai->port_dst);

		if (start_position<end_position){
			overwrite(tmp_str,src_port,start_position-9,start_position-1);
			overwrite(tmp_str,dst_port,end_position+1,end_position+9);
		}
		else{
			overwrite(tmp_str,src_port,start_position+1,start_position+9);
			overwrite(tmp_str,dst_port,end_position-9,end_position+1);
		}

		fprintf(of,"%s\n",tmp_str->str);
	}

exit:
	g_string_free(label_string, TRUE);
	g_string_free(empty_line, TRUE);
	g_string_free(separator_line, TRUE);
	g_string_free(tmp_str, TRUE);
	g_string_free(tmp_str2, TRUE);

	fclose (of);
	return TRUE;

}

/****************************************************************************/
static void save_to_file_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
	/* Note that we no longer have a Save to file dialog box. */
	save_to_file_w = NULL;
}

/****************************************************************************/
/* save in a file */

/* first an auxiliary function in case we need an overwrite confirmation dialog */

static void overwrite_existing_file_cb(gpointer dialog _U_, gint btn, gpointer user_data)
{
	switch(btn) {
	case(ESD_BTN_YES):
	    /* overwrite the file*/
	    dialog_graph_dump_to_file(user_data);
	    break;
	case(ESD_BTN_NO):
	    break;
	default:
	    g_assert_not_reached();
	}
}

/* and then the save in a file dialog itself */

static gboolean save_to_file_ok_cb(GtkWidget *ok_bt _U_, gpointer user_data)
{
	FILE *file_test;
	graph_analysis_data_t *user_data_p = user_data;

	user_data_p->dlg.save_file = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(save_to_file_w));

	/* Perhaps the user specified a directory instead of a file.
	   Check whether they did. */
	if (test_for_directory(user_data_p->dlg.save_file) == EISDIR) {
		/* It's a directory - set the file selection box to display it. */
		set_last_open_dir(user_data_p->dlg.save_file);
		file_selection_set_current_folder(save_to_file_w, get_last_open_dir());
		gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(save_to_file_w), "");
		g_free(user_data_p->dlg.save_file);
		return FALSE;  /* run the dialog again */
	}

	/* GtkFileChooserDialog/gtk_dialog_run is currently being used.         */
	/*      So: Trying to leave the graph_analysis window up if graph_dump  */
	/*          fails doesn't work well.                                    */
	/*  (See comment under on_save_bt_clicked)                              */
	/*                                                                      */
	/* As a work-around:                                                    */
	/*  We'll always destroy the window.                                    */

	/* check whether the file exists */
	file_test = ws_fopen(user_data_p->dlg.save_file,"r");
	if (file_test!=NULL){
		gpointer dialog;
		dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_YES_NO,
		  "%sFile: \"%s\" already exists!%s\n\n"
		  "Do you want to overwrite it?",
		  simple_dialog_primary_start(),user_data_p->dlg.save_file, simple_dialog_primary_end());
		simple_dialog_set_cb(dialog, overwrite_existing_file_cb, user_data);
		fclose(file_test);
		return TRUE;
	}

	else{
		if (!dialog_graph_dump_to_file(user_data)) {
			/* Couldn't open the file ?  */
			g_free(user_data_p->dlg.save_file);
			return TRUE;
		}
	}
	g_free(user_data_p->dlg.save_file);
	return TRUE;
}

/****************************************************************************/
static void
on_save_bt_clicked                    (GtkWidget       *button _U_,
                                       graph_analysis_data_t *user_data)
{
#if 0  /* XXX: GtkFileChooserDialog/gtk_dialog_run currently being used is effectively modal so this is not req'd */
	if (save_to_file_w != NULL) {
		/* There's already a Save to file dialog box; reactivate it. */
		reactivate_window(save_to_file_w);
		return;
	}
#endif
	save_to_file_w =
		gtk_file_chooser_dialog_new("Wireshark: Save graph to plain text file",
					    GTK_WINDOW(user_data->dlg.window),
					    GTK_FILE_CHOOSER_ACTION_SAVE,
					    GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
					    GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					    NULL);

	g_signal_connect(save_to_file_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(save_to_file_w, "destroy", G_CALLBACK(save_to_file_destroy_cb), NULL);

	gtk_widget_show(save_to_file_w);
	window_present(save_to_file_w);

	/* "Run" the GtkFileChooserDialog.                                              */
	/* Upon exit: If "Accept" run the OK callback.                                  */
	/*            If the OK callback returns with a FALSE status, re-run the dialog.*/
	/*            Destroy the window.                                               */
	/* XXX: If the OK callback pops up an alert box (eg: for an error) it *must*    */
	/*      return with a TRUE status so that the dialog window will be destroyed.  */
	/*      Trying to re-run the dialog after popping up an alert box will not work */
	/*       since the user will not be able to dismiss the alert box.              */
	/*      The (somewhat unfriendly) effect: the user must re-invoke the           */
	/*      GtkFileChooserDialog whenever the OK callback pops up an alert box.     */
	/*                                                                              */
	/*      ToDo: use GtkFileChooserWidget in a dialog window instead of            */
	/*            GtkFileChooserDialog.                                             */
	while (gtk_dialog_run(GTK_DIALOG(save_to_file_w)) == GTK_RESPONSE_ACCEPT) {
		if (save_to_file_ok_cb(NULL, user_data)) {
			break;  /* we're done */
		}
	}
	window_destroy(save_to_file_w);
}

/****************************************************************************/
static void dialog_graph_draw(graph_analysis_data_t *user_data)
{
	guint32 i, last_item, first_item, display_items;
	guint32 start_arrow, end_arrow, label_x, src_port_x, dst_port_x, arrow_width;
	guint32 current_item;
	guint32 left_x_border;
	guint32 right_x_border;
	guint32 top_y_border;
	guint32 bottom_y_border;
	graph_analysis_item_t *gai;
	guint16 first_conv_num;
	gboolean first_packet = TRUE;

	GdkGC *frame_fg_color;
	GdkGC *frame_bg_color;
	GdkGC *div_line_color;
	GdkGC *column_header_gc;

	PangoLayout  *layout;
	PangoLayout  *middle_layout;
	PangoLayout  *small_layout;
	PangoFontDescription *middle_font_desc;
	gint middle_font_size;
	PangoFontDescription *small_font_desc;
	gint small_font_size;

	gint label_width, label_height;
	guint32 draw_width, draw_height;
	char label_string[MAX_COMMENT];
	GList *list;

	GtkAllocation draw_area_time_alloc, draw_area_alloc, draw_area_comments_alloc;
	GtkStyle *draw_area_time_style, *draw_area_style, *draw_area_comments_style;

	/* new variables */

	if(!user_data->dlg.needs_redraw){
		return;
	}
	user_data->dlg.needs_redraw=FALSE;

	column_header_gc = gdk_gc_new(user_data->dlg.pixmap_time);
	gdk_gc_set_fill(column_header_gc,GDK_TILED);
	gdk_gc_set_tile(column_header_gc, gdk_pixmap_create_from_xpm_d(user_data->dlg.pixmap_time,NULL,NULL,(gchar **)voip_bg_xpm));

#if GTK_CHECK_VERSION(2,18,0)
	gtk_widget_get_allocation(user_data->dlg.draw_area_time, &draw_area_time_alloc);
	gtk_widget_get_allocation(user_data->dlg.draw_area, &draw_area_alloc);
	gtk_widget_get_allocation(user_data->dlg.draw_area_comments, &draw_area_comments_alloc);
#else
	draw_area_time_alloc = user_data->dlg.draw_area_time->allocation;
	draw_area_alloc = user_data->dlg.draw_area->allocation;
	draw_area_comments_alloc = user_data->dlg.draw_area_comments->allocation;
#endif

	draw_area_time_style = gtk_widget_get_style(user_data->dlg.draw_area_time);
	draw_area_style = gtk_widget_get_style(user_data->dlg.draw_area);
	draw_area_comments_style = gtk_widget_get_style(user_data->dlg.draw_area_comments);

	/* Clear out old plt */
	if ( GDK_IS_DRAWABLE(user_data->dlg.pixmap_time) )
		gdk_draw_rectangle(user_data->dlg.pixmap_time,
						   draw_area_time_style->white_gc,
						   TRUE,
						   0, 0,
						   draw_area_time_alloc.width,
						   draw_area_time_alloc.height);

	if ( GDK_IS_DRAWABLE(user_data->dlg.pixmap_main) )
		gdk_draw_rectangle(user_data->dlg.pixmap_main,
						   draw_area_style->white_gc,
						   TRUE,
						   0, 0,
						   draw_area_alloc.width,
						   draw_area_alloc.height);

	if ( GDK_IS_DRAWABLE(user_data->dlg.pixmap_comments) )
		gdk_draw_rectangle(user_data->dlg.pixmap_comments,
						   draw_area_style->white_gc,
						   TRUE,
						   0, 0,
						   draw_area_comments_alloc.width,
						   draw_area_comments_alloc.height);

	/* Calculate the y border */
	top_y_border=TOP_Y_BORDER;	/* to display the node address */
	bottom_y_border=BOTTOM_Y_BORDER;

	draw_height=draw_area_alloc.height-top_y_border-bottom_y_border;

	first_item = user_data->dlg.first_item;
	display_items = draw_height/ITEM_HEIGHT;

	/* get the items to display and fill the matrix array */
	list = g_list_first(user_data->graph_info->list);
	current_item = 0;
	i = 0;
	while (list)
	{
		gai = list->data;
		if (gai->display){
			if (current_item>=display_items) break;		/* the item is outside the display */
			if (i>=first_item){
				user_data->dlg.items[current_item].frame_num = gai->frame_num;
				user_data->dlg.items[current_item].time = gai->time;
				user_data->dlg.items[current_item].port_src = gai->port_src;
				user_data->dlg.items[current_item].port_dst = gai->port_dst;
				/* Add "..." if the length is 50 characters */
				if (strlen(gai->frame_label) > 48) {
					gai->frame_label[48] = '.';
					gai->frame_label[47] = '.';
					gai->frame_label[46] = '.';
				}
				user_data->dlg.items[current_item].frame_label = gai->frame_label;
				user_data->dlg.items[current_item].comment = gai->comment;
				user_data->dlg.items[current_item].conv_num = gai->conv_num;

				if (first_packet){
					first_conv_num = gai->conv_num;
					first_packet=FALSE;
				}

				user_data->dlg.items[current_item].src_node = gai->src_node;
				user_data->dlg.items[current_item].dst_node = gai->dst_node;
				user_data->dlg.items[current_item].line_style = gai->line_style;
				current_item++;
			}
			i++;
		}

		list = g_list_next(list);
	}
	/* in case the windows is resized so we have to move the top item */
	if ((first_item + display_items) > user_data->num_items){
		if (display_items>user_data->num_items)
			first_item=0;
		else
			first_item = user_data->num_items - display_items;
	}

	/* in case there are less items than possible displayed */
	display_items = current_item;
	last_item = first_item+display_items-1;

	/* if no items to display */
	if (display_items == 0)	return;


	/* Calculate the x borders */
	/* We use time from the last display item to calcultate the x left border */
	g_snprintf(label_string, MAX_LABEL, "%.3f", user_data->dlg.items[display_items-1].time);
	layout = gtk_widget_create_pango_layout(user_data->dlg.draw_area_time, label_string);
	middle_layout = gtk_widget_create_pango_layout(user_data->dlg.draw_area_time, label_string);
	small_layout = gtk_widget_create_pango_layout(user_data->dlg.draw_area_time, label_string);

	middle_font_desc = pango_font_description_copy(pango_context_get_font_description(pango_layout_get_context(middle_layout)));
	middle_font_size = pango_font_description_get_size(middle_font_desc);
	pango_font_description_set_size(middle_font_desc,(gint)(middle_font_size*0.8));
	pango_layout_set_font_description(middle_layout,middle_font_desc);

	small_font_desc = pango_font_description_copy(pango_context_get_font_description(pango_layout_get_context(small_layout)));
	small_font_size = pango_font_description_get_size(small_font_desc);
	pango_font_description_set_size(small_font_desc,(gint)(small_font_size*0.7));
	pango_layout_set_font_description(small_layout,small_font_desc);

	pango_layout_get_pixel_size(layout, &label_width, &label_height);

	/* resize the "time" draw area */
	left_x_border=0;
	user_data->dlg.left_x_border = left_x_border;

	right_x_border=0;
	draw_width=user_data->dlg.pixmap_width-right_x_border-left_x_border;

	/* Paint time title background */
	if ( GDK_IS_DRAWABLE(user_data->dlg.pixmap_time) )
		gdk_draw_rectangle(user_data->dlg.pixmap_time,
						   column_header_gc,
						   TRUE,						/* TRUE if the rectangle should be filled.*/
						   0,							/* the x coordinate of the left edge of the rectangle.*/
						   0,							/* the y coordinate of the top edge of the rectangle. */
						   draw_area_time_alloc.width, /* the width of the rectangle. */
						   top_y_border);				/* the height of the rectangle. */
	/* Paint main title background */
	if ( GDK_IS_DRAWABLE(user_data->dlg.pixmap_main) )
		gdk_draw_rectangle(user_data->dlg.pixmap_main,
						   column_header_gc,
						   TRUE,
						   0,
						   0,
						   draw_area_alloc.width,
						   top_y_border);
	/* Paint main comment background */
	if ( GDK_IS_DRAWABLE(user_data->dlg.pixmap_comments) )
		gdk_draw_rectangle(user_data->dlg.pixmap_comments,
						   column_header_gc,
						   TRUE,
						   0,
						   0,
						   draw_area_comments_alloc.width,
						   top_y_border);


	/* Draw the word "Time" on top of time column */
	g_snprintf(label_string, label_width, "%s", "  Time");
	pango_layout_set_text(layout, label_string, -1);
	pango_layout_get_pixel_size(layout, &label_width, &label_height);
	if (GDK_IS_DRAWABLE(user_data->dlg.pixmap_time)) {
		gdk_draw_layout(user_data->dlg.pixmap_time,
						draw_area_time_style->black_gc,
						left_x_border,
						top_y_border/2-label_height/2,
						layout);
	}

	/* Draw the word "Comment" on top of comment column */
	g_snprintf(label_string, label_width, "%s", "Comment");
	pango_layout_set_text(layout, label_string, -1);
	pango_layout_get_pixel_size(layout, &label_width, &label_height);
	if (GDK_IS_DRAWABLE(user_data->dlg.pixmap_comments)) {
		gdk_draw_layout(user_data->dlg.pixmap_comments,
			   draw_area_comments_style->black_gc,
			   MAX_COMMENT/2-label_width/2,
			   top_y_border/2-label_height/2,
			   layout);
	}

	/* Paint the background items */
	for (current_item=0; current_item<display_items; current_item++){
		/*select the color. if it is the selected item select blue color */
		if ( current_item+first_item == user_data->dlg.selected_item ) {
			gdk_gc_set_ts_origin(user_data->dlg.bg_gc[0],left_x_border,top_y_border+current_item*ITEM_HEIGHT);
			frame_bg_color = user_data->dlg.bg_gc[0];
		} else {
			frame_bg_color = user_data->dlg.bg_gc[1+user_data->dlg.items[current_item].conv_num%MAX_NUM_COL_CONV];
		}

		/* Paint background */
		if (GDK_IS_DRAWABLE(user_data->dlg.pixmap_main)) {
			gdk_draw_rectangle(user_data->dlg.pixmap_main,
							   frame_bg_color,
							   TRUE,
							   left_x_border,
							   top_y_border+current_item*ITEM_HEIGHT,
							   draw_width,
							   ITEM_HEIGHT);
		}
	}
	/* Draw the node names on top and the division lines */
	for (i=0; i<user_data->num_nodes; i++){
		/* print the node identifiers */
		/* XXX we assign 5 pixels per character in the node identity */
		g_strlcpy(label_string, get_addr_name(&(user_data->nodes[i])), NODE_WIDTH/5);
		pango_layout_set_text(layout, label_string, -1);
		pango_layout_get_pixel_size(layout, &label_width, &label_height);
		if (GDK_IS_DRAWABLE(user_data->dlg.pixmap_main)) {
			gdk_draw_layout(user_data->dlg.pixmap_main,
							draw_area_style->black_gc,
							left_x_border+NODE_WIDTH/2-label_width/2+NODE_WIDTH*i,
							top_y_border/2-((i&1)?0:label_height),
							layout);
		}

		/* draw the node division lines */
		if (GDK_IS_DRAWABLE(user_data->dlg.pixmap_main) ) {
			gdk_draw_line(user_data->dlg.pixmap_main, user_data->dlg.div_line_gc[0],
						  left_x_border+NODE_WIDTH/2+NODE_WIDTH*i,
						  top_y_border,
						  left_x_border+NODE_WIDTH/2+NODE_WIDTH*i,
						  draw_area_alloc.height-bottom_y_border);
		}

	}

	/* Draw the items */
	for (current_item=0; current_item<display_items; current_item++){
		/* draw the time */
		g_snprintf(label_string, MAX_LABEL, "%.3f", user_data->dlg.items[current_item].time);
		pango_layout_set_text(layout, label_string, -1);
		pango_layout_get_pixel_size(layout, &label_width, &label_height);
		if (GDK_IS_DRAWABLE(user_data->dlg.pixmap_time)) {
			gdk_draw_layout(user_data->dlg.pixmap_time,
							draw_area_style->black_gc,
							3,
							top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT/2-label_height/2,
							layout);
		}

		/*draw the comments */
		g_snprintf(label_string, MAX_COMMENT, "%s", user_data->dlg.items[current_item].comment);
		pango_layout_set_text(middle_layout, label_string, -1);
		pango_layout_get_pixel_size(middle_layout, &label_width, &label_height);
		if (GDK_IS_DRAWABLE(user_data->dlg.pixmap_comments)) {
			gdk_draw_layout(user_data->dlg.pixmap_comments,
							draw_area_style->black_gc,
							2,
							top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT/2-label_height/2,
							middle_layout);
		}
		/* select colors */
		if ( current_item+first_item == user_data->dlg.selected_item ){
			frame_fg_color = draw_area_style->white_gc;
			div_line_color = user_data->dlg.div_line_gc[1];
		} else {
			frame_fg_color = draw_area_style->black_gc;
			div_line_color = user_data->dlg.div_line_gc[0];
		}
		/* draw the arrow line */
		start_arrow = left_x_border+(user_data->dlg.items[current_item].src_node)*NODE_WIDTH+NODE_WIDTH/2;
		end_arrow = left_x_border+(user_data->dlg.items[current_item].dst_node)*NODE_WIDTH+NODE_WIDTH/2;

		if (GDK_IS_DRAWABLE(user_data->dlg.pixmap_main) ) {
			gdk_draw_line(user_data->dlg.pixmap_main, frame_fg_color,
				start_arrow,
				top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-7,
				end_arrow,
				top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-7);

			/* draw the additional line when line style is 2 pixels width */
			if (user_data->dlg.items[current_item].line_style == 2) {
				gdk_draw_line(user_data->dlg.pixmap_main, frame_fg_color,
					start_arrow,
					top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-6,
					end_arrow,
					top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-6);
			}
		}

		/* draw the arrow */
		if (start_arrow<end_arrow)
			draw_arrow(user_data->dlg.pixmap_main, frame_fg_color, end_arrow-WIDTH_ARROW,top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-7, RIGHT_ARROW);
		else
			draw_arrow(user_data->dlg.pixmap_main, frame_fg_color, end_arrow+WIDTH_ARROW,top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-7, LEFT_ARROW);

		/* draw the frame comment */
		g_snprintf(label_string, MAX_LABEL, "%s", user_data->dlg.items[current_item].frame_label);
		pango_layout_set_text(layout, label_string, -1);
		pango_layout_get_pixel_size(layout, &label_width, &label_height);
		if (start_arrow<end_arrow){
			arrow_width = end_arrow-start_arrow;
			label_x = arrow_width/2+start_arrow;
		}
		else {
			arrow_width = start_arrow-end_arrow;
			label_x = arrow_width/2+end_arrow;
		}

		if (label_width>(gint)arrow_width) arrow_width = label_width;

		if ((int)left_x_border > ((int)label_x-(int)label_width/2))
			label_x = left_x_border + label_width/2;

		if (GDK_IS_DRAWABLE(user_data->dlg.pixmap_main)) {
			gdk_draw_layout(user_data->dlg.pixmap_main,
							frame_fg_color,
							label_x - label_width/2,
							top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT/2-label_height/2-3,
							layout);
		}

		/* draw the source port number */
		g_snprintf(label_string, MAX_LABEL, "(%i)", user_data->dlg.items[current_item].port_src);
		pango_layout_set_text(small_layout, label_string, -1);
		pango_layout_get_pixel_size(small_layout, &label_width, &label_height);
		if (start_arrow<end_arrow){
			src_port_x = start_arrow - label_width - 2;
		}
		else {
			src_port_x = start_arrow + 2;
		}
		if (GDK_IS_DRAWABLE(user_data->dlg.pixmap_main)) {
			gdk_draw_layout(user_data->dlg.pixmap_main,
							div_line_color,
							src_port_x,
							top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-2-label_height/2-2,
							small_layout);
		}

		/* draw the destination port number */
		g_snprintf(label_string, MAX_LABEL, "(%i)", user_data->dlg.items[current_item].port_dst);
		pango_layout_set_text(small_layout, label_string, -1);
		pango_layout_get_pixel_size(small_layout, &label_width, &label_height);
		if (start_arrow<end_arrow){
			dst_port_x = end_arrow + 2;
		}
		else {
			dst_port_x = end_arrow - label_width - 2;
		}
		if (GDK_IS_DRAWABLE(user_data->dlg.pixmap_main)) {
			gdk_draw_layout(user_data->dlg.pixmap_main,
							div_line_color,
							dst_port_x,
							top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-2-label_height/2-2,
							small_layout);
		}
		/* draw the div line of the selected item with soft gray*/
		if ( current_item+first_item == user_data->dlg.selected_item )
			for (i=0; i<user_data->num_nodes; i++){
				if (GDK_IS_DRAWABLE(user_data->dlg.pixmap_main) ) {
					gdk_draw_line(user_data->dlg.pixmap_main, user_data->dlg.div_line_gc[1],
								  left_x_border+NODE_WIDTH/2+NODE_WIDTH*i,
								  (user_data->dlg.selected_item-first_item)*ITEM_HEIGHT+TOP_Y_BORDER,
								  left_x_border+NODE_WIDTH/2+NODE_WIDTH*i,
								  (user_data->dlg.selected_item-first_item)*ITEM_HEIGHT+TOP_Y_BORDER+ITEM_HEIGHT);
				}
			}
	}

	g_object_unref(G_OBJECT(layout));

	/* refresh the draw areas */
#if GTK_CHECK_VERSION(2,18,0)
	if (gtk_widget_is_drawable(user_data->dlg.draw_area_time) )
		gdk_draw_pixmap(gtk_widget_get_window(user_data->dlg.draw_area_time),
						draw_area_time_style->fg_gc[gtk_widget_get_state(user_data->dlg.draw_area_time)],

#else
	if (GDK_IS_DRAWABLE(user_data->dlg.draw_area_time->window) )
		gdk_draw_pixmap(user_data->dlg.draw_area_time->window,
						draw_area_time_style->fg_gc[GTK_WIDGET_STATE(user_data->dlg.draw_area_time)],

#endif
						user_data->dlg.pixmap_time,
						0, 0,
						0, 0,
						draw_area_time_alloc.width, draw_area_time_alloc.height);

#if GTK_CHECK_VERSION(2,18,0)
	if (gtk_widget_is_drawable(user_data->dlg.draw_area) )
		gdk_draw_pixmap(gtk_widget_get_window(user_data->dlg.draw_area),
						draw_area_style->fg_gc[gtk_widget_get_state(user_data->dlg.draw_area)],
#else
	if (GDK_IS_DRAWABLE(user_data->dlg.draw_area->window) )
		gdk_draw_pixmap(user_data->dlg.draw_area->window,
						draw_area_style->fg_gc[GTK_WIDGET_STATE(user_data->dlg.draw_area)],
#endif
						user_data->dlg.pixmap_main,
						0, 0,
						0, 0,
						draw_area_alloc.width, draw_area_alloc.height);

#if GTK_CHECK_VERSION(2,18,0)
	if (gtk_widget_is_drawable(user_data->dlg.draw_area_comments) )
		gdk_draw_pixmap(gtk_widget_get_window(user_data->dlg.draw_area_comments),
						draw_area_comments_style->fg_gc[gtk_widget_get_state(user_data->dlg.draw_area_comments)],
#else
	if (GDK_IS_DRAWABLE(user_data->dlg.draw_area_comments->window) )
		gdk_draw_pixmap(user_data->dlg.draw_area_comments->window,
						draw_area_comments_style->fg_gc[GTK_WIDGET_STATE(user_data->dlg.draw_area_comments)],
#endif
						user_data->dlg.pixmap_comments,
						0, 0,
						0, 0,
						draw_area_comments_alloc.width, draw_area_comments_alloc.height);

	/* update the v_scrollbar */
#if GTK_CHECK_VERSION(2,14,0)
	gtk_adjustment_set_upper(user_data->dlg.v_scrollbar_adjustment, (gdouble) user_data->num_items-1);
	gtk_adjustment_set_step_increment(user_data->dlg.v_scrollbar_adjustment, 1);
	gtk_adjustment_set_page_increment(user_data->dlg.v_scrollbar_adjustment, (gdouble) (last_item-first_item));
	gtk_adjustment_set_page_size(user_data->dlg.v_scrollbar_adjustment, (gdouble) (last_item-first_item));
	gtk_adjustment_set_value(user_data->dlg.v_scrollbar_adjustment, (gdouble) first_item);
#else
	user_data->dlg.v_scrollbar_adjustment->upper=(gfloat) user_data->num_items-1;
	user_data->dlg.v_scrollbar_adjustment->step_increment=1;
	user_data->dlg.v_scrollbar_adjustment->page_increment=(gfloat) (last_item-first_item);
	user_data->dlg.v_scrollbar_adjustment->page_size=(gfloat) (last_item-first_item);
	user_data->dlg.v_scrollbar_adjustment->value=(gfloat) first_item;
#endif

	gtk_adjustment_changed(user_data->dlg.v_scrollbar_adjustment);
	gtk_adjustment_value_changed(user_data->dlg.v_scrollbar_adjustment);
}

/****************************************************************************/
static void dialog_graph_redraw(graph_analysis_data_t *user_data)
{
	user_data->dlg.needs_redraw=TRUE;
	dialog_graph_draw(user_data);
}

/****************************************************************************/
static gboolean button_press_event(GtkWidget *widget _U_, GdkEventButton *event, gpointer data)
{
	graph_analysis_data_t *user_data = data;
	guint32 item;

	if (event->type != GDK_BUTTON_PRESS) return TRUE;

	if (event->y<TOP_Y_BORDER) return TRUE;

	/* get the item clicked */
	item = ((guint32)event->y - TOP_Y_BORDER) / ITEM_HEIGHT;
	if (item >= user_data->num_items) return TRUE;
	user_data->dlg.selected_item = item + user_data->dlg.first_item;

	user_data->dlg.needs_redraw=TRUE;
	dialog_graph_draw(user_data);

	cf_goto_frame(&cfile, user_data->dlg.items[item].frame_num);

	return TRUE;
}

/****************************************************************************/
static gboolean scroll_event(GtkWidget *widget _U_, GdkEventScroll *event, gpointer data)
{
	graph_analysis_data_t *user_data = data;

	/* Up scroll */
	switch(event->direction) {
	case(GDK_SCROLL_UP):
		if (user_data->dlg.first_item == 0) return TRUE;
		if (user_data->dlg.first_item < 3)
			user_data->dlg.first_item = 0;
		else
			user_data->dlg.first_item -= 3;
		break;
	case(GDK_SCROLL_DOWN):
#if GTK_CHECK_VERSION(2,14,0)
		if ((user_data->dlg.first_item+gtk_adjustment_get_page_size(user_data->dlg.v_scrollbar_adjustment)+1 == user_data->num_items)) return TRUE;
		if ((user_data->dlg.first_item+gtk_adjustment_get_page_size(user_data->dlg.v_scrollbar_adjustment)+1) > (user_data->num_items-3))
			user_data->dlg.first_item = user_data->num_items-(guint32)gtk_adjustment_get_page_size(user_data->dlg.v_scrollbar_adjustment)-1;
#else
		if ((user_data->dlg.first_item+user_data->dlg.v_scrollbar_adjustment->page_size+1 == user_data->num_items)) return TRUE;
		if ((user_data->dlg.first_item+user_data->dlg.v_scrollbar_adjustment->page_size+1) > (user_data->num_items-3))
			user_data->dlg.first_item = user_data->num_items-(guint32)user_data->dlg.v_scrollbar_adjustment->page_size-1;
#endif
		else
			user_data->dlg.first_item += 3;
	    break;
	case(GDK_SCROLL_LEFT):
	case(GDK_SCROLL_RIGHT):
		/* nothing to do */
		break;
	}
	dialog_graph_redraw(user_data);

	return TRUE;
}

/****************************************************************************/
static gboolean key_press_event(GtkWidget *widget _U_, GdkEventKey *event, gpointer data)
{
	graph_analysis_data_t *user_data = data;

	/* if there is nothing selected, just return */
	if (user_data->dlg.selected_item == 0xFFFFFFFF) return TRUE;

	/* Up arrow */
	if (event->keyval == GDK_Up){
		if (user_data->dlg.selected_item == 0) return TRUE;
		user_data->dlg.selected_item--;
#if GTK_CHECK_VERSION(2,14,0)
		if ( (user_data->dlg.selected_item<user_data->dlg.first_item) || (user_data->dlg.selected_item>user_data->dlg.first_item+gtk_adjustment_get_page_size(user_data->dlg.v_scrollbar_adjustment)) )
#else
		if ( (user_data->dlg.selected_item<user_data->dlg.first_item) || (user_data->dlg.selected_item>user_data->dlg.first_item+user_data->dlg.v_scrollbar_adjustment->page_size) )
#endif
			user_data->dlg.first_item = user_data->dlg.selected_item;
		/* Down arrow */
	} else if (event->keyval == GDK_Down){
		if (user_data->dlg.selected_item == user_data->num_items-1) return TRUE;
		user_data->dlg.selected_item++;
#if GTK_CHECK_VERSION(2,14,0)
		if ( (user_data->dlg.selected_item<user_data->dlg.first_item) || (user_data->dlg.selected_item>user_data->dlg.first_item+gtk_adjustment_get_page_size(user_data->dlg.v_scrollbar_adjustment)) )
			user_data->dlg.first_item = (guint32)user_data->dlg.selected_item-(guint32)gtk_adjustment_get_page_size(user_data->dlg.v_scrollbar_adjustment);
#else
		if ( (user_data->dlg.selected_item<user_data->dlg.first_item) || (user_data->dlg.selected_item>user_data->dlg.first_item+user_data->dlg.v_scrollbar_adjustment->page_size) )
			user_data->dlg.first_item = (guint32)user_data->dlg.selected_item-(guint32)user_data->dlg.v_scrollbar_adjustment->page_size;
#endif

	} else if (event->keyval == GDK_Left){
		if (user_data->dlg.first_node == 0) return TRUE;
		user_data->dlg.first_node--;
	} else return TRUE;

	user_data->dlg.needs_redraw=TRUE;
	dialog_graph_draw(user_data);

	cf_goto_frame(&cfile, user_data->dlg.items[user_data->dlg.selected_item-user_data->dlg.first_item].frame_num);

	return TRUE;
}

/****************************************************************************/
static gboolean expose_event(GtkWidget *widget, GdkEventExpose *event, gpointer data)
{
	graph_analysis_data_t *user_data = data;
#if GTK_CHECK_VERSION(2,18,0)
	GtkStyle *widget_style;
#endif

#if GTK_CHECK_VERSION(2,18,0)
	widget_style = gtk_widget_get_style(widget);

	if (gtk_widget_is_drawable(widget))
		gdk_draw_pixmap(gtk_widget_get_window(widget),
			widget_style->fg_gc[gtk_widget_get_state(widget)],
#else
	if (GDK_IS_DRAWABLE(widget->window))
		gdk_draw_pixmap(widget->window,
			widget->style->fg_gc[GTK_WIDGET_STATE(widget)],
#endif
			user_data->dlg.pixmap_main,
			event->area.x, event->area.y,
			event->area.x, event->area.y,
			event->area.width, event->area.height);

	return FALSE;
}

/****************************************************************************/
static gboolean expose_event_comments(GtkWidget *widget, GdkEventExpose *event, gpointer data)
{
	graph_analysis_data_t *user_data = data;
#if GTK_CHECK_VERSION(2,18,0)
	GtkStyle *widget_style;
#endif

#if GTK_CHECK_VERSION(2,18,0)
	widget_style = gtk_widget_get_style(widget);

	if (gtk_widget_is_drawable(widget))
		gdk_draw_pixmap(gtk_widget_get_window(widget),
			widget_style->fg_gc[gtk_widget_get_state(widget)],
#else
	if (GDK_IS_DRAWABLE(widget->window))
		gdk_draw_pixmap(widget->window,
			widget->style->fg_gc[GTK_WIDGET_STATE(widget)],
#endif
			user_data->dlg.pixmap_comments,
			event->area.x, event->area.y,
			event->area.x, event->area.y,
			event->area.width, event->area.height);

	return FALSE;
}

/****************************************************************************/
static gboolean expose_event_time(GtkWidget *widget, GdkEventExpose *event, gpointer data)
{
	graph_analysis_data_t *user_data = data;
#if GTK_CHECK_VERSION(2,18,0)
	GtkStyle *widget_style;
#endif

#if GTK_CHECK_VERSION(2,18,0)
	widget_style = gtk_widget_get_style(widget);

	if (gtk_widget_is_drawable(widget) )
		gdk_draw_pixmap(gtk_widget_get_window(widget),
			widget_style->fg_gc[gtk_widget_get_state(widget)],
#else
	if (GDK_IS_DRAWABLE(widget->window) )
		gdk_draw_pixmap(widget->window,
			widget->style->fg_gc[GTK_WIDGET_STATE(widget)],
#endif
			user_data->dlg.pixmap_time,
			event->area.x, event->area.y,
			event->area.x, event->area.y,
			event->area.width, event->area.height);

	return FALSE;
}

/****************************************************************************/
static gboolean configure_event(GtkWidget *widget, GdkEventConfigure *event _U_, gpointer data)
{
	graph_analysis_data_t *user_data = data;
	GtkAllocation widget_alloc;
	int i;
	GtkStyle *widget_style;

	/* gray and soft gray colors */
	static GdkColor color_div_line[2] = {
		{0, 0x64ff, 0x64ff, 0x64ff},
		{0, 0x25ff, 0x25ff, 0x25ff}
		/*{0, 0x7fff, 0x7fff, 0x7fff}*/
	};

	/* the first color is blue to highlight the selected item */
	static GdkColor col[MAX_NUM_COL_CONV+1] = {
		{0,     0x00FF, 0x00FF, 0xFFFF},
		{0,     0x90FF, 0xEEFF, 0x90FF},
		{0,     0xFFFF, 0xA0FF, 0x7AFF},
		{0,     0xFFFF, 0xB6FF, 0xC1FF},
		{0,     0xFAFF, 0xFAFF, 0xD2FF},
		{0,     0xFFFF, 0xFFFF, 0x33FF},
		{0,     0x66FF, 0xCDFF, 0xAAFF},
		{0,     0xE0FF, 0xFFFF, 0xFFFF},
		{0,     0xB0FF, 0xC4FF, 0xDEFF},
		{0,     0x87FF, 0xCEFF, 0xFAFF},
		{0,     0xD3FF, 0xD3FF, 0xD3FF}
	};

	if(user_data->dlg.pixmap_main){
		gdk_pixmap_unref(user_data->dlg.pixmap_main);
		user_data->dlg.pixmap_main=NULL;
	}

#if GTK_CHECK_VERSION(2,18,0)
	gtk_widget_get_allocation(widget, &widget_alloc);
	widget_style = gtk_widget_get_style(widget);
#else
	widget_alloc = widget->allocation;
	widget_style = widget->style;
#endif

#if GTK_CHECK_VERSION(2,14,0)
	user_data->dlg.pixmap_main=gdk_pixmap_new(gtk_widget_get_window(widget),
#else
	user_data->dlg.pixmap_main=gdk_pixmap_new(widget->window,
#endif
		widget_alloc.width,
		widget_alloc.height,
		-1);

	if ( GDK_IS_DRAWABLE(user_data->dlg.pixmap_main) )
			gdk_draw_rectangle(user_data->dlg.pixmap_main,
				widget_style->white_gc,
				TRUE,
				0, 0,
				widget_alloc.width,
				widget_alloc.height);

	/* create gc for division lines and set the line stype to dash */
	for (i=0; i<2; i++){
		user_data->dlg.div_line_gc[i]=gdk_gc_new(user_data->dlg.pixmap_main);
		gdk_gc_set_line_attributes(user_data->dlg.div_line_gc[i], 1, GDK_LINE_ON_OFF_DASH, 0, 0);
		gdk_gc_set_rgb_fg_color(user_data->dlg.div_line_gc[i], &color_div_line[i]);
	}

	/* create gcs for the background items */
	for (i=0; i<MAX_NUM_COL_CONV+1; i++){
		if (i==0) {
			user_data->dlg.pixmap_tile_select=gdk_pixmap_create_from_xpm_d(user_data->dlg.pixmap_main,NULL,NULL,(gchar **)voip_select_xpm);
			user_data->dlg.bg_gc[i]=gdk_gc_new(user_data->dlg.pixmap_tile_select);
			gdk_gc_set_fill(user_data->dlg.bg_gc[i], GDK_TILED);
			gdk_gc_set_tile(user_data->dlg.bg_gc[i], user_data->dlg.pixmap_tile_select);
		} else {
			user_data->dlg.bg_gc[i]=gdk_gc_new(user_data->dlg.pixmap_main);
			gdk_gc_set_rgb_fg_color(user_data->dlg.bg_gc[i], &col[i]);
		}
	}

	dialog_graph_redraw(user_data);

	return TRUE;
}

/****************************************************************************/
static gboolean configure_event_comments(GtkWidget *widget, GdkEventConfigure *event _U_, gpointer data)
{
	graph_analysis_data_t *user_data = data;
	GtkAllocation widget_alloc;
	GtkStyle *widget_style;

#if GTK_CHECK_VERSION(2,18,0)
	gtk_widget_get_allocation(widget, &widget_alloc);
	widget_style = gtk_widget_get_style(widget);
#else
	widget_alloc = widget->allocation;
	widget_style = widget->style;
#endif

	if(user_data->dlg.pixmap_comments){
		gdk_pixmap_unref(user_data->dlg.pixmap_comments);
		user_data->dlg.pixmap_comments=NULL;
	}

#if GTK_CHECK_VERSION(2,14,0)
	user_data->dlg.pixmap_comments=gdk_pixmap_new(gtk_widget_get_window(widget),
#else
	user_data->dlg.pixmap_comments=gdk_pixmap_new(widget->window,
#endif

						widget_alloc.width,
						widget_alloc.height,
						-1);

	if ( GDK_IS_DRAWABLE(user_data->dlg.pixmap_main) )
		gdk_draw_rectangle(user_data->dlg.pixmap_comments,
						widget_style->white_gc,
						TRUE,
						0, 0,
						widget_alloc.width,
						widget_alloc.height);

	dialog_graph_redraw(user_data);
	return TRUE;
}

/****************************************************************************/
static gboolean configure_event_time(GtkWidget *widget, GdkEventConfigure *event _U_, gpointer data)
{
	graph_analysis_data_t *user_data = data;
	GtkAllocation widget_alloc;
	GtkStyle *widget_style;

#if GTK_CHECK_VERSION(2,18,0)
	gtk_widget_get_allocation(widget, &widget_alloc);
	widget_style = gtk_widget_get_style(widget);
#else
	widget_alloc = widget->allocation;
	widget_style = widget->style;
#endif

	if(user_data->dlg.pixmap_time){
		gdk_pixmap_unref(user_data->dlg.pixmap_time);
		user_data->dlg.pixmap_time=NULL;
	}

#if GTK_CHECK_VERSION(2,14,0)
	user_data->dlg.pixmap_time=gdk_pixmap_new(gtk_widget_get_window(widget),
#else
	user_data->dlg.pixmap_time=gdk_pixmap_new(widget->window,
#endif
						widget_alloc.width,
						widget_alloc.height,
						-1);

	if ( GDK_IS_DRAWABLE(user_data->dlg.pixmap_time) )
		gdk_draw_rectangle(user_data->dlg.pixmap_time,
						widget_style->white_gc,
						TRUE,
						0, 0,
						widget_alloc.width,
						widget_alloc.height);

	dialog_graph_redraw(user_data);

	return TRUE;
}

/****************************************************************************/
static gboolean pane_callback(GtkWidget *widget, GParamSpec *pspec _U_, gpointer data)
{
	graph_analysis_data_t *user_data = data;
	GtkStyle *draw_area_comments_style;
	GtkAllocation draw_area_comments_alloc;

	if (gtk_paned_get_position(GTK_PANED(user_data->dlg.hpane)) > user_data->dlg.pixmap_width)
		gtk_paned_set_position(GTK_PANED(user_data->dlg.hpane), user_data->dlg.pixmap_width);
	else if (gtk_paned_get_position(GTK_PANED(user_data->dlg.hpane)) < NODE_WIDTH*2)
		gtk_paned_set_position(GTK_PANED(user_data->dlg.hpane), NODE_WIDTH*2);

	/* repaint the comment area because when moving the pane position there are times that the expose_event_comments is not called */

#if GTK_CHECK_VERSION(2,18,0)
	gtk_widget_get_allocation(user_data->dlg.draw_area_comments, &draw_area_comments_alloc);
	draw_area_comments_style = gtk_widget_get_style(user_data->dlg.draw_area_comments);
#else
	draw_area_comments_alloc = user_data->dlg.draw_area_comments->allocation;
	draw_area_comments_style = user_data->dlg.draw_area_comments->style;
#endif


#if GTK_CHECK_VERSION(2,18,0)
	if (gtk_widget_is_drawable(user_data->dlg.draw_area_comments))
		gdk_draw_pixmap(gtk_widget_get_window(user_data->dlg.draw_area_comments),
			draw_area_comments_style->fg_gc[gtk_widget_get_state(widget)],
#else
	if (GDK_IS_DRAWABLE(user_data->dlg.draw_area_comments->window))
		gdk_draw_pixmap(user_data->dlg.draw_area_comments->window,
			draw_area_comments_style->fg_gc[GTK_WIDGET_STATE(widget)],
#endif
			user_data->dlg.pixmap_comments,
			0,0,
			0,0,
			draw_area_comments_alloc.width,
			draw_area_comments_alloc.height);

	return TRUE;
}

/****************************************************************************/
static void v_scrollbar_changed(GtkWidget *widget _U_, gpointer data)
{
	graph_analysis_data_t *user_data = data;

#if GTK_CHECK_VERSION(2,14,0)
	if ((user_data->dlg.first_item+gtk_adjustment_get_page_size(user_data->dlg.v_scrollbar_adjustment)+1 == user_data->num_items)
	    && (gtk_adjustment_get_value(user_data->dlg.v_scrollbar_adjustment) >= user_data->dlg.first_item ))
		return;

	if (user_data->dlg.first_item == gtk_adjustment_get_value(user_data->dlg.v_scrollbar_adjustment))
		return;

	user_data->dlg.first_item = (guint32) gtk_adjustment_get_value(user_data->dlg.v_scrollbar_adjustment);
#else
	if ((user_data->dlg.first_item+user_data->dlg.v_scrollbar_adjustment->page_size+1 == user_data->num_items)
	    && (user_data->dlg.v_scrollbar_adjustment->value >= user_data->dlg.first_item ))
		return;

	if (user_data->dlg.first_item == user_data->dlg.v_scrollbar_adjustment->value)
		return;

	user_data->dlg.first_item = (guint32) user_data->dlg.v_scrollbar_adjustment->value;
#endif

	dialog_graph_redraw(user_data);

	return;
}

/****************************************************************************/
static void create_draw_area(graph_analysis_data_t *user_data, GtkWidget *box)
{
	GtkWidget *hbox;
	GtkWidget *viewport;
	GtkWidget *scroll_window_comments;
	GtkWidget *viewport_comments;
	GtkWidget *frame_time;
	GtkWidget *scroll_vbox;
	GtkWidget *frame_box;
	GtkRequisition scroll_requisition;
	GtkWidget *frame;

	hbox=gtk_hbox_new(FALSE, 0);
	gtk_widget_show(hbox);

	/* create "time" draw area */
	user_data->dlg.draw_area_time=gtk_drawing_area_new();
	gtk_widget_set_size_request(user_data->dlg.draw_area_time, TIME_WIDTH, user_data->dlg.pixmap_height);
	frame_time = gtk_frame_new(NULL);
	gtk_widget_show(frame_time);
	gtk_container_add(GTK_CONTAINER(frame_time),user_data->dlg.draw_area_time);

	/* create "comments" draw area */
	user_data->dlg.draw_area_comments=gtk_drawing_area_new();
	gtk_widget_set_size_request(user_data->dlg.draw_area_comments, COMMENT_WIDTH, user_data->dlg.pixmap_height);
	scroll_window_comments=gtk_scrolled_window_new(NULL, NULL);
	gtk_widget_set_size_request(scroll_window_comments, (gint)(COMMENT_WIDTH/1.5), user_data->dlg.pixmap_height);
	/* 
	 * Set the scrollbar policy for the horizontal and vertical scrollbars
	 * The policy determines when the scrollbar should appear
	 */
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scroll_window_comments), 
		GTK_POLICY_ALWAYS, /* Policy for horizontal bar. */
		GTK_POLICY_NEVER); /* Policy for vertical bar */

	/* Changes the type of shadow drawn around the contents of scrolled_window. */
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scroll_window_comments), 
		GTK_SHADOW_ETCHED_IN);
	
	viewport_comments = gtk_viewport_new(gtk_scrolled_window_get_hadjustment(GTK_SCROLLED_WINDOW(scroll_window_comments)),
					     gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(scroll_window_comments)));
	gtk_container_add(GTK_CONTAINER(viewport_comments), user_data->dlg.draw_area_comments);
	gtk_container_add(GTK_CONTAINER(scroll_window_comments), viewport_comments);
	gtk_viewport_set_shadow_type(GTK_VIEWPORT(viewport_comments), GTK_SHADOW_NONE);
	gtk_widget_add_events (user_data->dlg.draw_area_comments, GDK_BUTTON_PRESS_MASK);
	g_signal_connect(user_data->dlg.draw_area_comments, "scroll_event",  G_CALLBACK(scroll_event), user_data);

	/* create main Graph draw area */
	user_data->dlg.draw_area=gtk_drawing_area_new();
	if (user_data->num_nodes < 2)
		user_data->dlg.pixmap_width = 2 * NODE_WIDTH;
	else
		user_data->dlg.pixmap_width = user_data->num_nodes * NODE_WIDTH;
	gtk_widget_set_size_request(user_data->dlg.draw_area, user_data->dlg.pixmap_width, user_data->dlg.pixmap_height);
	user_data->dlg.scroll_window=gtk_scrolled_window_new(NULL, NULL);
	if ( user_data->num_nodes < 6)
		gtk_widget_set_size_request(user_data->dlg.scroll_window, NODE_WIDTH*user_data->num_nodes, user_data->dlg.pixmap_height);
	else
		gtk_widget_set_size_request(user_data->dlg.scroll_window, NODE_WIDTH*5, user_data->dlg.pixmap_height);

	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW(user_data->dlg.scroll_window), 
		GTK_POLICY_ALWAYS, 
		GTK_POLICY_NEVER);

	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(user_data->dlg.scroll_window), 
		GTK_SHADOW_ETCHED_IN);
	viewport = gtk_viewport_new(gtk_scrolled_window_get_hadjustment(GTK_SCROLLED_WINDOW(user_data->dlg.scroll_window)),
				    gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(user_data->dlg.scroll_window)));
	gtk_container_add(GTK_CONTAINER(viewport), user_data->dlg.draw_area);
	gtk_container_add(GTK_CONTAINER(user_data->dlg.scroll_window), viewport);
	gtk_viewport_set_shadow_type(GTK_VIEWPORT(viewport), GTK_SHADOW_NONE);
#if GTK_CHECK_VERSION(2,18,0)
	gtk_widget_set_can_focus(user_data->dlg.draw_area, TRUE);
#else
	GTK_WIDGET_SET_FLAGS(user_data->dlg.draw_area, GTK_CAN_FOCUS);
#endif
	gtk_widget_grab_focus(user_data->dlg.draw_area);

	/* signals needed to handle backing pixmap */
	g_signal_connect(user_data->dlg.draw_area, "expose_event", G_CALLBACK(expose_event), user_data);
	g_signal_connect(user_data->dlg.draw_area, "configure_event", G_CALLBACK(configure_event), user_data);

	/* signals needed to handle backing pixmap comments */
	g_signal_connect(user_data->dlg.draw_area_comments, "expose_event", G_CALLBACK(expose_event_comments), user_data);
	g_signal_connect(user_data->dlg.draw_area_comments, "configure_event", G_CALLBACK(configure_event_comments), user_data);

	/* signals needed to handle backing pixmap time */
	g_signal_connect(user_data->dlg.draw_area_time, "expose_event", G_CALLBACK(expose_event_time), user_data);
	g_signal_connect(user_data->dlg.draw_area_time, "configure_event", G_CALLBACK(configure_event_time), user_data);

	gtk_widget_add_events (user_data->dlg.draw_area, GDK_BUTTON_PRESS_MASK);
	g_signal_connect(user_data->dlg.draw_area, "button_press_event", G_CALLBACK(button_press_event), user_data);
	g_signal_connect(user_data->dlg.draw_area, "scroll_event",  G_CALLBACK(scroll_event), user_data);
	g_signal_connect(user_data->dlg.draw_area, "key_press_event",  G_CALLBACK(key_press_event), user_data);

	gtk_widget_show(user_data->dlg.draw_area_time);
	gtk_widget_show(user_data->dlg.draw_area);
	gtk_widget_show(viewport);
	gtk_widget_show(user_data->dlg.draw_area_comments);
	gtk_widget_show(viewport_comments);

	gtk_widget_show(user_data->dlg.scroll_window);
	gtk_widget_show(scroll_window_comments);

	gtk_box_pack_start(GTK_BOX(hbox), frame_time, FALSE, FALSE, 3);

	user_data->dlg.hpane = gtk_hpaned_new();
	gtk_paned_pack1(GTK_PANED (user_data->dlg.hpane), user_data->dlg.scroll_window, FALSE, TRUE);
	gtk_paned_pack2(GTK_PANED (user_data->dlg.hpane), scroll_window_comments, TRUE, TRUE);
	g_signal_connect(user_data->dlg.hpane, "notify::position",  G_CALLBACK(pane_callback), user_data);
	gtk_widget_show(user_data->dlg.hpane);

	gtk_box_pack_start(GTK_BOX(hbox), user_data->dlg.hpane, TRUE, TRUE, 0);

	/* Create the scroll_vbox to include the vertical scroll and a box at the bottom */
	scroll_vbox=gtk_vbox_new(FALSE, 0);
	gtk_widget_show(scroll_vbox);

	/* create the associated v_scrollbar */
	user_data->dlg.v_scrollbar_adjustment=(GtkAdjustment *)gtk_adjustment_new(0,0,0,0,0,0);
	user_data->dlg.v_scrollbar=gtk_vscrollbar_new(user_data->dlg.v_scrollbar_adjustment);
	gtk_widget_show(user_data->dlg.v_scrollbar);
	gtk_box_pack_start(GTK_BOX(scroll_vbox), user_data->dlg.v_scrollbar, TRUE, TRUE, 0);
	g_signal_connect(user_data->dlg.v_scrollbar_adjustment, "value_changed",
			 G_CALLBACK(v_scrollbar_changed), user_data);

	frame_box = gtk_frame_new(NULL);
	gtk_widget_size_request(user_data->dlg.v_scrollbar, &scroll_requisition);
	gtk_widget_set_size_request(frame_box, 1, scroll_requisition.width+2);
	gtk_frame_set_shadow_type(GTK_FRAME(frame_box), GTK_SHADOW_NONE);
	gtk_widget_show(frame_box);
	gtk_box_pack_end(GTK_BOX(scroll_vbox), frame_box, FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(hbox), scroll_vbox, FALSE, FALSE, 3);

	/* Frame around the main area */
	frame = gtk_frame_new(NULL);
	gtk_widget_show(frame);
	gtk_container_add(GTK_CONTAINER(frame), hbox);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);

	/*gtk_box_pack_start(GTK_BOX(box), hbox, TRUE, TRUE, 15);*/
	/*gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 15);*/
	gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(box), 10);
}
/****************************************************************************/
/* PUBLIC */
/****************************************************************************/


/****************************************************************************/
static void dialog_graph_create_window(graph_analysis_data_t *user_data)
{
	GtkWidget *vbox;
	GtkWidget *hbuttonbox;
	GtkWidget *bt_close;
	GtkWidget *bt_save;
	GtkTooltips *tooltips = gtk_tooltips_new();
	const gchar *title_name_ptr;
	gchar   *win_name;

	title_name_ptr = cf_get_display_name(&cfile);
	win_name = g_strdup_printf("%s - Graph Analysis", title_name_ptr);

	/* create the main window */
	user_data->dlg.window=dlg_window_new((user_data->dlg.title)?user_data->dlg.title:win_name);
	gtk_window_set_destroy_with_parent(GTK_WINDOW(user_data->dlg.window), TRUE);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(user_data->dlg.window), vbox);
	gtk_widget_show(vbox);

	create_draw_area(user_data, vbox);

	/* button row */
	hbuttonbox = gtk_hbutton_box_new ();
	gtk_box_pack_start (GTK_BOX (vbox), hbuttonbox, FALSE, FALSE, 10);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox), GTK_BUTTONBOX_SPREAD);
	gtk_box_set_spacing (GTK_BOX (hbuttonbox), 30);
	gtk_widget_show(hbuttonbox);

	bt_save = gtk_button_new_from_stock(GTK_STOCK_SAVE_AS);
	gtk_container_add(GTK_CONTAINER(hbuttonbox), bt_save);
	gtk_widget_show(bt_save);
	g_signal_connect(bt_save, "clicked", G_CALLBACK(on_save_bt_clicked), user_data);
	gtk_tooltips_set_tip (tooltips, bt_save, "Save an ASCII representation of the graph to a file", NULL);

	bt_close = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_close);
#if GTK_CHECK_VERSION(2,18,0)
	gtk_widget_set_can_default(bt_close, TRUE);
#else
	GTK_WIDGET_SET_FLAGS(bt_close, GTK_CAN_DEFAULT);
#endif
	gtk_widget_show(bt_close);
	gtk_tooltips_set_tip (tooltips, bt_close, "Close this dialog", NULL);
	window_set_cancel_button(user_data->dlg.window, bt_close, window_cancel_button_cb);

	g_signal_connect(user_data->dlg.window, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(user_data->dlg.window, "destroy", G_CALLBACK(on_destroy), user_data);

	gtk_widget_show(user_data->dlg.window);
	window_present(user_data->dlg.window);

	/* Destroy our graph window with our parent if the caller specified the parent */
	if(user_data->dlg.parent_w) {
		gtk_window_set_transient_for(GTK_WINDOW(user_data->dlg.window),
					     GTK_WINDOW(user_data->dlg.parent_w));
		/* Destruction of this child window */
		gtk_window_set_destroy_with_parent(GTK_WINDOW(user_data->dlg.window), TRUE);
	}
	g_free(win_name);
}

/* Return the index array if the node is in the array. Return -1 if there is room in the array
 * and Return -2 if the array is full
 */
/****************************************************************************/
static gint add_or_get_node(graph_analysis_data_t *user_data, address *node) {
	guint i;

	if (node->type == AT_NONE) return NODE_OVERFLOW;

	for (i=0; i<MAX_NUM_NODES && i < user_data->num_nodes ; i++){
		if ( CMP_ADDRESS(&(user_data->nodes[i]), node) == 0 ) return i;	/* it is in the array */
	}

	if (i == MAX_NUM_NODES) {
		return  NODE_OVERFLOW;
	} else {
		user_data->num_nodes++;
		COPY_ADDRESS(&(user_data->nodes[i]),node);
		return i;
	}
}

/* Get the nodes from the list */
/****************************************************************************/
static void get_nodes(graph_analysis_data_t *user_data)
{
	GList *list;
	graph_analysis_item_t *gai;

	/* fill the node array */
	list = g_list_first(user_data->graph_info->list);
	while (list)
	{
		gai = list->data;
		if (gai->display) {
			user_data->num_items++;
			if (!user_data->dlg.inverse) {
				gai->src_node = (guint16)add_or_get_node(user_data, &(gai->src_addr));
				gai->dst_node = (guint16)add_or_get_node(user_data, &(gai->dst_addr));
			} else {
				gai->dst_node = (guint16)add_or_get_node(user_data, &(gai->src_addr));
				gai->src_node = (guint16)add_or_get_node(user_data, &(gai->dst_addr));
			}
		}
		list = g_list_next(list);
	}
}

/****************************************************************************/
graph_analysis_data_t *graph_analysis_init(void)
{
	graph_analysis_data_t *user_data;
	/* init */
	user_data = g_malloc(sizeof(graph_analysis_data_t));

	/* init user_data */
	graph_analysis_init_dlg(user_data);

	return user_data;
}
/****************************************************************************/
/* PUBLIC */
/****************************************************************************/

/****************************************************************************/
void graph_analysis_create(graph_analysis_data_t *user_data)
{
	/* reset the data */
	graph_analysis_reset(user_data);

	/* get nodes (each node is an address) */
	get_nodes(user_data);

	/* create the graph windows */
	dialog_graph_create_window(user_data);

	/* redraw the graph */
	dialog_graph_redraw(user_data);

	return;
}

/****************************************************************************/
void graph_analysis_update(graph_analysis_data_t *user_data)
{
	/* reset the data */
	graph_analysis_reset(user_data);

	/* get nodes (each node is an address) */
	get_nodes(user_data);

	user_data->dlg.pixmap_width = user_data->num_nodes * NODE_WIDTH;
	gtk_widget_set_size_request(user_data->dlg.draw_area, user_data->dlg.pixmap_width, user_data->dlg.pixmap_height);
	if (user_data->num_nodes < 6)
		gtk_widget_set_size_request(user_data->dlg.scroll_window, NODE_WIDTH*user_data->num_nodes, user_data->dlg.pixmap_height);
	else
		gtk_widget_set_size_request(user_data->dlg.scroll_window, NODE_WIDTH*5, user_data->dlg.pixmap_height);

	/* redraw the graph */
	dialog_graph_redraw(user_data);

	window_present(user_data->dlg.window);
	return;
}


/****************************************************************************/
void graph_analysis_redraw(graph_analysis_data_t *user_data)
{
	/* get nodes (each node is an address) */
	get_nodes(user_data);

	user_data->dlg.pixmap_width = user_data->num_nodes * NODE_WIDTH;
	gtk_widget_set_size_request(user_data->dlg.draw_area, user_data->dlg.pixmap_width, user_data->dlg.pixmap_height);
	if (user_data->num_nodes < 6)
		gtk_widget_set_size_request(user_data->dlg.scroll_window, NODE_WIDTH*user_data->num_nodes, user_data->dlg.pixmap_height);
	else
		gtk_widget_set_size_request(user_data->dlg.scroll_window, NODE_WIDTH*5, user_data->dlg.pixmap_height);


	/* redraw the graph */
	dialog_graph_redraw(user_data);

	window_present(user_data->dlg.window);
	return;
}
