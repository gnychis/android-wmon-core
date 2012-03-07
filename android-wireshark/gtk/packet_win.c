/* packet_win.c
 * Routines for popping a window to display current packet
 *
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet_win.c 36161 2011-03-08 01:52:25Z sake $
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
 * To do:
 * - Add close button to bottom.
 * - improve the window Title and allow user to config it
 * - Add print support ? ( could be a mess)
 * - Add button to have main window jump to this packet ?
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <gtk/gtk.h>

#include <string.h>

#include <epan/epan.h>
#include <epan/timestamp.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/addr_resolv.h>
#include <epan/plugins.h>
#include <epan/epan_dissect.h>
#include <epan/strutil.h>

#include "../file.h"
#include "../print.h"
#include "../ui_util.h"
#include "../summary.h"

#include "gtk/main.h"
#include "gtk/packet_win.h"
#include "gtk/main_proto_draw.h"
#include "gtk/keys.h"
#include "gtk/gtkglobals.h"
#include "gtk/gui_utils.h"


/* Data structure holding information about a packet-detail window. */
struct PacketWinData {
	frame_data *frame;	   /* The frame being displayed */
	union wtap_pseudo_header pseudo_header; /* Pseudo-header for packet */
	guint8     *pd;		   /* Data for packet */
	GtkWidget  *main;
	GtkWidget  *tv_scrollw;
	GtkWidget  *tree_view;
	GtkWidget  *bv_nb_ptr;
 	field_info *finfo_selected;
	epan_dissect_t	*edt;
};

/* List of all the packet-detail windows popped up. */
static GList *detail_windows;

static void new_tree_view_selection_changed_cb(GtkTreeSelection *sel,
                                               gpointer user_data);


static void destroy_new_window(GtkObject *object, gpointer user_data);

static gboolean
button_press_handler(GtkWidget *widget, GdkEvent *event, gpointer data _U_)
{
  if (widget == NULL || event == NULL) {
    return FALSE;
  }

  tree_view_select(widget, (GdkEventButton *) event);

  /* GDK_2BUTTON_PRESS is a doubleclick -> expand/collapse tree row */
  if (event->type == GDK_2BUTTON_PRESS) {
    GtkTreePath      *path;

    if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(widget),
				      (gint) (((GdkEventButton *)event)->x),
				      (gint) (((GdkEventButton *)event)->y),
				      &path, NULL, NULL, NULL))
    {
      if (gtk_tree_view_row_expanded(GTK_TREE_VIEW(widget), path)) {
	gtk_tree_view_collapse_row(GTK_TREE_VIEW(widget), path);
      }	else {
	gtk_tree_view_expand_row(GTK_TREE_VIEW(widget), path, FALSE);
      }
      gtk_tree_path_free(path);
    }
  }

  return FALSE;
}

void new_window_cb(GtkWidget *w _U_)
{
#define NewWinTitleLen 1000
  char Title[NewWinTitleLen] = "";
  const char *TextPtr;
  gint tv_size = 95, bv_size = 75;
  GtkWidget *main_w, *main_vbox, *pane,
                      *tree_view, *tv_scrollw,
                      *bv_nb_ptr;
  struct PacketWinData *DataPtr;
  int i;

  if (!cfile.current_frame) {
    /* nothing has been captured so far */
    return;
  }

  /* With the new packetlists "lazy columns" it's neccesary to reread the frame */
  if (!cf_read_frame(&cfile, cfile.current_frame)) {
    /* error reading the frame */
    return;
  }

  /* Allocate data structure to represent this window. */
  DataPtr = (struct PacketWinData *) g_malloc(sizeof(struct PacketWinData));

  DataPtr->frame = cfile.current_frame;
  memcpy(&DataPtr->pseudo_header, &cfile.pseudo_header, sizeof DataPtr->pseudo_header);
  DataPtr->pd = g_malloc(DataPtr->frame->cap_len);
  memcpy(DataPtr->pd, cfile.pd, DataPtr->frame->cap_len);
  DataPtr->edt = epan_dissect_new(TRUE, TRUE);
  epan_dissect_run(DataPtr->edt, &DataPtr->pseudo_header, DataPtr->pd,
          DataPtr->frame, &cfile.cinfo);
  epan_dissect_fill_in_columns(DataPtr->edt, FALSE, TRUE);

  /*
   * Build title of window by getting column data constructed when the
   * frame was dissected.
   */
  for (i = 0; i < cfile.cinfo.num_cols; ++i) {
    TextPtr = cfile.cinfo.col_data[i];
    if ((strlen(Title) + strlen(TextPtr)) < NewWinTitleLen - 1) {
      g_strlcat(Title, TextPtr, NewWinTitleLen);
      g_strlcat(Title, " ", NewWinTitleLen);
    }
  }

  main_w = window_new(GTK_WINDOW_TOPLEVEL, Title);
  gtk_window_set_default_size(GTK_WINDOW(main_w), DEF_WIDTH, -1);

  /* Container for paned windows  */
  main_vbox = gtk_vbox_new(FALSE, 1);
  gtk_container_set_border_width(GTK_CONTAINER(main_vbox), 1);
  gtk_container_add(GTK_CONTAINER(main_w), main_vbox);
  gtk_widget_show(main_vbox);

  /* Panes for the tree and byte view */
  pane = gtk_vpaned_new();
  gtk_container_add(GTK_CONTAINER(main_vbox), pane);
  gtk_widget_show(pane);

  /* Tree view */
  tv_scrollw = main_tree_view_new(&prefs, &tree_view);
  gtk_paned_pack1(GTK_PANED(pane), tv_scrollw, TRUE, TRUE);
  gtk_widget_set_size_request(tv_scrollw, -1, tv_size);
  gtk_widget_show(tv_scrollw);
  gtk_widget_show(tree_view);

  /* Byte view */
  bv_nb_ptr = byte_view_new();
  gtk_paned_pack2(GTK_PANED(pane), bv_nb_ptr, FALSE, FALSE);
  gtk_widget_set_size_request(bv_nb_ptr, -1, bv_size);
  gtk_widget_show(bv_nb_ptr);

  DataPtr->main = main_w;
  DataPtr->tv_scrollw = tv_scrollw;
  DataPtr->tree_view = tree_view;
  DataPtr->bv_nb_ptr = bv_nb_ptr;
  detail_windows = g_list_append(detail_windows, DataPtr);

  /* load callback handlers */
  g_signal_connect(gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view)),
                 "changed", G_CALLBACK(new_tree_view_selection_changed_cb), DataPtr);
  g_signal_connect(tree_view, "button_press_event", G_CALLBACK(button_press_handler), NULL);
  g_signal_connect(main_w, "destroy", G_CALLBACK(destroy_new_window), DataPtr);

  /* draw the protocol tree & print hex data */
  add_byte_views(DataPtr->edt, tree_view, DataPtr->bv_nb_ptr);
  proto_tree_draw(DataPtr->edt->tree, tree_view);

  DataPtr->finfo_selected = NULL;
  gtk_widget_show(main_w);
}

static void
destroy_new_window(GtkObject *object _U_, gpointer user_data)
{
  struct PacketWinData *DataPtr = user_data;

  detail_windows = g_list_remove(detail_windows, DataPtr);
  epan_dissect_free(DataPtr->edt);
  g_free(DataPtr->pd);
  g_free(DataPtr);
}

/* called when a tree row is (un)selected in the popup packet window */
static void
new_tree_view_selection_changed_cb(GtkTreeSelection *sel, gpointer user_data)
{
    field_info   *finfo;
    GtkWidget    *byte_view;
    const guint8 *data;
    guint         len;
    GtkTreeModel *model;
    GtkTreeIter   iter;

    struct PacketWinData *DataPtr = (struct PacketWinData*)user_data;

    /* if something is selected */
    if (gtk_tree_selection_get_selected(sel, &model, &iter))
    {
        gtk_tree_model_get(model, &iter, 1, &finfo, -1);
        if (!finfo) return;

        set_notebook_page(DataPtr->bv_nb_ptr, finfo->ds_tvb);
        byte_view = get_notebook_bv_ptr(DataPtr->bv_nb_ptr);
        if (!byte_view)	/* exit if no hex window to write in */
            return;

        data = get_byte_view_data_and_length(byte_view, &len);
        if (data == NULL) {
            data = DataPtr->pd;
            len =  DataPtr->frame->cap_len;
        }

        DataPtr->finfo_selected = finfo;
        packet_hex_print(byte_view, data, DataPtr->frame, finfo, len);
    }
    else
    {
        DataPtr->finfo_selected = NULL;

        byte_view = get_notebook_bv_ptr(DataPtr->bv_nb_ptr);
        if (!byte_view)	/* exit if no hex window to write in */
            return;

        data = get_byte_view_data_and_length(byte_view, &len);
        g_assert(data != NULL);
        packet_hex_reprint(byte_view);
    }
}

/* Functions called from elsewhere to act on all popup packet windows. */

/* Destroy all popup packet windows. */
void
destroy_packet_wins(void)
{
	struct PacketWinData *DataPtr;

	/* Destroying a packet window causes it to be removed from
	   the list of packet windows, so we can't do a "g_list_foreach()"
	   to go through the list of all packet windows and destroy them
	   as we find them; instead, as long as the list is non-empty,
	   we destroy the first window on the list. */
	while (detail_windows != NULL) {
		DataPtr = (struct PacketWinData *)(detail_windows->data);
		window_destroy(DataPtr->main);
	}
}

static void
redraw_packet_bytes_cb(gpointer data, gpointer user_data _U_)
{
	struct PacketWinData *DataPtr = (struct PacketWinData *)data;

	redraw_packet_bytes(DataPtr->bv_nb_ptr, DataPtr->frame, DataPtr->finfo_selected);
}

/* Redraw the packet bytes part of all the popup packet windows. */
void
redraw_packet_bytes_packet_wins(void)
{
	g_list_foreach(detail_windows, redraw_packet_bytes_cb, NULL);
}
