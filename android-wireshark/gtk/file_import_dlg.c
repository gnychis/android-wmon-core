/* file_import_dlg.c
 * Dialog to setup for import of a text file, like text2pcap
 * November 2010, Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * $Id: file_import_dlg.c 35620 2011-01-22 14:02:38Z stig $
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>

#include "globals.h"
#include "wtap.h"
#include "pcap-encap.h"

#include <epan/prefs.h>

#include <gtk/gtk.h>

#include "filters.h"
#include "simple_dialog.h"
#include "alert_box.h"

#include "gtk/gtkglobals.h"
#include "gtk/stock_icons.h"
#include "gtk/dlg_utils.h"
#include "gtk/gui_utils.h"
#include "gtk/file_dlg.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/help_dlg.h"

#include "gtk/file_import_dlg.h"
#include "gtk/text_import.h"
#include "gtk/text_import_scanner.h"

#include "file.h"
#include "wsutil/file_util.h"
#include "tempfile.h"

#define INPUT_FRM_KEY                   "input_frame"

#define INPUT_FILENAME_TE_KEY           "input_filename_text"

#define INPUT_OFFSET_HEX_RB_KEY         "input_offset_hex_radio"
#define INPUT_OFFSET_OCT_RB_KEY         "input_offset_oct_radio"
#define INPUT_OFFSET_DEC_RB_KEY         "input_offset_dec_radio"

#define INPUT_DATETIME_CB_KEY           "input_datetime_checkbox"
#define INPUT_TIMEFMT_LBL_KEY           "input_timeformat_label"
#define INPUT_TIMEFMT_TE_KEY            "input_timeformat_entry"

#define IMPORT_FRM_KEY                  "import_frame"
#define IMPORT_ENCAP_CO_KEY             "import_encap_combo"

#define IMPORT_HEADER_FRM_KEY           "import_header_frame"
#define IMPORT_HEADER_CB_KEY            "import_header_checkbox"
#define IMPORT_HEADER_ETH_RB_KEY        "import_header_ethernet_radio"
#define IMPORT_HEADER_ETYPE_LBL_KEY     "import_header_etype_label"
#define IMPORT_HEADER_ETYPE_TE_KEY      "import_header_etype_text"
#define IMPORT_HEADER_IPV4_RB_KEY       "import_header_ipv4_radio"
#define IMPORT_HEADER_PROT_LBL_KEY      "import_header_prot_label"
#define IMPORT_HEADER_PROT_TE_KEY       "import_header_prot_text"
#define IMPORT_HEADER_UDP_RB_KEY        "import_header_udp_radio"
#define IMPORT_HEADER_SRC_PORT_LBL_KEY  "import_header_src_port_label"
#define IMPORT_HEADER_SRC_PORT_TE_KEY   "import_header_src_port_text"
#define IMPORT_HEADER_TCP_RB_KEY        "import_header_tcp_radio"
#define IMPORT_HEADER_DST_PORT_LBL_KEY  "import_header_dst_port_label"
#define IMPORT_HEADER_DST_PORT_TE_KEY   "import_header_dst_port_text"
#define IMPORT_HEADER_SCTP_RB_KEY       "import_header_sctp_radio"
#define IMPORT_HEADER_TAG_LBL_KEY       "import_header_tag_label"
#define IMPORT_HEADER_TAG_TE_KEY        "import_header_tag_text"
#define IMPORT_HEADER_SCTP_D_RB_KEY     "import_header_sctp_data_radio"
#define IMPORT_HEADER_PPI_LBL_KEY       "import_header_ppi_label"
#define IMPORT_HEADER_PPI_TE_KEY        "import_header_ppi_text"

#define IMPORT_FRAME_LENGTH_TE_KEY      "import_frame_length_text"

static GtkWidget *file_import_dlg_w = NULL;
static GtkListStore *encap_list_store = NULL;

/*****************************************************************************/

static void
file_import_dlg_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
    file_import_dlg_w = NULL;
}

/*****************************************************************************/

static void
browse_file_cb(GtkWidget *browse_bt, GtkWidget *filename_te)
{
    file_selection_browse(browse_bt, filename_te, "Wireshark: Import from Text",
        FILE_SELECTION_READ_BROWSE);
}

static void
timefmt_cb_toggle(GtkWidget *widget, gpointer data _U_)
{
    GtkWidget *timefmt_lbl, *timefmt_te;
    gboolean apply_fmt;

    timefmt_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(widget), INPUT_TIMEFMT_LBL_KEY));
    timefmt_te = GTK_WIDGET(g_object_get_data(G_OBJECT(widget), INPUT_TIMEFMT_TE_KEY));

    apply_fmt = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
    gtk_widget_set_sensitive(timefmt_lbl, apply_fmt);
    gtk_widget_set_sensitive(timefmt_te, apply_fmt);
}

/*****************************************************************************/
static void
create_encap_list_store(void)
{
    GtkTreeIter iter;
    gint encap;
    const gchar *name;

    encap_list_store = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_UINT);

    /* Scan all Wiretap encapsulation types */
    for (encap = 1; encap < wtap_get_num_encap_types(); encap++)
    {
        /* Check if we can write it to a PCAP file */
        if ((wtap_wtap_encap_to_pcap_encap(encap) > 0) &&
            /*
             * Exclude wtap encapsulations that require a pseudo header,
             * because we won't setup one from the text we import and
             * wiretap doesn't allow us to write 'raw' frames
             */
            !((encap == WTAP_ENCAP_ATM_PDUS) ||
              (encap == WTAP_ENCAP_IRDA) ||
              (encap == WTAP_ENCAP_MTP2_WITH_PHDR) ||
              (encap == WTAP_ENCAP_LINUX_LAPD) ||
              (encap == WTAP_ENCAP_SITA) ||
              (encap == WTAP_ENCAP_ERF) ||
              (encap == WTAP_ENCAP_I2C) ||
              (encap == WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR) ||
              (encap == WTAP_ENCAP_PPP_WITH_PHDR)
           ) )
        {
            /* If it has got a name */
            if ((name = wtap_encap_string(encap)))
            {
                gtk_list_store_append(encap_list_store, &iter);
                gtk_list_store_set(encap_list_store, &iter, 0, name, 1, encap, -1);
            }
        }
    }

}

static GtkWidget *
fill_encap_combo(void)
{
    GtkWidget *encap_co = NULL;
    GtkCellRenderer *cell;
    
    encap_co = gtk_combo_box_new_with_model(GTK_TREE_MODEL(encap_list_store));
    cell = gtk_cell_renderer_text_new();
    gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(encap_co), cell, TRUE);
    gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(encap_co), cell, "text", 0, NULL);

    return encap_co;
}

static void header_frm_child_set(GtkWidget *widget, gpointer data);

static void
encap_co_changed(GtkComboBox *widget, gpointer data)
{
    GtkTreeIter iter;
    gboolean result;
    GtkWidget *header_cb;

    result = gtk_combo_box_get_active_iter(widget, &iter);

    if (result)
    {
        guint8 encap;
        GtkTreeModel *model = gtk_combo_box_get_model(widget);
        gtk_tree_model_get(model, &iter, 1, &encap, -1);

        if (encap != WTAP_ENCAP_ETHERNET)
            result = FALSE;
    }

    if (result)
    {
        header_cb = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_CB_KEY));
        g_signal_emit_by_name(G_OBJECT(header_cb), "toggled", data);
    } else {
        gtk_container_foreach(GTK_CONTAINER(data), header_frm_child_set, GUINT_TO_POINTER(result));
    }
}

/*****************************************************************************/

static void
header_frm_child_set(GtkWidget *widget, gpointer data)
{
    gtk_widget_set_sensitive(widget, GPOINTER_TO_UINT(data));
}

static void
header_cb_toggle(GtkWidget *widget, gpointer data)
{
    gtk_container_foreach(GTK_CONTAINER(data), header_frm_child_set,
        GUINT_TO_POINTER(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget))));
    /* The frame's checkbox must stay sensitive, of course... */
    gtk_widget_set_sensitive(widget, TRUE);
}

/*
 * Header radio button toggle handlers
 */
static void
header_eth_rb_toggle(GtkWidget *widget, gpointer data)
{
    GtkWidget *etype_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_ETYPE_LBL_KEY));
    GtkWidget *etype_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_ETYPE_TE_KEY));
    GtkWidget *prot_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PROT_LBL_KEY));
    GtkWidget *prot_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PROT_TE_KEY));
    GtkWidget *src_port_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_SRC_PORT_LBL_KEY));
    GtkWidget *src_port_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_SRC_PORT_TE_KEY));
    GtkWidget *dst_port_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_DST_PORT_LBL_KEY));
    GtkWidget *dst_port_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_DST_PORT_TE_KEY));
    GtkWidget *tag_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_TAG_LBL_KEY));
    GtkWidget *tag_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_TAG_TE_KEY));
    GtkWidget *ppi_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PPI_LBL_KEY));
    GtkWidget *ppi_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PPI_TE_KEY));

    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
    {
        gtk_widget_set_sensitive(etype_lbl, TRUE);
        gtk_widget_set_sensitive(etype_te, TRUE);
        gtk_widget_set_sensitive(prot_lbl, FALSE);
        gtk_widget_set_sensitive(prot_te, FALSE);
        gtk_widget_set_sensitive(src_port_lbl, FALSE);
        gtk_widget_set_sensitive(src_port_te, FALSE);
        gtk_widget_set_sensitive(dst_port_lbl, FALSE);
        gtk_widget_set_sensitive(dst_port_te, FALSE);
        gtk_widget_set_sensitive(tag_lbl, FALSE);
        gtk_widget_set_sensitive(tag_te, FALSE);
        gtk_widget_set_sensitive(ppi_lbl, FALSE);
        gtk_widget_set_sensitive(ppi_te, FALSE);
    }
    else
    {
        gtk_widget_set_sensitive(etype_lbl, FALSE);
        gtk_widget_set_sensitive(etype_te, FALSE);
    }
}

static void
header_ipv4_rb_toggle(GtkWidget *widget, gpointer data)
{
    GtkWidget *etype_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_ETYPE_LBL_KEY));
    GtkWidget *etype_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_ETYPE_TE_KEY));
    GtkWidget *prot_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PROT_LBL_KEY));
    GtkWidget *prot_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PROT_TE_KEY));
    GtkWidget *src_port_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_SRC_PORT_LBL_KEY));
    GtkWidget *src_port_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_SRC_PORT_TE_KEY));
    GtkWidget *dst_port_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_DST_PORT_LBL_KEY));
    GtkWidget *dst_port_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_DST_PORT_TE_KEY));
    GtkWidget *tag_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_TAG_LBL_KEY));
    GtkWidget *tag_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_TAG_TE_KEY));
    GtkWidget *ppi_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PPI_LBL_KEY));
    GtkWidget *ppi_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PPI_TE_KEY));

    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
    {
        gtk_widget_set_sensitive(etype_lbl, FALSE);
        gtk_widget_set_sensitive(etype_te, FALSE);
        gtk_widget_set_sensitive(prot_lbl, TRUE);
        gtk_widget_set_sensitive(prot_te, TRUE);
        gtk_widget_set_sensitive(src_port_lbl, FALSE);
        gtk_widget_set_sensitive(src_port_te, FALSE);
        gtk_widget_set_sensitive(dst_port_lbl, FALSE);
        gtk_widget_set_sensitive(dst_port_te, FALSE);
        gtk_widget_set_sensitive(tag_lbl, FALSE);
        gtk_widget_set_sensitive(tag_te, FALSE);
        gtk_widget_set_sensitive(ppi_lbl, FALSE);
        gtk_widget_set_sensitive(ppi_te, FALSE);
    }
    else
    {
        gtk_widget_set_sensitive(prot_lbl, FALSE);
        gtk_widget_set_sensitive(prot_te, FALSE);
    }
}

static void
header_udp_rb_toggle(GtkWidget *widget, gpointer data)
{
    GtkWidget *etype_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_ETYPE_LBL_KEY));
    GtkWidget *etype_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_ETYPE_TE_KEY));
    GtkWidget *prot_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PROT_LBL_KEY));
    GtkWidget *prot_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PROT_TE_KEY));
    GtkWidget *src_port_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_SRC_PORT_LBL_KEY));
    GtkWidget *src_port_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_SRC_PORT_TE_KEY));
    GtkWidget *dst_port_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_DST_PORT_LBL_KEY));
    GtkWidget *dst_port_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_DST_PORT_TE_KEY));
    GtkWidget *tag_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_TAG_LBL_KEY));
    GtkWidget *tag_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_TAG_TE_KEY));
    GtkWidget *ppi_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PPI_LBL_KEY));
    GtkWidget *ppi_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PPI_TE_KEY));

    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
    {
        gtk_widget_set_sensitive(etype_lbl, FALSE);
        gtk_widget_set_sensitive(etype_te, FALSE);
        gtk_widget_set_sensitive(prot_lbl, FALSE);
        gtk_widget_set_sensitive(prot_te, FALSE);
        gtk_widget_set_sensitive(src_port_lbl, TRUE);
        gtk_widget_set_sensitive(src_port_te, TRUE);
        gtk_widget_set_sensitive(dst_port_lbl, TRUE);
        gtk_widget_set_sensitive(dst_port_te, TRUE);
        gtk_widget_set_sensitive(tag_lbl, FALSE);
        gtk_widget_set_sensitive(tag_te, FALSE);
        gtk_widget_set_sensitive(ppi_lbl, FALSE);
        gtk_widget_set_sensitive(ppi_te, FALSE);
    }
    else
    {
        gtk_widget_set_sensitive(src_port_lbl, FALSE);
        gtk_widget_set_sensitive(src_port_te, FALSE);
        gtk_widget_set_sensitive(dst_port_lbl, FALSE);
        gtk_widget_set_sensitive(dst_port_te, FALSE);
    }
}

static void
header_tcp_rb_toggle(GtkWidget *widget, gpointer data)
{
    GtkWidget *etype_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_ETYPE_LBL_KEY));
    GtkWidget *etype_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_ETYPE_TE_KEY));
    GtkWidget *prot_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PROT_LBL_KEY));
    GtkWidget *prot_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PROT_TE_KEY));
    GtkWidget *src_port_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_SRC_PORT_LBL_KEY));
    GtkWidget *src_port_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_SRC_PORT_TE_KEY));
    GtkWidget *dst_port_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_DST_PORT_LBL_KEY));
    GtkWidget *dst_port_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_DST_PORT_TE_KEY));
    GtkWidget *tag_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_TAG_LBL_KEY));
    GtkWidget *tag_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_TAG_TE_KEY));
    GtkWidget *ppi_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PPI_LBL_KEY));
    GtkWidget *ppi_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PPI_TE_KEY));

    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
    {
        gtk_widget_set_sensitive(etype_lbl, FALSE);
        gtk_widget_set_sensitive(etype_te, FALSE);
        gtk_widget_set_sensitive(prot_lbl, FALSE);
        gtk_widget_set_sensitive(prot_te, FALSE);
        gtk_widget_set_sensitive(src_port_lbl, TRUE);
        gtk_widget_set_sensitive(src_port_te, TRUE);
        gtk_widget_set_sensitive(dst_port_lbl, TRUE);
        gtk_widget_set_sensitive(dst_port_te, TRUE);
        gtk_widget_set_sensitive(tag_lbl, FALSE);
        gtk_widget_set_sensitive(tag_te, FALSE);
        gtk_widget_set_sensitive(ppi_lbl, FALSE);
        gtk_widget_set_sensitive(ppi_te, FALSE);
    }
    else
    {
        gtk_widget_set_sensitive(src_port_lbl, FALSE);
        gtk_widget_set_sensitive(src_port_te, FALSE);
        gtk_widget_set_sensitive(dst_port_lbl, FALSE);
        gtk_widget_set_sensitive(dst_port_te, FALSE);
    }
}

static void
header_sctp_rb_toggle(GtkWidget *widget, gpointer data)
{
    GtkWidget *etype_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_ETYPE_LBL_KEY));
    GtkWidget *etype_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_ETYPE_TE_KEY));
    GtkWidget *prot_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PROT_LBL_KEY));
    GtkWidget *prot_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PROT_TE_KEY));
    GtkWidget *src_port_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_SRC_PORT_LBL_KEY));
    GtkWidget *src_port_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_SRC_PORT_TE_KEY));
    GtkWidget *dst_port_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_DST_PORT_LBL_KEY));
    GtkWidget *dst_port_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_DST_PORT_TE_KEY));
    GtkWidget *tag_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_TAG_LBL_KEY));
    GtkWidget *tag_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_TAG_TE_KEY));
    GtkWidget *ppi_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PPI_LBL_KEY));
    GtkWidget *ppi_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PPI_TE_KEY));

    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
    {
        gtk_widget_set_sensitive(etype_lbl, FALSE);
        gtk_widget_set_sensitive(etype_te, FALSE);
        gtk_widget_set_sensitive(prot_lbl, FALSE);
        gtk_widget_set_sensitive(prot_te, FALSE);
        gtk_widget_set_sensitive(src_port_lbl, TRUE);
        gtk_widget_set_sensitive(src_port_te, TRUE);
        gtk_widget_set_sensitive(dst_port_lbl, TRUE);
        gtk_widget_set_sensitive(dst_port_te, TRUE);
        gtk_widget_set_sensitive(tag_lbl, TRUE);
        gtk_widget_set_sensitive(tag_te, TRUE);
        gtk_widget_set_sensitive(ppi_lbl, FALSE);
        gtk_widget_set_sensitive(ppi_te, FALSE);
    }
    else
    {
        gtk_widget_set_sensitive(src_port_lbl, FALSE);
        gtk_widget_set_sensitive(src_port_te, FALSE);
        gtk_widget_set_sensitive(dst_port_lbl, FALSE);
        gtk_widget_set_sensitive(dst_port_te, FALSE);
        gtk_widget_set_sensitive(tag_lbl, FALSE);
        gtk_widget_set_sensitive(tag_te, FALSE);
    }
}

static void
header_sctp_data_rb_toggle(GtkWidget *widget, gpointer data)
{
    GtkWidget *etype_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_ETYPE_LBL_KEY));
    GtkWidget *etype_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_ETYPE_TE_KEY));
    GtkWidget *prot_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PROT_LBL_KEY));
    GtkWidget *prot_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PROT_TE_KEY));
    GtkWidget *src_port_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_SRC_PORT_LBL_KEY));
    GtkWidget *src_port_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_SRC_PORT_TE_KEY));
    GtkWidget *dst_port_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_DST_PORT_LBL_KEY));
    GtkWidget *dst_port_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_DST_PORT_TE_KEY));
    GtkWidget *tag_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_TAG_LBL_KEY));
    GtkWidget *tag_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_TAG_TE_KEY));
    GtkWidget *ppi_lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PPI_LBL_KEY));
    GtkWidget *ppi_te  = GTK_WIDGET(g_object_get_data(G_OBJECT(data), IMPORT_HEADER_PPI_TE_KEY));

    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
    {
        gtk_widget_set_sensitive(etype_lbl, FALSE);
        gtk_widget_set_sensitive(etype_te, FALSE);
        gtk_widget_set_sensitive(prot_lbl, FALSE);
        gtk_widget_set_sensitive(prot_te, FALSE);
        gtk_widget_set_sensitive(src_port_lbl, TRUE);
        gtk_widget_set_sensitive(src_port_te, TRUE);
        gtk_widget_set_sensitive(dst_port_lbl, TRUE);
        gtk_widget_set_sensitive(dst_port_te, TRUE);
        gtk_widget_set_sensitive(tag_lbl, FALSE);
        gtk_widget_set_sensitive(tag_te, FALSE);
        gtk_widget_set_sensitive(ppi_lbl, TRUE);
        gtk_widget_set_sensitive(ppi_te, TRUE);
    }
    else
    {
        gtk_widget_set_sensitive(src_port_lbl, FALSE);
        gtk_widget_set_sensitive(src_port_te, FALSE);
        gtk_widget_set_sensitive(dst_port_lbl, FALSE);
        gtk_widget_set_sensitive(dst_port_te, FALSE);
        gtk_widget_set_sensitive(ppi_lbl, FALSE);
        gtk_widget_set_sensitive(ppi_te, FALSE);
    }
}

/*****************************************************************************/

static void
file_import_open(text_import_info_t *info)
{
    int import_file_fd;
    char *tmpname, *capfile_name = NULL;
    int err;

    /* Choose a random name for the temporary import buffer */
    import_file_fd = create_tempfile(&tmpname, "import");
    capfile_name = g_strdup(tmpname);

    info->wdh = wtap_dump_fdopen(import_file_fd, WTAP_FILE_PCAP, info->encapsulation, info->max_frame_length, FALSE, &err);
    if (info->wdh == NULL) {
        open_failure_alert_box(capfile_name, err, TRUE);
        fclose(info->import_text_file);
        goto end;
    }

    text_import_setup(info);

    text_importin = info->import_text_file;
    
    text_importlex();

    text_import_cleanup();
    
    if (fclose(info->import_text_file))
    {
        read_failure_alert_box(info->import_text_filename, errno);
    }

    if (!wtap_dump_close(info->wdh, &err))
    {
        write_failure_alert_box(capfile_name, err);
    }

    if (cf_open(&cfile, capfile_name, TRUE /* temporary file */, &err) != CF_OK)
    {
        open_failure_alert_box(capfile_name, err, FALSE);
        goto end;
    }

    switch (cf_read(&cfile, FALSE)) {
    case CF_READ_OK:
    case CF_READ_ERROR:
    /* Just because we got an error, that doesn't mean we were unable
       to read any of the file; we handle what we could get from the
       file. */
    break;

    case CF_READ_ABORTED:
    /* The user bailed out of re-reading the capture file; the
       capture file has been closed - just free the capture file name
       string and return (without changing the last containing
       directory). */
    break;
    }

end:
    g_free(info->import_text_filename);
    g_free(info->date_timestamp_format);
    g_free(info);
    g_free(capfile_name);
    window_destroy(file_import_dlg_w);
}

static text_import_info_t *
setup_file_import(GtkWidget *main_w)
{
    GtkWidget *input_frm, *import_frm;

    text_import_info_t *text_import_info = g_malloc0(sizeof(text_import_info_t));
    
    /* Retrieve the input and import settings from the dialog */
  
    /* First the main components */
    input_frm = GTK_WIDGET(g_object_get_data(G_OBJECT(main_w), INPUT_FRM_KEY));
    import_frm = GTK_WIDGET(g_object_get_data(G_OBJECT(main_w), IMPORT_FRM_KEY));

    /* Then the input frame controls of interest */
    {
        GtkWidget *filename_te = GTK_WIDGET(g_object_get_data(G_OBJECT(input_frm), INPUT_FILENAME_TE_KEY));
        GtkWidget *offset_hex_rb = GTK_WIDGET(g_object_get_data(G_OBJECT(input_frm), INPUT_OFFSET_HEX_RB_KEY));
        GtkWidget *offset_oct_rb = GTK_WIDGET(g_object_get_data(G_OBJECT(input_frm), INPUT_OFFSET_OCT_RB_KEY));
        GtkWidget *offset_dec_rb = GTK_WIDGET(g_object_get_data(G_OBJECT(input_frm), INPUT_OFFSET_DEC_RB_KEY));
        GtkWidget *timefmt_cb = GTK_WIDGET(g_object_get_data(G_OBJECT(input_frm), INPUT_DATETIME_CB_KEY));
        GtkWidget *timefmt_te = GTK_WIDGET(g_object_get_data(G_OBJECT(input_frm), INPUT_TIMEFMT_TE_KEY));

        text_import_info->import_text_filename = g_strdup(gtk_entry_get_text(GTK_ENTRY(filename_te)));

        /* Try to open the input file */
        text_import_info->import_text_file = ws_fopen(text_import_info->import_text_filename, "rb");
        if (!text_import_info->import_text_file) {
            open_failure_alert_box(text_import_info->import_text_filename, errno, FALSE);
            g_free(text_import_info->import_text_filename);
            g_free(text_import_info->date_timestamp_format);
            g_free(text_import_info);
            return NULL;
        }

        text_import_info->offset_type =
            gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(offset_hex_rb)) ? OFFSET_HEX :
            gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(offset_oct_rb)) ? OFFSET_OCT :
            gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(offset_dec_rb)) ? OFFSET_DEC :
            0;
        text_import_info->date_timestamp = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(timefmt_cb));
        text_import_info->date_timestamp_format = g_strdup(gtk_entry_get_text(GTK_ENTRY(timefmt_te)));
    }

    /* Then the import frame controls of interest */
    {
        GtkWidget *encap_co = GTK_WIDGET(g_object_get_data(G_OBJECT(import_frm), IMPORT_ENCAP_CO_KEY));
        GtkWidget *header_frm = GTK_WIDGET(g_object_get_data(G_OBJECT(import_frm), IMPORT_HEADER_FRM_KEY));
        GtkWidget *framelen_te = GTK_WIDGET(g_object_get_data(G_OBJECT(import_frm), IMPORT_FRAME_LENGTH_TE_KEY));

        /* Then the header frame controls of interest */
        GtkWidget *header_cb = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_CB_KEY));

        GtkWidget *header_eth_rb = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_ETH_RB_KEY));
        GtkWidget *header_ipv4_rb = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_IPV4_RB_KEY));
        GtkWidget *header_udp_rb = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_UDP_RB_KEY));
        GtkWidget *header_tcp_rb = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_TCP_RB_KEY));
        GtkWidget *header_sctp_rb = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_SCTP_RB_KEY));
        GtkWidget *header_sctp_data_rb = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_SCTP_D_RB_KEY));

        GtkWidget *etype_te = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_ETYPE_TE_KEY));
        GtkWidget *protocol_te = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_PROT_TE_KEY));
        GtkWidget *src_port_te = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_SRC_PORT_TE_KEY));
        GtkWidget *dst_port_te = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_DST_PORT_TE_KEY));
        GtkWidget *tag_te = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_TAG_TE_KEY));
        GtkWidget *ppi_te = GTK_WIDGET(g_object_get_data(G_OBJECT(header_frm), IMPORT_HEADER_PPI_TE_KEY));

        GtkTreeIter iter;

        if (gtk_combo_box_get_active_iter(GTK_COMBO_BOX(encap_co), &iter))
        {
            GtkTreeModel *model = gtk_combo_box_get_model(GTK_COMBO_BOX(encap_co));
            gtk_tree_model_get(model, &iter, 1, &text_import_info->encapsulation, -1);
        }

        if ((text_import_info->encapsulation == WTAP_ENCAP_ETHERNET) &&
            (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(header_cb))))
        {
            text_import_info->dummy_header_type =
                gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(header_eth_rb)) ? HEADER_ETH :
                gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(header_ipv4_rb)) ? HEADER_IPV4 :
                gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(header_udp_rb)) ? HEADER_UDP :
                gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(header_tcp_rb)) ? HEADER_TCP :
                gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(header_sctp_rb)) ? HEADER_SCTP :
                gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(header_sctp_data_rb)) ? HEADER_SCTP_DATA :
                HEADER_NONE;

            switch (text_import_info->dummy_header_type)
            {
            case HEADER_ETH:
                text_import_info->pid = strtol(gtk_entry_get_text(GTK_ENTRY(etype_te)), NULL, 16);
                if (text_import_info->pid > 0xffff)
                {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The Ethertype (%x) is too large.",
                        text_import_info->pid);
                    g_free(text_import_info->import_text_filename);
                    fclose(text_import_info->import_text_file);
                    g_free(text_import_info->date_timestamp_format);
                    g_free(text_import_info);
                    return NULL;
                }
                break;

            case HEADER_IPV4:
                text_import_info->protocol = strtol(gtk_entry_get_text(GTK_ENTRY(protocol_te)), NULL, 10);
                if (text_import_info->protocol > 0xff)
                {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The IPv4 protocol (%u) is too large.",
                        text_import_info->protocol);
                    g_free(text_import_info->import_text_filename);
                    fclose(text_import_info->import_text_file);
                    g_free(text_import_info->date_timestamp_format);
                    g_free(text_import_info);
                    return NULL;
                }
                break;

            case HEADER_UDP:
            case HEADER_TCP:
                text_import_info->src_port = strtol(gtk_entry_get_text(GTK_ENTRY(src_port_te)), NULL, 10);
                if (text_import_info->src_port > 0xffff)
                {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The source port (%u) is too large.",
                        text_import_info->src_port);
                    g_free(text_import_info->import_text_filename);
                    fclose(text_import_info->import_text_file);
                    g_free(text_import_info->date_timestamp_format);
                    g_free(text_import_info);
                    return NULL;
                }
                text_import_info->dst_port = strtol(gtk_entry_get_text(GTK_ENTRY(dst_port_te)), NULL, 10);
                if (text_import_info->dst_port > 0xffff)
                {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The destination port (%u) is too large.",
                        text_import_info->dst_port);
                    g_free(text_import_info->import_text_filename);
                    fclose(text_import_info->import_text_file);
                    g_free(text_import_info->date_timestamp_format);
                    g_free(text_import_info);
                    return NULL;
                }
                break;

            case HEADER_SCTP:
                text_import_info->src_port = strtol(gtk_entry_get_text(GTK_ENTRY(src_port_te)), NULL, 10);
                if (text_import_info->src_port > 0xffff)
                {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The source port (%u) is too large.",
                        text_import_info->src_port);
                    g_free(text_import_info->import_text_filename);
                    fclose(text_import_info->import_text_file);
                    g_free(text_import_info->date_timestamp_format);
                    g_free(text_import_info);
                    return NULL;
                }
                text_import_info->dst_port = strtol(gtk_entry_get_text(GTK_ENTRY(dst_port_te)), NULL, 10);
                if (text_import_info->dst_port > 0xffff)
                {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The destination port (%u) is too large.",
                        text_import_info->dst_port);
                    g_free(text_import_info->import_text_filename);
                    fclose(text_import_info->import_text_file);
                    g_free(text_import_info->date_timestamp_format);
                    g_free(text_import_info);
                    return NULL;
                }
                text_import_info->tag = strtol(gtk_entry_get_text(GTK_ENTRY(tag_te)), NULL, 10);
                break;

            case HEADER_SCTP_DATA:
                text_import_info->src_port = strtol(gtk_entry_get_text(GTK_ENTRY(src_port_te)), NULL, 10);
                if (text_import_info->src_port > 0xffff)
                {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The source port (%u) is too large.",
                        text_import_info->src_port);
                    g_free(text_import_info->import_text_filename);
                    fclose(text_import_info->import_text_file);
                    g_free(text_import_info->date_timestamp_format);
                    g_free(text_import_info);
                    return NULL;
                }
                text_import_info->dst_port = strtol(gtk_entry_get_text(GTK_ENTRY(dst_port_te)), NULL, 10);
                if (text_import_info->dst_port > 0xffff)
                {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The destination port (%u) is too large.",
                        text_import_info->dst_port);
                    g_free(text_import_info->import_text_filename);
                    fclose(text_import_info->import_text_file);
                    g_free(text_import_info->date_timestamp_format);
                    g_free(text_import_info);
                    return NULL;
                }
                text_import_info->ppi = strtol(gtk_entry_get_text(GTK_ENTRY(ppi_te)), NULL, 10);
                break;

            default:
                break;
            }
        } else {
            text_import_info->dummy_header_type = HEADER_NONE;
        }

        text_import_info->max_frame_length = strtol(gtk_entry_get_text(GTK_ENTRY(framelen_te)), NULL, 10);
        if (text_import_info->max_frame_length == 0) {
            text_import_info->max_frame_length = IMPORT_MAX_PACKET;
        }
        else if (text_import_info->max_frame_length > IMPORT_MAX_PACKET)
        {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The maximum frame length (%u) is too long.",
                text_import_info->max_frame_length);
            g_free(text_import_info->import_text_filename);
            fclose(text_import_info->import_text_file);
            g_free(text_import_info->date_timestamp_format);
            g_free(text_import_info);
            return NULL;
        }
    }

    return text_import_info;
}

/*****************************************************************************/

static void
file_import_answered_cb(gpointer dialog _U_, gint btn, gpointer data)
{
    text_import_info_t *text_import_info;
    
    switch (btn) {
    case ESD_BTN_SAVE:
        /* save file first */
        file_save_as_cmd(after_save_no_action, NULL);
        break;
    case ESD_BTN_DONT_SAVE:
        cf_close(&cfile);
        break;
    case ESD_BTN_CANCEL:
        return;
    default:
        g_assert_not_reached();
    }

    text_import_info = setup_file_import(data);
    if (text_import_info)
        file_import_open(text_import_info);
}

static void
file_import_ok_cb(GtkWidget *widget _U_, gpointer data)
{
    text_import_info_t *text_import_info;
    
    if((cfile.state != FILE_CLOSED) && !cfile.user_saved && prefs.gui_ask_unsaved) {
        gpointer dialog;
        /* user didn't save his current file, ask him */
        dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_DONTSAVE_CANCEL,
                "%sSave capture file before opening a new one?%s\n\n"
                "If you open a new capture file without saving, your capture data will be discarded.",
                simple_dialog_primary_start(), simple_dialog_primary_end());
        simple_dialog_set_cb(dialog, file_import_answered_cb, data);
    } else {
        /* unchanged file, just open a new one */
        text_import_info = setup_file_import(data);
        if (text_import_info)
            file_import_open(text_import_info);
    }

}

/*****************************************************************************/

/*
 * Dialog creator
 */
static GtkWidget *
file_import_dlg_new()
{
    GtkWidget  *main_w, *main_vb,
               *input_frm, *input_tb, *input_vb,
               *filename_hb, *filename_lbl, *filename_te, *browse_bt,
               *offset_hb, *offset_lbl_vb, *offset_lbl, *offset_rb_vb,
               *offset_hex_rb, *offset_oct_rb, *offset_dec_rb,
               *timefmt_hb, *timefmt_cb, *timefmt_lbl, *timefmt_te,
               *import_frm, *import_vb,
               *encap_hb, *encap_lbl, *encap_co,
               *header_cb, *header_frm, *header_hb,
               *header_eth_rb, *header_ipv4_rb, *header_udp_rb,
               *header_tcp_rb, *header_sctp_rb, *header_sctp_data_rb,
               *header_rblbl_vb,
               *header_rblbl_1_hb, *header_rblbl_1_lbl,
               *header_rblbl_2_hb, *header_rblbl_2_lbl,
               *header_rblbl_3_hb, *header_rblbl_3_lbl,
               *header_rblbl_4_hb, *header_rblbl_4_lbl,
               *header_rblbl_5_hb, *header_rblbl_5_lbl,
               *header_rblbl_6_hb, *header_rblbl_6_lbl,
               *etype_te, *protocol_te, *src_port_te,
               *dst_port_te, *tag_te, *ppi_te,
               *framelen_hb, *framelen_lbl, *framelen_te,
               *bbox, *help_bt, *close_bt, *ok_bt;

    GSList     *offset_grp,       /* Offset radio button group */
               *header_grp;       /* Dummy header radio button group */

#if GTK_CHECK_VERSION(2,12,0)
#else
    GtkTooltips *tooltips = gtk_tooltips_new();
#endif

    /* Setup the dialog */

    main_w = dlg_window_new("Wireshark: Import from Text");
    gtk_window_set_default_size(GTK_WINDOW(main_w), 400, 300);

    main_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 3);
    gtk_container_add(GTK_CONTAINER(main_w), main_vb);

    /* Setup the input frame */

    input_frm = gtk_frame_new("Input");
    gtk_box_pack_start(GTK_BOX(main_vb), input_frm, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(main_w), INPUT_FRM_KEY, input_frm);
    
    input_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(input_frm), input_vb);

    input_tb = gtk_table_new(2, 3, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(input_tb), 5);
    gtk_box_pack_start(GTK_BOX(input_vb), input_tb, FALSE, FALSE, 0);
    gtk_table_set_row_spacings(GTK_TABLE(input_tb), 5);
    gtk_table_set_col_spacings(GTK_TABLE(input_tb), 5);

    /* Filename */
    filename_hb = gtk_hbox_new(FALSE, 3);
    gtk_container_set_border_width(GTK_CONTAINER(filename_hb), 3);

    filename_lbl = gtk_label_new("Filename:");
    gtk_table_attach(GTK_TABLE(input_tb), filename_lbl, 0, 1, 0, 1, 0, 0, 0, 0);

    filename_te = gtk_entry_new();
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(filename_te, "Set name of text file to import");
#else
    gtk_tooltips_set_tip(tooltips, filename_te, "Set name of text file to import", NULL);
#endif
    gtk_table_attach_defaults(GTK_TABLE(input_tb), filename_te, 1, 2, 0, 1);

    g_object_set_data(G_OBJECT(input_frm), INPUT_FILENAME_TE_KEY, filename_te);
    
    browse_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_BROWSE);
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(browse_bt, "Browse for text file to import");
#else
    gtk_tooltips_set_tip(tooltips, browse_bt, "Browse for text file to import", NULL);
#endif
    gtk_table_attach(GTK_TABLE(input_tb), browse_bt, 2, 3, 0, 1, 0, 0, 0, 0);

    g_signal_connect(browse_bt, "clicked", G_CALLBACK(browse_file_cb), filename_te);

    /* Offsets */
    offset_hb = gtk_hbox_new(FALSE, 3);
    gtk_container_set_border_width(GTK_CONTAINER(offset_hb), 3);
    gtk_box_pack_start(GTK_BOX(input_vb), offset_hb, FALSE, FALSE, 0);

    offset_lbl_vb = gtk_vbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(offset_hb), offset_lbl_vb, FALSE, FALSE, 0);

    offset_lbl = gtk_label_new("Offsets:");
    gtk_misc_set_alignment(GTK_MISC(offset_lbl), 1.0f, 0.0f);
    gtk_table_attach(GTK_TABLE(input_tb), offset_lbl, 0, 1, 1, 2, 0, 0, 0, 0);

    offset_rb_vb = gtk_vbox_new(FALSE, 0);
    gtk_table_attach_defaults(GTK_TABLE(input_tb), offset_rb_vb, 1, 2, 1, 2);

    offset_hex_rb = gtk_radio_button_new_with_label(NULL, "Hexadecimal");
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(offset_hex_rb, "Offsets in the text file are in hexadecimal notation");
#else
    gtk_tooltips_set_tip(tooltips, offset_hex_rb, "Offsets in the text file are in hexadecimal notation", NULL);
#endif
    gtk_box_pack_start(GTK_BOX(offset_rb_vb), offset_hex_rb, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(input_frm), INPUT_OFFSET_HEX_RB_KEY, offset_hex_rb);
    
    offset_grp = gtk_radio_button_get_group(GTK_RADIO_BUTTON(offset_hex_rb));
    offset_oct_rb = gtk_radio_button_new_with_label(offset_grp, "Octal");
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(offset_oct_rb, "Offsets in the text file are in octal notation");
#else
    gtk_tooltips_set_tip(tooltips, offset_oct_rb, "Offsets in the text file are in octal notation", NULL);
#endif
    gtk_box_pack_start(GTK_BOX(offset_rb_vb), offset_oct_rb, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(input_frm), INPUT_OFFSET_OCT_RB_KEY, offset_oct_rb);
    
    offset_grp = gtk_radio_button_get_group(GTK_RADIO_BUTTON(offset_oct_rb));
    offset_dec_rb = gtk_radio_button_new_with_label(offset_grp, "Decimal");
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(offset_dec_rb, "Offsets in the text file are in decimal notation");
#else
    gtk_tooltips_set_tip(tooltips, offset_dec_rb, "Offsets in the text file are in decimal notation", NULL);
#endif
    gtk_box_pack_start(GTK_BOX(offset_rb_vb), offset_dec_rb, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(input_frm), INPUT_OFFSET_DEC_RB_KEY, offset_dec_rb);
        
    /* Time format */
    timefmt_hb = gtk_hbox_new(FALSE, 3);
    gtk_container_set_border_width(GTK_CONTAINER(timefmt_hb), 3);
    gtk_box_pack_start(GTK_BOX(input_vb), timefmt_hb, FALSE, FALSE, 0);

    timefmt_cb = gtk_check_button_new_with_label("Date/Time");
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(timefmt_cb, "Whether or not the text file contains timestamp information");
#else
    gtk_tooltips_set_tip(tooltips, timefmt_cb, "Whether or not the text file contains timestamp information", NULL);
#endif
    gtk_box_pack_start(GTK_BOX(timefmt_hb), timefmt_cb, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(input_frm), INPUT_DATETIME_CB_KEY, timefmt_cb);

    timefmt_lbl = gtk_label_new("   Format:");
    gtk_box_pack_start(GTK_BOX(timefmt_hb), timefmt_lbl, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(timefmt_cb), INPUT_TIMEFMT_LBL_KEY, timefmt_lbl);

    timefmt_te = gtk_entry_new();
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(timefmt_te, "The format in which to parse timestamps in the text file (eg. %H:%M:%S.). Format specifiers are based on strptime(3)");
#else
    gtk_tooltips_set_tip(tooltips, timefmt_te, "The format in which to parse timestamps in the text file (eg. %H:%M:%S.). Format specifiers are based on strptime(3)", NULL);
#endif
    gtk_box_pack_start(GTK_BOX(timefmt_hb), timefmt_te, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(timefmt_cb), INPUT_TIMEFMT_TE_KEY, timefmt_te);
    g_object_set_data(G_OBJECT(input_frm), INPUT_TIMEFMT_TE_KEY, timefmt_te);
    
    g_signal_connect(timefmt_cb, "toggled", G_CALLBACK(timefmt_cb_toggle), NULL);
    g_signal_emit_by_name(G_OBJECT(timefmt_cb), "toggled", NULL);

    /* Setup the import frame */

    import_frm = gtk_frame_new("Import");
    gtk_box_pack_start(GTK_BOX(main_vb), import_frm, TRUE, TRUE, 3);

    g_object_set_data(G_OBJECT(main_w), IMPORT_FRM_KEY, import_frm);
        
    import_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(import_frm), import_vb);

    /* Encapsulation */
    encap_hb = gtk_hbox_new(FALSE, 3);
    gtk_container_set_border_width(GTK_CONTAINER(encap_hb), 3);
    gtk_box_pack_start(GTK_BOX(import_vb), encap_hb, FALSE, FALSE, 0);

    encap_lbl = gtk_label_new("Encapsulation type:");
    gtk_box_pack_start(GTK_BOX(encap_hb), encap_lbl, FALSE, FALSE, 0);

    encap_co = fill_encap_combo();
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(encap_co, "Encapsulation type for the frames in the import capture file");
#else
    gtk_tooltips_set_tip(tooltips, encap_co, "Encapsulation type for the frames in the import capture file", NULL);
#endif
    gtk_box_pack_start(GTK_BOX(encap_hb), encap_co, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(import_frm), IMPORT_ENCAP_CO_KEY, encap_co);
    
    /* Dummy header */
    header_frm = gtk_frame_new(NULL);
    header_cb = gtk_check_button_new_with_label("Dummy header");
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(header_cb, "Whether or not to prefix a dummy header to the frames");
#else
    gtk_tooltips_set_tip(tooltips, header_cb, "Whether or not to prefix a dummy header to the frames", NULL);
#endif
    gtk_frame_set_label_widget(GTK_FRAME(header_frm), header_cb);
    gtk_container_set_border_width(GTK_CONTAINER(header_frm), 3);
    gtk_box_pack_start(GTK_BOX(import_vb), header_frm, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(import_frm), IMPORT_HEADER_FRM_KEY, header_frm);
    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_CB_KEY, header_cb);
    
    header_hb = gtk_hbox_new(FALSE, 3);
    gtk_container_set_border_width(GTK_CONTAINER(header_hb), 3);
    gtk_container_add(GTK_CONTAINER(header_frm), header_hb);

    header_rblbl_vb = gtk_vbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header_hb), header_rblbl_vb, TRUE, TRUE, 0);

    /* Line 1 */
    header_rblbl_1_hb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header_rblbl_vb), header_rblbl_1_hb, FALSE, FALSE, 2);

    header_eth_rb = gtk_radio_button_new_with_label(NULL, "Ethernet");
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(header_eth_rb, "Prefix an Ethernet header to the frames");
#else
    gtk_tooltips_set_tip(tooltips, header_eth_rb, "Prefix an Ethernet header to the frames", NULL);
#endif
    header_grp = gtk_radio_button_get_group(GTK_RADIO_BUTTON(header_eth_rb));
    g_signal_connect(header_eth_rb, "toggled", G_CALLBACK(header_eth_rb_toggle), header_frm);
    gtk_box_pack_start(GTK_BOX(header_rblbl_1_hb), header_eth_rb, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_ETH_RB_KEY, header_eth_rb);
    
    header_rblbl_1_lbl = gtk_label_new("  Ethertype (hex):");
    gtk_box_pack_start(GTK_BOX(header_rblbl_1_hb), header_rblbl_1_lbl, TRUE, TRUE, 0);
    gtk_misc_set_alignment(GTK_MISC(header_rblbl_1_lbl), 1.0f, 0.5f);

    etype_te = gtk_entry_new();
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(etype_te, "The type to set in the Ethernet header");
#else
    gtk_tooltips_set_tip(tooltips, etype_te, "The type to set in the Ethernet header", NULL);
#endif
    gtk_box_pack_end(GTK_BOX(header_rblbl_1_hb), etype_te, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_ETYPE_LBL_KEY, header_rblbl_1_lbl);
    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_ETYPE_TE_KEY, etype_te);

    /* Line 2 */
    header_rblbl_2_hb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header_rblbl_vb), header_rblbl_2_hb, FALSE, FALSE, 2);

    header_ipv4_rb = gtk_radio_button_new_with_label(header_grp, "IPv4");
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(header_ipv4_rb, "Prefix an Ethernet and IPv4 header to the frames");
#else
    gtk_tooltips_set_tip(tooltips, header_ipv4_rb, "Prefix an Ethernet and IPv4 header to the frames", NULL);
#endif
    header_grp = gtk_radio_button_get_group(GTK_RADIO_BUTTON(header_ipv4_rb));
    g_signal_connect(header_ipv4_rb, "toggled", G_CALLBACK(header_ipv4_rb_toggle), header_frm);
    gtk_box_pack_start(GTK_BOX(header_rblbl_2_hb), header_ipv4_rb, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_IPV4_RB_KEY, header_ipv4_rb);
    
    header_rblbl_2_lbl = gtk_label_new("  Protocol (dec):");
    gtk_box_pack_start(GTK_BOX(header_rblbl_2_hb), header_rblbl_2_lbl, TRUE, TRUE, 0);
    gtk_misc_set_alignment(GTK_MISC(header_rblbl_2_lbl), 1.0f, 0.5f);

    protocol_te = gtk_entry_new();
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(protocol_te, "The protocol id to set in the IPv4 header");
#else
    gtk_tooltips_set_tip(tooltips, protocol_te, "The protocol id to set in the IPv4 header", NULL);
#endif
    gtk_box_pack_end(GTK_BOX(header_rblbl_2_hb), protocol_te, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_PROT_LBL_KEY, header_rblbl_2_lbl);
    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_PROT_TE_KEY, protocol_te);

    /* Line 3 */
    header_rblbl_3_hb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header_rblbl_vb), header_rblbl_3_hb, FALSE, FALSE, 2);

    header_udp_rb = gtk_radio_button_new_with_label(header_grp, "UDP");
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(header_udp_rb, "Prefix an Ethernet, IPv4 and UDP header to the frames");
#else
    gtk_tooltips_set_tip(tooltips, header_udp_rb, "Prefix an Ethernet, IPv4 and UDP header to the frames", NULL);
#endif
    header_grp = gtk_radio_button_get_group(GTK_RADIO_BUTTON(header_udp_rb));
    g_signal_connect(header_udp_rb, "toggled", G_CALLBACK(header_udp_rb_toggle), header_frm);
    gtk_box_pack_start(GTK_BOX(header_rblbl_3_hb), header_udp_rb, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_UDP_RB_KEY, header_udp_rb);
    
    header_rblbl_3_lbl = gtk_label_new("  Source port:");
    gtk_box_pack_start(GTK_BOX(header_rblbl_3_hb), header_rblbl_3_lbl, TRUE, TRUE, 0);
    gtk_misc_set_alignment(GTK_MISC(header_rblbl_3_lbl), 1.0f, 0.5f);

    src_port_te = gtk_entry_new();
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(src_port_te, "The source port to set in the UDP, TCP or SCTP header");
#else
    gtk_tooltips_set_tip(tooltips, src_port_te, "The source port to set in the UDP, TCP or SCTP header", NULL);
#endif
    gtk_box_pack_end(GTK_BOX(header_rblbl_3_hb), src_port_te, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_SRC_PORT_LBL_KEY, header_rblbl_3_lbl);
    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_SRC_PORT_TE_KEY, src_port_te);

    /* Line 4 */
    header_rblbl_4_hb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header_rblbl_vb), header_rblbl_4_hb, FALSE, FALSE, 2);

    header_tcp_rb = gtk_radio_button_new_with_label(header_grp, "TCP");
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(header_tcp_rb, "Prefix an Ethernet, IPv4 and TCP header to the frames");
#else
    gtk_tooltips_set_tip(tooltips, header_tcp_rb, "Prefix an Ethernet, IPv4 and TCP header to the frames", NULL);
#endif
    header_grp = gtk_radio_button_get_group(GTK_RADIO_BUTTON(header_tcp_rb));
    g_signal_connect(header_tcp_rb, "toggled", G_CALLBACK(header_tcp_rb_toggle), header_frm);
    gtk_box_pack_start(GTK_BOX(header_rblbl_4_hb), header_tcp_rb, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_TCP_RB_KEY, header_tcp_rb);
    
    header_rblbl_4_lbl = gtk_label_new("  Destination port:");
    gtk_box_pack_start(GTK_BOX(header_rblbl_4_hb), header_rblbl_4_lbl, TRUE, TRUE, 0);
    gtk_misc_set_alignment(GTK_MISC(header_rblbl_4_lbl), 1.0f, 0.5f);

    dst_port_te = gtk_entry_new();
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(dst_port_te, "The destination port to set in the UDP, TCP or SCTP header");
#else
    gtk_tooltips_set_tip(tooltips, dst_port_te, "The destination port to set in the UDP, TCP or SCTP header", NULL);
#endif
    gtk_box_pack_end(GTK_BOX(header_rblbl_4_hb), dst_port_te, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_DST_PORT_LBL_KEY, header_rblbl_4_lbl);
    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_DST_PORT_TE_KEY, dst_port_te);

    /* Line 5 */
    header_rblbl_5_hb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header_rblbl_vb), header_rblbl_5_hb, FALSE, FALSE, 2);

    header_sctp_rb = gtk_radio_button_new_with_label(header_grp, "SCTP");
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(header_sctp_rb, "Prefix an Ethernet, IPv4 and SCTP header to the frames");
#else
    gtk_tooltips_set_tip(tooltips, header_sctp_rb, "Prefix an Ethernet, IPv4 and SCTP header to the frames", NULL);
#endif
    header_grp = gtk_radio_button_get_group(GTK_RADIO_BUTTON(header_sctp_rb));
    g_signal_connect(header_sctp_rb, "toggled", G_CALLBACK(header_sctp_rb_toggle), header_frm);
    gtk_box_pack_start(GTK_BOX(header_rblbl_5_hb), header_sctp_rb, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_SCTP_RB_KEY, header_sctp_rb);
        
    header_rblbl_5_lbl = gtk_label_new("  Tag:");
    gtk_box_pack_start(GTK_BOX(header_rblbl_5_hb), header_rblbl_5_lbl, TRUE, TRUE, 0);
    gtk_misc_set_alignment(GTK_MISC(header_rblbl_5_lbl), 1.0f, 0.5f);

    tag_te = gtk_entry_new();
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(tag_te, "The verification tag to set in the SCTP header");
#else
    gtk_tooltips_set_tip(tooltips, tag_te, "The verification tag to set in the SCTP header", NULL);
#endif
    gtk_box_pack_end(GTK_BOX(header_rblbl_5_hb), tag_te, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_TAG_LBL_KEY, header_rblbl_5_lbl);
    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_TAG_TE_KEY, tag_te);

    /* Line 6 */
    header_rblbl_6_hb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header_rblbl_vb), header_rblbl_6_hb, FALSE, FALSE, 2);

    header_sctp_data_rb = gtk_radio_button_new_with_label(header_grp, "SCTP (DATA)");
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(header_sctp_data_rb, "Prefix an Ethernet, IPv4 and SCTP DATA header to the frames");
#else
    gtk_tooltips_set_tip(tooltips, header_sctp_data_rb, "Prefix an Ethernet, IPv4 and SCTP DATA header to the frames", NULL);
#endif
    header_grp = gtk_radio_button_get_group(GTK_RADIO_BUTTON(header_sctp_data_rb));
    g_signal_connect(header_sctp_data_rb, "toggled", G_CALLBACK(header_sctp_data_rb_toggle), header_frm);
    gtk_box_pack_start(GTK_BOX(header_rblbl_6_hb), header_sctp_data_rb, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_SCTP_D_RB_KEY, header_sctp_data_rb);
        
    header_rblbl_6_lbl = gtk_label_new("  PPI:");
    gtk_box_pack_start(GTK_BOX(header_rblbl_6_hb), header_rblbl_6_lbl, TRUE, TRUE, 0);
    gtk_misc_set_alignment(GTK_MISC(header_rblbl_6_lbl), 1.0f, 0.5f);

    ppi_te = gtk_entry_new();
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(ppi_te, "The payload protocol identifier to set in the SCTP DATA header");
#else
    gtk_tooltips_set_tip(tooltips, ppi_te, "The payload protocol identifier to set in the SCTP DATA header", NULL);
#endif
    gtk_box_pack_end(GTK_BOX(header_rblbl_6_hb), ppi_te, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_PPI_LBL_KEY, header_rblbl_6_lbl);
    g_object_set_data(G_OBJECT(header_frm), IMPORT_HEADER_PPI_TE_KEY, ppi_te);

    /* Set sensitivity */
    g_signal_connect(header_cb, "toggled", G_CALLBACK(header_cb_toggle), header_frm);
    g_signal_emit_by_name(G_OBJECT(header_cb), "toggled", header_frm);

    g_signal_emit_by_name(G_OBJECT(header_eth_rb), "toggled", header_frm);

    gtk_combo_box_set_active(GTK_COMBO_BOX(encap_co), 0);
    g_signal_connect(encap_co, "changed", G_CALLBACK(encap_co_changed), header_frm);

    /* Frame length */
    framelen_hb = gtk_hbox_new(FALSE, 3);
    gtk_container_set_border_width(GTK_CONTAINER(framelen_hb), 3);
    gtk_box_pack_start(GTK_BOX(import_vb), framelen_hb, FALSE, FALSE, 0);

    framelen_lbl = gtk_label_new("Max. frame length:");
    gtk_box_pack_start(GTK_BOX(framelen_hb), framelen_lbl, FALSE, FALSE, 0);

    framelen_te = gtk_entry_new();
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(framelen_te, "The maximum size of the frames to write to the import capture file (max 64000)");
#else
    gtk_tooltips_set_tip(tooltips, framelen_te, "The maximum size of the frames to write to the import capture file (max 64000)", NULL);
#endif
    gtk_box_pack_start(GTK_BOX(framelen_hb), framelen_te, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(import_frm), IMPORT_FRAME_LENGTH_TE_KEY, framelen_te);
    
    /* Setup the button row */

    bbox = dlg_button_row_new(GTK_STOCK_HELP, GTK_STOCK_OK, GTK_STOCK_CANCEL, NULL);
    gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 3);

    help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_IMPORT_DIALOG);
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(help_bt, "Show topic specific help");
#else
    gtk_tooltips_set_tip(tooltips, help_bt, "Show topic specific help", NULL);
#endif
    
    close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
    window_set_cancel_button(main_w, close_bt, window_cancel_button_cb);
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(close_bt, "Close this dialog");
#else
    gtk_tooltips_set_tip(tooltips, close_bt, "Close this dialog", NULL);
#endif
   
    ok_bt =  g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
    g_signal_connect(ok_bt, "clicked", G_CALLBACK(file_import_ok_cb), main_w);
    gtk_widget_grab_default(ok_bt);
#if GTK_CHECK_VERSION(2,12,0)
    gtk_widget_set_tooltip_text(ok_bt, "Import the selected file into a temporary capture file");
#else
    gtk_tooltips_set_tip(tooltips, ok_bt, "Import the selected file into a temporary capture file", NULL);
#endif

    /* Setup widget handling */

    g_signal_connect(main_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(main_w, "destroy", G_CALLBACK(file_import_dlg_destroy_cb), NULL);

    gtk_widget_show_all(main_w);
    window_present(main_w);

    return main_w;
}

void
file_import_cmd_cb(GtkWidget *widget _U_)
{
    /* Do we have an encapsulation type list? */
    if (!encap_list_store)
    {
        /* No. Create one. */
        create_encap_list_store();
    }
  
    /* Has a file import dialog already been opened? */
    if (file_import_dlg_w)
    {
        /* Yes. Just re-activate that dialog box. */
        reactivate_window(file_import_dlg_w);
    } else {
        /* No. Create one */
        file_import_dlg_w = file_import_dlg_new();
    }

    return;
}

