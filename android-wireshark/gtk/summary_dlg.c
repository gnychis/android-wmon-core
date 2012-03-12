/* summary_dlg.c
 * Routines for capture file summary window
 *
 * $Id: summary_dlg.c 31289 2009-12-17 12:05:13Z stig $
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
#include <sys/types.h>
#endif
#include <string.h>
#include <time.h>

#include <gtk/gtk.h>

#include <epan/strutil.h>

#include <wiretap/wtap.h>

#include "../globals.h"
#include "../file.h"
#include "../summary.h"
#ifdef HAVE_LIBPCAP
#include "../capture.h"
#include "gtk/main.h"
#include "gtk/capture_globals.h"
#endif

#include "gtk/summary_dlg.h"
#include "gtk/dlg_utils.h"
#include "gtk/gui_utils.h"
#include "gtk/help_dlg.h"


#define SUM_STR_MAX     1024
#define FILTER_SNIP_LEN 50


static void
add_string_to_table_sensitive(GtkWidget *list, guint *row, const gchar *title, const gchar *value, gboolean sensitive)
{
    GtkWidget *label;
    gchar     *indent;

    if(strlen(value) != 0) {
        indent = g_strdup_printf("   %s", title);
    } else {
        indent = g_strdup(title);
    }
    label = gtk_label_new(indent);
    if (strlen(value) == 0) {
      gchar *message = g_strdup_printf("<span weight=\"bold\">%s</span>", title);
      gtk_label_set_markup(GTK_LABEL(label), message);
      g_free (message);
    }
    g_free(indent);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_widget_set_sensitive(label, sensitive);
    gtk_table_attach_defaults(GTK_TABLE(list), label, 0, 1, *row, *row+1);

    label = gtk_label_new(value);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_widget_set_sensitive(label, sensitive);
    gtk_table_attach_defaults(GTK_TABLE(list), label, 1, 2, *row, *row+1);

    *row = *row + 1;
}

static void
add_string_to_table(GtkWidget *list, guint *row, gchar *title, gchar *value)
{
    add_string_to_table_sensitive(list, row, title, value, TRUE);
}


static void
add_string_to_list(GtkWidget *list, gchar *title, gchar *captured, gchar *displayed, gchar *marked)
{
    simple_list_append(list, 0, title, 1, captured, 2, displayed, 3, marked, -1);
}

void
summary_open_cb(GtkWidget *w _U_, gpointer d _U_)
{
  summary_tally summary;
  GtkWidget     *sum_open_w,
                *main_vb, *bbox, *close_bt, *help_bt;
  GtkWidget     *table;
  GtkWidget     *list;
  static const char *titles[] = { "Traffic", "Captured", "Displayed", "Marked" };

  gchar         string_buff[SUM_STR_MAX];
  gchar         string_buff2[SUM_STR_MAX];
  gchar         string_buff3[SUM_STR_MAX];

  double        seconds;
  double        disp_seconds;
  double        marked_seconds;
  guint         offset;
  guint         snip;
  guint         row;
  gchar        *str_dup;
  gchar        *str_work;

  time_t        ti_time;
  struct tm    *ti_tm;
  unsigned int  elapsed_time;

  /* initial computations */
  summary_fill_in(&cfile, &summary);
#ifdef HAVE_LIBPCAP
  summary_fill_in_capture(&global_capture_opts, &summary);
#endif
  seconds = summary.stop_time - summary.start_time;
  disp_seconds = summary.filtered_stop - summary.filtered_start;
  marked_seconds = summary.marked_stop - summary.marked_start;

  sum_open_w = window_new(GTK_WINDOW_TOPLEVEL, "Wireshark: Summary");

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 12);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 12);
  gtk_container_add(GTK_CONTAINER(sum_open_w), main_vb);

  /* table */
  table = gtk_table_new(1, 2, FALSE);
  gtk_table_set_col_spacings(GTK_TABLE(table), 6);
  gtk_table_set_row_spacings(GTK_TABLE(table), 3);
  gtk_container_add(GTK_CONTAINER(main_vb), table);
  row = 0;


  /* File */
  add_string_to_table(table, &row, "File", "");

  /* filename */
  g_snprintf(string_buff, SUM_STR_MAX, "%s", summary.filename);
  add_string_to_table(table, &row, "Name:", string_buff);

  /* length */
  g_snprintf(string_buff, SUM_STR_MAX, "%" G_GINT64_MODIFIER "d bytes", summary.file_length);
  add_string_to_table(table, &row, "Length:", string_buff);

  /* format */
  g_snprintf(string_buff, SUM_STR_MAX, "%s", wtap_file_type_string(summary.file_type));
  add_string_to_table(table, &row, "Format:", string_buff);

  /* encapsulation */
  g_snprintf(string_buff, SUM_STR_MAX, "%s", wtap_encap_string(summary.encap_type));
  add_string_to_table(table, &row, "Encapsulation:", string_buff);

  if (summary.has_snap) {
    /* snapshot length */
    g_snprintf(string_buff, SUM_STR_MAX, "%u bytes", summary.snap);
    add_string_to_table(table, &row, "Packet size limit:", string_buff);
  }


  /* Time */
  add_string_to_table(table, &row, "", "");
  add_string_to_table(table, &row, "Time", "");

  /* start time */
  ti_time = (time_t)summary.start_time;
  ti_tm = localtime(&ti_time);
  g_snprintf(string_buff, SUM_STR_MAX,
             "%04d-%02d-%02d %02d:%02d:%02d",
             ti_tm->tm_year + 1900,
             ti_tm->tm_mon + 1,
             ti_tm->tm_mday,
             ti_tm->tm_hour,
             ti_tm->tm_min,
             ti_tm->tm_sec);
  add_string_to_table(table, &row, "First packet:", string_buff);

  /* stop time */
  ti_time = (time_t)summary.stop_time;
  ti_tm = localtime(&ti_time);
  g_snprintf(string_buff, SUM_STR_MAX,
             "%04d-%02d-%02d %02d:%02d:%02d",
             ti_tm->tm_year + 1900,
             ti_tm->tm_mon + 1,
             ti_tm->tm_mday,
             ti_tm->tm_hour,
             ti_tm->tm_min,
             ti_tm->tm_sec);
  add_string_to_table(table, &row, "Last packet:", string_buff);

  /* elapsed seconds */
  elapsed_time = (unsigned int)summary.elapsed_time;
  if(elapsed_time/86400) {
      g_snprintf(string_buff, SUM_STR_MAX, "%02u days %02u:%02u:%02u",
        elapsed_time/86400, elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
  } else {
      g_snprintf(string_buff, SUM_STR_MAX, "%02u:%02u:%02u",
        elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
  }
  add_string_to_table(table, &row, "Elapsed:", string_buff);


  /* Capture */
  add_string_to_table(table, &row, "", "");
  add_string_to_table_sensitive(table, &row, "Capture", "", (summary.iface != NULL));

  /* interface */
  if (summary.iface) {
    g_snprintf(string_buff, SUM_STR_MAX, "%s", summary.iface_descr);
  } else {
    g_snprintf(string_buff, SUM_STR_MAX, "unknown");
  }
  add_string_to_table_sensitive(table, &row, "Interface:", string_buff, (summary.iface) != NULL);

  /* Dropped count */
  if (summary.drops_known) {
    g_snprintf(string_buff, SUM_STR_MAX, "%" G_GINT64_MODIFIER "u", summary.drops);
  } else {
    g_snprintf(string_buff, SUM_STR_MAX, "unknown");
  }
  add_string_to_table_sensitive(table, &row, "Dropped packets:", string_buff, (summary.iface != NULL));

#ifdef HAVE_LIBPCAP
  /* Capture filter */
  if (summary.cfilter && summary.cfilter[0] != '\0') {
    g_snprintf(string_buff, SUM_STR_MAX, "%s", summary.cfilter);
  } else {
    if(summary.iface) {
      g_snprintf(string_buff, SUM_STR_MAX, "none");
    } else {
      g_snprintf(string_buff, SUM_STR_MAX, "unknown");
    }
  }
  add_string_to_table_sensitive(table, &row, "Capture filter:", string_buff, (summary.iface != NULL));
#endif


  /* Data */
  add_string_to_table(table, &row, "", "");
  add_string_to_table(table, &row, "Display", "");

  if (summary.dfilter) {
    /* Display filter */
    /* limit each row to some reasonable length */
    str_dup = g_strdup_printf("%s", summary.dfilter);
    str_work = g_strdup(str_dup);
    offset = 0;
    snip = 0;
    while(strlen(str_work) > FILTER_SNIP_LEN) {
        str_work[FILTER_SNIP_LEN] = '\0';
        add_string_to_table(table, &row, (snip == 0) ? "Display filter:" : "", str_work);
        g_free(str_work);
        offset+=FILTER_SNIP_LEN;
        str_work = g_strdup(&str_dup[offset]);
        snip++;
    }

    add_string_to_table(table, &row, (snip == 0) ? "Display filter:" : "", str_work);
    g_free(str_work);
    g_free(str_dup);
  } else {
    /* Display filter */
    add_string_to_table(table, &row, "Display filter:", "none");
  }

  /* Ignored packet count */
  g_snprintf(string_buff, SUM_STR_MAX, "%i", summary.ignored_count);
  add_string_to_table(table, &row, "Ignored packets:", string_buff);

  /* Traffic */
  list = simple_list_new(4, titles);
  gtk_container_add(GTK_CONTAINER(main_vb), list);

  /* Packet count */
  g_snprintf(string_buff, SUM_STR_MAX, "%i", summary.packet_count);
  if (summary.dfilter) {
    g_snprintf(string_buff2, SUM_STR_MAX, "%i", summary.filtered_count);
  } else {
    g_strlcpy(string_buff2, string_buff, SUM_STR_MAX);
  }
  g_snprintf(string_buff3, SUM_STR_MAX, "%i", summary.marked_count);
  add_string_to_list(list, "Packets", string_buff, string_buff2, string_buff3);

  /* Time between first and last */
  if (seconds > 0) {
    g_snprintf(string_buff, SUM_STR_MAX, "%.3f sec", seconds);
  } else {
    string_buff[0] = '\0';
  }
  if (summary.dfilter && disp_seconds > 0) {
    g_snprintf(string_buff2, SUM_STR_MAX, "%.3f sec", disp_seconds);
  } else {
    string_buff2[0] = '\0';
  }
  if (summary.marked_count && marked_seconds > 0) {
    g_snprintf(string_buff3, SUM_STR_MAX, "%.3f sec", marked_seconds);
  } else {
    string_buff3[0] = '\0';
  }
  add_string_to_list(list, "Between first and last packet", string_buff, string_buff2, string_buff3);

  /* Packets per second */
  if (seconds > 0) {
    g_snprintf(string_buff, SUM_STR_MAX, "%.3f", summary.packet_count/seconds);
  } else {
    string_buff[0] = '\0';
  }
  if(summary.dfilter && disp_seconds > 0) {
    g_snprintf(string_buff2, SUM_STR_MAX, "%.3f", summary.filtered_count/disp_seconds);
  } else {
    string_buff2[0] = '\0';
  }
  if(summary.marked_count && marked_seconds > 0) {
    g_snprintf(string_buff3, SUM_STR_MAX, "%.3f", summary.marked_count/marked_seconds);
  } else {
    string_buff3[0] = '\0';
  }
  add_string_to_list(list, "Avg. packets/sec", string_buff, string_buff2, string_buff3);

  /* Packet size */
  if (summary.packet_count > 1) {
    g_snprintf(string_buff, SUM_STR_MAX, "%.3f bytes",
	       /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
	       (float) ((gint64) summary.bytes)/summary.packet_count);
  } else {
    string_buff[0] = '\0';
  }
  if (summary.dfilter && summary.filtered_count > 1) {
    g_snprintf(string_buff2, SUM_STR_MAX, "%.3f bytes",
	       /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
	       (float) ((gint64) summary.filtered_bytes)/summary.filtered_count);
  } else {
    string_buff2[0] = '\0';
  }
  if (summary.marked_count > 1) {
    g_snprintf(string_buff3, SUM_STR_MAX, "%.3f bytes",
	       /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
	       (float) ((gint64) summary.marked_bytes)/summary.marked_count);
  } else {
    string_buff3[0] = '\0';
  }
  add_string_to_list(list, "Avg. packet size", string_buff, string_buff2, string_buff3);

  /* Byte count */
  g_snprintf(string_buff, SUM_STR_MAX, "%" G_GINT64_MODIFIER "u", summary.bytes);
  if (summary.dfilter && summary.filtered_count > 0) {
    g_snprintf(string_buff2, SUM_STR_MAX, "%" G_GINT64_MODIFIER "u", summary.filtered_bytes);
  } else {
    string_buff2[0] = '\0';
  }
  if (summary.marked_count) {
    g_snprintf(string_buff3, SUM_STR_MAX, "%" G_GINT64_MODIFIER "u", summary.marked_bytes);
  } else {
    string_buff3[0] = '\0';
  }
  add_string_to_list(list, "Bytes", string_buff, string_buff2, string_buff3);

  /* Bytes per second */
  if (seconds > 0){
    /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
    g_snprintf(string_buff, SUM_STR_MAX, "%.3f", ((gint64) summary.bytes)/seconds);
  } else {
    string_buff[0] = '\0';
  }
  if (summary.dfilter && disp_seconds > 0) {
    /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
    g_snprintf(string_buff2, SUM_STR_MAX, "%.3f", ((gint64) summary.filtered_bytes)/disp_seconds);
  } else {
    string_buff2[0] = '\0';
  }
  if (summary.marked_count && marked_seconds > 0) {
    /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
    g_snprintf(string_buff3, SUM_STR_MAX, "%.3f", ((gint64) summary.marked_bytes)/marked_seconds);
  } else {
    string_buff3[0] = '\0';
  }
  add_string_to_list(list, "Avg. bytes/sec", string_buff, string_buff2, string_buff3);

  /* MBit per second */
  if (seconds > 0) {
    g_snprintf(string_buff, SUM_STR_MAX, "%.3f",
	       /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
	       ((gint64) summary.bytes) * 8.0 / (seconds * 1000.0 * 1000.0));
  } else {
    string_buff[0] = '\0';
  }
  if (summary.dfilter && disp_seconds > 0) {
    g_snprintf(string_buff2, SUM_STR_MAX, "%.3f",
	       /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
	       ((gint64) summary.filtered_bytes) * 8.0 / (disp_seconds * 1000.0 * 1000.0));
  } else {
    string_buff2[0] = '\0';
  }
  if (summary.marked_count && marked_seconds > 0) {
    g_snprintf(string_buff3, SUM_STR_MAX, "%.3f",
	       /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
	       ((gint64) summary.marked_bytes) * 8.0 / (marked_seconds * 1000.0 * 1000.0));
  } else {
    string_buff3[0] = '\0';
  }
  add_string_to_list(list, "Avg. MBit/sec", string_buff, string_buff2, string_buff3);


  /* Button row. */
  bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);

  close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
  window_set_cancel_button(sum_open_w, close_bt, window_cancel_button_cb);

  help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
  g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_SUMMARY_DIALOG);

  gtk_widget_grab_focus(close_bt);

  g_signal_connect(sum_open_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);

  gtk_widget_show_all(sum_open_w);
  window_present(sum_open_w);
}
