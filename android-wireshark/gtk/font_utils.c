/* font_utils.c
 * Utilities to use for font manipulation
 *
 * $Id: font_utils.c 36161 2011-03-08 01:52:25Z sake $
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
#include <stdlib.h>
#include <stdio.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <wsutil/unicode-utils.h>
#endif

#include "../simple_dialog.h"

#include "gtk/main.h"
#include "gtk/recent.h"
#include "gtk/gtkglobals.h"
#include "gtk/font_utils.h"
#include "gtk/main_proto_draw.h"
#include "gtk/follow_tcp.h"
#include "gtk/new_packet_list.h"


static PangoFontDescription *m_r_font, *m_b_font;


/* Get the regular user font.
 *
 * @return the regular user font
 */
PangoFontDescription *user_font_get_regular(void)
{
    return m_r_font;
}

/* Get the bold user font.
 *
 * @return the bold user font
 */
PangoFontDescription *user_font_get_bold(void)
{
    return m_b_font;
}

static void
set_fonts(PangoFontDescription *regular, PangoFontDescription *bold)
{
    /* Yes, assert. The code that loads the font should check
     * for NULL and provide its own error message. */
    g_assert(m_r_font && m_b_font);
    m_r_font = regular;
    m_b_font = bold;
}

void
view_zoom_in_cb(GtkWidget *w _U_, gpointer d _U_)
{
    gint save_gui_zoom_level;

    save_gui_zoom_level = recent.gui_zoom_level;
    recent.gui_zoom_level++;
    switch (user_font_apply()) {

    case FA_SUCCESS:
        break;

    case FA_FONT_NOT_RESIZEABLE:
        /* "font_apply()" popped up an alert box. */
        recent.gui_zoom_level = save_gui_zoom_level;    /* undo zoom */
        break;

    case FA_FONT_NOT_AVAILABLE:
        /* We assume this means that the specified size isn't available. */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Your current font isn't available in the next larger size.\n");
        recent.gui_zoom_level = save_gui_zoom_level;    /* undo zoom */
        break;
    }
}

void
view_zoom_out_cb(GtkWidget *w _U_, gpointer d _U_)
{
    gint save_gui_zoom_level;

    save_gui_zoom_level = recent.gui_zoom_level;
    recent.gui_zoom_level--;
    switch (user_font_apply()) {

    case FA_SUCCESS:
        break;

    case FA_FONT_NOT_RESIZEABLE:
        /* "font_apply()" popped up an alert box. */
        recent.gui_zoom_level = save_gui_zoom_level;    /* undo zoom */
        break;

    case FA_FONT_NOT_AVAILABLE:
        /* We assume this means that the specified size isn't available. */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Your current font isn't available in the next smaller size.\n");
        recent.gui_zoom_level = save_gui_zoom_level;    /* undo zoom */
        break;
    }
}

void
view_zoom_100_cb(GtkWidget *w _U_, gpointer d _U_)
{
    gint save_gui_zoom_level;

    save_gui_zoom_level = recent.gui_zoom_level;
    recent.gui_zoom_level = 0;
    switch (user_font_apply()) {

    case FA_SUCCESS:
        break;

    case FA_FONT_NOT_RESIZEABLE:
        /* "font_apply()" popped up an alert box. */
        recent.gui_zoom_level = save_gui_zoom_level;    /* undo zoom */
        break;

    case FA_FONT_NOT_AVAILABLE:
        /* We assume this means that the specified size isn't available.
           XXX - this "shouldn't happen". */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Your current font couldn't be reloaded at the size you selected.\n");
        recent.gui_zoom_level = save_gui_zoom_level;    /* undo zoom */
        break;
    }
}



gboolean
user_font_test(gchar *font_name)
{
    PangoFontDescription *new_r_font, *new_b_font;

    new_r_font = pango_font_description_from_string(font_name);
    if (new_r_font == NULL) {
        /* Oops, that font didn't work.
           Tell the user, but don't tear down the font selection
           dialog, so that they can try again. */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "The font you selected can't be loaded.");

        return FALSE;
    }

    new_b_font = pango_font_description_copy(new_r_font);
    pango_font_description_set_weight(new_b_font, PANGO_WEIGHT_BOLD);
    if (new_b_font == NULL) {
        /* Oops, that font didn't work.
           Tell the user, but don't tear down the font selection
           dialog, so that they can try again. */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "The font you selected doesn't have a boldface version.");

        pango_font_description_free(new_r_font);
        return FALSE;
    }

    return TRUE;
}



/* Given a font name, construct the name of a version of that font with
   the current zoom factor applied. */
static char *
font_zoom(char *gui_font_name)
{
    char *new_font_name;
    char *font_name_dup;
    char *font_name_p;
    long font_point_size_l;

    if (recent.gui_zoom_level == 0) {
        /* There is no zoom factor - just return the name, so that if
           this is GTK+ 1.2[.x] and the font name isn't an XLFD font
           name, we don't fail. */
        return g_strdup(gui_font_name);
    }

    font_name_dup = g_strdup(gui_font_name);

    /* find the start of the font_size string */
    font_name_p = strrchr(font_name_dup, ' ');
    *font_name_p = '\0';
    font_name_p++;

    /* calculate the new font size */
    font_point_size_l = strtol(font_name_p, NULL, 10);
    font_point_size_l += recent.gui_zoom_level;

    /* build a new font name */
    new_font_name = g_strdup_printf("%s %ld", font_name_dup, font_point_size_l);

    g_free(font_name_dup);

    return new_font_name;
}

fa_ret_t
user_font_apply(void) {
    char *gui_font_name;
    PangoFontDescription *new_r_font, *new_b_font;
    PangoFontDescription *old_r_font = NULL, *old_b_font = NULL;

    /* convert font name to reflect the zoom level */
    gui_font_name = font_zoom(prefs.gui_font_name);
    if (gui_font_name == NULL) {
        /*
         * This means the font name isn't an XLFD font name.
         * We just report that for now as a font not available in
         * multiple sizes.
         */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Your current font isn't available in any other sizes.\n");
        return FA_FONT_NOT_RESIZEABLE;
    }

    /* load normal and bold font */
    new_r_font = pango_font_description_from_string(gui_font_name);
    new_b_font = pango_font_description_copy(new_r_font);
    pango_font_description_set_weight(new_b_font, PANGO_WEIGHT_BOLD);

    if (new_r_font == NULL || new_b_font == NULL) {
        /* We're no longer using the new fonts; unreference them. */
        if (new_r_font != NULL)
            pango_font_description_free(new_r_font);
        if (new_b_font != NULL)
            pango_font_description_free(new_b_font);
        g_free(gui_font_name);

        /* We let our caller pop up a dialog box, as the error message
           depends on the context (did they zoom in or out, or did they
           do something else? */
        return FA_FONT_NOT_AVAILABLE;
    }

    /* the font(s) seem to be ok */
    new_packet_list_set_font(new_r_font);
    set_ptree_font_all(new_r_font);
    old_r_font = m_r_font;
    old_b_font = m_b_font;
    set_fonts(new_r_font, new_b_font);

    /* Redraw the packet bytes windows. */
    redraw_packet_bytes_all();

    /* Redraw the "Follow TCP Stream" windows. */
    follow_tcp_redraw_all();

    /* We're no longer using the old fonts; unreference them. */
    if (old_r_font != NULL)
        pango_font_description_free(old_r_font);
    if (old_b_font != NULL)
        pango_font_description_free(old_b_font);
    g_free(gui_font_name);

    return FA_SUCCESS;
}


#ifdef _WIN32

#define NAME_BUFFER_LEN 32

static char appfontname[128] = "tahoma 8";

static void
set_app_font_gtk2(const char *fontname)
{
    GtkSettings *settings;

    if (fontname != NULL && *fontname == 0) return;

    settings = gtk_settings_get_default();

    if (fontname == NULL) {
        g_object_set(G_OBJECT(settings), "gtk-font-name", appfontname, NULL);
    } else {
        GtkWidget *w;
        PangoFontDescription *pfd;
        PangoContext *pc;
        PangoFont *pfont;

        w = gtk_label_new(NULL);
        pfd = pango_font_description_from_string(fontname);
        pc = gtk_widget_get_pango_context(w);
        pfont = pango_context_load_font(pc, pfd);

        if (pfont != NULL) {
            g_strlcpy(appfontname, fontname, 128);
            appfontname[127] = '\0';
            g_object_set(G_OBJECT(settings), "gtk-font-name", appfontname, NULL);
        }

        gtk_widget_destroy(w);
        pango_font_description_free(pfd);
    }
}

static char *default_windows_menu_fontspec_gtk2(void)
{
    gchar *fontspec = NULL;
    NONCLIENTMETRICS ncm;

    memset(&ncm, 0, sizeof ncm);
    ncm.cbSize = sizeof ncm;

    if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, ncm.cbSize, &ncm, 0)) {
        HDC screen = GetDC(0);
        double y_scale = 72.0 / GetDeviceCaps(screen, LOGPIXELSY);
        int point_size = (int) (ncm.lfMenuFont.lfHeight * y_scale);

        if (point_size < 0) point_size = -point_size;
        fontspec = g_strdup_printf("%s %d", ncm.lfMenuFont.lfFaceName,
                                   point_size);
        ReleaseDC(0, screen);
    }

    return fontspec;
}

static void try_to_get_windows_font_gtk2(void)
{
    gchar *fontspec;

    fontspec = default_windows_menu_fontspec_gtk2();

    if (fontspec != NULL) {
        int match = 0;
        PangoFontDescription *pfd;
        PangoFont *pfont;
        PangoContext *pc;
        GtkWidget *w;

        pfd = pango_font_description_from_string(fontspec);

        w = gtk_label_new(NULL);
        pc = gtk_widget_get_pango_context(w);
        pfont = pango_context_load_font(pc, pfd);
        match = (pfont != NULL);

        pango_font_description_free(pfd);
        g_object_unref(G_OBJECT(pc));
        gtk_widget_destroy(w);

        if (match) set_app_font_gtk2(fontspec);
        g_free(fontspec);
    }
}
#endif /* _WIN32 */


void font_init(void)
{
#ifdef _WIN32
    /* try to load the application font for GTK2 */
    try_to_get_windows_font_gtk2();
#endif

    /* Try to load the regular and boldface fixed-width fonts */
    m_r_font = pango_font_description_from_string(prefs.gui_font_name);
    m_b_font = pango_font_description_copy(m_r_font);
    pango_font_description_set_weight(m_b_font, PANGO_WEIGHT_BOLD);
    if (m_r_font == NULL || m_b_font == NULL) {
        /* XXX - pop this up as a dialog box? no */
        if (m_r_font == NULL) {
            fprintf(stderr, "wireshark: Warning: font %s not found - defaulting to Monospace 9\n",
                    prefs.gui_font_name);
        } else {
            pango_font_description_free(m_r_font);
        }
        if (m_b_font == NULL) {
            fprintf(stderr, "wireshark: Warning: bold font %s not found - defaulting"
                    " to Monospace 9\n", prefs.gui_font_name);
        } else {
            pango_font_description_free(m_b_font);
        }
        if ((m_r_font = pango_font_description_from_string("Monospace 9")) == NULL)
        {
            fprintf(stderr, "wireshark: Error: font Monospace 9 not found\n");
            exit(1);
        }
        if ((m_b_font = pango_font_description_copy(m_r_font)) == NULL) {
            fprintf(stderr, "wireshark: Error: font Monospace 9 bold not found\n");
            exit(1);
        }
        g_free(prefs.gui_font_name);
        pango_font_description_set_weight(m_b_font, PANGO_WEIGHT_BOLD);
        prefs.gui_font_name = g_strdup("Monospace 9");
    }

    /* Call this for the side-effects that set_fonts() produces */
    set_fonts(m_r_font, m_b_font);
}
