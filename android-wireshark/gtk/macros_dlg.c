/* macros_dlg.c
 *
 * $Id: macros_dlg.c 34030 2010-08-31 07:53:51Z stig $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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
#include <stdlib.h>

#include <gtk/gtk.h>

#include <epan/dfilter/dfilter-macro.h>
#include <epan/uat-int.h>

#include "globals.h"
#include "gtk/uat_gui.h"
#include "gtk/macros_dlg.h"
#include "gtk/gtkglobals.h"

void macros_post_update(void) {
	g_free (cfile.dfilter);
	cfile.dfilter = NULL;
	g_signal_emit_by_name(main_display_filter_widget, "changed");
}

void macros_init (void) {
	void* dfmuat;
	dfilter_macro_get_uat(&dfmuat);
	((uat_t*)dfmuat)->post_update_cb = macros_post_update;
}

void macros_dialog_cb(GtkWidget *w _U_, gpointer data _U_) {
	void* dfmuat;
	dfilter_macro_get_uat(&dfmuat);
	uat_window_cb(NULL,dfmuat);
}

