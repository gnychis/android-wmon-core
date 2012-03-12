/* easy_codec_plugin.c
* Easy codecs plugin registration file
* 2007 Tomas Kukosa
*
* $Id: easy_codec_plugin.c 27401 2009-02-09 12:54:40Z kukosa $
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
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef ENABLE_STATIC
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gmodule.h>
#include <epan/codecs.h>

#include "codec-g7231.h"
#include "codec-g729a.h"
#include "codec-g722.h"

G_MODULE_EXPORT const gchar version[] = "0.0.1";

G_MODULE_EXPORT void register_codec_module(void)
{
  register_codec("g723", codec_g7231_init, codec_g7231_release, codec_g7231_decode);
  register_codec("g729", codec_g729a_init, codec_g729a_release, codec_g729a_decode);
  register_codec("g722", codec_g722_init, codec_g722_release, codec_g722_decode);
}

#endif
