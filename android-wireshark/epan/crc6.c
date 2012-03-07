/*
 *  crc6.c
 *  
 * $Id: crc6.c 22348 2007-07-18 08:25:09Z lego $
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include "crc6.h"


guint16 update_crc6_by_bytes(guint16 crc6, guint8 byte1, guint8 byte2) {
    int bit;
    guint32 remainder = ( byte1<<8 | byte2 ) << 6;
    guint32 polynomial = 0x6F << 15;
	
    for (bit = 15;
		 bit >= 0;
		 --bit)
    {
        if (remainder & (0x40 << bit))
        {
            remainder ^= polynomial;
        }
        polynomial >>= 1;
    }
	
    return (guint16)(remainder ^ crc6);
}


