/* tpg.c
 * helper functions for TPG
 *
 *  (c) 2005, Luis E. Garcia Ontanon <luis@ontanon.org>
 * 
 * $Id: tpg.c 25937 2008-08-05 21:03:46Z lego $
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

#include "tpg.h"
#include <epan/emem.h>
#include <epan/packet.h>

extern guint32 tpg_ipv4(tvbparse_elem_t* e _U_) {    
    /* XXX TO DO */
    return 0;
}

extern guint8* tpg_ipv6(tvbparse_elem_t* e _U_) {
    /* XXX TO DO */
    return NULL;
}

extern tpg_parser_data_t* tpg_start(proto_tree* root_tree,
                                    tvbuff_t* tvb,
                                    int offset,
                                    int len,
                                    tvbparse_wanted_t* ignore,
                                    void* private_data) {
    tpg_parser_data_t* tpg = ep_alloc(sizeof(tpg_parser_data_t));
    tpg->private_data = private_data;
    tpg->tt = tvbparse_init(tvb,offset,len,tpg,ignore);

    tpg->stack = ep_stack_new();
    ep_stack_push(tpg->stack,root_tree);
    
    return tpg;
}

