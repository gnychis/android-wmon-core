/* packet-q932-ros.c
 * Routines for Q.932 packet dissection
 * 2007  Tomas Kukosa
 *
 * $Id: packet-q932-ros-template.c 32417 2010-04-07 16:54:29Z wmeier $
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

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-ber.h"

#define PNAME  "Q.932 Operations Service Element"
#define PSNAME "Q932.ROS"
#define PFNAME "q932.ros"

/* Initialize the protocol and registered fields */
static int proto_q932_ros = -1;
#include "packet-q932-ros-hf.c" 

/* Initialize the subtree pointers */
#include "packet-q932-ros-ett.c" 

/* Preferences */

/* Subdissectors */
static dissector_handle_t data_handle = NULL; 

/* Gloabl variables */
static rose_ctx_t *rose_ctx_tmp;

static guint32 problem_val;
static gchar problem_str[64];
static tvbuff_t *arg_next_tvb, *res_next_tvb, *err_next_tvb;


#include "packet-q932-ros-fn.c" 

/*--- dissect_q932_ros -----------------------------------------------------*/
static int dissect_q932_ros(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  rose_ctx_tmp = get_rose_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(rose_ctx_tmp);
  return dissect_ROS_PDU(tvb, pinfo, tree);
}

/*--- proto_register_q932_ros -----------------------------------------------*/
void proto_register_q932_ros(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-q932-ros-hfarr.c" 
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-q932-ros-ettarr.c" 
  };

  /* Register protocol and dissector */
  proto_q932_ros = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_set_cant_toggle(proto_q932_ros);

  /* Register fields and subtrees */
  proto_register_field_array(proto_q932_ros, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  new_register_dissector(PFNAME, dissect_q932_ros, proto_q932_ros);
}

/*--- proto_reg_handoff_q932_ros --------------------------------------------*/
void proto_reg_handoff_q932_ros(void) {
  data_handle = find_dissector("data");
}

/*---------------------------------------------------------------------------*/
