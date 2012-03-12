/* packet-hilscher.c
 * Dissector for Hilscher analyzer protocols.
 * Copyright 2008, Hilscher GmbH, Holger Pfrommer hpfrommer[AT]hilscher.com
 *
 * $Id: packet-hilscher.c 36587 2011-04-12 15:49:29Z wmeier $
 *
 * This is a new dissector plugin for Hilscher analyzer frames.
 * These frames are generated by Hilscher analyzer products and are identified via
 * their unique source MAC address (this is a reserved MAC from Hilscher-range and
 * will never be used by another network device). Most likely these frames are
 * only generated on a virtual network interface or the generating device is
 * attached directly via patch cable to a real network interface, but not routed
 * through a network. The Ethernet-header (destination MAC, source MAC and
 * Length/Type) is not displayed in the protocol tree for these frames as this is
 * overhead-information which has no practical use in this case.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
 * Copyright 1999 Gerald Combs
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
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>


static int  proto_hilscher              = -1;
static module_t *hilscher_module;

/*  Ethernet heuristic dissectors (such as this one) get called for
 *  every Ethernet frame Wireshark handles.  In order to not impose that
 *  performance penalty on everyone this dissector disables itself by
 *  default.
 *
 *  This is done separately from the disabled protocols list mainly so
 *  we can disable it by default.  XXX Maybe there's a better way.
 */
static gboolean  hilscher_enable_dissector = FALSE;

void proto_reg_handoff_hilscher(void);

static gint ett_information_type        = -1;
static gint ett_gpio_number             = -1;
static gint ett_gpio_edge               = -1;

static int  hf_information_type         = -1;
static int  hf_gpio_number              = -1;
static int  hf_gpio_edge                = -1;

#define  INFO_TYPE_OFFSET    14

static const value_string information_type[] = {
    { 0x0, "netANALYZER GPIO event" },
    { 0,   NULL }
};

static const value_string gpio_number[] = {
    { 0x0, "GPIO 0" },
    { 0x1, "GPIO 1" },
    { 0x2, "GPIO 2" },
    { 0x3, "GPIO 3" },
    { 0,   NULL }
};

static const value_string gpio_edge[] = {
    { 0x0, "rising edge" },
    { 0x1, "falling edge" },
    { 0,   NULL }
};

/* netANAYLZER dissector */
static void
dissect_hilscher_netanalyzer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint               gpio_num;
    guint               gpio_edgex;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "netANALYZER");

    if (tree)
        proto_tree_add_item(tree, hf_information_type, tvb, offset, 1, FALSE);

    /* GPIO NUMBER */
    offset++;
    if (tree)
        proto_tree_add_item (tree, hf_gpio_number, tvb, offset, 1, FALSE);
    gpio_num = (tvb_get_guint8(tvb, offset) & 0x03);

    /* GPIO EDGE */
    offset++;
    if (tree)
        proto_tree_add_item (tree, hf_gpio_edge, tvb, offset, 1, FALSE);
    gpio_edgex = (tvb_get_guint8(tvb, offset) & 0x01);

    if (gpio_edgex == 0x00)
        col_add_fstr(pinfo->cinfo, COL_INFO, "netANALYZER event on GPIO %d (rising edge)", gpio_num);
    else
        col_add_fstr(pinfo->cinfo, COL_INFO, "netANALYZER event on GPIO %d (falling edge)", gpio_num);
}


/* General Hilscher analyzer dissector */
static gboolean
dissect_hilscher_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       info_type;
    gint        offset;

    /* Check that there's enough data */
    if (tvb_length(tvb) < 14)
        return FALSE;

    /* check for Hilscher frame, this has a unique source MAC from Hilscher range and ethertype 0x88ff
       First 14 bytes must be: xx xx xx xx xx xx 00 02 a2 ff ff ff 88 ff */
    if ((tvb_get_guint8(tvb, 6) == 0x00) &&
        (tvb_get_guint8(tvb, 7) == 0x02) &&
        (tvb_get_guint8(tvb, 8) == 0xa2) &&
        (tvb_get_guint8(tvb, 9) == 0xff) &&
        (tvb_get_guint8(tvb, 10) == 0xff) &&
        (tvb_get_guint8(tvb, 11) == 0xff) &&
        (tvb_get_guint8(tvb, 12) == 0x88) &&
        (tvb_get_guint8(tvb, 13) == 0xff) )
    {

        /* determine type of analyzer */
        offset = INFO_TYPE_OFFSET;
        info_type = tvb_get_guint8(tvb, offset);

        switch (info_type)
        {
            /* this is a netANALYZER frame */
        case 0x00:
            dissect_hilscher_netanalyzer(tvb, pinfo, tree, offset);
            break;

            /* this is no Hilscher analyzer frame */
        default:
            return FALSE;
            break;
        }

    }
    else
    {
        /* this is no Hilscher analyzer frame */
        return FALSE;
    }

    return TRUE;
}



void proto_register_hilscher(void)
{
    static hf_register_info hf[] = {
        { &hf_information_type,
          { "Hilscher information block type", "hilscher.information_type",
            FT_UINT8, BASE_HEX, VALS(information_type), 0x0, NULL, HFILL }
        },
        { &hf_gpio_number,
          { "Event on", "hilscher.net_analyzer.gpio_number", FT_UINT8,
            BASE_HEX, VALS(gpio_number), 0x0, NULL, HFILL }
        },
        { &hf_gpio_edge,
                { "Event type", "hilscher.net_analyzer.gpio_edge", FT_UINT8,
                  BASE_HEX, VALS(gpio_edge), 0x0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_information_type,
        &ett_gpio_number,
        &ett_gpio_edge,
    };

    proto_hilscher = proto_register_protocol ("Hilscher analyzer dissector",    /* name */
                                              "Hilscher",               /* short name */
                                              "hilscher");              /* abbrev */

    hilscher_module = prefs_register_protocol(proto_hilscher, proto_reg_handoff_hilscher);

    prefs_register_bool_preference(hilscher_module, "enable", "Enable dissector",
                                   "Enable this dissector (default is false)",
                                   &hilscher_enable_dissector);

    proto_register_field_array(proto_hilscher, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}

void proto_reg_handoff_hilscher(void)
{
    static gboolean prefs_initialized = FALSE;

    if (!prefs_initialized) {
        /* add heuristic dissector */
        heur_dissector_add("eth", dissect_hilscher_heur, proto_hilscher);
        prefs_initialized = TRUE;
    }

    proto_set_decoding(proto_hilscher, hilscher_enable_dissector);
}
