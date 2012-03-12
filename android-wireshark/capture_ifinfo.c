/* capture_ifinfo.c
 * Routines for getting interface information from dumpcap
 *
 * $Id: capture_ifinfo.c 33012 2010-05-28 20:19:55Z morriss $
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

#ifdef HAVE_LIBPCAP

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>         /* needed to define AF_ values on UNIX */
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>           /* needed to define AF_ values on Windows */
#endif

#ifdef NEED_INET_V6DEFS_H
# include "wsutil/inet_v6defs.h"
#endif

#include <glib.h>

#include "capture_opts.h"
#include "capture_sync.h"
#include "log.h"

#include "capture_ifinfo.h"

/**
 * Fetch the interface list from a child process (dumpcap).
 *
 * @return A GList containing if_info_t structs if successful, NULL (with err and possibly err_str set) otherwise.
 *
 */

/* XXX - We parse simple text output to get our interface list.  Should
 * we use "real" data serialization instead, e.g. via XML? */
GList *
capture_interface_list(int *err, char **err_str)
{
    int        ret;
    GList     *if_list = NULL;
    int        i, j;
    gchar     *data, *primary_msg, *secondary_msg;
    gchar    **raw_list, **if_parts, **addr_parts;
    gchar     *name;
    if_info_t *if_info;
    if_addr_t *if_addr;

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Interface List ...");

    /* Try to get our interface list */
    ret = sync_interface_list_open(&data, &primary_msg, &secondary_msg);
    if (ret != 0) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Interface List failed!");
        if (err_str) {
            *err_str = primary_msg;
        } else {
            g_free(primary_msg);
        }
        g_free(secondary_msg);
        *err = CANT_GET_INTERFACE_LIST;
        return NULL;
    }

    /* Split our lines */
#ifdef _WIN32
    raw_list = g_strsplit(data, "\r\n", 0);
#else
    raw_list = g_strsplit(data, "\n", 0);
#endif
    g_free(data);

    for (i = 0; raw_list[i] != NULL; i++) {
        if_parts = g_strsplit(raw_list[i], "\t", 4);
        if (if_parts[0] == NULL || if_parts[1] == NULL || if_parts[2] == NULL ||
                if_parts[3] == NULL) {
            g_strfreev(if_parts);
            continue;
        }

        /* Number followed by the name, e.g "1. eth0" */
        name = strchr(if_parts[0], ' ');
        if (name) {
            name++;
        } else {
            g_strfreev(if_parts);
            continue;
        }

        if_info = g_malloc0(sizeof(if_info_t));
        if_info->name = g_strdup(name);
        if (strlen(if_parts[1]) > 0)
            if_info->description = g_strdup(if_parts[1]);
        addr_parts = g_strsplit(if_parts[2], ",", 0);
        for (j = 0; addr_parts[j] != NULL; j++) {
            if_addr = g_malloc0(sizeof(if_addr_t));
            if (inet_pton(AF_INET, addr_parts[j], &if_addr->addr.ip4_addr)) {
                if_addr->ifat_type = IF_AT_IPv4;
            } else if (inet_pton(AF_INET6, addr_parts[j],
                    &if_addr->addr.ip6_addr)) {
                if_addr->ifat_type = IF_AT_IPv6;
            } else {
                g_free(if_addr);
                if_addr = NULL;
            }
            if (if_addr) {
                if_info->addrs = g_slist_append(if_info->addrs, if_addr);
            }
        }
        if (strcmp(if_parts[3], "loopback") == 0)
            if_info->loopback = TRUE;
        g_strfreev(if_parts);
        g_strfreev(addr_parts);
        if_list = g_list_append(if_list, if_info);
    }
    g_strfreev(raw_list);

    /* Check to see if we built a list */
    if (if_list == NULL) {
        *err = NO_INTERFACES_FOUND;
        if (err_str)
            *err_str = g_strdup("No interfaces found");
    }
    return if_list;
}

/* XXX - We parse simple text output to get our interface list.  Should
 * we use "real" data serialization instead, e.g. via XML? */
if_capabilities_t *
capture_get_if_capabilities(const gchar *ifname, gboolean monitor_mode,
                            char **err_str)
{
    if_capabilities_t *caps;
    GList              *linktype_list = NULL;
    int                 err, i;
    gchar              *data, *primary_msg, *secondary_msg;
    gchar             **raw_list, **lt_parts;
    data_link_info_t   *data_link_info;

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Interface Capabilities ...");

    /* Try to get our interface list */
    err = sync_if_capabilities_open(ifname, monitor_mode, &data,
                                    &primary_msg, &secondary_msg);
    if (err != 0) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Interface Capabilities failed!");
        if (err_str) {
            *err_str = primary_msg;
        } else {
            g_free(primary_msg);
        }
        g_free(secondary_msg);
        return NULL;
    }

    /* Split our lines */
#ifdef _WIN32
    raw_list = g_strsplit(data, "\r\n", 0);
#else
    raw_list = g_strsplit(data, "\n", 0);
#endif
    g_free(data);

    /*
     * First line is 0 if monitor mode isn't supported, 1 if it is.
     */
    if (raw_list[0] == NULL || *raw_list[0] == '\0') {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Interface Capabilities returned no information!");
        if (err_str) {
            *err_str = g_strdup("Dumpcap returned no interface capability information");
        }
        return NULL;
    }

    /*
     * Allocate the interface capabilities structure.
     */
    caps = g_malloc(sizeof *caps);
    switch (*raw_list[0]) {

    case '0':
        caps->can_set_rfmon = FALSE;
        break;

    case '1':
        caps->can_set_rfmon = TRUE;
        break;

    default:
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Interface Capabilities returned bad information!");
        if (err_str) {
            *err_str = g_strdup_printf("Dumpcap returned \"%s\" for monitor-mode capability",
                                       raw_list[0]);
        }
        g_free(caps);
        return NULL;
    }

    /*
     * The rest are link-layer types.
     */
    for (i = 1; raw_list[i] != NULL; i++) {
        /* ...and what if the interface name has a tab in it, Mr. Clever Programmer? */
        lt_parts = g_strsplit(raw_list[i], "\t", 3);
        if (lt_parts[0] == NULL || lt_parts[1] == NULL || lt_parts[2] == NULL) {
            g_strfreev(lt_parts);
            continue;
        }

        data_link_info = g_malloc(sizeof (data_link_info_t));
        data_link_info->dlt = (int) strtol(lt_parts[0], NULL, 10);
        data_link_info->name = g_strdup(lt_parts[1]);
        if (strcmp(lt_parts[2], "(not supported)") != 0)
            data_link_info->description = g_strdup(lt_parts[2]);
        else
            data_link_info->description = NULL;

        linktype_list = g_list_append(linktype_list, data_link_info);
    }
    g_strfreev(raw_list);

    /* Check to see if we built a list */
    if (linktype_list == NULL) {
        /* No. */
        if (err_str)
            *err_str = g_strdup("Dumpcap returned no link-layer types");
        g_free(caps);
        return NULL;
    }
    caps->data_link_types = linktype_list;
    return caps;
}

#endif /* HAVE_LIBPCAP */
