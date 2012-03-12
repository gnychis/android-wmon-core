/*
 * wslua_listener.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 *  Implementation of tap Listeners
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * $Id: wslua_listener.c 34602 2010-10-21 12:41:15Z morriss $
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

/* WSLUA_MODULE Listener Post-dissection packet analysis */

#include "wslua.h"

WSLUA_CLASS_DEFINE(Listener,NOP,NOP);
/*
    A Listener, is called once for every packet that matches a certain filter or has a certain tap.
    It can read the tree, the packet's Tvb eventually the tapped data but it cannot
    add elements to the tree.
 */

static int tap_packet_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    static gchar* last_error = NULL;
    static int repeated = 0;
    static int next = 2;
    const gchar* where =  (lua_pinfo) ?

    ep_strdup_printf("Lua: on packet %i Error During execution of Listener Packet Callback",lua_pinfo->fd->num) :
    ep_strdup_printf("Lua: Error During execution of Listener Packet Callback") ;

    /* show the error the 1st, 3rd, 5th, 9th, 17th, 33th... time it appears to avoid window flooding */
    /* XXX the last series of identical errors won't be shown (the user however gets at least one message) */

    if (! last_error) {
        report_failure("%s:\n%s",where,error);
        last_error = g_strdup(error);
        repeated = 0;
        next = 2;
        return 0;
    }

    if (g_str_equal(last_error,error) ) {
        repeated++;
        if ( repeated == next ) {
            report_failure("%s happened %i times:\n %s",where,repeated,error);
            next *= 2;
        }
    } else {
        report_failure("%s happened %i times:\n %s",where,repeated,last_error);
        g_free(last_error);
        last_error = g_strdup(error);
        repeated = 0;
        next = 2;
        report_failure("%s:\n %s",where,error);
    }

    return 0;
}


static int lua_tap_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data) {
    Listener tap = tapdata;
    int retval = 0;

    if (tap->packet_ref == LUA_NOREF) return 0;

    lua_settop(tap->L,0);

    lua_pushcfunction(tap->L,tap_packet_cb_error_handler);
    lua_rawgeti(tap->L, LUA_REGISTRYINDEX, tap->packet_ref);

    push_Pinfo(tap->L, pinfo);
    push_Tvb(tap->L, edt->tvb);

    if (tap->extractor) {
        tap->extractor(tap->L,data);
    } else {
        lua_pushnil(tap->L);
    }

    lua_pinfo = pinfo;
    lua_tvb = edt->tvb;
    lua_tree = g_malloc(sizeof(struct _wslua_treeitem));
    lua_tree->tree = edt->tree;
    lua_tree->item = NULL;
    lua_tree->expired = FALSE;

    switch ( lua_pcall(tap->L,3,1,1) ) {
        case 0:
            retval = luaL_optint(tap->L,-1,1);
            break;
        case LUA_ERRRUN:
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling listenet tap callback packet");
            break;
        default:
            g_assert_not_reached();
            break;
    }

    clear_outstanding_Pinfo();
    clear_outstanding_Tvb();

    lua_pinfo = NULL;
    lua_tvb = NULL;
    lua_tree = NULL;

    return retval;
}

static int tap_reset_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error During execution of Listener init Callback:\n %s",error);
    return 1;
}

static void lua_tap_reset(void *tapdata) {
    Listener tap = tapdata;

    if (tap->init_ref == LUA_NOREF) return;

    lua_pushcfunction(tap->L,tap_reset_cb_error_handler);
    lua_rawgeti(tap->L, LUA_REGISTRYINDEX, tap->init_ref);

    switch ( lua_pcall(tap->L,0,0,1) ) {
        case 0:
            break;
        case LUA_ERRRUN:
            g_warning("Runtime error while calling a listener's init()");
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling a listener's init()");
            break;
        default:
            g_assert_not_reached();
            break;
    }
}

static void lua_tap_draw(void *tapdata) {
    Listener tap = tapdata;
    const gchar* error;
    if (tap->draw_ref == LUA_NOREF) return;

    lua_pushcfunction(tap->L,tap_reset_cb_error_handler);
    lua_rawgeti(tap->L, LUA_REGISTRYINDEX, tap->draw_ref);

    switch ( lua_pcall(tap->L,0,0,1) ) {
        case 0:
            /* OK */
            break;
        case LUA_ERRRUN:
            error = lua_tostring(tap->L,-1);
            g_warning("Runtime error while calling a listener's draw(): %s",error);
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling a listener's draw()");
            break;
        default:
            g_assert_not_reached();
            break;
    }
}

WSLUA_CONSTRUCTOR Listener_new(lua_State* L) {
    /* Creates a new Listener listener */
#define WSLUA_OPTARG_Listener_new_TAP 1 /* The name of this tap */
#define WSLUA_OPTARG_Listener_new_FILTER 2 /* A filter that when matches the tap.packet function gets called (use nil to be called for every packet) */

    const gchar* tap_type = luaL_optstring(L,WSLUA_OPTARG_Listener_new_TAP,"frame");
    const gchar* filter = luaL_optstring(L,WSLUA_OPTARG_Listener_new_FILTER,NULL);
    Listener tap;
    GString* error;

    tap = g_malloc(sizeof(struct _wslua_tap));

    tap->name = g_strdup(tap_type);
    tap->filter = filter ? g_strdup(filter) : NULL;
    tap->extractor = wslua_get_tap_extractor(tap_type);
    tap->L = L;
    tap->packet_ref = LUA_NOREF;
    tap->draw_ref = LUA_NOREF;
    tap->init_ref = LUA_NOREF;

    /*
     * XXX - do all Lua taps require the protocol tree?  If not, it might
     * be useful to have a way to indicate whether any do.
     *
     * XXX - do any Lua taps require the columns?  If so, we either need
     * to request them for this tap, or do so if any Lua taps require them.
     */
    error = register_tap_listener(tap_type, tap, tap->filter, TL_REQUIRES_PROTO_TREE, lua_tap_reset, lua_tap_packet, lua_tap_draw);

    if (error) {
        g_free(tap->filter);
        g_free(tap->name);
        g_free(tap);
        /* WSLUA_ERROR(new_tap,"tap registration error"); */
        luaL_error(L,"Error while registering tap:\n%s",error->str);
        g_string_free(error,TRUE); /* XXX LEAK? */
    }

    pushListener(L,tap);
    WSLUA_RETURN(1); /* The newly created Listener listener object */
}

WSLUA_METHOD Listener_remove(lua_State* L) {
    /* Removes a tap listener */
    Listener tap = checkListener(L,1);

    if (!tap) return 0;

    remove_tap_listener(tap);

    return 0;
}

WSLUA_METAMETHOD Listener_tostring(lua_State* L) {
    Listener tap = checkListener(L,1);
    gchar* str;

    if (!tap) return 0;

    str = ep_strdup_printf("Listener(%s) filter: %s",tap->name, tap->filter ? tap->filter : "NONE");
    lua_pushstring(L,str);

    return 1;
}


static int Listener_newindex(lua_State* L) {
    /* WSLUA_ATTRIBUTE Listener_packet WO A function that will be called once every packet matches the Listener listener filter.

        function tap.packet(pinfo,tvb,userdata) ... end
    */
    /* WSLUA_ATTRIBUTE Listener_draw WO A function that will be called once every few seconds to redraw the gui objects
                in tshark this funtion is called oly at the very end of the capture file.

        function tap.draw(userdata) ... end
    */
    /* WSLUA_ATTRIBUTE Listener_reset WO A function that will be called at the end of the capture run.

        function tap.reset(userdata) ... end
    */
    Listener tap = shiftListener(L,1);
    const gchar* idx = lua_shiftstring(L,1);
    int* refp = NULL;

    if (!idx) return 0;

    if (g_str_equal(idx,"packet")) {
        refp = &(tap->packet_ref);
    } else if (g_str_equal(idx,"draw")) {
        refp = &(tap->draw_ref);
    } else if (g_str_equal(idx,"reset")) {
        refp = &(tap->init_ref);
    } else {
        luaL_error(L,"No such attribute `%s' for a tap",idx);
        return 0;
    }

    if (! lua_isfunction(L,1)) {
        luaL_error(L,"Listener's attribute `%s' must be a function");
        return 0;
    }

    lua_pushvalue(L, 1);
    *refp = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}


static const luaL_reg Listener_methods[] = {
    {"new", Listener_new},
    {"remove", Listener_remove},
    { NULL, NULL }
};

static const luaL_reg Listener_meta[] = {
    {"__tostring", Listener_tostring},
    {"__newindex", Listener_newindex},
    { NULL, NULL }
};

int Listener_register(lua_State* L) {
    wslua_set_tap_enums(L);
    WSLUA_REGISTER_CLASS(Listener);
    return 1;
}

