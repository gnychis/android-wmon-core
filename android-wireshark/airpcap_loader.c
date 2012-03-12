/* airpcap_loader.c
 *
 * $Id: airpcap_loader.c 33924 2010-08-25 20:30:59Z gerald $
 *
 * Giorgio Tino <giorgio.tino@cacetech.com>
 * Copyright (c) CACE Technologies, LLC 2006
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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

#ifdef HAVE_AIRPCAP

#ifdef HAVE_LIBPCAP
#include <glib.h>
#include <gmodule.h>


#include <wtap.h>
#include <pcap.h>
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/crypt/wep-wpadefs.h>
#include <epan/crypt/airpdcap_ws.h>
#include <epan/strutil.h>
#include <epan/frequency-utils.h>
#include "capture_ui_utils.h"
#include <wsutil/file_util.h>

#include "simple_dialog.h"

#include <airpcap.h>
#include "airpcap_loader.h"


/*
 * Set to TRUE if the DLL was successfully loaded AND all functions
 * are present.
 */
static gboolean AirpcapLoaded = FALSE;

#ifdef _WIN32
/*
 * We load dynamically the dag library in order link it only when
 * it's present on the system
 */
static void * AirpcapLib = NULL;

static AirpcapGetLastErrorHandler g_PAirpcapGetLastError;
static AirpcapSetKernelBufferHandler g_PAirpcapSetKernelBuffer;
static AirpcapSetFilterHandler g_PAirpcapSetFilter;
static AirpcapGetMacAddressHandler g_PAirpcapGetMacAddress;
static AirpcapSetMinToCopyHandler g_PAirpcapSetMinToCopy;
static AirpcapGetReadEventHandler g_PAirpcapGetReadEvent;
static AirpcapReadHandler g_PAirpcapRead;
static AirpcapGetStatsHandler g_PAirpcapGetStats;
#endif

static int AirpcapVersion = 3;

static AirpcapGetDeviceListHandler g_PAirpcapGetDeviceList;
static AirpcapFreeDeviceListHandler g_PAirpcapFreeDeviceList;
static AirpcapOpenHandler g_PAirpcapOpen;
static AirpcapCloseHandler g_PAirpcapClose;
static AirpcapGetLinkTypeHandler g_PAirpcapGetLinkType;
static AirpcapSetLinkTypeHandler g_PAirpcapSetLinkType;
static AirpcapTurnLedOnHandler g_PAirpcapTurnLedOn;
static AirpcapTurnLedOffHandler g_PAirpcapTurnLedOff;
static AirpcapGetDeviceChannelHandler g_PAirpcapGetDeviceChannel;
static AirpcapSetDeviceChannelHandler g_PAirpcapSetDeviceChannel;
static AirpcapGetFcsPresenceHandler g_PAirpcapGetFcsPresence;
static AirpcapSetFcsPresenceHandler g_PAirpcapSetFcsPresence;
static AirpcapGetFcsValidationHandler g_PAirpcapGetFcsValidation;
static AirpcapSetFcsValidationHandler g_PAirpcapSetFcsValidation;
static AirpcapGetDeviceKeysHandler g_PAirpcapGetDeviceKeys;
static AirpcapSetDeviceKeysHandler g_PAirpcapSetDeviceKeys;
static AirpcapGetDriverKeysHandler g_PAirpcapGetDriverKeys;
static AirpcapSetDriverKeysHandler g_PAirpcapSetDriverKeys;
static AirpcapGetDecryptionStateHandler g_PAirpcapGetDecryptionState;
static AirpcapSetDecryptionStateHandler g_PAirpcapSetDecryptionState;
static AirpcapGetDriverDecryptionStateHandler g_PAirpcapGetDriverDecryptionState;
static AirpcapSetDriverDecryptionStateHandler g_PAirpcapSetDriverDecryptionState;
static AirpcapStoreCurConfigAsAdapterDefaultHandler g_PAirpcapStoreCurConfigAsAdapterDefault;
static AirpcapGetVersionHandler g_PAirpcapGetVersion;
static AirpcapSetDeviceChannelExHandler g_PAirpcapSetDeviceChannelEx;
static AirpcapGetDeviceChannelExHandler g_PAirpcapGetDeviceChannelEx;
static AirpcapGetDeviceSupportedChannelsHandler g_PAirpcapGetDeviceSupportedChannels;

/* Airpcap interface list */
GList *airpcap_if_list = NULL;

/* Airpcap current selected interface */
airpcap_if_info_t *airpcap_if_selected = NULL;

/* Airpcap current active interface */
airpcap_if_info_t *airpcap_if_active = NULL;

/* WLAN preferences pointer */
module_t *wlan_prefs = NULL;

Dot11Channel *pSupportedChannels;
guint numSupportedChannels;

static AirpcapChannelInfo LegacyChannels[] =
{
	{2412, 0, {0,0,0}},
	{2417, 0, {0,0,0}},
	{2422, 0, {0,0,0}},
	{2427, 0, {0,0,0}},
	{2432, 0, {0,0,0}},
	{2437, 0, {0,0,0}},
	{2442, 0, {0,0,0}},
	{2447, 0, {0,0,0}},
	{2452, 0, {0,0,0}},
	{2457, 0, {0,0,0}},
	{2462, 0, {0,0,0}},
	{2467, 0, {0,0,0}},
	{2472, 0, {0,0,0}},
	{2484, 0, {0,0,0}},
};

static guint num_legacy_channels = 14;

/*
 * Callback used by the load_wlan_keys() routine in order to read a WEP decryption key
 */
static guint
get_wep_key(pref_t *pref, gpointer ud)
{
    gchar *my_string = NULL;
    keys_cb_data_t* user_data;

    decryption_key_t* new_key;

    /* Retrieve user data info */
    user_data = (keys_cb_data_t*)ud;

    if (g_ascii_strncasecmp(pref->name, "wep_key", 7) == 0 && pref->type == PREF_STRING)
    {
	my_string = g_strdup(*pref->varp.string);

	    /* Here we have the string describing the key... */
	    new_key = parse_key_string(my_string);

	if( new_key != NULL)
	{
	    /* Key is added only if not null ... */
	    user_data->list = g_list_append(user_data->list,new_key);
	    user_data->number_of_keys++;
	    user_data->current_index++;
	}
    }
    return 0;
}

/* Returs TRUE if the WEP key is valid, false otherwise */
gboolean
wep_key_is_valid(char* key)
{
    GString *new_key_string;
    guint i=0;

    if(key == NULL)
	return FALSE;

    new_key_string = g_string_new(key);

    if( ((new_key_string->len) > WEP_KEY_MAX_CHAR_SIZE) || ((new_key_string->len) < 2))
    {
	g_string_free(new_key_string,FALSE);
	return FALSE;
    }
    if((new_key_string->len % 2) != 0)
    {
	g_string_free(new_key_string,FALSE);
	return FALSE;
    }
    for(i = 0; i < new_key_string->len; i++)
    {
	if(!g_ascii_isxdigit(new_key_string->str[i]))
	{
	    g_string_free(new_key_string,FALSE);
	    return FALSE;
	}
    }

    g_string_free(new_key_string,FALSE);
    return TRUE;
}

/* Callback used by the save_wlan_keys() routine in order to write a decryption key */
static guint
set_wep_key(pref_t *pref, gpointer ud _U_)
{
    gchar *my_string = NULL;
    keys_cb_data_t* user_data;
    gint wep_key_number = 0;

    decryption_key_t* new_key;

    /* Retrieve user data info */
    user_data = (keys_cb_data_t*)ud;

    if (g_ascii_strncasecmp(pref->name, "wep_key", 7) == 0 && pref->type == PREF_STRING)
    {
	/* Ok, the pref we're gonna set is a wep_key ... but what number? */
	sscanf(pref->name,"wep_key%d",&wep_key_number);

	if(user_data->current_index < user_data->number_of_keys)
	{
	    if(wep_key_number == (user_data->current_index+1))
	    {
		/* Retrieve the nth decryption_key_t structure pointer */
		new_key = (decryption_key_t*)g_list_nth_data(user_data->list,user_data->current_index);

		/* Free the old key string */
		g_free((void *)*pref->varp.string);

		/* Create the new string describing the decryption key */
		my_string = get_key_string(new_key);

		/* Duplicate the string, and assign it to the variable pointer */
		*pref->varp.string = (void *)g_strdup(my_string);

		/* Free the previously allocated string */
		g_free(my_string);
	    }
	}
	else /* If the number of keys has been reduced somehow, we need to delete all the other keys
	      * (remember that the new ones have been probably overwritten)
	      */
	{
	    g_free((void *)*pref->varp.string);
	    *pref->varp.string = (void *)g_strdup("");  /* Do not just free memory!!! Put an 'empty' string! */
	}
	user_data->current_index++;
    }

    return 0;
}

/*
 * Function used to read the Decryption Keys from the preferences and store them
 * properly into the airpcap adapter.
 */
gboolean
load_wlan_driver_wep_keys(void)
{
    keys_cb_data_t* user_data;
    guint i;

    /* Retrieve the wlan preferences */
    wlan_prefs = prefs_find_module("wlan");

    /* Allocate a structure used to keep infos  between the callbacks */
    user_data = (keys_cb_data_t*)g_malloc(sizeof(keys_cb_data_t));

    /* Fill the structure */
    user_data->list = NULL;
    user_data->current_index = 0;
    user_data->number_of_keys= 0; /* Still unknown */

    /* Run the callback on each 802.11 preference */
    prefs_pref_foreach(wlan_prefs, get_wep_key, (gpointer)user_data);

    /* Now the key list should be filled */

    /*
     * Signal that we've changed things, and run the 802.11 dissector's
     * callback
     */
    wlan_prefs->prefs_changed = TRUE;

    prefs_apply(wlan_prefs);

    write_wlan_driver_wep_keys_to_registry(user_data->list);

    /* FREE MEMORY */
    /* free the WEP key string */
    for(i=0;i<g_list_length(user_data->list);i++)
    {
	g_free(g_list_nth(user_data->list,i)->data);
    }

    /* free the (empty) list */
    g_list_free(user_data->list);

    /* free the user_data structure */
    g_free(user_data);

    /* airpcap_if_info_free(fake_info_if); */

    return TRUE;
}

/*
 * This function will tell the airpcap driver the key list to use
 * This will be stored into the registry...
 */
gboolean
write_wlan_wep_keys_to_registry(airpcap_if_info_t* info_if, GList* key_list)
{
    guint i,j;
    GString *new_key;
    gchar s[3];
    PAirpcapKeysCollection KeysCollection;
    guint KeysCollectionSize;
    guint8 KeyByte;
    guint keys_in_list = 0;
    decryption_key_t* key_item = NULL;

    keys_in_list = g_list_length(key_list);

    /*
     * Save the encryption keys, if we have any of them
     */
    KeysCollectionSize = 0;

    /*
     * Calculate the size of the keys collection
     */
    KeysCollectionSize = sizeof(AirpcapKeysCollection) + keys_in_list * sizeof(AirpcapKey);

    /*
     * Allocate the collection
     */
    KeysCollection = (PAirpcapKeysCollection)g_malloc(KeysCollectionSize);
    if(!KeysCollection)
    {
	return FALSE;
    }

    /*
     * Populate the key collection
     */
    KeysCollection->nKeys = keys_in_list;

    for(i = 0; i < keys_in_list; i++)
    {
	KeysCollection->Keys[i].KeyType = AIRPDCAP_KEY_TYPE_WEP;

	/* Retrieve the Item corresponding to the i-th key */
	key_item = (decryption_key_t*)g_list_nth_data(key_list,i);
	new_key = g_string_new(key_item->key->str);

	KeysCollection->Keys[i].KeyLen = (guint) new_key->len / 2;
	memset(&KeysCollection->Keys[i].KeyData, 0, sizeof(KeysCollection->Keys[i].KeyData));

	for(j = 0 ; j < new_key->len; j += 2)
	{
	    s[0] = new_key->str[j];
	    s[1] = new_key->str[j+1];
	    s[2] = '\0';
	    KeyByte = (guint8)strtol(s, NULL, 16);
	    KeysCollection->Keys[i].KeyData[j / 2] = KeyByte;
	}

	g_string_free(new_key,TRUE);

    }
    /*
     * Free the old adapter key collection!
     */
    if(info_if->keysCollection != NULL)
	g_free(info_if->keysCollection);

    /*
     * Set this collection ad the new one
     */
    info_if->keysCollection = KeysCollection;
    info_if->keysCollectionSize = KeysCollectionSize;

    /*
     * Configuration must be saved
     */
    info_if->saved = FALSE;

    /*
     * Write down the changes to the registry
     */
    airpcap_save_selected_if_configuration(info_if);

    return TRUE;
}

/*
 * This function will tell the airpcap driver the key list to use
 * This will be stored into the registry...
 */
gboolean
write_wlan_driver_wep_keys_to_registry(GList* key_list)
{
    guint i,j,k,n,y;
    GString *new_key;
    gchar s[3];
    PAirpcapKeysCollection KeysCollection;
    guint KeysCollectionSize;
    guint8 KeyByte;
    guint keys_in_list = 0;
    decryption_key_t* key_item = NULL;
    airpcap_if_info_t* fake_info_if = NULL;

    /* Create the fake_info_if from the first adapter of the list */
    fake_info_if = airpcap_driver_fake_if_info_new();

    if(fake_info_if == NULL)
	return FALSE;

    /*
     * XXX - When WPA will be supported, change this to: keys_in_list = g_list_length(key_list);
     * but right now we will have to count only the WEP keys (or we will have a malloc-mess :-) )
     */
    n = g_list_length(key_list);
    for(k = 0; k < n; k++ )
	if(((decryption_key_t*)g_list_nth_data(key_list,k))->type == AIRPDCAP_KEY_TYPE_WEP)
	    keys_in_list++;

    /*
     * Save the encryption keys, if we have any of them
     */
    KeysCollectionSize = 0;

    /*
     * Calculate the size of the keys collection
     */
    KeysCollectionSize = sizeof(AirpcapKeysCollection) + keys_in_list * sizeof(AirpcapKey);

    /*
     * Allocate the collection
     */
    KeysCollection = (PAirpcapKeysCollection)g_malloc(KeysCollectionSize);
    if(!KeysCollection)
    {
	return FALSE;
    }

    /*
     * Populate the key collection
     */
    KeysCollection->nKeys = keys_in_list;

    /*
     * XXX - If we have, let's say, six keys, the first three are WEP, then two are WPA, and the
     * last is WEP, we have to scroll the whole list (n) but increment the array counter only
     * when a WEP key is found (y) .. When WPA will be supported by the driver, I'll have to change
     * this
     */
    y = 0; /* Current position in the key list */

    for(i = 0; i < n; i++)
    {
	/* Retrieve the Item corresponding to the i-th key */
	key_item = (decryption_key_t*)g_list_nth_data(key_list,i);

	/*
	 * XXX - The AIRPDCAP_KEY_TYPE_WEP is the only supported right now!
	 * We will have to modify the AirpcapKey structure in order to
	 * support the other two types! What happens now, is that simply the
	 * not supported keys will just be discarded (they will be saved in Wireshark though)
	 */
	if(key_item->type == AIRPDCAP_KEY_TYPE_WEP)
	{
	    KeysCollection->Keys[y].KeyType = AIRPDCAP_KEY_TYPE_WEP;

	    new_key = g_string_new(key_item->key->str);

	    KeysCollection->Keys[y].KeyLen = (guint) new_key->len / 2;
	    memset(&KeysCollection->Keys[y].KeyData, 0, sizeof(KeysCollection->Keys[y].KeyData));

	    for(j = 0 ; j < new_key->len; j += 2)
	    {
		s[0] = new_key->str[j];
		s[1] = new_key->str[j+1];
		s[2] = '\0';
		KeyByte = (guint8)strtol(s, NULL, 16);
		KeysCollection->Keys[y].KeyData[j / 2] = KeyByte;
	    }
	    /* XXX - Change when WPA will be supported!!! */
	    y++;
	    g_string_free(new_key,TRUE);
	}
	else if(key_item->type == AIRPDCAP_KEY_TYPE_WPA_PWD)
	{
	    /* XXX - The driver cannot deal with this kind of key yet... */
	}
	else if(key_item->type == AIRPDCAP_KEY_TYPE_WPA_PMK)
	{
	    /* XXX - The driver cannot deal with this kind of key yet... */
	}
    }

    /*
     * Free the old adapter key collection!
     */
    if(fake_info_if->keysCollection != NULL)
	g_free(fake_info_if->keysCollection);

    /*
     * Set this collection ad the new one
     */
    fake_info_if->keysCollection = KeysCollection;
    fake_info_if->keysCollectionSize = KeysCollectionSize;

    /*
     * Configuration must be saved
     */
    fake_info_if->saved = FALSE;

    /*
     * Write down the changes to the registry
     */
    airpcap_save_driver_if_configuration(fake_info_if);

    airpcap_if_info_free(fake_info_if);

    return TRUE;
}

/*
 *  Function used to save to the preference file the Decryption Keys.
 */
int
save_wlan_driver_wep_keys(void)
{
    GList* key_list = NULL;
    char* tmp_key = NULL;
    guint keys_in_list,i;
    keys_cb_data_t* user_data;
    airpcap_if_info_t* fake_info_if = NULL;

    /* Create the fake_info_if from the first adapter of the list */
    fake_info_if = airpcap_driver_fake_if_info_new();

    if(fake_info_if == NULL)
	return 0;

    /* Retrieve the wlan preferences */
    wlan_prefs = prefs_find_module("wlan");

    /* Allocate a structure used to keep infos  between the callbacks */
    user_data = (keys_cb_data_t*)g_malloc(sizeof(keys_cb_data_t));

    /* Number of keys in key list */
    if(fake_info_if->keysCollectionSize != 0)
	keys_in_list = (guint)(fake_info_if->keysCollectionSize -  sizeof(AirpcapKeysCollection))/sizeof(AirpcapKey);
    else
	keys_in_list = 0;

    for(i=0; i<keys_in_list; i++)
    {
    /* Only if it is a WEP key... */
	if(fake_info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WEP)
	{
	    tmp_key = airpcap_get_key_string(fake_info_if->keysCollection->Keys[i]);
	    key_list = g_list_append(key_list,g_strdup(tmp_key));
	    g_free(tmp_key);
	}
    }

    /* Now we know the exact number of WEP keys in the list, so store it ... */
    keys_in_list = g_list_length(key_list);

    /* Fill the structure */
    user_data->list = key_list;
    user_data->current_index = 0;
    user_data->number_of_keys= keys_in_list;

    /* Retrieve the wlan preferences */
    wlan_prefs = prefs_find_module("wlan");

    /* Run the callback on each 802.11 preference */
    prefs_pref_foreach(wlan_prefs, set_wep_key,  (gpointer)user_data);

    /* Signal that we've changed things, and run the 802.11 dissector's
     * callback */
    wlan_prefs->prefs_changed = TRUE;

    /* Apply changes for the specified preference */
    prefs_apply(wlan_prefs);

    /* FREE MEMORY */
    /* free the WEP key string */
    for(i=0;i<g_list_length(user_data->list);i++)
    {
	g_free(g_list_nth(user_data->list,i)->data);
    }

    /* free the (empty) list */
    g_list_free(user_data->list);

    /* free the user_data structure */
    g_free(user_data);

    airpcap_if_info_free(fake_info_if);

    return keys_in_list;
}

/*
 *  Function used to save to the preference file the Decryption Keys.
 */
int
save_wlan_wireshark_wep_keys(GList* key_ls)
{
    GList* key_list = NULL;
    guint keys_in_list,i;
    keys_cb_data_t* user_data;
    decryption_key_t* tmp_dk;

    /* Retrieve the wlan preferences */
    wlan_prefs = prefs_find_module("wlan");

    /* Allocate a structure used to keep infos  between the callbacks */
    user_data = (keys_cb_data_t*)g_malloc(sizeof(keys_cb_data_t));

    keys_in_list = g_list_length(key_ls);

    key_list = key_ls;

    /* Fill the structure */
    user_data->list = key_list;
    user_data->current_index = 0;
    user_data->number_of_keys= keys_in_list;

    /* Retrieve the wlan preferences */
    wlan_prefs = prefs_find_module("wlan");

    /* Run the callback on each 802.11 preference */
    prefs_pref_foreach(wlan_prefs, set_wep_key,  (gpointer)user_data);

    /* Signal that we've changed things, and run the 802.11 dissector's
     * callback */
    wlan_prefs->prefs_changed = TRUE;

    /* Apply changes for the specified preference */
    prefs_apply(wlan_prefs);

    /* FREE MEMORY */
    /* free the WEP key string */
    for(i=0;i<g_list_length(user_data->list);i++)
    {
	tmp_dk = (decryption_key_t*)g_list_nth(user_data->list,i)->data;
	g_string_free(tmp_dk->key,TRUE);
	if(tmp_dk->ssid != NULL) g_byte_array_free(tmp_dk->ssid,TRUE);
    }

    /* free the (empty) list */
    g_list_free(user_data->list);

    /* free the user_data structure */
    g_free(user_data);

    return keys_in_list;
}

/*
 * Get an error message string for a CANT_GET_INTERFACE_LIST error from
 * "get_airpcap_interface_list()".
 */
static gchar *
cant_get_airpcap_if_list_error_message(const char *err_str)
{
    return g_strdup_printf("Can't get list of Wireless interfaces: %s", err_str);
}

/*
 * Airpcap wrapper, used to store the current settings for the selected adapter
 */
gboolean
airpcap_if_store_cur_config_as_adapter_default(PAirpcapHandle ah)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapStoreCurConfigAsAdapterDefault(ah);
}

/*
 * Airpcap wrapper, used to open an airpcap adapter
 */
PAirpcapHandle
airpcap_if_open(gchar * name, gchar * err)
{
    if (!AirpcapLoaded) return NULL;
    if (name == NULL) return NULL;
    return g_PAirpcapOpen(name,err);
}

/*
 * Airpcap wrapper, used to close an airpcap adapter
 */
void
airpcap_if_close(PAirpcapHandle handle)
{
    if (!AirpcapLoaded) return;
    g_PAirpcapClose(handle);
}

/*
 * Retrieve the state of the Airpcap DLL
 */
int
airpcap_get_dll_state(void)
{
  return AirpcapVersion;
}

/*
 * Airpcap wrapper, used to turn on the led of an airpcap adapter
 */
gboolean
airpcap_if_turn_led_on(PAirpcapHandle AdapterHandle, guint LedNumber)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapTurnLedOn(AdapterHandle,LedNumber);
}

/*
 * Airpcap wrapper, used to turn off the led of an airpcap adapter
 */
gboolean
airpcap_if_turn_led_off(PAirpcapHandle AdapterHandle, guint LedNumber)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapTurnLedOff(AdapterHandle,LedNumber);
}

/*
 * Airpcap wrapper, used to get the channel of an airpcap adapter
 */
gboolean
airpcap_if_get_device_channel(PAirpcapHandle ah, guint * ch)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapGetDeviceChannel(ah,ch);
}

/*
 * Airpcap wrapper, used to get the supported channels of an airpcap adapter
 */
gboolean
airpcap_if_get_device_supported_channels(PAirpcapHandle ah, AirpcapChannelInfo **cInfo, guint * nInfo)
{
    if (!AirpcapLoaded) return FALSE;
    if (airpcap_get_dll_state() == AIRPCAP_DLL_OLD){
      *nInfo = num_legacy_channels;
      *cInfo = (AirpcapChannelInfo*)&LegacyChannels;

      return TRUE;
    } else if (airpcap_get_dll_state() == AIRPCAP_DLL_OK){
      return g_PAirpcapGetDeviceSupportedChannels(ah, cInfo, nInfo);
    }
    return FALSE;
}

/*
 * Airpcap wrapper, used to get the supported channels of an airpcap adapter
 */
Dot11Channel*
airpcap_if_get_device_supported_channels_array(PAirpcapHandle ah, guint * pNumSupportedChannels)
{
    AirpcapChannelInfo *chanInfo;
    guint i=0, j=0, numInfo = 0;

    if (!AirpcapLoaded)
        return NULL;
    if (airpcap_if_get_device_supported_channels(ah, &chanInfo, &numInfo) == FALSE)
        return NULL;
    numSupportedChannels = 0;

    /*
     * allocate a bigger array
     */
    if (numInfo == 0)
        return NULL;

    pSupportedChannels = g_malloc(numInfo * (sizeof *pSupportedChannels));

    for (i = 0; i < numInfo; i++)
    {
        guint supportedChannel = G_MAXUINT;

        /*
         * search if we have it already
         */
        for (j = 0; j < numSupportedChannels; j++)
        {
            if (pSupportedChannels[j].Frequency == chanInfo[i].Frequency)
            {
                supportedChannel = j;
                break;
            }
        }

        if (supportedChannel == G_MAXUINT)
        {
            /*
             * not found, create a new item
             */
            pSupportedChannels[numSupportedChannels].Frequency = chanInfo[i].Frequency;

            switch(chanInfo[i].ExtChannel)
            {
                case -1:
                    pSupportedChannels[numSupportedChannels].Flags = FLAG_CAN_BE_LOW;
                    break;
                case +1:
                    pSupportedChannels[numSupportedChannels].Flags = FLAG_CAN_BE_HIGH;
                    break;
                case 0:
                default:
                    pSupportedChannels[numSupportedChannels].Flags = 0;
            }

            /*
             * Gather channel information
             */

            pSupportedChannels[numSupportedChannels].Flags |=
                FREQ_IS_BG(pSupportedChannels[numSupportedChannels].Frequency) ?
                    FLAG_IS_BG_CHANNEL : FLAG_IS_A_CHANNEL;
            pSupportedChannels[numSupportedChannels].Channel =
                ieee80211_mhz_to_chan(pSupportedChannels[numSupportedChannels].Frequency);
            numSupportedChannels++;
        }
        else
        {
            /*
             * just update the ext channel flags
             */
            switch(chanInfo[i].ExtChannel)
            {
                case -1:
                    pSupportedChannels[supportedChannel].Flags |= FLAG_CAN_BE_LOW;
                    break;
                case +1:
                    pSupportedChannels[supportedChannel].Flags |= FLAG_CAN_BE_HIGH;
                    break;
                case 0:
                default:
                    break;
            }
        }
    }

    if (numSupportedChannels < 1)
        return NULL;
    /*
     * Now sort the list by frequency
     */
    for (i = 0 ; i < numSupportedChannels - 1; i++)
    {
        for (j = i + 1; j < numSupportedChannels; j++)
        {
            if (pSupportedChannels[i].Frequency > pSupportedChannels[j].Frequency)
            {
                Dot11Channel temp = pSupportedChannels[i];
                pSupportedChannels[i] = pSupportedChannels[j];
                pSupportedChannels[j] = temp;
            }
        }
    }

    *pNumSupportedChannels = numSupportedChannels;
    return pSupportedChannels;
}

/*
 * Airpcap wrapper, used to set the channel of an airpcap adapter
 */
gboolean
airpcap_if_set_device_channel(PAirpcapHandle ah, guint ch)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapSetDeviceChannel(ah,ch);
}

/*
 * Airpcap wrapper, used to set the frequency of an airpcap adapter
 */
gboolean
airpcap_if_set_device_channel_ex(PAirpcapHandle ah, AirpcapChannelInfo ChannelInfo)
{
    if (!AirpcapLoaded) return FALSE;
    if (airpcap_get_dll_state() == AIRPCAP_DLL_OLD){
      gint channel = 0;
      channel = ieee80211_mhz_to_chan(ChannelInfo.Frequency);

      if (channel < 0){
        return FALSE;
      } else {
        return airpcap_if_set_device_channel(ah, channel);
      }
    } else if (airpcap_get_dll_state() == AIRPCAP_DLL_OK){
      return g_PAirpcapSetDeviceChannelEx (ah, ChannelInfo);
    }

    return FALSE;
}

/*
 * Airpcap wrapper, used to get the frequency of an airpcap adapter
 */
gboolean
airpcap_if_get_device_channel_ex(PAirpcapHandle ah, PAirpcapChannelInfo pChannelInfo)
{
    if (!AirpcapLoaded) return FALSE;

    pChannelInfo->Frequency = 0;
    pChannelInfo->ExtChannel = 0;
    pChannelInfo->Reserved[0] = 0;
    pChannelInfo->Reserved[1] = 0;
    pChannelInfo->Reserved[2] = 0;

    if (airpcap_get_dll_state() == AIRPCAP_DLL_OLD){
      guint channel = 0;
      guint chan_freq = 0;

      if (!airpcap_if_get_device_channel(ah, &channel)) return FALSE;

      chan_freq = ieee80211_chan_to_mhz(channel, TRUE);
      if (chan_freq == 0) return FALSE;
      pChannelInfo->Frequency = chan_freq;

      return TRUE;
    } else if (airpcap_get_dll_state() == AIRPCAP_DLL_OK){
      return g_PAirpcapGetDeviceChannelEx (ah, pChannelInfo);
    }
    return FALSE;
}

/*
 * Airpcap wrapper, used to get the link type of an airpcap adapter
 */
gboolean
airpcap_if_get_link_type(PAirpcapHandle ah, PAirpcapLinkType lt)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapGetLinkType(ah,lt);
}

/*
 * Airpcap wrapper, used to set the link type of an airpcap adapter
 */
gboolean
airpcap_if_set_link_type(PAirpcapHandle ah, AirpcapLinkType lt)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapSetLinkType(ah,lt);
}

/*
 * Airpcap wrapper, used to get the fcs presence of an airpcap adapter
 */
gboolean
airpcap_if_get_fcs_presence(PAirpcapHandle ah, gboolean * fcs)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapGetFcsPresence(ah,fcs);
}

/*
 * Airpcap wrapper, used to set the fcs presence of an airpcap adapter
 */
gboolean
airpcap_if_set_fcs_presence(PAirpcapHandle ah, gboolean fcs)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapSetFcsPresence(ah,fcs);
}

/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap adapter
 */
gboolean
airpcap_if_get_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState PEnable)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapGetDecryptionState(ah,PEnable);
}

/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap adapter
 */
gboolean
airpcap_if_set_decryption_state(PAirpcapHandle ah, AirpcapDecryptionState Enable)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapSetDecryptionState(ah,Enable);
}

/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap driver
 */
gboolean
airpcap_if_get_driver_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState PEnable)
{
    if (!AirpcapLoaded || (g_PAirpcapGetDriverDecryptionState==NULL)) return FALSE;
    return g_PAirpcapGetDriverDecryptionState(ah,PEnable);
}

/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap driver
 */
gboolean
airpcap_if_set_driver_decryption_state(PAirpcapHandle ah, AirpcapDecryptionState Enable)
{
    if (!AirpcapLoaded || (g_PAirpcapSetDriverDecryptionState==NULL)) return FALSE;
    return g_PAirpcapSetDriverDecryptionState(ah,Enable);
}

/*
 * Airpcap wrapper, used to get the fcs validation of an airpcap adapter
 */
gboolean
airpcap_if_get_fcs_validation(PAirpcapHandle ah, PAirpcapValidationType val)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapGetFcsValidation(ah,val);
}

/*
 * Airpcap wrapper, used to set the fcs validation of an airpcap adapter
 */
gboolean
airpcap_if_set_fcs_validation(PAirpcapHandle ah, AirpcapValidationType val)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapSetFcsValidation(ah,val);
}

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
gboolean
airpcap_if_set_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapSetDeviceKeys(AdapterHandle,KeysCollection);
}

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
gboolean
airpcap_if_get_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, guint * PKeysCollectionSize)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapGetDeviceKeys(AdapterHandle,KeysCollection,PKeysCollectionSize);
}

/*
 * Airpcap wrapper, used to save the driver's set of keys
 */
gboolean
airpcap_if_set_driver_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection)
{
    if (!AirpcapLoaded || (g_PAirpcapSetDriverKeys==NULL)) return FALSE;
    return g_PAirpcapSetDriverKeys(AdapterHandle,KeysCollection);
}

/*
 * Airpcap wrapper, used to load the driver's set of keys
 */
gboolean
airpcap_if_get_driver_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, guint * PKeysCollectionSize)
{
    if (!AirpcapLoaded || (g_PAirpcapGetDriverKeys==NULL)) return FALSE;
    return g_PAirpcapGetDriverKeys(AdapterHandle,KeysCollection,PKeysCollectionSize);
}

/*
 * This function will create a new airpcap_if_info_t using a name and a description
 */
airpcap_if_info_t *
airpcap_if_info_new(char *name, char *description)
{
    PAirpcapHandle ad;
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];

    airpcap_if_info_t *if_info = NULL;

    /* Probably I have to switch on the leds!!! */
    ad = airpcap_if_open(name, ebuf);
    if(ad)
    {
  		if_info = g_malloc0(sizeof (airpcap_if_info_t));
  		if_info->name = g_strdup(name);
  		if (description == NULL){
  			if_info->description = NULL;
  		}else{
  			if_info->description = g_strdup(description);
  		}

  		if_info->ip_addr = NULL;
  		if_info->loopback = FALSE;
  		airpcap_if_get_fcs_validation(ad,&(if_info->CrcValidationOn));
  		airpcap_if_get_fcs_presence(ad,&(if_info->IsFcsPresent));
  		airpcap_if_get_link_type(ad,&(if_info->linkType));
  		airpcap_if_get_device_channel_ex(ad,&(if_info->channelInfo));
  		if_info->pSupportedChannels = airpcap_if_get_device_supported_channels_array(ad, &(if_info->numSupportedChannels));
  		airpcap_if_turn_led_on(ad, 0);
  		airpcap_if_get_decryption_state(ad, &(if_info->DecryptionOn));
  		if_info->led = TRUE;
  		if_info->blinking = FALSE;
  		if_info->saved = TRUE; /* NO NEED TO BE SAVED */

  		/* get the keys, if everything is ok, close the adapter */
  		if(airpcap_if_load_keys(ad,if_info))
  		{
  			airpcap_if_close(ad);
  		}
    }
    return if_info;
}

/*
 * This function will create a new fake drivers' interface, to load global keys...
 */
airpcap_if_info_t*
airpcap_driver_fake_if_info_new(void)
{
    PAirpcapHandle ad;
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];

    airpcap_if_info_t *if_info = NULL;
    airpcap_if_info_t *fake_if_info = NULL;

    /* Maybe for some reason no airpcap adapter is found */
    if(airpcap_if_list == NULL)
	return NULL;

    /*
     * Retrieve the first AirPcap adapter available. If no interface is found,
     * it is not possible to retrieve the driver's settings, so return NULL.
     */
    if_info = g_list_nth_data(airpcap_if_list,0);
    if(if_info == NULL)
	return NULL;

    /* Open the 'fake' adapter */
    ad = airpcap_if_open(if_info->name, ebuf);
    if(ad)
    {
		fake_if_info = g_malloc(sizeof (airpcap_if_info_t));
		fake_if_info->name = g_strdup(if_info->name);
		fake_if_info->description = g_strdup(if_info->description);
		fake_if_info->loopback = FALSE;
		fake_if_info->ip_addr = NULL;
		airpcap_if_get_driver_decryption_state(ad, &(fake_if_info->DecryptionOn));
		airpcap_if_get_fcs_validation(ad,&(fake_if_info->CrcValidationOn));
		airpcap_if_get_fcs_presence(ad,&(fake_if_info->IsFcsPresent));
		airpcap_if_get_link_type(ad,&(fake_if_info->linkType));
		airpcap_if_get_device_channel_ex(ad,&(fake_if_info->channelInfo));
		airpcap_if_turn_led_on(ad, 0);
		fake_if_info->led = TRUE;
		fake_if_info->blinking = FALSE;
		fake_if_info->saved = TRUE; /* NO NEED TO BE SAVED */

		/* get the keys, if everything is ok, close the adapter */
		if(airpcap_if_load_driver_keys(ad,fake_if_info))
		{
			airpcap_if_close(ad);
		}
    }

    return fake_if_info;
}

/*
 * USED FOR DEBUG ONLY... PRINTS AN AirPcap ADAPTER STRUCTURE in a fancy way.
 */
void
airpcap_if_info_print(airpcap_if_info_t* if_info)
{
    guint i;
    if(if_info == NULL)
    {
		g_print("\nWARNING : AirPcap Interface pointer is NULL!\n");
		return;
    }

    g_print("\n----------------- AirPcap Interface \n");
    g_print("                      NAME: %s\n",if_info->name);
    g_print("               DESCRIPTION: %s\n",if_info->description);
    g_print("                  BLINKING: %s\n",if_info->blinking ? "TRUE" : "FALSE");
    g_print("     channelInfo.Frequency: %u\n",if_info->channelInfo.Frequency);
    g_print("    channelInfo.ExtChannel: %d\n",if_info->channelInfo.ExtChannel);
    g_print("             CRCVALIDATION: %s\n",if_info->CrcValidationOn ? "ON" : "OFF");
    g_print("                DECRYPTION: %s\n",if_info->DecryptionOn ? "ON" : "OFF");
    g_print("                   IP ADDR: %s\n",if_info->ip_addr!=NULL ? "NOT NULL" : "NULL");
    g_print("                FCSPRESENT: %s\n",if_info->IsFcsPresent ? "TRUE" : "FALSE");
    g_print("            KEYSCOLLECTION: %s\n",if_info->keysCollection!=NULL ? "NOT NULL" : "NULL");
    g_print("        KEYSCOLLECTIONSIZE: %u\n",if_info->keysCollectionSize);
    g_print("                       LED: %s\n",if_info->led ? "ON" : "OFF");
    g_print("                  LINKTYPE: %d\n",if_info->linkType);
    g_print("                  LOOPBACK: %s\n",if_info->loopback ? "YES" : "NO");
    g_print("                 (GTK) TAG: %d\n",if_info->tag);
    g_print("SUPPORTED CHANNELS POINTER: %p\n",if_info->pSupportedChannels);
    g_print("    NUM SUPPORTED CHANNELS: %u\n",if_info->numSupportedChannels);

    for(i=0; i<(if_info->numSupportedChannels); i++){
      g_print("\n        SUPPORTED CHANNEL #%u\n",i+1);
      g_print("                   CHANNEL: %u\n",if_info->pSupportedChannels[i].Channel);
      g_print("                 FREQUENCY: %u\n",if_info->pSupportedChannels[i].Frequency);
      g_print("                     FLAGS: %u\n",if_info->pSupportedChannels[i].Flags);
    }
    g_print("\n\n");
}

/*
 * Function used to load the WEP keys for a selected interface
 */
gboolean
airpcap_if_load_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
    if(!if_info) return FALSE;

    if_info->keysCollectionSize = 0;
    if_info->keysCollection = NULL;

    if(!airpcap_if_get_device_keys(ad, NULL, &(if_info->keysCollectionSize)))
    {
	if(if_info->keysCollectionSize == 0)
	{
	    if_info->keysCollection = NULL;
	    airpcap_if_close(ad);
	    return FALSE;
	}

	if_info->keysCollection = (PAirpcapKeysCollection)g_malloc(if_info->keysCollectionSize);
	if(!if_info->keysCollection)
	{
	    if_info->keysCollectionSize = 0;
	    if_info->keysCollection = NULL;
	    airpcap_if_close(ad);
	    return FALSE;
	}

	airpcap_if_get_device_keys(ad, if_info->keysCollection, &(if_info->keysCollectionSize));
	return TRUE;
    }

    airpcap_if_close(ad);
    return FALSE;
}

/*
 * Function used to load the WEP keys for a selected interface
 */
gboolean
airpcap_if_load_driver_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
    if_info->keysCollectionSize = 0;
    if_info->keysCollection = NULL;

    if(!airpcap_if_get_driver_keys(ad, NULL, &(if_info->keysCollectionSize)))
    {
	if(if_info->keysCollectionSize == 0)
	{
	    if_info->keysCollection = NULL;
	    airpcap_if_close(ad);
	    return FALSE;
	}

	if_info->keysCollection = (PAirpcapKeysCollection)g_malloc(if_info->keysCollectionSize);
	if(!if_info->keysCollection)
	{
	    if_info->keysCollectionSize = 0;
	    if_info->keysCollection = NULL;
	    airpcap_if_close(ad);
	    return FALSE;
	}

	airpcap_if_get_driver_keys(ad, if_info->keysCollection, &(if_info->keysCollectionSize));
	return TRUE;
    }

    airpcap_if_close(ad);
    return FALSE;
}

/*
 * Function used to save the WEP keys for a selected interface
 */
void
airpcap_if_save_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
    if(!if_info || !AirpcapLoaded) return;

    if(if_info->keysCollection != NULL)
	g_PAirpcapSetDeviceKeys(ad,if_info->keysCollection);
}

/*
 * Function used to save the WEP keys for a selected interface
 */
void
airpcap_if_save_driver_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
    if(if_info->keysCollection != NULL)
	airpcap_if_set_driver_keys(ad,if_info->keysCollection);
}

/*
 * Callback used to free an instance of airpcap_if_info_t
 */
static void
free_airpcap_if_cb(gpointer data, gpointer user_data _U_)
{
    airpcap_if_info_t *if_info = data;

    if (if_info->name != NULL)
	g_free(if_info->name);

    if (if_info->description != NULL)
	g_free(if_info->description);

    /* XXX - FREE THE WEP KEY LIST HERE!!!*/
    if(if_info->keysCollection != NULL)
    {
	g_free(if_info->keysCollection);
	if_info->keysCollection = NULL;
    }

    if(if_info->ip_addr != NULL)
	g_slist_free(if_info->ip_addr);

    if(if_info != NULL)
	g_free(if_info);
}

/*
 * Function used to free the airpcap interface list
 */
void
free_airpcap_interface_list(GList *if_list)
{
    g_list_foreach(if_list, free_airpcap_if_cb, NULL);
    g_list_free(if_list);
    if_list = NULL;
}

/*
 * This function will use the airpcap.dll to find all the airpcap devices.
 * Will return null if no device is found.
 */
GList*
get_airpcap_interface_list(int *err, char **err_str)
{
    GList  *il = NULL;
    airpcap_if_info_t *if_info;
    int n_adapts;
    AirpcapDeviceDescription *devsList, *adListEntry;
    char errbuf[PCAP_ERRBUF_SIZE];

    *err = 0;

    if (!AirpcapLoaded)
    {
		*err = AIRPCAP_NOT_LOADED;
		return il;
    }

    if (!g_PAirpcapGetDeviceList(&devsList, errbuf))
    {
		/* No interfaces, return il = NULL; */
		*err = CANT_GET_AIRPCAP_INTERFACE_LIST;
		if (err_str != NULL)
			*err_str = cant_get_airpcap_if_list_error_message(errbuf);
		return il;
    }

    /*
     * Count the adapters
     */
    adListEntry = devsList;
    n_adapts = 0;
    while(adListEntry)
    {
	n_adapts++;
	adListEntry = adListEntry->next;
    }

    if(n_adapts == 0)
    {
		/* No interfaces, return il= NULL */
		g_PAirpcapFreeDeviceList(devsList);
		*err = NO_AIRPCAP_INTERFACES_FOUND;
		if (err_str != NULL)
			*err_str = NULL;
		return il;
    }

    /*
     * Insert the adapters in our list
     */
    adListEntry = devsList;
    while(adListEntry)
    {
		if_info = airpcap_if_info_new(adListEntry->Name, adListEntry->Description);
		if (if_info != NULL){
			il = g_list_append(il, if_info);
		}

		adListEntry = adListEntry->next;
    }

    g_PAirpcapFreeDeviceList(devsList);

    return il;
}

/*
 * Used to retrieve the interface given the name
 * (the name is used in AirpcapOpen)
 */
airpcap_if_info_t* get_airpcap_if_from_name(GList* if_list, const gchar* name)
{
    unsigned int ifn;
    GList* curr;
    airpcap_if_info_t* if_info;

    ifn = 0;
    if(if_list != NULL)
    {
	while( ifn < g_list_length(if_list) )
	{
	    curr = g_list_nth(if_list, ifn);

	    if_info = NULL;
	    if(curr != NULL)
		    if_info = curr->data;
	    if(if_info != NULL)
	    {
		if ( g_ascii_strcasecmp(if_info->name,name) == 0
#ifdef HAVE_PCAP_REMOTE /* The interface will be prepended with "rpcap://" */
			|| g_str_has_suffix(name, if_info->name)
#endif
			)
		{
		    return if_info;
		}
	    }
	    ifn++;
	}
    }
    return NULL;
}

/*
 * Returns the ASCII string of a key given the key bytes
 */
gchar*
airpcap_get_key_string(AirpcapKey key)
{
    unsigned int j = 0;
    gchar *dst,*src;

    dst = NULL;
    src = NULL;

    if(key.KeyType == AIRPDCAP_KEY_TYPE_WEP)
    {
	if(key.KeyLen != 0)
	{
	    /* Allocate the string used to store the ASCII representation of the WEP key */
	    dst = (gchar*)g_malloc(sizeof(gchar)*WEP_KEY_MAX_CHAR_SIZE + 1);
	    /* Make sure that the first char is '\0' in order to make g_strlcat() work */
	    dst[0]='\0';

	    for(j = 0; j < key.KeyLen; j++)
	    {
		src = g_strdup_printf("%.2x", key.KeyData[j]);
		/*
		 * XXX - use g_strconcat() or GStrings instead ???
		 */
		g_strlcat(dst, src, WEP_KEY_MAX_CHAR_SIZE+1);
	    }
	    g_free(src);
	}
    }
    else if(key.KeyType == AIRPDCAP_KEY_TYPE_WPA_PWD)
    {
	/* XXX - Add code here */
    }
    else if(key.KeyType == AIRPDCAP_KEY_TYPE_WPA_PMK)
    {
	/* XXX - Add code here */
    }
    else
    {
	/* XXX - Add code here */
    }

    return dst;
}

/*
 * Clear keys and decryption status for the specified interface
 */
void
airpcap_if_clear_decryption_settings(airpcap_if_info_t* info_if)
{
    if(info_if != NULL)
    {
	if(info_if->keysCollection != NULL)
	{
	    g_free(info_if->keysCollection);
	    info_if->keysCollection = NULL;
	}

	info_if->keysCollectionSize = 0;

	info_if->DecryptionOn = FALSE;
	info_if->saved = FALSE;
    }
}

/*
 * Used to retrieve the two chars string from interface
 */
gchar*
airpcap_get_if_string_number(airpcap_if_info_t* if_info)
{
    gchar* number;
    guint n;
    int a;

    a = sscanf(if_info->name,AIRPCAP_DEVICE_NUMBER_EXTRACT_STRING,&n);

    /* If sscanf() returned 1, it means that has read a number, so interface is not "Any"
     * Otherwise, check if it is the "Any" adapter...
     */
    if(a == 0)
    {
	if(g_ascii_strcasecmp(if_info->name,AIRPCAP_DEVICE_ANY_EXTRACT_STRING)!=0)
	    number = g_strdup_printf("??");
	else
	    number = g_strdup_printf(AIRPCAP_CHANNEL_ANY_NAME);
    }
    else
    {
	number = g_strdup_printf("%.2u",n);
    }

    return number;
}

/*
 * Used to retrieve the two chars string from interface
 */
gchar*
airpcap_get_if_string_number_from_description(gchar* description)
{
    gchar* number;
    gchar* pointer;

    number = (gchar*)g_malloc(sizeof(gchar)*3);

    pointer = g_strrstr(description,"#\0");

    number[0] = *(pointer+1);
    number[1] = *(pointer+2);
    number[2] = '\0';

    return number;
}

/*
 * Returns the default airpcap interface of a list, NULL if list is empty
 */
airpcap_if_info_t*
airpcap_get_default_if(GList* airpcap_if_list)
{
    gchar* s;
    airpcap_if_info_t* if_info = NULL;

    if(prefs.capture_device != NULL)
    {
	s = g_strdup(get_if_name(prefs.capture_device));
	if_info = get_airpcap_if_from_name(airpcap_if_list,g_strdup(get_if_name(prefs.capture_device)));
	g_free(s);
    }
    return if_info;
}

/*
 * Load the configuration for the specified interface
 */
void
airpcap_load_selected_if_configuration(airpcap_if_info_t* if_info)
{
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];
    PAirpcapHandle ad;

    if(if_info != NULL)
    {
	ad = airpcap_if_open(if_info->name, ebuf);

	if(ad)
	{
	    /* Stop blinking (if it was blinking!)*/
	    if(if_info->blinking)
	    {
		/* Turn on the light (if it was off) */
		if(!(if_info->led)) airpcap_if_turn_led_on(ad, 0);
	    }

	    /* Apply settings... */
	    airpcap_if_get_device_channel_ex(ad,&(if_info->channelInfo));
	    airpcap_if_get_fcs_validation(ad,&(if_info->CrcValidationOn));
	    airpcap_if_get_fcs_presence(ad,&(if_info->IsFcsPresent));
	    airpcap_if_get_link_type(ad,&(if_info->linkType));
	    airpcap_if_get_decryption_state(ad, &(if_info->DecryptionOn));
	    /* get the keys, if everything is ok, close the adapter */
	    if(airpcap_if_load_keys(ad,if_info))
		airpcap_if_close(ad);

	    if_info->saved = TRUE;
	}
	else
	{
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, " Error in opening adapter for %s",if_info->description);
	}
    }
}

/*
 * Save the configuration for the specified interface
 */
void
airpcap_save_selected_if_configuration(airpcap_if_info_t* if_info)
{
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];
    PAirpcapHandle ad;

    if(if_info != NULL)
    {
	ad = airpcap_if_open(if_info->name, ebuf);

	if(ad)
	{
	    /* Stop blinking (if it was blinking!)*/
	    if(if_info->blinking)
	    {
		/* Turn on the light (if it was off) */
		if(!(if_info->led)) airpcap_if_turn_led_on(ad, 0);
	    }

	    /* Apply settings... */
	    airpcap_if_set_device_channel_ex(ad,if_info->channelInfo);
	    airpcap_if_set_fcs_validation(ad,if_info->CrcValidationOn);
	    airpcap_if_set_fcs_presence(ad,if_info->IsFcsPresent);
	    airpcap_if_set_link_type(ad,if_info->linkType);
	    airpcap_if_set_decryption_state(ad, if_info->DecryptionOn);
	    airpcap_if_save_keys(ad,if_info);

	    /* ... and save them */
	    if(!airpcap_if_store_cur_config_as_adapter_default(ad))
	    {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Cannot save Wireless configuration!!!\nRemember that in order to store the configuration in the registry you have to:\n\n- Close all the airpcap-based applications.\n- Be sure to have administrative privileges.");
		if_info->saved = FALSE;
		airpcap_if_close(ad);
		return;
	    }

	    if_info->saved = TRUE;
	    airpcap_if_close(ad);
	}
	else
	{
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, " Error in opening adapter for %s",if_info->description);
	}
    }
}

/*
 * Save the configuration for the specified interface
 */
void
airpcap_save_driver_if_configuration(airpcap_if_info_t* fake_if_info)
{
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];
    PAirpcapHandle ad;

    if(fake_if_info != NULL)
    {
	ad = airpcap_if_open(fake_if_info->name, ebuf);

	if(ad)
	{
	    /* Apply decryption settings... */
	    airpcap_if_set_driver_decryption_state(ad, fake_if_info->DecryptionOn);
	    airpcap_if_save_driver_keys(ad,fake_if_info);
	    airpcap_if_close(ad);
	}
	else
	{
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, " Error in opening adapter for %s",fake_if_info->description);
	}
    }

    return;
}

/*
 * DECRYPTION KEYS FUNCTIONS
 */
/*
 * This function is used for DEBUG POURPOSES ONLY!!!
 */
void
print_key_list(GList* key_list)
{
    gint n,i;
    decryption_key_t* tmp;

    if(key_list == NULL)
    {
	g_print("\n\n******* KEY LIST NULL *******\n\n");
	return;
    }

    n = g_list_length(key_list);

    g_print("\n\n********* KEY LIST **********\n\n");

    g_print("NUMBER OF KEYS IN LIST : %d\n\n",n);

    for(i =0; i < n; i++)
    {
	g_print("[%d] :\n",i+1);
	tmp = (decryption_key_t*)(g_list_nth_data(key_list,i));
	g_print("KEY : %s\n",tmp->key->str);

	g_print("BITS: %d\n",tmp->bits);

	if(tmp->type == AIRPDCAP_KEY_TYPE_WEP)
	    g_print("TYPE: %s\n",AIRPCAP_WEP_KEY_STRING);
	else if(tmp->type == AIRPDCAP_KEY_TYPE_WPA_PWD)
	    g_print("TYPE: %s\n",AIRPCAP_WPA_PWD_KEY_STRING);
	else if(tmp->type == AIRPDCAP_KEY_TYPE_WPA_PMK)
	    g_print("TYPE: %s\n",AIRPCAP_WPA_BIN_KEY_STRING);
	else
	    g_print("TYPE: %s\n","???");

	g_print("SSID: %s\n",(tmp->ssid != NULL) ?
		format_text((guchar *)tmp->ssid->data, tmp->ssid->len) : "---");
	g_print("\n");
    }

    g_print("\n*****************************\n\n");
}

/*
 * Retrieves a GList of decryption_key_t structures containing infos about the
 * keys for the given adapter... returns NULL if no keys are found.
 */
GList*
get_airpcap_device_keys(airpcap_if_info_t* info_if)
{
    /* tmp vars */
    char* tmp_key = NULL;
    guint i,keys_in_list = 0;

    /* real vars*/
    decryption_key_t *new_key  = NULL;
    GList            *key_list = NULL;

    /* Number of keys in key list */
    if(info_if->keysCollectionSize != 0)
	keys_in_list = (guint)(info_if->keysCollectionSize -  sizeof(AirpcapKeysCollection))/sizeof(AirpcapKey);
    else
	keys_in_list = 0;

    for(i=0; i<keys_in_list; i++)
    {
	/* Different things to do depending on the key type  */
	if(info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WEP)
	{
	    /* allocate memory for the new key item */
	    new_key = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));

	    /* fill the fields */
	    /* KEY */
	    tmp_key = airpcap_get_key_string(info_if->keysCollection->Keys[i]);
	    new_key->key = g_string_new(tmp_key);
	    g_free(tmp_key);

	    /* BITS */
	    new_key->bits = (guint) new_key->key->len *4; /* every char is 4 bits in WEP keys (it is an hexadecimal number) */

	    /* SSID not used in WEP keys */
	    new_key->ssid = NULL;

	    /* TYPE (WEP in this case) */
	    new_key->type = info_if->keysCollection->Keys[i].KeyType;

	    /* Append the new element in the list */
	    key_list = g_list_append(key_list,(gpointer)new_key);
	}
	else if(info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WPA_PWD)
	{
	    /* XXX - Not supported yet */
	}
	else if(info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WPA_PMK)
	{
	    /* XXX - Not supported yet */
	}
    }

    return key_list;
}

/*
 * Retrieves a GList of decryption_key_t structures containing infos about the
 * keys for the global AirPcap driver... returns NULL if no keys are found.
 */
GList*
get_airpcap_driver_keys(void)
{
    /* tmp vars */
    char* tmp_key = NULL;
    guint i,keys_in_list = 0;

    /* real vars*/
    decryption_key_t *new_key  = NULL;
    GList            *key_list = NULL;

    /*
     * To read the drivers general settings we need to create and use one airpcap adapter...
     * The only way to do that is to instantiate a fake adapter, and then close it and delete it.
     */
    airpcap_if_info_t* fake_info_if = NULL;

    /* Create the fake_info_if from the first adapter of the list */
    fake_info_if = airpcap_driver_fake_if_info_new();

    if(fake_info_if == NULL)
	return NULL;

    /* Number of keys in key list */
    if(fake_info_if->keysCollectionSize != 0)
	keys_in_list = (guint)(fake_info_if->keysCollectionSize -  sizeof(AirpcapKeysCollection))/sizeof(AirpcapKey);
    else
	keys_in_list = 0;

    for(i=0; i<keys_in_list; i++)
    {
	/* Different things to do depending on the key type  */
	if(fake_info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WEP)
	{
	    /* allocate memory for the new key item */
	    new_key = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));

	    /* fill the fields */
	    /* KEY */
	    tmp_key = airpcap_get_key_string(fake_info_if->keysCollection->Keys[i]);
	    new_key->key = g_string_new(tmp_key);
	    if(tmp_key != NULL) g_free(tmp_key);

	    /* BITS */
	    new_key->bits = (guint) new_key->key->len *4; /* every char is 4 bits in WEP keys (it is an hexadecimal number) */

	    /* SSID not used in WEP keys */
	    new_key->ssid = NULL;

	    /* TYPE (WEP in this case) */
	    new_key->type = fake_info_if->keysCollection->Keys[i].KeyType;

	    /* Append the new element in the list */
	    key_list = g_list_append(key_list,(gpointer)new_key);
	}
	else if(fake_info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WPA_PWD)
	{
	    /* XXX - Not supported yet */
	}
	else if(fake_info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WPA_PMK)
	{
	    /* XXX - Not supported yet */
	}
    }

    airpcap_if_info_free(fake_info_if);

    return key_list;
}

/*
 * Returns the list of the decryption keys specified for wireshark, NULL if
 * no key is found
 */
GList*
get_wireshark_keys(void)
{
    keys_cb_data_t* wep_user_data = NULL;

    GList* final_list = NULL;
    GList* wep_final_list = NULL;

    /* Retrieve the wlan preferences */
    wlan_prefs = prefs_find_module("wlan");

    /* Allocate a structure used to keep infos  between the callbacks */
    wep_user_data = (keys_cb_data_t*)g_malloc(sizeof(keys_cb_data_t));

    /* Fill the structure */
    wep_user_data->list = NULL;
    wep_user_data->current_index = 0;
    wep_user_data->number_of_keys= 0; /* Still unknown */

    /* Run the callback on each 802.11 preference */
    /* XXX - Right now, only WEP keys will be loaded */
    prefs_pref_foreach(wlan_prefs, get_wep_key, (gpointer)wep_user_data);

    /* Copy the list field in the user data structure pointer into the final_list */
    if(wep_user_data != NULL)  wep_final_list  = wep_user_data->list;

    /* XXX - Merge the three lists!!!!! */
    final_list = wep_final_list;

    /* free the wep_user_data structure */
    g_free(wep_user_data);

    return final_list;
}

/*
 * Merges two lists of keys and return a newly created GList. If a key is
 * found multiple times, it will just appear once!
 * list1 and list 2 pointer will have to be freed manually if needed!!!
 * If the total number of keys exceeeds the maximum number allowed,
 * exceeding keys will be discarded...
 */
GList*
merge_key_list(GList* list1, GList* list2)
{
    guint n1=0,n2=0;
    guint i;
    decryption_key_t *dk1=NULL,
		      *dk2=NULL,
		      *new_dk=NULL;

    GList* merged_list = NULL;

    if( (list1 == NULL) && (list2 == NULL) )
	return NULL;

    if(list1 == NULL)
    {
	n1 = 0;
	n2 = g_list_length(list2);

	for(i=0;i<n2;i++)
	{
	    new_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
	    dk2 = (decryption_key_t *)g_list_nth_data(list2,i);

	    new_dk->bits = dk2->bits;
	    new_dk->type = dk2->type;
	    new_dk->key  = g_string_new(dk2->key->str);
	    new_dk->ssid = byte_array_dup(dk2->ssid);

	    /* Check the total length of the merged list */
	    if(g_list_length(merged_list) < MAX_ENCRYPTION_KEYS)
		merged_list = g_list_append(merged_list,(gpointer)new_dk);
	}
    }
    else if(list2 == NULL)
    {
	n1 = g_list_length(list1);
	n2 = 0;

	for(i=0;i<n1;i++)
	{
	    new_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
	    dk1 = (decryption_key_t*)g_list_nth_data(list1,i);

	    new_dk->bits = dk1->bits;
	    new_dk->type = dk1->type;
	    new_dk->key  = g_string_new(dk1->key->str);
	    new_dk->ssid = byte_array_dup(dk1->ssid);

	    /* Check the total length of the merged list */
	    if(g_list_length(merged_list) < MAX_ENCRYPTION_KEYS)
		merged_list = g_list_append(merged_list,(gpointer)new_dk);
	}
    }
    else
    {
	n1 = g_list_length(list1);
	n2 = g_list_length(list2);

	/* Copy the whole list1 into merged_list */
	for(i=0;i<n1;i++)
	{
	    new_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
	    dk1 = (decryption_key_t *)g_list_nth_data(list1,i);

	    new_dk->bits = dk1->bits;
	    new_dk->type = dk1->type;
	    new_dk->key  = g_string_new(dk1->key->str);
	    new_dk->ssid = byte_array_dup(dk1->ssid);

	    /* Check the total length of the merged list */
	    if(g_list_length(merged_list) < MAX_ENCRYPTION_KEYS)
		merged_list = g_list_append(merged_list,(gpointer)new_dk);
	}

	/* Look for keys that are present in list2 but aren't in list1 yet...
	 * Add them to merged_list
	 */
	for(i=0;i<n2;i++)
	{
	    dk2 = (decryption_key_t *)g_list_nth_data(list2,i);

	    if(!key_is_in_list(dk2,merged_list))
	    {
		new_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));

		new_dk->bits = dk2->bits;
		new_dk->type = dk2->type;
		new_dk->key  = g_string_new(dk2->key->str);
		new_dk->ssid = byte_array_dup(dk2->ssid);

		/* Check the total length of the merged list */
		if(g_list_length(merged_list) < MAX_ENCRYPTION_KEYS)
		    merged_list = g_list_append(merged_list,(gpointer)new_dk);
	    }
	}
    }

    return merged_list;
}

/*
 * Use this function to free a key list.
 */
void
free_key_list(GList *list)
{
    guint i,n;
    decryption_key_t *curr_key;

    if(list == NULL)
	return;

    n = g_list_length(list);

    for(i = 0; i < n; i++)
    {
	curr_key = (decryption_key_t*)g_list_nth_data(list,i);

	/* Free all the strings */
	if(curr_key->key != NULL)
	    g_string_free(curr_key->key, TRUE);

	if(curr_key->ssid != NULL)
	g_byte_array_free(curr_key->ssid, TRUE);

	/* free the decryption_key_t structure*/
	g_free(curr_key);
	curr_key = NULL;
    }

    /* Free the list */
    g_list_free(list);

    return;
}


/*
 * If the given key is contained in the list, returns TRUE.
 * Returns FALSE otherwise.
 */
gboolean
key_is_in_list(decryption_key_t *dk,GList *list)
{
    guint i,n;
    decryption_key_t* curr_key = NULL;
    gboolean found = FALSE;

    if( (list == NULL) || (dk == NULL) )
	return FALSE;

    n = g_list_length(list);

    if(n < 1)
	return FALSE;

    for(i = 0; i < n; i++)
    {
	curr_key = (decryption_key_t*)g_list_nth_data(list,i);
	if(keys_are_equals(dk,curr_key))
	    found = TRUE;
    }

    return found;
}

/*
 * Returns TRUE if keys are equals, FALSE otherwise
 */
gboolean
keys_are_equals(decryption_key_t *k1,decryption_key_t *k2)
{

    if((k1==NULL) || (k2==NULL))
	return FALSE;

    /* XXX - Remove this check when we will have the WPA/WPA2 decryption in the Driver! */
    /** if( (k1->type == AIRPDCAP_KEY_TYPE_WPA_PWD) || (k2->type == AIRPDCAP_KEY_TYPE_WPA_PWD) || (k1->type == AIRPDCAP_KEY_TYPE_WPA_PMK) || (k2->type == AIRPDCAP_KEY_TYPE_WPA_PMK) ) **/
    /** 	return TRUE;  **/

    if( g_string_equal(k1->key,k2->key) &&
	(k1->bits == k2->bits) && /* If the previous is TRUE, this must be TRUE as well */
	k1->type == k2->type)
    {
	/* Check the ssid... if the key type is WEP, the two fields should be NULL */
	if((k1->ssid == NULL) && (k2->ssid == NULL))
	    return TRUE;

	/* If they are not null, they must share the same ssid */
	return byte_array_equal(k1->ssid,k2->ssid);
    }

    /* Some field is not equal ... */
    return FALSE;
}

/*
 * Tests if two collection of keys are equal or not, to be considered equals, they have to
 * contain the same keys in the SAME ORDER! (If both lists are NULL, which means empty will
 * return TRUE)
 */
gboolean
key_lists_are_equal(GList* list1, GList* list2)
{
    guint n1=0,n2=0;
    /* XXX - Remove */
    guint wep_n1=0,wep_n2=0;
    GList *wep_list1=NULL;
    GList *wep_list2=NULL;
    /* XXX - END*/
    guint i/*,j*/;
    decryption_key_t *dk1=NULL,*dk2=NULL;

    n1 = g_list_length(list1);
    n2 = g_list_length(list2);

    /*
     * XXX - START : Retrieve the aublists of WEP keys!!! This is needed only 'till Driver WPA decryption
     * is implemented.
     */
    for(i=0;i<n1;i++)
    {
	dk1=(decryption_key_t*)g_list_nth_data(list1,i);
	if(dk1->type == AIRPDCAP_KEY_TYPE_WEP)
	{
	    wep_list1 = g_list_append(wep_list1,(gpointer)dk1);
	    wep_n1++;
	}
    }
    for(i=0;i<n2;i++)
    {
	dk2=(decryption_key_t*)g_list_nth_data(list2,i);
	if(dk2->type == AIRPDCAP_KEY_TYPE_WEP)
	{
	    wep_list2 = g_list_append(wep_list2,(gpointer)dk2);
	    wep_n2++;
	}
    }

    /*
     * XXX - END : Remove from START to END when the WPA/WPA2 decryption will be implemented in
     * the Driver
     */

    /*
     * Commented, because in the new AirPcap version all the keys will be saved
     * into the driver, and all the keys for every specific adapter will be
     * removed. This means that this check will always fail... and the user will
     * always be asked what to do... and it doesn't make much sense.
     */
    /* if(n1 != n2) return FALSE; */
    if(wep_n1 != wep_n2) return FALSE;

    n1 = wep_n1;
    n2 = wep_n2;

    /*for(i=0;i<n1;i++)
    {
    dk1=(decryption_key_t*)g_list_nth_data(list1,i);
    dk2=(decryption_key_t*)g_list_nth_data(list2,i);

    if(!g_string_equal(dk1->key,dk2->key)) return FALSE;
    }*/
    for(i=0;i<n2;i++)
    {
	dk2=(decryption_key_t*)g_list_nth_data(wep_list2,i);
	if(!key_is_in_list(dk2,wep_list1)) return FALSE;
    }

    return TRUE;
}

static guint
test_if_on(pref_t *pref, gpointer ud)
{
    gboolean *is_on;
    gboolean number;

    /* Retrieve user data info */
    is_on = (gboolean*)ud;


    if (g_ascii_strncasecmp(pref->name, "enable_decryption", 17) == 0 && pref->type == PREF_BOOL)
    {
	number = *pref->varp.boolp;

	if(number) *is_on = TRUE;
	else *is_on = FALSE;

	return 1;
    }
    return 0;
}

/*
 * Returns TRUE if the Wireshark decryption is active, false otherwise
 */
gboolean
wireshark_decryption_on(void)
{
    gboolean is_on;

    /* Retrieve the wlan preferences */
    wlan_prefs = prefs_find_module("wlan");

    /* Run the callback on each 802.11 preference */
    prefs_pref_foreach(wlan_prefs, test_if_on, (gpointer)&is_on);

    return is_on;
}

/*
 * Returns TRUE if the AirPcap decryption for the current adapter is active, false otherwise
 */
gboolean
airpcap_decryption_on(void)
{
    gboolean is_on = FALSE;

    airpcap_if_info_t* fake_if_info = NULL;

    fake_if_info = airpcap_driver_fake_if_info_new();

    if(fake_if_info != NULL)
    {
	if(fake_if_info->DecryptionOn == AIRPCAP_DECRYPTION_ON)
	    is_on = TRUE;
	else if(fake_if_info->DecryptionOn == AIRPCAP_DECRYPTION_OFF)
	    is_on = FALSE;
    }

    airpcap_if_info_free(fake_if_info);

    return is_on;
}

/*
 * Free an instance of airpcap_if_info_t
 */
void
airpcap_if_info_free(airpcap_if_info_t *if_info)
{
    if(if_info != NULL)
    {
	if (if_info->name != NULL)
	    g_free(if_info->name);

	if (if_info->description != NULL)
	    g_free(if_info->description);

	if(if_info->keysCollection != NULL)
	{
	    g_free(if_info->keysCollection);
	    if_info->keysCollection = NULL;
	}

	if(if_info->ip_addr != NULL)
	{
	    g_slist_free(if_info->ip_addr);
	    if_info->ip_addr = NULL;
	}

	if(if_info != NULL)
	{
	    g_free(if_info);
	    if_info = NULL;
	}
    }
}

static guint
set_on_off(pref_t *pref, gpointer ud)
{
    gboolean *is_on;
    gboolean number;

    /* Retrieve user data info */
    is_on = (gboolean*)ud;

    if (g_ascii_strncasecmp(pref->name, "enable_decryption", 17) == 0 && pref->type == PREF_BOOL)
    {
	number = *pref->varp.boolp;

	if(*is_on)
	    *pref->varp.boolp = TRUE;
	else
	    *pref->varp.boolp = FALSE;

	return 1;
    }
    return 0;
}

/*
 * Enables decryption for Wireshark if on_off is TRUE, disables it otherwise.
 */
void
set_wireshark_decryption(gboolean on_off)
{
    gboolean is_on;

    is_on = on_off;

    /* Retrieve the wlan preferences */
    wlan_prefs = prefs_find_module("wlan");

    /* Run the callback on each 802.11 preference */
    prefs_pref_foreach(wlan_prefs, set_on_off, (gpointer)&is_on);

    /*
     * Signal that we've changed things, and run the 802.11 dissector's
     * callback
     */
    wlan_prefs->prefs_changed = TRUE;

    prefs_apply(wlan_prefs);
}

/*
 * Enables decryption for all the adapters if on_off is TRUE, disables it otherwise.
 */
gboolean
set_airpcap_decryption(gboolean on_off)
{
    /* We need to directly access the .dll functions here... */
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];
    PAirpcapHandle ad,ad_driver;

    gboolean success = TRUE;

    gint n = 0;
    gint i = 0;
    airpcap_if_info_t* curr_if = NULL;
    airpcap_if_info_t* fake_if_info = NULL;

    fake_if_info = airpcap_driver_fake_if_info_new();

    if(fake_if_info == NULL)
	/* We apparently don't have any adapters installed.
	 * This isn't a failure, so return TRUE
	 */
	return TRUE;

	/* Set the driver decryption */
	ad_driver = airpcap_if_open(fake_if_info->name, ebuf);
	if(ad_driver)
	{
	    if(on_off)
		airpcap_if_set_driver_decryption_state(ad_driver,AIRPCAP_DECRYPTION_ON);
	    else
		airpcap_if_set_driver_decryption_state(ad_driver,AIRPCAP_DECRYPTION_OFF);

	    airpcap_if_close(ad_driver);
	}

	airpcap_if_info_free(fake_if_info);

	n = g_list_length(airpcap_if_list);

	/* Set to FALSE the decryption for all the adapters */
	/* Apply this change to all the adapters !!! */
	for(i = 0; i < n; i++)
	{
	    curr_if = (airpcap_if_info_t*)g_list_nth_data(airpcap_if_list,i);

	    if( curr_if != NULL )
	    {
		ad = airpcap_if_open(curr_if->name, ebuf);
		if(ad)
		{
		    curr_if->DecryptionOn = (gboolean)AIRPCAP_DECRYPTION_OFF;
		    airpcap_if_set_decryption_state(ad,curr_if->DecryptionOn);
		    /* Save configuration for the curr_if */
		    if(!airpcap_if_store_cur_config_as_adapter_default(ad))
		    {
			success = FALSE;
		    }
		    airpcap_if_close(ad);
		}
	    }
	}

	return success;
}


/* DYNAMIC LIBRARY LOADER */
/*
 *  Used to dynamically load the airpcap library in order link it only when
 *  it's present on the system
 */
int load_airpcap(void)
{
#ifdef _WIN32
    gboolean base_functions = TRUE;
    gboolean eleven_n_functions = TRUE;

    if((AirpcapLib = ws_load_library("airpcap.dll")) == NULL)
    {
  		/* Report the error but go on */
  		AirpcapVersion = AIRPCAP_DLL_NOT_FOUND;
  		return AirpcapVersion;
    }
    else
    {
  		if((g_PAirpcapGetLastError = (AirpcapGetLastErrorHandler) GetProcAddress(AirpcapLib, "AirpcapGetLastError")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetDeviceList = (AirpcapGetDeviceListHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceList")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapFreeDeviceList = (AirpcapFreeDeviceListHandler) GetProcAddress(AirpcapLib, "AirpcapFreeDeviceList")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapOpen = (AirpcapOpenHandler) GetProcAddress(AirpcapLib, "AirpcapOpen")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapClose = (AirpcapCloseHandler) GetProcAddress(AirpcapLib, "AirpcapClose")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetLinkType = (AirpcapGetLinkTypeHandler) GetProcAddress(AirpcapLib, "AirpcapGetLinkType")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapSetLinkType = (AirpcapSetLinkTypeHandler) GetProcAddress(AirpcapLib, "AirpcapSetLinkType")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapSetKernelBuffer = (AirpcapSetKernelBufferHandler) GetProcAddress(AirpcapLib, "AirpcapSetKernelBuffer")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapSetFilter = (AirpcapSetFilterHandler) GetProcAddress(AirpcapLib, "AirpcapSetFilter")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetMacAddress = (AirpcapGetMacAddressHandler) GetProcAddress(AirpcapLib, "AirpcapGetMacAddress")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapSetMinToCopy = (AirpcapSetMinToCopyHandler) GetProcAddress(AirpcapLib, "AirpcapSetMinToCopy")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetReadEvent = (AirpcapGetReadEventHandler) GetProcAddress(AirpcapLib, "AirpcapGetReadEvent")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapRead = (AirpcapReadHandler) GetProcAddress(AirpcapLib, "AirpcapRead")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetStats = (AirpcapGetStatsHandler) GetProcAddress(AirpcapLib, "AirpcapGetStats")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapTurnLedOn = (AirpcapTurnLedOnHandler) GetProcAddress(AirpcapLib, "AirpcapTurnLedOn")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapTurnLedOff = (AirpcapTurnLedOffHandler) GetProcAddress(AirpcapLib, "AirpcapTurnLedOff")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetDeviceChannel = (AirpcapGetDeviceChannelHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceChannel")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapSetDeviceChannel = (AirpcapSetDeviceChannelHandler) GetProcAddress(AirpcapLib, "AirpcapSetDeviceChannel")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetFcsPresence = (AirpcapGetFcsPresenceHandler) GetProcAddress(AirpcapLib, "AirpcapGetFcsPresence")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapSetFcsPresence = (AirpcapSetFcsPresenceHandler) GetProcAddress(AirpcapLib, "AirpcapSetFcsPresence")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetFcsValidation = (AirpcapGetFcsValidationHandler) GetProcAddress(AirpcapLib, "AirpcapGetFcsValidation")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapSetFcsValidation = (AirpcapSetFcsValidationHandler) GetProcAddress(AirpcapLib, "AirpcapSetFcsValidation")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetDeviceKeys = (AirpcapGetDeviceKeysHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceKeys")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapSetDeviceKeys = (AirpcapSetDeviceKeysHandler) GetProcAddress(AirpcapLib, "AirpcapSetDeviceKeys")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetDecryptionState = (AirpcapGetDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapGetDecryptionState")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapSetDecryptionState = (AirpcapSetDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapSetDecryptionState")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapStoreCurConfigAsAdapterDefault = (AirpcapStoreCurConfigAsAdapterDefaultHandler) GetProcAddress(AirpcapLib, "AirpcapStoreCurConfigAsAdapterDefault")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetVersion = (AirpcapGetVersionHandler) GetProcAddress(AirpcapLib, "AirpcapGetVersion")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetDriverDecryptionState = (AirpcapGetDriverDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapGetDriverDecryptionState")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapSetDriverDecryptionState = (AirpcapSetDriverDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapSetDriverDecryptionState")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapGetDriverKeys = (AirpcapGetDriverKeysHandler) GetProcAddress(AirpcapLib, "AirpcapGetDriverKeys")) == NULL) base_functions = FALSE;
  		if((g_PAirpcapSetDriverKeys = (AirpcapSetDriverKeysHandler) GetProcAddress(AirpcapLib, "AirpcapSetDriverKeys")) == NULL) base_functions = FALSE;

  		/* TEST IF AIRPCAP SUPPORTS 11N */
  		if((g_PAirpcapSetDeviceChannelEx = (AirpcapSetDeviceChannelExHandler) GetProcAddress(AirpcapLib, "AirpcapSetDeviceChannelEx")) == NULL) eleven_n_functions = FALSE;
  		if((g_PAirpcapGetDeviceChannelEx = (AirpcapGetDeviceChannelExHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceChannelEx")) == NULL) eleven_n_functions = FALSE;
  		if((g_PAirpcapGetDeviceSupportedChannels = (AirpcapGetDeviceSupportedChannelsHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceSupportedChannels")) == NULL) eleven_n_functions = FALSE;

  		if(base_functions && eleven_n_functions){
  			AirpcapLoaded = TRUE;
  			AirpcapVersion = AIRPCAP_DLL_OK;
  		}else if(base_functions){
  			AirpcapLoaded = TRUE;
  			AirpcapVersion = AIRPCAP_DLL_OLD;
  			return AIRPCAP_DLL_OK;
  		}else{
  			AirpcapLoaded = FALSE;
  			AirpcapVersion = AIRPCAP_DLL_ERROR;
  		}
    }
    return AirpcapVersion;
#else /* _WIN32 */
    return AIRPCAP_DLL_NOT_FOUND;
#endif /* _WIN32 */
}

/*
 * Append the version of AirPcap with which we were compiled to a GString.
 */
void
get_compiled_airpcap_version(GString *str)
{
    g_string_append(str, "with AirPcap");
}

/*
 * Append the version of AirPcap with which we we're running to a GString.
 */
void
get_runtime_airpcap_version(GString *str)
{
    guint vmaj, vmin, vrev, build;

    /* See if the DLL has been loaded successfully.  Bail if it hasn't */
    if (AirpcapLoaded == FALSE) {
	g_string_append(str, "without AirPcap");
	return;
    }

    g_PAirpcapGetVersion(&vmaj, &vmin, &vrev, &build);
    g_string_append_printf(str, "with AirPcap %d.%d.%d build %d", vmaj, vmin,
	vrev, build);
}
#endif /* HAVE_AIRPCAP */
