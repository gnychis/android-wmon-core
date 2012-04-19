/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2007 - 2012 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called LICENSE.GPL.
 *
 * Contact Information:
 *  Intel Linux Wireless <ilw@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2005 - 2012 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/
#ifndef __iwl_shared_h__
#define __iwl_shared_h__

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/gfp.h>
#include <net/mac80211.h>

#include "iwl-commands.h"
#include "iwl-fw.h"
#include "iwl-config.h"

/**
 * DOC: shared area - role and goal
 *
 * The shared area contains all the data exported by the upper layer to the
 * other layers. Since the bus and transport layer shouldn't dereference
 * iwl_priv, all the data needed by the upper layer and the transport / bus
 * layer must be here.
 * The shared area also holds pointer to all the other layers. This allows a
 * layer to call a function from another layer.
 *
 * NOTE: All the layers hold a pointer to the shared area which must be shrd.
 *	A few macros assume that (_m)->shrd points to the shared area no matter
 *	what _m is.
 *
 * gets notifications about enumeration, suspend, resume.
 * For the moment, the bus layer is not a linux kernel module as itself, and
 * the module_init function of the driver must call the bus specific
 * registration functions. These functions are listed at the end of this file.
 * For the moment, there is only one implementation of this interface: PCI-e.
 * This implementation is iwl-pci.c
 */

struct iwl_priv;
struct iwl_trans;
struct iwl_trans_ops;

#define DRV_NAME        "iwlwifi"
#define IWLWIFI_VERSION "in-tree:"
#define DRV_COPYRIGHT	"Copyright(c) 2003-2012 Intel Corporation"
#define DRV_AUTHOR     "<ilw@linux.intel.com>"

extern struct iwl_mod_params iwlagn_mod_params;

#define IWL_DISABLE_HT_ALL	BIT(0)
#define IWL_DISABLE_HT_TXAGG	BIT(1)
#define IWL_DISABLE_HT_RXAGG	BIT(2)

/**
 * struct iwl_mod_params
 *
 * Holds the module parameters
 *
 * @sw_crypto: using hardware encryption, default = 0
 * @disable_11n: disable 11n capabilities, default = 0,
 *	use IWL_DISABLE_HT_* constants
 * @amsdu_size_8K: enable 8K amsdu size, default = 1
 * @antenna: both antennas (use diversity), default = 0
 * @restart_fw: restart firmware, default = 1
 * @plcp_check: enable plcp health check, default = true
 * @wd_disable: enable stuck queue check, default = 0
 * @bt_coex_active: enable bt coex, default = true
 * @led_mode: system default, default = 0
 * @no_sleep_autoadjust: disable autoadjust, default = true
 * @power_save: disable power save, default = false
 * @power_level: power level, default = 1
 * @debug_level: levels are IWL_DL_*
 * @ant_coupling: antenna coupling in dB, default = 0
 * @bt_ch_announce: BT channel inhibition, default = enable
 * @wanted_ucode_alternative: ucode alternative to use, default = 1
 * @auto_agg: enable agg. without check, default = true
 */
struct iwl_mod_params {
	int sw_crypto;
	unsigned int disable_11n;
	int amsdu_size_8K;
	int antenna;
	int restart_fw;
	bool plcp_check;
	int  wd_disable;
	bool bt_coex_active;
	int led_mode;
	bool no_sleep_autoadjust;
	bool power_save;
	int power_level;
	u32 debug_level;
	int ant_coupling;
	bool bt_ch_announce;
	int wanted_ucode_alternative;
	bool auto_agg;
};

/**
 * struct iwl_shared - shared fields for all the layers of the driver
 *
 * @status: STATUS_*
 * @wowlan: are we running wowlan uCode
 * @bus: pointer to the bus layer data
 * @cfg: see struct iwl_cfg
 * @priv: pointer to the upper layer data
 * @trans: pointer to the transport layer data
 * @nic: pointer to the nic data
 * @lock: protect general shared data
 * @eeprom: pointer to the eeprom/OTP image
 */
struct iwl_shared {
	unsigned long status;

	const struct iwl_cfg *cfg;
	struct iwl_trans *trans;
	void *drv;
};

/*Whatever _m is (iwl_trans, iwl_priv, these macros will work */
#define cfg(_m)		((_m)->shrd->cfg)
#define trans(_m)	((_m)->shrd->trans)

static inline bool iwl_have_debug_level(u32 level)
{
	return iwlagn_mod_params.debug_level & level;
}

enum iwl_rxon_context_id {
	IWL_RXON_CTX_BSS,
	IWL_RXON_CTX_PAN,

	NUM_IWL_RXON_CTX
};

int iwlagn_hw_valid_rtc_data_addr(u32 addr);
const char *get_cmd_string(u8 cmd);

#define IWL_CMD(x) case x: return #x

/*****************************************************
* DRIVER STATUS FUNCTIONS
******************************************************/
#define STATUS_HCMD_ACTIVE	0	/* host command in progress */
/* 1 is unused (used to be STATUS_HCMD_SYNC_ACTIVE) */
#define STATUS_INT_ENABLED	2
#define STATUS_RF_KILL_HW	3
#define STATUS_CT_KILL		4
#define STATUS_INIT		5
#define STATUS_ALIVE		6
#define STATUS_READY		7
#define STATUS_TEMPERATURE	8
#define STATUS_GEO_CONFIGURED	9
#define STATUS_EXIT_PENDING	10
#define STATUS_STATISTICS	12
#define STATUS_SCANNING		13
#define STATUS_SCAN_ABORTING	14
#define STATUS_SCAN_HW		15
#define STATUS_POWER_PMI	16
#define STATUS_FW_ERROR		17
#define STATUS_DEVICE_ENABLED	18
#define STATUS_CHANNEL_SWITCH_PENDING 19
#define STATUS_SCAN_COMPLETE	20

#endif /* #__iwl_shared_h__ */
