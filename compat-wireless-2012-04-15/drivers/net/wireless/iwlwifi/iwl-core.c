/******************************************************************************
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2008 - 2012 Intel Corporation. All rights reserved.
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
 *****************************************************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <net/mac80211.h>

#include "iwl-eeprom.h"
#include "iwl-debug.h"
#include "iwl-core.h"
#include "iwl-io.h"
#include "iwl-power.h"
#include "iwl-shared.h"
#include "iwl-agn.h"
#include "iwl-trans.h"

const u8 iwl_bcast_addr[ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static bool iwl_is_channel_extension(struct iwl_priv *priv,
				     enum ieee80211_band band,
				     u16 channel, u8 extension_chan_offset)
{
	const struct iwl_channel_info *ch_info;

	ch_info = iwl_get_channel_info(priv, band, channel);
	if (!is_channel_valid(ch_info))
		return false;

	if (extension_chan_offset == IEEE80211_HT_PARAM_CHA_SEC_ABOVE)
		return !(ch_info->ht40_extension_channel &
					IEEE80211_CHAN_NO_HT40PLUS);
	else if (extension_chan_offset == IEEE80211_HT_PARAM_CHA_SEC_BELOW)
		return !(ch_info->ht40_extension_channel &
					IEEE80211_CHAN_NO_HT40MINUS);

	return false;
}

bool iwl_is_ht40_tx_allowed(struct iwl_priv *priv,
			    struct iwl_rxon_context *ctx,
			    struct ieee80211_sta_ht_cap *ht_cap)
{
	if (!ctx->ht.enabled || !ctx->ht.is_40mhz)
		return false;

	/*
	 * We do not check for IEEE80211_HT_CAP_SUP_WIDTH_20_40
	 * the bit will not set if it is pure 40MHz case
	 */
	if (ht_cap && !ht_cap->ht_supported)
		return false;

#ifdef CONFIG_IWLWIFI_DEBUGFS
	if (priv->disable_ht40)
		return false;
#endif

	return iwl_is_channel_extension(priv, priv->band,
			le16_to_cpu(ctx->staging.channel),
			ctx->ht.extension_chan_offset);
}

static void _iwl_set_rxon_ht(struct iwl_priv *priv,
			     struct iwl_ht_config *ht_conf,
			     struct iwl_rxon_context *ctx)
{
	struct iwl_rxon_cmd *rxon = &ctx->staging;

	if (!ctx->ht.enabled) {
		rxon->flags &= ~(RXON_FLG_CHANNEL_MODE_MSK |
			RXON_FLG_CTRL_CHANNEL_LOC_HI_MSK |
			RXON_FLG_HT40_PROT_MSK |
			RXON_FLG_HT_PROT_MSK);
		return;
	}

	/* FIXME: if the definition of ht.protection changed, the "translation"
	 * will be needed for rxon->flags
	 */
	rxon->flags |= cpu_to_le32(ctx->ht.protection << RXON_FLG_HT_OPERATING_MODE_POS);

	/* Set up channel bandwidth:
	 * 20 MHz only, 20/40 mixed or pure 40 if ht40 ok */
	/* clear the HT channel mode before set the mode */
	rxon->flags &= ~(RXON_FLG_CHANNEL_MODE_MSK |
			 RXON_FLG_CTRL_CHANNEL_LOC_HI_MSK);
	if (iwl_is_ht40_tx_allowed(priv, ctx, NULL)) {
		/* pure ht40 */
		if (ctx->ht.protection == IEEE80211_HT_OP_MODE_PROTECTION_20MHZ) {
			rxon->flags |= RXON_FLG_CHANNEL_MODE_PURE_40;
			/* Note: control channel is opposite of extension channel */
			switch (ctx->ht.extension_chan_offset) {
			case IEEE80211_HT_PARAM_CHA_SEC_ABOVE:
				rxon->flags &= ~RXON_FLG_CTRL_CHANNEL_LOC_HI_MSK;
				break;
			case IEEE80211_HT_PARAM_CHA_SEC_BELOW:
				rxon->flags |= RXON_FLG_CTRL_CHANNEL_LOC_HI_MSK;
				break;
			}
		} else {
			/* Note: control channel is opposite of extension channel */
			switch (ctx->ht.extension_chan_offset) {
			case IEEE80211_HT_PARAM_CHA_SEC_ABOVE:
				rxon->flags &= ~(RXON_FLG_CTRL_CHANNEL_LOC_HI_MSK);
				rxon->flags |= RXON_FLG_CHANNEL_MODE_MIXED;
				break;
			case IEEE80211_HT_PARAM_CHA_SEC_BELOW:
				rxon->flags |= RXON_FLG_CTRL_CHANNEL_LOC_HI_MSK;
				rxon->flags |= RXON_FLG_CHANNEL_MODE_MIXED;
				break;
			case IEEE80211_HT_PARAM_CHA_SEC_NONE:
			default:
				/* channel location only valid if in Mixed mode */
				IWL_ERR(priv, "invalid extension channel offset\n");
				break;
			}
		}
	} else {
		rxon->flags |= RXON_FLG_CHANNEL_MODE_LEGACY;
	}

	iwlagn_set_rxon_chain(priv, ctx);

	IWL_DEBUG_ASSOC(priv, "rxon flags 0x%X operation mode :0x%X "
			"extension channel offset 0x%x\n",
			le32_to_cpu(rxon->flags), ctx->ht.protection,
			ctx->ht.extension_chan_offset);
}

void iwl_set_rxon_ht(struct iwl_priv *priv, struct iwl_ht_config *ht_conf)
{
	struct iwl_rxon_context *ctx;

	for_each_context(priv, ctx)
		_iwl_set_rxon_ht(priv, ht_conf, ctx);
}

/**
 * iwl_set_rxon_channel - Set the band and channel values in staging RXON
 * @ch: requested channel as a pointer to struct ieee80211_channel

 * NOTE:  Does not commit to the hardware; it sets appropriate bit fields
 * in the staging RXON flag structure based on the ch->band
 */
void iwl_set_rxon_channel(struct iwl_priv *priv, struct ieee80211_channel *ch,
			 struct iwl_rxon_context *ctx)
{
	enum ieee80211_band band = ch->band;
	u16 channel = ch->hw_value;

	if ((le16_to_cpu(ctx->staging.channel) == channel) &&
	    (priv->band == band))
		return;

	ctx->staging.channel = cpu_to_le16(channel);
	if (band == IEEE80211_BAND_5GHZ)
		ctx->staging.flags &= ~RXON_FLG_BAND_24G_MSK;
	else
		ctx->staging.flags |= RXON_FLG_BAND_24G_MSK;

	priv->band = band;

	IWL_DEBUG_INFO(priv, "Staging channel set to %d [%d]\n", channel, band);

}

void iwl_set_flags_for_band(struct iwl_priv *priv,
			    struct iwl_rxon_context *ctx,
			    enum ieee80211_band band,
			    struct ieee80211_vif *vif)
{
	if (band == IEEE80211_BAND_5GHZ) {
		ctx->staging.flags &=
		    ~(RXON_FLG_BAND_24G_MSK | RXON_FLG_AUTO_DETECT_MSK
		      | RXON_FLG_CCK_MSK);
		ctx->staging.flags |= RXON_FLG_SHORT_SLOT_MSK;
	} else {
		/* Copied from iwl_post_associate() */
		if (vif && vif->bss_conf.use_short_slot)
			ctx->staging.flags |= RXON_FLG_SHORT_SLOT_MSK;
		else
			ctx->staging.flags &= ~RXON_FLG_SHORT_SLOT_MSK;

		ctx->staging.flags |= RXON_FLG_BAND_24G_MSK;
		ctx->staging.flags |= RXON_FLG_AUTO_DETECT_MSK;
		ctx->staging.flags &= ~RXON_FLG_CCK_MSK;
	}
}

/*
 * initialize rxon structure with default values from eeprom
 */
void iwl_connection_init_rx_config(struct iwl_priv *priv,
				   struct iwl_rxon_context *ctx)
{
	const struct iwl_channel_info *ch_info;

	memset(&ctx->staging, 0, sizeof(ctx->staging));

	if (!ctx->vif) {
		ctx->staging.dev_type = ctx->unused_devtype;
	} else switch (ctx->vif->type) {
	case NL80211_IFTYPE_AP:
		ctx->staging.dev_type = ctx->ap_devtype;
		break;

	case NL80211_IFTYPE_STATION:
		ctx->staging.dev_type = ctx->station_devtype;
		ctx->staging.filter_flags = RXON_FILTER_ACCEPT_GRP_MSK;
		break;

	case NL80211_IFTYPE_ADHOC:
		ctx->staging.dev_type = ctx->ibss_devtype;
		ctx->staging.flags = RXON_FLG_SHORT_PREAMBLE_MSK;
		ctx->staging.filter_flags = RXON_FILTER_BCON_AWARE_MSK |
						  RXON_FILTER_ACCEPT_GRP_MSK;
		break;

	default:
		IWL_ERR(priv, "Unsupported interface type %d\n",
			ctx->vif->type);
		break;
	}

#if 0
	/* TODO:  Figure out when short_preamble would be set and cache from
	 * that */
	if (!hw_to_local(priv->hw)->short_preamble)
		ctx->staging.flags &= ~RXON_FLG_SHORT_PREAMBLE_MSK;
	else
		ctx->staging.flags |= RXON_FLG_SHORT_PREAMBLE_MSK;
#endif

	ch_info = iwl_get_channel_info(priv, priv->band,
				       le16_to_cpu(ctx->active.channel));

	if (!ch_info)
		ch_info = &priv->channel_info[0];

	ctx->staging.channel = cpu_to_le16(ch_info->channel);
	priv->band = ch_info->band;

	iwl_set_flags_for_band(priv, ctx, priv->band, ctx->vif);

	ctx->staging.ofdm_basic_rates =
	    (IWL_OFDM_RATES_MASK >> IWL_FIRST_OFDM_RATE) & 0xFF;
	ctx->staging.cck_basic_rates =
	    (IWL_CCK_RATES_MASK >> IWL_FIRST_CCK_RATE) & 0xF;

	/* clear both MIX and PURE40 mode flag */
	ctx->staging.flags &= ~(RXON_FLG_CHANNEL_MODE_MIXED |
					RXON_FLG_CHANNEL_MODE_PURE_40);
	if (ctx->vif)
		memcpy(ctx->staging.node_addr, ctx->vif->addr, ETH_ALEN);

	ctx->staging.ofdm_ht_single_stream_basic_rates = 0xff;
	ctx->staging.ofdm_ht_dual_stream_basic_rates = 0xff;
	ctx->staging.ofdm_ht_triple_stream_basic_rates = 0xff;
}

void iwl_set_rate(struct iwl_priv *priv)
{
	const struct ieee80211_supported_band *hw = NULL;
	struct ieee80211_rate *rate;
	struct iwl_rxon_context *ctx;
	int i;

	hw = iwl_get_hw_mode(priv, priv->band);
	if (!hw) {
		IWL_ERR(priv, "Failed to set rate: unable to get hw mode\n");
		return;
	}

	priv->active_rate = 0;

	for (i = 0; i < hw->n_bitrates; i++) {
		rate = &(hw->bitrates[i]);
		if (rate->hw_value < IWL_RATE_COUNT_LEGACY)
			priv->active_rate |= (1 << rate->hw_value);
	}

	IWL_DEBUG_RATE(priv, "Set active_rate = %0x\n", priv->active_rate);

	for_each_context(priv, ctx) {
		ctx->staging.cck_basic_rates =
		    (IWL_CCK_BASIC_RATES_MASK >> IWL_FIRST_CCK_RATE) & 0xF;

		ctx->staging.ofdm_basic_rates =
		   (IWL_OFDM_BASIC_RATES_MASK >> IWL_FIRST_OFDM_RATE) & 0xFF;
	}
}

void iwl_chswitch_done(struct iwl_priv *priv, bool is_success)
{
	/*
	 * MULTI-FIXME
	 * See iwlagn_mac_channel_switch.
	 */
	struct iwl_rxon_context *ctx = &priv->contexts[IWL_RXON_CTX_BSS];

	if (test_bit(STATUS_EXIT_PENDING, &priv->status))
		return;

	if (test_and_clear_bit(STATUS_CHANNEL_SWITCH_PENDING, &priv->status))
		ieee80211_chswitch_done(ctx->vif, is_success);
}

#ifdef CONFIG_IWLWIFI_DEBUG
void iwl_print_rx_config_cmd(struct iwl_priv *priv,
			     enum iwl_rxon_context_id ctxid)
{
	struct iwl_rxon_context *ctx = &priv->contexts[ctxid];
	struct iwl_rxon_cmd *rxon = &ctx->staging;

	IWL_DEBUG_RADIO(priv, "RX CONFIG:\n");
	iwl_print_hex_dump(priv, IWL_DL_RADIO, (u8 *) rxon, sizeof(*rxon));
	IWL_DEBUG_RADIO(priv, "u16 channel: 0x%x\n", le16_to_cpu(rxon->channel));
	IWL_DEBUG_RADIO(priv, "u32 flags: 0x%08X\n", le32_to_cpu(rxon->flags));
	IWL_DEBUG_RADIO(priv, "u32 filter_flags: 0x%08x\n",
			le32_to_cpu(rxon->filter_flags));
	IWL_DEBUG_RADIO(priv, "u8 dev_type: 0x%x\n", rxon->dev_type);
	IWL_DEBUG_RADIO(priv, "u8 ofdm_basic_rates: 0x%02x\n",
			rxon->ofdm_basic_rates);
	IWL_DEBUG_RADIO(priv, "u8 cck_basic_rates: 0x%02x\n", rxon->cck_basic_rates);
	IWL_DEBUG_RADIO(priv, "u8[6] node_addr: %pM\n", rxon->node_addr);
	IWL_DEBUG_RADIO(priv, "u8[6] bssid_addr: %pM\n", rxon->bssid_addr);
	IWL_DEBUG_RADIO(priv, "u16 assoc_id: 0x%x\n", le16_to_cpu(rxon->assoc_id));
}
#endif

void iwlagn_fw_error(struct iwl_priv *priv, bool ondemand)
{
	unsigned int reload_msec;
	unsigned long reload_jiffies;

#ifdef CONFIG_IWLWIFI_DEBUG
	if (iwl_have_debug_level(IWL_DL_FW_ERRORS))
		iwl_print_rx_config_cmd(priv, IWL_RXON_CTX_BSS);
#endif

	/* uCode is no longer loaded. */
	priv->ucode_loaded = false;

	/* Set the FW error flag -- cleared on iwl_down */
	set_bit(STATUS_FW_ERROR, &priv->status);

	/* Cancel currently queued command. */
	clear_bit(STATUS_HCMD_ACTIVE, &priv->shrd->status);

	iwl_abort_notification_waits(&priv->notif_wait);

	/* Keep the restart process from trying to send host
	 * commands by clearing the ready bit */
	clear_bit(STATUS_READY, &priv->status);

	wake_up(&trans(priv)->wait_command_queue);

	if (!ondemand) {
		/*
		 * If firmware keep reloading, then it indicate something
		 * serious wrong and firmware having problem to recover
		 * from it. Instead of keep trying which will fill the syslog
		 * and hang the system, let's just stop it
		 */
		reload_jiffies = jiffies;
		reload_msec = jiffies_to_msecs((long) reload_jiffies -
					(long) priv->reload_jiffies);
		priv->reload_jiffies = reload_jiffies;
		if (reload_msec <= IWL_MIN_RELOAD_DURATION) {
			priv->reload_count++;
			if (priv->reload_count >= IWL_MAX_CONTINUE_RELOAD_CNT) {
				IWL_ERR(priv, "BUG_ON, Stop restarting\n");
				return;
			}
		} else
			priv->reload_count = 0;
	}

	if (!test_bit(STATUS_EXIT_PENDING, &priv->status)) {
		if (iwlagn_mod_params.restart_fw) {
			IWL_DEBUG_FW_ERRORS(priv,
				  "Restarting adapter due to uCode error.\n");
			queue_work(priv->workqueue, &priv->restart);
		} else
			IWL_DEBUG_FW_ERRORS(priv,
				  "Detected FW error, but not restarting\n");
	}
}

int iwl_set_tx_power(struct iwl_priv *priv, s8 tx_power, bool force)
{
	int ret;
	s8 prev_tx_power;
	bool defer;
	struct iwl_rxon_context *ctx = &priv->contexts[IWL_RXON_CTX_BSS];

	lockdep_assert_held(&priv->mutex);

	if (priv->tx_power_user_lmt == tx_power && !force)
		return 0;

	if (tx_power < IWLAGN_TX_POWER_TARGET_POWER_MIN) {
		IWL_WARN(priv,
			 "Requested user TXPOWER %d below lower limit %d.\n",
			 tx_power,
			 IWLAGN_TX_POWER_TARGET_POWER_MIN);
		return -EINVAL;
	}

	if (tx_power > priv->tx_power_device_lmt) {
		IWL_WARN(priv,
			"Requested user TXPOWER %d above upper limit %d.\n",
			 tx_power, priv->tx_power_device_lmt);
		return -EINVAL;
	}

	if (!iwl_is_ready_rf(priv))
		return -EIO;

	/* scan complete and commit_rxon use tx_power_next value,
	 * it always need to be updated for newest request */
	priv->tx_power_next = tx_power;

	/* do not set tx power when scanning or channel changing */
	defer = test_bit(STATUS_SCANNING, &priv->status) ||
		memcmp(&ctx->active, &ctx->staging, sizeof(ctx->staging));
	if (defer && !force) {
		IWL_DEBUG_INFO(priv, "Deferring tx power set\n");
		return 0;
	}

	prev_tx_power = priv->tx_power_user_lmt;
	priv->tx_power_user_lmt = tx_power;

	ret = iwlagn_send_tx_power(priv);

	/* if fail to set tx_power, restore the orig. tx power */
	if (ret) {
		priv->tx_power_user_lmt = prev_tx_power;
		priv->tx_power_next = prev_tx_power;
	}
	return ret;
}

void iwl_send_bt_config(struct iwl_priv *priv)
{
	struct iwl_bt_cmd bt_cmd = {
		.lead_time = BT_LEAD_TIME_DEF,
		.max_kill = BT_MAX_KILL_DEF,
		.kill_ack_mask = 0,
		.kill_cts_mask = 0,
	};

	if (!iwlagn_mod_params.bt_coex_active)
		bt_cmd.flags = BT_COEX_DISABLE;
	else
		bt_cmd.flags = BT_COEX_ENABLE;

	priv->bt_enable_flag = bt_cmd.flags;
	IWL_DEBUG_INFO(priv, "BT coex %s\n",
		(bt_cmd.flags == BT_COEX_DISABLE) ? "disable" : "active");

	if (iwl_dvm_send_cmd_pdu(priv, REPLY_BT_CONFIG,
			     CMD_SYNC, sizeof(struct iwl_bt_cmd), &bt_cmd))
		IWL_ERR(priv, "failed to send BT Coex Config\n");
}

int iwl_send_statistics_request(struct iwl_priv *priv, u8 flags, bool clear)
{
	struct iwl_statistics_cmd statistics_cmd = {
		.configuration_flags =
			clear ? IWL_STATS_CONF_CLEAR_STATS : 0,
	};

	if (flags & CMD_ASYNC)
		return iwl_dvm_send_cmd_pdu(priv, REPLY_STATISTICS_CMD,
					      CMD_ASYNC,
					       sizeof(struct iwl_statistics_cmd),
					       &statistics_cmd);
	else
		return iwl_dvm_send_cmd_pdu(priv, REPLY_STATISTICS_CMD,
					CMD_SYNC,
					sizeof(struct iwl_statistics_cmd),
					&statistics_cmd);
}




#ifdef CONFIG_IWLWIFI_DEBUGFS

#define IWL_TRAFFIC_DUMP_SIZE	(IWL_TRAFFIC_ENTRY_SIZE * IWL_TRAFFIC_ENTRIES)

void iwl_reset_traffic_log(struct iwl_priv *priv)
{
	priv->tx_traffic_idx = 0;
	priv->rx_traffic_idx = 0;
	if (priv->tx_traffic)
		memset(priv->tx_traffic, 0, IWL_TRAFFIC_DUMP_SIZE);
	if (priv->rx_traffic)
		memset(priv->rx_traffic, 0, IWL_TRAFFIC_DUMP_SIZE);
}

int iwl_alloc_traffic_mem(struct iwl_priv *priv)
{
	u32 traffic_size = IWL_TRAFFIC_DUMP_SIZE;

	if (iwl_have_debug_level(IWL_DL_TX)) {
		if (!priv->tx_traffic) {
			priv->tx_traffic =
				kzalloc(traffic_size, GFP_KERNEL);
			if (!priv->tx_traffic)
				return -ENOMEM;
		}
	}
	if (iwl_have_debug_level(IWL_DL_RX)) {
		if (!priv->rx_traffic) {
			priv->rx_traffic =
				kzalloc(traffic_size, GFP_KERNEL);
			if (!priv->rx_traffic)
				return -ENOMEM;
		}
	}
	iwl_reset_traffic_log(priv);
	return 0;
}

void iwl_free_traffic_mem(struct iwl_priv *priv)
{
	kfree(priv->tx_traffic);
	priv->tx_traffic = NULL;

	kfree(priv->rx_traffic);
	priv->rx_traffic = NULL;
}

void iwl_dbg_log_tx_data_frame(struct iwl_priv *priv,
		      u16 length, struct ieee80211_hdr *header)
{
	__le16 fc;
	u16 len;

	if (likely(!iwl_have_debug_level(IWL_DL_TX)))
		return;

	if (!priv->tx_traffic)
		return;

	fc = header->frame_control;
	if (ieee80211_is_data(fc)) {
		len = (length > IWL_TRAFFIC_ENTRY_SIZE)
		       ? IWL_TRAFFIC_ENTRY_SIZE : length;
		memcpy((priv->tx_traffic +
		       (priv->tx_traffic_idx * IWL_TRAFFIC_ENTRY_SIZE)),
		       header, len);
		priv->tx_traffic_idx =
			(priv->tx_traffic_idx + 1) % IWL_TRAFFIC_ENTRIES;
	}
}

void iwl_dbg_log_rx_data_frame(struct iwl_priv *priv,
		      u16 length, struct ieee80211_hdr *header)
{
	__le16 fc;
	u16 len;

	if (likely(!iwl_have_debug_level(IWL_DL_RX)))
		return;

	if (!priv->rx_traffic)
		return;

	fc = header->frame_control;
	if (ieee80211_is_data(fc)) {
		len = (length > IWL_TRAFFIC_ENTRY_SIZE)
		       ? IWL_TRAFFIC_ENTRY_SIZE : length;
		memcpy((priv->rx_traffic +
		       (priv->rx_traffic_idx * IWL_TRAFFIC_ENTRY_SIZE)),
		       header, len);
		priv->rx_traffic_idx =
			(priv->rx_traffic_idx + 1) % IWL_TRAFFIC_ENTRIES;
	}
}

const char *get_mgmt_string(int cmd)
{
	switch (cmd) {
		IWL_CMD(MANAGEMENT_ASSOC_REQ);
		IWL_CMD(MANAGEMENT_ASSOC_RESP);
		IWL_CMD(MANAGEMENT_REASSOC_REQ);
		IWL_CMD(MANAGEMENT_REASSOC_RESP);
		IWL_CMD(MANAGEMENT_PROBE_REQ);
		IWL_CMD(MANAGEMENT_PROBE_RESP);
		IWL_CMD(MANAGEMENT_BEACON);
		IWL_CMD(MANAGEMENT_ATIM);
		IWL_CMD(MANAGEMENT_DISASSOC);
		IWL_CMD(MANAGEMENT_AUTH);
		IWL_CMD(MANAGEMENT_DEAUTH);
		IWL_CMD(MANAGEMENT_ACTION);
	default:
		return "UNKNOWN";

	}
}

const char *get_ctrl_string(int cmd)
{
	switch (cmd) {
		IWL_CMD(CONTROL_BACK_REQ);
		IWL_CMD(CONTROL_BACK);
		IWL_CMD(CONTROL_PSPOLL);
		IWL_CMD(CONTROL_RTS);
		IWL_CMD(CONTROL_CTS);
		IWL_CMD(CONTROL_ACK);
		IWL_CMD(CONTROL_CFEND);
		IWL_CMD(CONTROL_CFENDACK);
	default:
		return "UNKNOWN";

	}
}

void iwl_clear_traffic_stats(struct iwl_priv *priv)
{
	memset(&priv->tx_stats, 0, sizeof(struct traffic_stats));
	memset(&priv->rx_stats, 0, sizeof(struct traffic_stats));
}

/*
 * if CONFIG_IWLWIFI_DEBUGFS defined, iwl_update_stats function will
 * record all the MGMT, CTRL and DATA pkt for both TX and Rx pass.
 * Use debugFs to display the rx/rx_statistics
 * if CONFIG_IWLWIFI_DEBUGFS not being defined, then no MGMT and CTRL
 * information will be recorded, but DATA pkt still will be recorded
 * for the reason of iwl_led.c need to control the led blinking based on
 * number of tx and rx data.
 *
 */
void iwl_update_stats(struct iwl_priv *priv, bool is_tx, __le16 fc, u16 len)
{
	struct traffic_stats	*stats;

	if (is_tx)
		stats = &priv->tx_stats;
	else
		stats = &priv->rx_stats;

	if (ieee80211_is_mgmt(fc)) {
		switch (fc & cpu_to_le16(IEEE80211_FCTL_STYPE)) {
		case cpu_to_le16(IEEE80211_STYPE_ASSOC_REQ):
			stats->mgmt[MANAGEMENT_ASSOC_REQ]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_ASSOC_RESP):
			stats->mgmt[MANAGEMENT_ASSOC_RESP]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_REASSOC_REQ):
			stats->mgmt[MANAGEMENT_REASSOC_REQ]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_REASSOC_RESP):
			stats->mgmt[MANAGEMENT_REASSOC_RESP]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_PROBE_REQ):
			stats->mgmt[MANAGEMENT_PROBE_REQ]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_PROBE_RESP):
			stats->mgmt[MANAGEMENT_PROBE_RESP]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_BEACON):
			stats->mgmt[MANAGEMENT_BEACON]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_ATIM):
			stats->mgmt[MANAGEMENT_ATIM]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_DISASSOC):
			stats->mgmt[MANAGEMENT_DISASSOC]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_AUTH):
			stats->mgmt[MANAGEMENT_AUTH]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_DEAUTH):
			stats->mgmt[MANAGEMENT_DEAUTH]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_ACTION):
			stats->mgmt[MANAGEMENT_ACTION]++;
			break;
		}
	} else if (ieee80211_is_ctl(fc)) {
		switch (fc & cpu_to_le16(IEEE80211_FCTL_STYPE)) {
		case cpu_to_le16(IEEE80211_STYPE_BACK_REQ):
			stats->ctrl[CONTROL_BACK_REQ]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_BACK):
			stats->ctrl[CONTROL_BACK]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_PSPOLL):
			stats->ctrl[CONTROL_PSPOLL]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_RTS):
			stats->ctrl[CONTROL_RTS]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_CTS):
			stats->ctrl[CONTROL_CTS]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_ACK):
			stats->ctrl[CONTROL_ACK]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_CFEND):
			stats->ctrl[CONTROL_CFEND]++;
			break;
		case cpu_to_le16(IEEE80211_STYPE_CFENDACK):
			stats->ctrl[CONTROL_CFENDACK]++;
			break;
		}
	} else {
		/* data */
		stats->data_cnt++;
		stats->data_bytes += len;
	}
}
#endif

int iwl_force_rf_reset(struct iwl_priv *priv, bool external)
{
	struct iwl_rf_reset *rf_reset;

	if (test_bit(STATUS_EXIT_PENDING, &priv->status))
		return -EAGAIN;

	if (!iwl_is_any_associated(priv)) {
		IWL_DEBUG_SCAN(priv, "force reset rejected: not associated\n");
		return -ENOLINK;
	}

	rf_reset = &priv->rf_reset;
	rf_reset->reset_request_count++;
	if (!external && rf_reset->last_reset_jiffies &&
	    time_after(rf_reset->last_reset_jiffies +
		       IWL_DELAY_NEXT_FORCE_RF_RESET, jiffies)) {
		IWL_DEBUG_INFO(priv, "RF reset rejected\n");
		rf_reset->reset_reject_count++;
		return -EAGAIN;
	}
	rf_reset->reset_success_count++;
	rf_reset->last_reset_jiffies = jiffies;

	/*
	 * There is no easy and better way to force reset the radio,
	 * the only known method is switching channel which will force to
	 * reset and tune the radio.
	 * Use internal short scan (single channel) operation to should
	 * achieve this objective.
	 * Driver should reset the radio when number of consecutive missed
	 * beacon, or any other uCode error condition detected.
	 */
	IWL_DEBUG_INFO(priv, "perform radio reset.\n");
	iwl_internal_short_hw_scan(priv);
	return 0;
}


int iwl_cmd_echo_test(struct iwl_priv *priv)
{
	int ret;
	struct iwl_host_cmd cmd = {
		.id = REPLY_ECHO,
		.len = { 0 },
		.flags = CMD_SYNC,
	};

	ret = iwl_dvm_send_cmd(priv, &cmd);
	if (ret)
		IWL_ERR(priv, "echo testing fail: 0X%x\n", ret);
	else
		IWL_DEBUG_INFO(priv, "echo testing pass\n");
	return ret;
}

/**
 * iwl_beacon_time_mask_low - mask of lower 32 bit of beacon time
 * @priv -- pointer to iwl_priv data structure
 * @tsf_bits -- number of bits need to shift for masking)
 */
static inline u32 iwl_beacon_time_mask_low(struct iwl_priv *priv,
					   u16 tsf_bits)
{
	return (1 << tsf_bits) - 1;
}

/**
 * iwl_beacon_time_mask_high - mask of higher 32 bit of beacon time
 * @priv -- pointer to iwl_priv data structure
 * @tsf_bits -- number of bits need to shift for masking)
 */
static inline u32 iwl_beacon_time_mask_high(struct iwl_priv *priv,
					    u16 tsf_bits)
{
	return ((1 << (32 - tsf_bits)) - 1) << tsf_bits;
}

/*
 * extended beacon time format
 * time in usec will be changed into a 32-bit value in extended:internal format
 * the extended part is the beacon counts
 * the internal part is the time in usec within one beacon interval
 */
u32 iwl_usecs_to_beacons(struct iwl_priv *priv, u32 usec, u32 beacon_interval)
{
	u32 quot;
	u32 rem;
	u32 interval = beacon_interval * TIME_UNIT;

	if (!interval || !usec)
		return 0;

	quot = (usec / interval) &
		(iwl_beacon_time_mask_high(priv, IWLAGN_EXT_BEACON_TIME_POS) >>
		IWLAGN_EXT_BEACON_TIME_POS);
	rem = (usec % interval) & iwl_beacon_time_mask_low(priv,
				   IWLAGN_EXT_BEACON_TIME_POS);

	return (quot << IWLAGN_EXT_BEACON_TIME_POS) + rem;
}

/* base is usually what we get from ucode with each received frame,
 * the same as HW timer counter counting down
 */
__le32 iwl_add_beacon_time(struct iwl_priv *priv, u32 base,
			   u32 addon, u32 beacon_interval)
{
	u32 base_low = base & iwl_beacon_time_mask_low(priv,
				IWLAGN_EXT_BEACON_TIME_POS);
	u32 addon_low = addon & iwl_beacon_time_mask_low(priv,
				IWLAGN_EXT_BEACON_TIME_POS);
	u32 interval = beacon_interval * TIME_UNIT;
	u32 res = (base & iwl_beacon_time_mask_high(priv,
				IWLAGN_EXT_BEACON_TIME_POS)) +
				(addon & iwl_beacon_time_mask_high(priv,
				IWLAGN_EXT_BEACON_TIME_POS));

	if (base_low > addon_low)
		res += base_low - addon_low;
	else if (base_low < addon_low) {
		res += interval + base_low - addon_low;
		res += (1 << IWLAGN_EXT_BEACON_TIME_POS);
	} else
		res += (1 << IWLAGN_EXT_BEACON_TIME_POS);

	return cpu_to_le32(res);
}

void iwl_set_hw_rfkill_state(struct iwl_op_mode *op_mode, bool state)
{
	struct iwl_priv *priv = IWL_OP_MODE_GET_DVM(op_mode);

	if (state)
		set_bit(STATUS_RF_KILL_HW, &priv->status);
	else
		clear_bit(STATUS_RF_KILL_HW, &priv->status);

	wiphy_rfkill_set_hw_state(priv->hw->wiphy, state);
}

void iwl_free_skb(struct iwl_op_mode *op_mode, struct sk_buff *skb)
{
	struct ieee80211_tx_info *info;

	info = IEEE80211_SKB_CB(skb);
	kmem_cache_free(iwl_tx_cmd_pool, (info->driver_data[1]));
	dev_kfree_skb_any(skb);
}
