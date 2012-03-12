/* tfs.c
 * true_false strings
 * Copyright 2007, Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * $Id: tfs.c 35727 2011-01-31 20:37:17Z etxrab $
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "tfs.h"

/*
 * A default set of true/false strings that dissectors can use for
 * FT_BOOLEAN header fields.
 */
const true_false_string tfs_true_false = { "True", "False" };
const true_false_string tfs_yes_no = { "Yes", "No" };
const true_false_string tfs_set_notset = { "Set", "Not set" };
const true_false_string tfs_enabled_disabled = { "Enabled", "Disabled" };
const true_false_string tfs_ok_error = { "Ok", "Error" };
const true_false_string tfs_error_ok = { "Error", "Ok" };
const true_false_string tfs_success_fail = { "Success", "Fail" };
const true_false_string tfs_fail_success = { "Fail", "Success" };
const true_false_string tfs_on_off = { "On", "Off" };
const true_false_string tfs_ack_nack = { "Ack", "Nack" };
const true_false_string tfs_odd_even = { "Odd", "Even" };
const true_false_string tfs_allow_block = { "Allow", "Block" };
const true_false_string tfs_restricted_allowed = { "Restricted", "Allowed" };
const true_false_string tfs_accept_reject = { "Accept", "Reject" };
const true_false_string tfs_more_nomore = { "More", "No more" };
const true_false_string tfs_present_absent = { "Present", "Absent" };
const true_false_string tfs_present_not_present = { "Present", "Not Present" };
const true_false_string tfs_active_inactive = { "Active", "Inactive" };
const true_false_string tfs_found_not_found = { "Found", "Not found" };
const true_false_string tfs_command_response = { "Command", "Response" };
const true_false_string tfs_capable_not_capable = { "Capable", "Not capable" };
const true_false_string tfs_supported_not_supported = { "Supported", "Not supported" };
const true_false_string tfs_used_notused = { "Used", "Not used" };
const true_false_string tfs_high_low = { "High", "Low" };
const true_false_string tfs_pressed_not_pressed = { "Pressed", "Not pressed" };
const true_false_string tfs_implemented_not_implemented = { "Implemented", "Not Implemented" };
const true_false_string tfs_requested_not_requested = { "Requested", "Not Requested" };
const true_false_string tfs_reliable_not_reliable = { "Reliable", "Not Reliable" };
const true_false_string tfs_allowed_not_allowed = { "Allowed", "Not Allowed" };
const true_false_string tfs_accepted_not_accepted = { "Accepted", "Not Accepted" };
const true_false_string tfs_detected_not_detected = { "Detected", "Not Detected" };

