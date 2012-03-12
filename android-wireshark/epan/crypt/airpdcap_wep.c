/* airpcap_wep.c
 *
 *  $Id: airpdcap_wep.c 35989 2011-02-17 23:11:49Z guy $
 *
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/************************************************************************/
/*	File includes							*/

#include <epan/tvbuff.h>
#include <epan/crc32.h>

#include "airpdcap_system.h"
#include "airpdcap_int.h"

#include "airpdcap_debug.h"

/************************************************************************/

/* Note: copied from FreeBSD source code, RELENG 6,			*/
/*		sys/net80211/ieee80211_crypto_wep.c, 391		*/
INT AirPDcapWepDecrypt(
	const UCHAR *seed,
	const size_t seed_len,
	UCHAR *cypher_text,
	const size_t data_len)
{
	UINT32 i, j, k, crc;
	UINT8 S[256];
	UINT8 icv[4];
	size_t buflen;

	/* Generate key stream (RC4 Pseudo-Random Number Generator) */
	for (i = 0; i < 256; i++)
		S[i] = (UINT8)i;
	for (j = i = 0; i < 256; i++) {
		j = (j + S[i] + seed[i % seed_len]) & 0xff;
		S_SWAP(i, j);
	}

	/* Apply RC4 to data and compute CRC32 over decrypted data */
	crc = ~(UINT32)0;
	buflen = data_len;

	for (i = j = k = 0; k < buflen; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*cypher_text ^= S[(S[i] + S[j]) & 0xff];
		crc = crc32_ccitt_table[(crc ^ *cypher_text) & 0xff] ^ (crc >> 8);
		cypher_text++;
	}

	crc = ~crc;

	/* Encrypt little-endian CRC32 and verify that it matches with the received ICV */
	icv[0] = (UINT8)crc;
	icv[1] = (UINT8)(crc >> 8);
	icv[2] = (UINT8)(crc >> 16);
	icv[3] = (UINT8)(crc >> 24);
	for (k = 0; k < 4; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		if ((icv[k] ^ S[(S[i] + S[j]) & 0xff]) != *cypher_text++) {
			/* ICV mismatch - drop frame */
			return AIRPDCAP_RET_UNSUCCESS;
		}
	}

	return AIRPDCAP_RET_SUCCESS;
}
