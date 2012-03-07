/* commview.c
 * Routines for opening CommView file format packet captures
 * Copyright 2007, Stephen Fisher (see AUTHORS file)
 *
 * $Id: commview.c 36575 2011-04-12 00:44:44Z guy $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on csids.c and nettl.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

/* A brief description of this file format is available at:
 *    http://www.tamos.com/htmlhelp/commview/logformat.htm
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "wtap.h"
#include "wtap-int.h"
#include "buffer.h"
#include "file_wrappers.h"
#include "commview.h"

typedef struct commview_header {
	guint16		data_len;
	guint16		source_data_len;
	guint8		version;
	guint16		year;
	guint8		month;
	guint8  	day;
	guint8		hours;
	guint8		minutes;
	guint8		seconds;
	guint32		usecs;
	guint8		flags;		/* Bit-field positions defined below */
	guint8		signal_level_percent;
	guint8		rate;
	guint8		band;
	guint8		channel;
	guint8		direction;	/* Or for WiFi, high order byte of
					 * packet rate. */
	guint8		signal_level_dbm;
	guint8		noise_level;	/* In dBm (WiFi only) */
} commview_header_t;

#define COMMVIEW_HEADER_SIZE 24

/* Bit-field positions for various fields in the flags variable of the header */
#define FLAGS_MEDIUM		0x0F
#define FLAGS_DECRYPTED		0x10
#define FLAGS_BROKEN		0x20
#define FLAGS_COMPRESSED	0x40
#define FLAGS_RESERVED		0x80

/* Capture mediums as defined by the commview file format */
#define MEDIUM_ETHERNET		0
#define MEDIUM_WIFI		1
#define MEDIUM_TOKEN_RING	2

static gboolean commview_read(wtap *wth, int *err, gchar **err_info _U_,
			      gint64 *data_offset);
static gboolean commview_seek_read(wtap *wth, gint64 seek_off,
				   union wtap_pseudo_header *pseudo_header,
				   guchar *pd, int length, int *err,
				   gchar **err_info _U_);
static gboolean  commview_read_header(commview_header_t *cv_hdr, FILE_T fh,
				      int *err);
static gboolean commview_dump(wtap_dumper *wdh,	const struct wtap_pkthdr *phdr,
			      const union wtap_pseudo_header *pseudo_header _U_,
			      const guchar *pd, int *err);

int commview_open(wtap *wth, int *err, gchar **err_info _U_)
{
	commview_header_t cv_hdr;

	if(!commview_read_header(&cv_hdr, wth->fh, err))
		return -1;

	/* If any of these fields do not match what we expect, bail out. */
	if(cv_hdr.version != 0 ||
	   cv_hdr.year < 1970 || cv_hdr.year >= 2038 ||
	   cv_hdr.month < 1 || cv_hdr.month > 12 ||
	   cv_hdr.day < 1 || cv_hdr.day > 31 ||
	   cv_hdr.hours > 23 ||
	   cv_hdr.minutes > 59 ||
	   cv_hdr.seconds > 60 ||
	   cv_hdr.signal_level_percent > 100 ||
	   (cv_hdr.flags & FLAGS_RESERVED) != 0 ||
	   ((cv_hdr.flags & FLAGS_MEDIUM) != MEDIUM_ETHERNET &&
	    (cv_hdr.flags & FLAGS_MEDIUM) != MEDIUM_WIFI &&
	    (cv_hdr.flags & FLAGS_MEDIUM) != MEDIUM_TOKEN_RING))
		return 0; /* Not our kind of file */

	/* No file header. Reset the fh to 0 so we can read the first packet */
	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return -1;

	/* Set up the pointers to the handlers for this file type */
	wth->subtype_read = commview_read;
	wth->subtype_seek_read = commview_seek_read;

	wth->data_offset = 0;
	wth->file_type = WTAP_FILE_COMMVIEW;
	wth->file_encap = WTAP_ENCAP_PER_PACKET;
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;

	return 1; /* Our kind of file */
}

static gboolean
commview_read(wtap *wth, int *err, gchar **err_info _U_, gint64 *data_offset)
{
	commview_header_t cv_hdr;
	struct tm tm;
	int bytes_read;

	*data_offset = wth->data_offset;

	if(!commview_read_header(&cv_hdr, wth->fh, err))
		return FALSE;

	wth->data_offset += COMMVIEW_HEADER_SIZE;

	switch(cv_hdr.flags & FLAGS_MEDIUM) {

	case MEDIUM_ETHERNET :
		wth->phdr.pkt_encap = WTAP_ENCAP_ETHERNET;
		break;

	case MEDIUM_WIFI :
		wth->phdr.pkt_encap = WTAP_ENCAP_IEEE_802_11_WITH_RADIO;
		break;

	case MEDIUM_TOKEN_RING :
		wth->phdr.pkt_encap = WTAP_ENCAP_TOKEN_RING;
		break;
	default:
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("commview: unsupported encap: %u",
					    cv_hdr.flags & FLAGS_MEDIUM);
		return FALSE;
	}

	buffer_assure_space(wth->frame_buffer, cv_hdr.data_len);
	bytes_read = file_read(buffer_start_ptr(wth->frame_buffer),
			       cv_hdr.data_len, wth->fh);
	if(bytes_read != cv_hdr.data_len) {
		*err = file_error(wth->fh);
		if(*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	tm.tm_year = cv_hdr.year - 1900;
	tm.tm_mon = cv_hdr.month - 1;
	tm.tm_mday = cv_hdr.day;
	tm.tm_hour = cv_hdr.hours;
	tm.tm_min = cv_hdr.minutes;
	tm.tm_sec = cv_hdr.seconds;
	tm.tm_isdst = -1;

	wth->data_offset += cv_hdr.data_len;

	wth->phdr.len = cv_hdr.data_len;
	wth->phdr.caplen = cv_hdr.data_len;

	wth->phdr.ts.secs = mktime(&tm);
	wth->phdr.ts.nsecs = cv_hdr.usecs * 1000;

	return TRUE;
}

static gboolean
commview_seek_read(wtap *wth, gint64 seek_off, union wtap_pseudo_header
		   *pseudo_header, guchar *pd, int length, int *err,
		   gchar **err_info _U_)
{
	commview_header_t cv_hdr;
	int bytes_read;

	if(file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if(!commview_read_header(&cv_hdr, wth->random_fh, err)) {
		if(*err == 0)
			*err = WTAP_ERR_SHORT_READ;

		return FALSE;
	}

	if(length != cv_hdr.data_len) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("commview: record length %u doesn't match requested length %d", cv_hdr.data_len, length);
		return FALSE;
	}

	/* Pass some data to the 802.11 dissector if this is a WiFi packet */
	if((cv_hdr.flags & FLAGS_MEDIUM) == MEDIUM_WIFI) {
		pseudo_header->ieee_802_11.fcs_len = -1; /* Unknown */
		pseudo_header->ieee_802_11.channel = cv_hdr.channel;
		pseudo_header->ieee_802_11.data_rate = cv_hdr.rate;
		pseudo_header->ieee_802_11.signal_level = cv_hdr.signal_level_percent;
	}

	bytes_read = file_read(pd, cv_hdr.data_len, wth->random_fh);
	if(bytes_read != cv_hdr.data_len) {
		*err = file_error(wth->random_fh);
		if(*err == 0)
			*err = WTAP_ERR_SHORT_READ;

		return FALSE;
	}

	return TRUE;
}

static gboolean
commview_read_header(commview_header_t *cv_hdr, FILE_T fh, int *err)
{
	int bytes_read = 0;

	bytes_read += file_read(&cv_hdr->data_len, 2, fh);
	bytes_read += file_read(&cv_hdr->source_data_len, 2, fh);
	bytes_read += file_read(&cv_hdr->version, 1, fh);
	bytes_read += file_read(&cv_hdr->year, 2, fh);
	bytes_read += file_read(&cv_hdr->month, 1, fh);
	bytes_read += file_read(&cv_hdr->day, 1, fh);
	bytes_read += file_read(&cv_hdr->hours, 1, fh);
	bytes_read += file_read(&cv_hdr->minutes, 1, fh);
	bytes_read += file_read(&cv_hdr->seconds, 1, fh);
	bytes_read += file_read(&cv_hdr->usecs, 4, fh);
	bytes_read += file_read(&cv_hdr->flags, 1, fh);
	bytes_read += file_read(&cv_hdr->signal_level_percent, 1, fh);
	bytes_read += file_read(&cv_hdr->rate, 1, fh);
	bytes_read += file_read(&cv_hdr->band, 1, fh);
	bytes_read += file_read(&cv_hdr->channel, 1, fh);
	bytes_read += file_read(&cv_hdr->direction, 1, fh);
	bytes_read += file_read(&cv_hdr->signal_level_dbm, 1, fh);
	bytes_read += file_read(&cv_hdr->noise_level, 1, fh);

	/* Convert multi-byte values from little endian to host endian format */
	cv_hdr->data_len = GUINT16_FROM_LE(cv_hdr->data_len);
	cv_hdr->source_data_len = GUINT16_FROM_LE(cv_hdr->source_data_len);
	cv_hdr->year = GUINT16_FROM_LE(cv_hdr->year);
	cv_hdr->usecs = GUINT32_FROM_LE(cv_hdr->usecs);

	if(bytes_read < COMMVIEW_HEADER_SIZE) {
		*err = file_error(fh);
		if(*err == 0 && bytes_read > 0)
			*err = WTAP_ERR_SHORT_READ;

		return FALSE;
	}

	return TRUE;
}

/* Returns 0 if we can write out the specified encapsulation type
 * into a CommView format file. */
int commview_dump_can_write_encap(int encap)
{
	switch (encap) {

	case WTAP_ENCAP_ETHERNET :
	case WTAP_ENCAP_IEEE_802_11 :
	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO :
	case WTAP_ENCAP_TOKEN_RING :
	case WTAP_ENCAP_PER_PACKET :
		return 0;

	default:
		return WTAP_ERR_UNSUPPORTED_ENCAP;
	}
}

/* Returns TRUE on success, FALSE on failure;
   sets "*err" to an error code on failure */
gboolean commview_dump_open(wtap_dumper *wdh, int *err _U_)
{
	wdh->subtype_write = commview_dump;
	wdh->subtype_close = NULL;

	/* There is no file header to write out */
	wdh->bytes_dumped = 0;

	return TRUE;
}

/* Write a record for a packet to a dump file.
 * Returns TRUE on success, FALSE on failure. */
static gboolean commview_dump(wtap_dumper *wdh,
			      const struct wtap_pkthdr *phdr,
			      const union wtap_pseudo_header *pseudo_header,
			      const guchar *pd, int *err)
{
	commview_header_t cv_hdr;
	char date_time[5];

	memset(&cv_hdr, 0, sizeof(cv_hdr));

	cv_hdr.data_len = GUINT16_TO_LE((guint16)phdr->caplen);
	cv_hdr.source_data_len = GUINT16_TO_LE((guint16)phdr->caplen);
	cv_hdr.version = 0;

	strftime(date_time, 5, "%Y", localtime(&phdr->ts.secs));
	cv_hdr.year = GUINT16_TO_LE((guint16)strtol(date_time, NULL, 10));

	strftime(date_time, 5, "%m", localtime(&phdr->ts.secs));
	cv_hdr.month = (guint8)strtol(date_time, NULL, 10);

	strftime(date_time, 5, "%d", localtime(&phdr->ts.secs));
	cv_hdr.day = (guint8)strtol(date_time, NULL, 10);

	strftime(date_time, 5, "%H", localtime(&phdr->ts.secs));
	cv_hdr.hours = (guint8)strtol(date_time, NULL, 10);

	strftime(date_time, 5, "%M", localtime(&phdr->ts.secs));
	cv_hdr.minutes = (guint8)strtol(date_time, NULL, 10);

	strftime(date_time, 5, "%S", localtime(&phdr->ts.secs));
	cv_hdr.seconds = (guint8)strtol(date_time, NULL, 10);

	cv_hdr.usecs = GUINT32_TO_LE(phdr->ts.nsecs / 1000);

	switch(phdr->pkt_encap) {

	case WTAP_ENCAP_ETHERNET :
		cv_hdr.flags |= MEDIUM_ETHERNET;
		break;

	case WTAP_ENCAP_IEEE_802_11 :
		cv_hdr.flags |=  MEDIUM_WIFI;
		break;

	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO :
		cv_hdr.flags |=  MEDIUM_WIFI;

		cv_hdr.channel = pseudo_header->ieee_802_11.channel;
		cv_hdr.rate = pseudo_header->ieee_802_11.data_rate;
		cv_hdr.signal_level_percent = pseudo_header->ieee_802_11.signal_level;
		break;

	case WTAP_ENCAP_TOKEN_RING :
		cv_hdr.flags |= MEDIUM_TOKEN_RING;
		break;

	default :
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return FALSE;
	}

	if (!wtap_dump_file_write(wdh, &cv_hdr.data_len, 2, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.source_data_len, 2, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.version, 1, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.year, 2, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.month, 1, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.day, 1, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.hours, 1, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.minutes, 1, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.seconds, 1, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.usecs, 4, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.flags, 1, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.signal_level_percent, 1, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.rate, 1, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.band, 1, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.channel, 1, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.direction, 1, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.signal_level_dbm, 2, err))
		return FALSE;
	if (!wtap_dump_file_write(wdh, &cv_hdr.noise_level, 2, err))
		return FALSE;
	wdh->bytes_dumped += COMMVIEW_HEADER_SIZE;

	if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
		return FALSE;
	wdh->bytes_dumped += phdr->caplen;

	return TRUE;
}
