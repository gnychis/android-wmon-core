/* tap-smbstat.c
 * smbstat   2003 Ronnie Sahlberg
 *
 * $Id: tap-smbstat.c 36297 2011-03-23 20:00:13Z cmaynard $
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include "epan/value_string.h"
#include <epan/dissectors/packet-smb.h>
#include "timestats.h"

#define MICROSECS_PER_SEC   1000000
#define NANOSECS_PER_SEC    1000000000

/* used to keep track of the statistics for an entire program interface */
typedef struct _smbstat_t {
	char *filter;
	timestat_t proc[256];
	timestat_t trans2[256];
	timestat_t nt_trans[256];
} smbstat_t;



static int
smbstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi)
{
	smbstat_t *ss=(smbstat_t *)pss;
	const smb_info_t *si=psi;
	nstime_t t, deltat;
	timestat_t *sp=NULL;

	/* we are only interested in reply packets */
	if(si->request){
		return 0;
	}
	/* if we havnt seen the request, just ignore it */
	if(!si->sip){
		return 0;
	}

	if(si->cmd==0xA0 && si->sip->extra_info_type == SMB_EI_NTI){
		smb_nt_transact_info_t *sti=(smb_nt_transact_info_t *)si->sip->extra_info;

		/*nt transaction*/
		if(sti){
			sp=&(ss->nt_trans[sti->subcmd]);
		}
	} else if(si->cmd==0x32 && si->sip->extra_info_type == SMB_EI_T2I){
		smb_transact2_info_t *st2i=(smb_transact2_info_t *)si->sip->extra_info;

		/*transaction2*/
		if(st2i){
			sp=&(ss->trans2[st2i->subcmd]);
		}
	} else {
		sp=&(ss->proc[si->cmd]);
	}

	/* calculate time delta between request and reply */
	t=pinfo->fd->abs_ts;
	nstime_delta(&deltat, &t, &si->sip->req_time);

	if(sp){
		time_stat_update(sp,&deltat, pinfo);
	}

	return 1;
}

static void
smbstat_draw(void *pss)
{
	smbstat_t *ss=(smbstat_t *)pss;
	guint32 i;
	guint64 td;
	printf("\n");
	printf("=================================================================\n");
	printf("SMB SRT Statistics:\n");
	printf("Filter: %s\n",ss->filter?ss->filter:"");
	printf("Commands                   Calls    Min SRT    Max SRT    Avg SRT\n");
	for(i=0;i<256;i++){
		/* nothing seen, nothing to do */
		if(ss->proc[i].num==0){
			continue;
		}

		/* we deal with transaction2 later */
		if(i==0x32){
			continue;
		}

		/* we deal with nt transaction later */
		if(i==0xA0){
			continue;
		}

		/* Scale the average SRT in units of 1us and round to the nearest us. */
		td = ((guint64)(ss->proc[i].tot.secs)) * NANOSECS_PER_SEC + ss->proc[i].tot.nsecs;

		td = ((td / ss->proc[i].num) + 500) / 1000;

		printf("%-25s %6d %3d.%06d %3d.%06d %3" G_GINT64_MODIFIER "u.%06" G_GINT64_MODIFIER "u\n",
			val_to_str_ext(i, &smb_cmd_vals_ext, "Unknown (0x%02x)"),
			ss->proc[i].num,
			(int)(ss->proc[i].min.secs),(ss->proc[i].min.nsecs+500)/1000,
			(int)(ss->proc[i].max.secs),(ss->proc[i].max.nsecs+500)/1000,
			td/MICROSECS_PER_SEC, td%MICROSECS_PER_SEC
		);
	}

	printf("\n");
	printf("Transaction2 Commands      Calls    Min SRT    Max SRT    Avg SRT\n");
	for(i=0;i<256;i++){
		/* nothing seen, nothing to do */
		if(ss->trans2[i].num==0){
			continue;
		}

		/* Scale the average SRT in units of 1us and round to the nearest us. */
		td = ((guint64)(ss->trans2[i].tot.secs)) * NANOSECS_PER_SEC + ss->trans2[i].tot.nsecs;
		td = ((td / ss->trans2[i].num) + 500) / 1000;

		printf("%-25s %6d %3d.%06d %3d.%06d %3" G_GINT64_MODIFIER "u.%06" G_GINT64_MODIFIER "u\n",
			val_to_str_ext(i, &trans2_cmd_vals_ext, "Unknown (0x%02x)"),
			ss->trans2[i].num,
			(int)(ss->trans2[i].min.secs),(ss->trans2[i].min.nsecs+500)/1000,
			(int)(ss->trans2[i].max.secs),(ss->trans2[i].max.nsecs+500)/1000,
			td/MICROSECS_PER_SEC, td%MICROSECS_PER_SEC
		);
	}

	printf("\n");
	printf("NT Transaction Commands    Calls    Min SRT    Max SRT    Avg SRT\n");
	for(i=0;i<256;i++){
		/* nothing seen, nothing to do */
		if(ss->nt_trans[i].num==0){
			continue;
		}
		/* Scale the average SRT in units of 1us and round to the nearest us. */
		td = ((guint64)(ss->nt_trans[i].tot.secs)) * NANOSECS_PER_SEC + ss->nt_trans[i].tot.nsecs;
		td = ((td / ss->nt_trans[i].num) + 500) / 1000;

		printf("%-25s %6d %3d.%06d %3d.%06d %3" G_GINT64_MODIFIER "u.%06" G_GINT64_MODIFIER "u\n",
			val_to_str_ext(i, &nt_cmd_vals_ext, "Unknown (0x%02x)"),
			ss->nt_trans[i].num,
			(int)(ss->nt_trans[i].min.secs),(ss->nt_trans[i].min.nsecs+500)/1000,
			(int)(ss->nt_trans[i].max.secs),(ss->nt_trans[i].max.nsecs+500)/1000,
			td/MICROSECS_PER_SEC, td%MICROSECS_PER_SEC
		);
	}

	printf("=================================================================\n");
}


static void
smbstat_init(const char *optarg,void* userdata _U_)
{
	smbstat_t *ss;
	guint32 i;
	const char *filter=NULL;
	GString *error_string;

	if(!strncmp(optarg,"smb,srt,",8)){
		filter=optarg+8;
	} else {
		filter=NULL;
	}

	ss=g_malloc(sizeof(smbstat_t));
	if(filter){
		ss->filter=g_strdup(filter);
	} else {
		ss->filter=NULL;
	}

	for(i=0;i<256;i++){
		ss->proc[i].num=0;
		ss->proc[i].min_num=0;
		ss->proc[i].max_num=0;
		ss->proc[i].min.secs=0;
		ss->proc[i].min.nsecs=0;
		ss->proc[i].max.secs=0;
		ss->proc[i].max.nsecs=0;
		ss->proc[i].tot.secs=0;
		ss->proc[i].tot.nsecs=0;

		ss->trans2[i].num=0;
		ss->trans2[i].min_num=0;
		ss->trans2[i].max_num=0;
		ss->trans2[i].min.secs=0;
		ss->trans2[i].min.nsecs=0;
		ss->trans2[i].max.secs=0;
		ss->trans2[i].max.nsecs=0;
		ss->trans2[i].tot.secs=0;
		ss->trans2[i].tot.nsecs=0;

		ss->nt_trans[i].num=0;
		ss->nt_trans[i].min_num=0;
		ss->nt_trans[i].max_num=0;
		ss->nt_trans[i].min.secs=0;
		ss->nt_trans[i].min.nsecs=0;
		ss->nt_trans[i].max.secs=0;
		ss->nt_trans[i].max.nsecs=0;
		ss->nt_trans[i].tot.secs=0;
		ss->nt_trans[i].tot.nsecs=0;
	}

	error_string=register_tap_listener("smb", ss, filter, 0, NULL, smbstat_packet, smbstat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(ss->filter);
		g_free(ss);

		fprintf(stderr, "tshark: Couldn't register smb,srt tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_smbstat(void)
{
	register_stat_cmd_arg("smb,srt", smbstat_init,NULL);
}

