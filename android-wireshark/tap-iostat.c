/* tap-iostat.c
 * iostat   2002 Ronnie Sahlberg
 *
 * $Id: tap-iostat.c 34926 2010-11-17 14:26:38Z cmaynard $
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
#include "epan/epan_dissect.h"
#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/strutil.h>


typedef struct _io_stat_t {
	gint32 interval;	/* unit is ms */
	guint32 num_items;
	struct _io_stat_item_t *items;
	const char **filters;
} io_stat_t;

#define CALC_TYPE_BYTES	0
#define CALC_TYPE_COUNT	1
#define CALC_TYPE_SUM	2
#define CALC_TYPE_MIN	3
#define CALC_TYPE_MAX	4
#define CALC_TYPE_AVG	5

typedef struct _io_stat_item_t {
	io_stat_t *parent;
	struct _io_stat_item_t *next;
	struct _io_stat_item_t *prev;
	gint32 time;		/* unit is ms since start of capture */
	int calc_type;
	int hf_index;
	guint64 frames;
	guint64 num;
	guint64 counter;
} io_stat_item_t;


static int
iostat_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_)
{
	io_stat_item_t *mit = arg;
	io_stat_item_t *it;
	gint32 current_time;
	GPtrArray *gp;
	guint i;

	current_time=(gint32) ((pinfo->fd->rel_ts.secs*1000)+(pinfo->fd->rel_ts.nsecs/1000000));

	/* the prev item before the main one is always the last interval we saw packets for */
	it=mit->prev;

	/* XXX for the time being, just ignore all frames that are in the past.
	   should be fixed in the future but hopefully it is uncommon */
	if(current_time<it->time){
		return FALSE;
	}

	/* we have moved into a new interval, we need to create a new struct */
	if(current_time>=(it->time+mit->parent->interval)){
		it->next=g_malloc(sizeof(io_stat_item_t));
		it->next->prev=it;
		it->next->next=NULL;
		it=it->next;
		mit->prev=it;

		it->time=(current_time / mit->parent->interval) * mit->parent->interval;
		it->frames=0;
		it->counter=0;
		it->num=0;
		it->calc_type=it->prev->calc_type;
		it->hf_index=it->prev->hf_index;
	}

	/* it will now give us the current structure to use to store the data in */
	it->frames++;

	switch(it->calc_type){
	case CALC_TYPE_BYTES:
		it->counter+=pinfo->fd->pkt_len;
		break;
	case CALC_TYPE_COUNT:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			it->counter+=gp->len;
		}
		break;
	case CALC_TYPE_SUM:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			for(i=0;i<gp->len;i++){
				switch(proto_registrar_get_ftype(it->hf_index)){
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
					it->counter+=fvalue_get_uinteger(&((field_info *)gp->pdata[i])->value);
					break;
				case FT_UINT64:
					it->counter+=fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					break;
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					it->counter+=fvalue_get_sinteger(&((field_info *)gp->pdata[i])->value);
					break;
				case FT_INT64:
					it->counter+=(gint64)fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					break;
				}
			}
		}
		break;
	case CALC_TYPE_MIN:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			int type;
			guint64 val;
			nstime_t *new_time;

			type=proto_registrar_get_ftype(it->hf_index);
			for(i=0;i<gp->len;i++){
				switch(type){
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
					val=fvalue_get_uinteger(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if(val<it->counter){
						it->counter=val;
					}
					break;
				case FT_UINT64:
					val=fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if(val<it->counter){
						it->counter=val;
					}
					break;
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					val=fvalue_get_sinteger(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if((gint32)val<(gint32)(it->counter)){
						it->counter=val;
					}
					break;
				case FT_INT64:
					val=fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if((gint64)val<(gint64)(it->counter)){
						it->counter=val;
					}
					break;
				case FT_RELATIVE_TIME:
					new_time=fvalue_get(&((field_info *)gp->pdata[i])->value);
					val=(guint64) (new_time->secs*1000+new_time->nsecs/1000000);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if(val<it->counter){
						it->counter=val;
					}
					break;
				}
			}
		}
		break;
	case CALC_TYPE_MAX:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			int type;
			guint64 val;
			nstime_t *new_time;

			type=proto_registrar_get_ftype(it->hf_index);
			for(i=0;i<gp->len;i++){
				switch(type){
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
					val=fvalue_get_uinteger(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if(val>it->counter){
						it->counter=val;
					}
					break;
				case FT_UINT64:
					val=fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if(val>it->counter){
						it->counter=val;
					}
					break;
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					val=fvalue_get_sinteger(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if((gint32)val>(gint32)(it->counter)){
						it->counter=val;
					}
					break;
				case FT_INT64:
					val=fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if((gint64)val>(gint64)(it->counter)){
						it->counter=val;
					}
					break;
				case FT_RELATIVE_TIME:
					new_time=fvalue_get(&((field_info *)gp->pdata[i])->value);
					val=(guint64) (new_time->secs*1000+new_time->nsecs/1000000);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if(val>it->counter){
						it->counter=val;
					}
					break;
				}
			}
		}
		break;
	case CALC_TYPE_AVG:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			int type;
			guint64 val;
			nstime_t *new_time;

			type=proto_registrar_get_ftype(it->hf_index);
			for(i=0;i<gp->len;i++){
				it->num++;
				switch(type){
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
					val=fvalue_get_uinteger(&((field_info *)gp->pdata[i])->value);
					it->counter+=val;
					break;
				case FT_UINT64:
				case FT_INT64:
					val=fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					it->counter+=val;
					break;
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					val=fvalue_get_sinteger(&((field_info *)gp->pdata[i])->value);
					it->counter+=val;
					break;
				case FT_RELATIVE_TIME:
					new_time=fvalue_get(&((field_info *)gp->pdata[i])->value);
					val=(guint64) (new_time->secs*1000+new_time->nsecs/1000000);
					it->counter+=val;
					break;
				}
			}
		}
		break;
	}

	return TRUE;
}

static void
iostat_draw(void *arg)
{
	io_stat_item_t *mit = arg;
	io_stat_t *iot;
	io_stat_item_t **items;
	guint64 *frames;
	guint64 *counters;
	guint64 *num;
	guint32 i;
	gboolean more_items;
	gint t;

	iot=mit->parent;

	printf("\n");
	printf("===================================================================\n");
	printf("IO Statistics\n");
	if(iot->interval!=G_MAXINT32)
		printf("Interval: %d.%03d secs\n", iot->interval/1000, iot->interval%1000);
	for(i=0;i<iot->num_items;i++){
		printf("Column #%u: %s\n",i,iot->filters[i]?iot->filters[i]:"");
	}
	printf("                ");
	for(i=0;i<iot->num_items;i++){
		printf("|   Column #%-2u   ",i);
	}
	printf("\n");
	printf("Time            ");
	for(i=0;i<iot->num_items;i++){
		switch(iot->items[i].calc_type){
		case CALC_TYPE_BYTES:
			printf("|frames|  bytes  ");
			break;
		case CALC_TYPE_COUNT:
			printf("|          COUNT ");
			break;
		case CALC_TYPE_SUM:
			printf("|            SUM ");
			break;
		case CALC_TYPE_MIN:
			printf("|            MIN ");
			break;
		case CALC_TYPE_MAX:
			printf("|            MAX ");
			break;
		case CALC_TYPE_AVG:
			printf("|            AVG ");
			break;
		}
	}
	printf("\n");

	items=g_malloc(sizeof(io_stat_item_t *)*iot->num_items);
	frames=g_malloc(sizeof(guint64)*iot->num_items);
	counters=g_malloc(sizeof(guint64)*iot->num_items);
	num=g_malloc(sizeof(guint64)*iot->num_items);
	/* preset all items at the first interval */
	for(i=0;i<iot->num_items;i++){
		items[i]=&iot->items[i];
	}

	/* loop the items until we run out of them all */
	t=0;
	do {
		more_items=FALSE;
		for(i=0;i<iot->num_items;i++){
			frames[i]=0;
			counters[i]=0;
			num[i]=0;
		}
		for(i=0;i<iot->num_items;i++){
			if(items[i] && (t>=(items[i]->time+iot->interval))){
				items[i]=items[i]->next;
			}

			if(items[i] && (t<(items[i]->time+iot->interval)) && (t>=items[i]->time) ){
				frames[i]=items[i]->frames;
				counters[i]=items[i]->counter;
				num[i]=items[i]->num;
			}

			if(items[i]){
				more_items=TRUE;
			}
		}

		if(more_items){
			if(iot->interval==G_MAXINT32) {
				printf("000.000-         ");
			} else {
				printf("%03d.%03d-%03d.%03d  ",
					t/1000,t%1000,
					(t+iot->interval)/1000,
					(t+iot->interval)%1000);
			}
			for(i=0;i<iot->num_items;i++){
				switch(iot->items[i].calc_type){
				case CALC_TYPE_BYTES:
					printf("%6" G_GINT64_MODIFIER "u %9" G_GINT64_MODIFIER "u ",frames[i], counters[i]);
					break;
				case CALC_TYPE_COUNT:
					printf(" %15" G_GINT64_MODIFIER "u ", counters[i]);
					break;
				case CALC_TYPE_SUM:
					printf(" %15" G_GINT64_MODIFIER "u ", counters[i]);
					break;
				case CALC_TYPE_MIN:
					switch(proto_registrar_get_ftype(iot->items[i].hf_index)){
					case FT_UINT8:
					case FT_UINT16:
					case FT_UINT24:
					case FT_UINT32:
					case FT_UINT64:
						printf(" %15" G_GINT64_MODIFIER "u ", counters[i]);
						break;
					case FT_INT8:
					case FT_INT16:
					case FT_INT24:
					case FT_INT32:
					case FT_INT64:
						printf(" %15" G_GINT64_MODIFIER "d ", counters[i]);
						break;
					case FT_RELATIVE_TIME:
						printf(" %11" G_GINT64_MODIFIER "d.%03d ", counters[i]/1000, (gint)counters[i]%1000);
						break;
					}
					break;
				case CALC_TYPE_MAX:
					switch(proto_registrar_get_ftype(iot->items[i].hf_index)){
					case FT_UINT8:
					case FT_UINT16:
					case FT_UINT24:
					case FT_UINT32:
					case FT_UINT64:
						printf(" %15" G_GINT64_MODIFIER "u ", counters[i]);
						break;
					case FT_INT8:
					case FT_INT16:
					case FT_INT24:
					case FT_INT32:
					case FT_INT64:
						printf(" %15" G_GINT64_MODIFIER "d ", counters[i]);
						break;
					case FT_RELATIVE_TIME:
						printf(" %11" G_GINT64_MODIFIER "d.%03d ", counters[i]/1000, (gint)counters[i]%1000);
						break;
					}
					break;
				case CALC_TYPE_AVG:
					if(num[i]==0){
						num[i]=1;
					}
					switch(proto_registrar_get_ftype(iot->items[i].hf_index)){
					case FT_UINT8:
					case FT_UINT16:
					case FT_UINT24:
					case FT_UINT32:
					case FT_UINT64:
						printf(" %15" G_GINT64_MODIFIER "u ", counters[i]/num[i]);
						break;
					case FT_INT8:
					case FT_INT16:
					case FT_INT24:
					case FT_INT32:
					case FT_INT64:
						printf(" %15" G_GINT64_MODIFIER "d ", counters[i]/num[i]);
						break;
					case FT_RELATIVE_TIME:
						counters[i]/=num[i];
						printf(" %11" G_GINT64_MODIFIER "d.%03d ", counters[i]/1000, (gint)counters[i]%1000);
						break;
					}
					break;

				}
			}
			printf("\n");
		}

		t+=iot->interval;
	} while(more_items);

	printf("===================================================================\n");

	g_free(items);
	g_free(frames);
	g_free(counters);
	g_free(num);
}


typedef struct {
	const char *func_name;
	int calc_type;
} calc_type_ent_t;

static calc_type_ent_t calc_type_table[] = {
	{ "COUNT", CALC_TYPE_COUNT },
	{ "SUM", CALC_TYPE_SUM },
	{ "MIN", CALC_TYPE_MIN },
	{ "MAX", CALC_TYPE_MAX },
	{ "AVG", CALC_TYPE_AVG },
	{ NULL, 0 }
};

static void
register_io_tap(io_stat_t *io, int i, const char *filter)
{
	GString *error_string;
	const char *flt;
	int j;
	size_t namelen;
	const char *p, *parenp;
	char *field;
	header_field_info *hfi;

	io->items[i].prev=&io->items[i];
	io->items[i].next=NULL;
	io->items[i].parent=io;
	io->items[i].time=0;
	io->items[i].calc_type=CALC_TYPE_BYTES;
	io->items[i].frames=0;
	io->items[i].counter=0;
	io->items[i].num=0;
	io->filters[i]=filter;
	flt=filter;

	field=NULL;
	hfi=NULL;
	for(j=0; calc_type_table[j].func_name; j++){
		namelen=strlen(calc_type_table[j].func_name);
		if(filter
		    && strncmp(filter, calc_type_table[j].func_name, namelen) == 0
		    && *(filter+namelen)=='('){
			io->items[i].calc_type=calc_type_table[j].calc_type;

			p=filter+namelen+1;
			parenp=strchr(p, ')');
			if(!parenp){
				fprintf(stderr, "tshark: Closing parenthesis missing from calculated expression.\n");
				exit(10);
			}
			/* bail out if there was no field specified */
			if(parenp==p){
				fprintf(stderr, "tshark: You didn't specify a field name for %s(*).\n",
				    calc_type_table[j].func_name);
				exit(10);
			}
			field=g_malloc(parenp-p+1);
			if(!field){
				fprintf(stderr, "tshark: Out of memory.\n");
				exit(10);
			}
			memcpy(field, p, parenp-p);
			field[parenp-p] = '\0';
			flt=parenp + 1;

			hfi=proto_registrar_get_byname(field);
			if(!hfi){
				fprintf(stderr, "tshark: There is no field named '%s'.\n",
				    field);
				g_free(field);
				exit(10);
			}

			io->items[i].hf_index=hfi->id;
			break;
		}
	}
	if(hfi && io->items[i].calc_type!=CALC_TYPE_BYTES){
		/* check that the type is compatible */
		switch(hfi->type){
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_UINT64:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_INT64:
			/* these types support all calculations */
			break;
		case FT_RELATIVE_TIME:
			/* this type only supports SUM, COUNT, MAX, MIN, AVG */
			switch(io->items[i].calc_type){
			case CALC_TYPE_SUM:
			case CALC_TYPE_COUNT:
			case CALC_TYPE_MAX:
			case CALC_TYPE_MIN:
			case CALC_TYPE_AVG:
				break;
			default:
				fprintf(stderr,
				    "tshark: %s is a relative-time field, so %s(*) calculations are not supported on it.",
				    field,
				    calc_type_table[j].func_name);
				exit(10);
			}
			break;
		default:
			/*
			 * XXX - support all operations on floating-point
			 * numbers?
			 */
			if(io->items[i].calc_type!=CALC_TYPE_COUNT){
				fprintf(stderr,
				    "tshark: %s doesn't have integral values, so %s(*) calculations are not supported on it.\n",
				    field,
				    calc_type_table[j].func_name);
				exit(10);
			}
			break;
		}
		g_free(field);
	}

/*
CALC_TYPE_SUM	2
CALC_TYPE_MIN	3
CALC_TYPE_MAX	4
CALC_TYPE_AVG	5
*/

	error_string=register_tap_listener("frame", &io->items[i], flt, TL_REQUIRES_PROTO_TREE, NULL, iostat_packet, i?NULL:iostat_draw);
	if(error_string){
		g_free(io->items);
		g_free(io);
		fprintf(stderr, "tshark: Couldn't register io,stat tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static void
iostat_init(const char *optarg, void* userdata _U_)
{
	float interval_float;
	gint32 interval;
	int idx=0;
	io_stat_t *io;
	const char *filter=NULL;

	if(sscanf(optarg,"io,stat,%f%n",&interval_float,&idx)==1){
		if(idx){
			if(*(optarg+idx)==',')
				filter=optarg+idx+1;
			else
				filter=optarg+idx;
		} else {
			filter=NULL;
		}
	} else {
		fprintf(stderr, "tshark: invalid \"-z io,stat,<interval>[,<filter>]\" argument\n");
		exit(1);
	}

	/* if interval is 0, calculate statistics over the whole file
	 * by setting the interval to G_MAXINT32
	 */
	if(interval_float==0) {
		interval=G_MAXINT32;
	} else {
		/* make interval be number of ms */
		interval=(gint32)(interval_float*1000.0+0.9);
	}

	if(interval<1){
		fprintf(stderr, "tshark: \"-z\" interval must be >=0.001 seconds or 0.\n");
		exit(10);
	}

	io=g_malloc(sizeof(io_stat_t));
	io->interval=interval;
	if((!filter)||(filter[0]==0)){
		io->num_items=1;
		io->items=g_malloc(sizeof(io_stat_item_t)*io->num_items);
		io->filters=g_malloc(sizeof(char *)*io->num_items);

		register_io_tap(io, 0, NULL);
	} else {
		const char *str,*pos;
		char *tmp;
		int i;
		/* find how many ',' separated filters we have */
		str=filter;
		io->num_items=1;
		while((str=strchr(str,','))){
			io->num_items++;
			str++;
		}

		io->items=g_malloc(sizeof(io_stat_item_t)*io->num_items);
		io->filters=g_malloc(sizeof(char *)*io->num_items);

		/* for each filter, register a tap listener */
		i=0;
		str=filter;
		do{
			pos=strchr(str,',');
			if(pos==str){
				register_io_tap(io, i, NULL);
			} else if(pos==NULL) {
				tmp=g_strdup(str);
				register_io_tap(io, i, tmp);
			} else {
				tmp=g_malloc((pos-str)+1);
				g_strlcpy(tmp,str,(pos-str)+1);
				register_io_tap(io, i, tmp);
			}
			str=pos+1;
			i++;
		} while(pos);
	}
}

void
register_tap_listener_iostat(void)
{
	register_stat_cmd_arg("io,stat,", iostat_init, NULL);
}
