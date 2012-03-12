/* packet-scsi-osd.c
 * Dissector for the SCSI OSD (object based storage) commandset
 *
 * Ronnie sahlberg 2006
 * Joe Breher 2006
 *
 * $Id: packet-scsi-osd.c 32410 2010-04-06 21:14:01Z wmeier $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2002 Gerald Combs
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

#include <glib.h>
#include <epan/strutil.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-scsi-osd.h"


static int proto_scsi_osd		= -1;
int hf_scsi_osd_opcode			= -1;
static int hf_scsi_osd_add_cdblen	= -1;
static int hf_scsi_osd_svcaction	= -1;
static int hf_scsi_osd_option		= -1;
static int hf_scsi_osd_option_dpo	= -1;
static int hf_scsi_osd_option_fua	= -1;
static int hf_scsi_osd_getsetattrib	= -1;
static int hf_scsi_osd_timestamps_control	= -1;
static int hf_scsi_osd_formatted_capacity	= -1;
static int hf_scsi_osd_get_attributes_page	= -1;
static int hf_scsi_osd_get_attributes_allocation_length	= -1;
static int hf_scsi_osd_get_attributes_list_length= -1;
static int hf_scsi_osd_get_attributes_list_offset= -1;
static int hf_scsi_osd_retrieved_attributes_offset = -1;
static int hf_scsi_osd_set_attributes_page	= -1;
static int hf_scsi_osd_set_attribute_length	= -1;
static int hf_scsi_osd_set_attribute_number	= -1;
static int hf_scsi_osd_set_attributes_offset	= -1;
static int hf_scsi_osd_set_attributes_list_length= -1;
static int hf_scsi_osd_set_attributes_list_offset= -1;
static int hf_scsi_osd_capability_format	= -1;
static int hf_scsi_osd_key_version	= -1;
static int hf_scsi_osd_icva		= -1;
static int hf_scsi_osd_security_method	= -1;
static int hf_scsi_osd_capability_expiration_time= -1;
static int hf_scsi_osd_audit= -1;
static int hf_scsi_osd_capability_discriminator	= -1;
static int hf_scsi_osd_object_created_time= -1;
static int hf_scsi_osd_object_type	= -1;
static int hf_scsi_osd_permissions	= -1;
static int hf_scsi_osd_permissions_read = -1;
static int hf_scsi_osd_permissions_write	= -1;
static int hf_scsi_osd_permissions_get_attr	= -1;
static int hf_scsi_osd_permissions_set_attr	= -1;
static int hf_scsi_osd_permissions_create	= -1;
static int hf_scsi_osd_permissions_remove	= -1;
static int hf_scsi_osd_permissions_obj_mgmt	= -1;
static int hf_scsi_osd_permissions_append	= -1;
static int hf_scsi_osd_permissions_dev_mgmt	= -1;
static int hf_scsi_osd_permissions_global	= -1;
static int hf_scsi_osd_permissions_pol_sec	= -1;
static int hf_scsi_osd_object_descriptor_type	= -1;
static int hf_scsi_osd_object_descriptor= -1;
static int hf_scsi_osd_ricv		= -1;
static int hf_scsi_osd_request_nonce	= -1;
static int hf_scsi_osd_diicvo		= -1;
static int hf_scsi_osd_doicvo		= -1;
static int hf_scsi_osd_requested_partition_id	= -1;
static int hf_scsi_osd_sortorder	= -1;
static int hf_scsi_osd_partition_id	= -1;
static int hf_scsi_osd_list_identifier	= -1;
static int hf_scsi_osd_allocation_length= -1;
static int hf_scsi_osd_length= -1;
static int hf_scsi_osd_starting_byte_address	= -1;
static int hf_scsi_osd_initial_object_id= -1;
static int hf_scsi_osd_additional_length= -1;
static int hf_scsi_osd_continuation_object_id= -1;
static int hf_scsi_osd_list_flags_lstchg= -1;
static int hf_scsi_osd_list_flags_root= -1;
static int hf_scsi_osd_user_object_id= -1;
static int hf_scsi_osd_requested_user_object_id	= -1;
static int hf_scsi_osd_number_of_user_objects	= -1;
static int hf_scsi_osd_key_to_set		= -1;
static int hf_scsi_osd_set_key_version		= -1;
static int hf_scsi_osd_key_identifier		= -1;
static int hf_scsi_osd_seed			= -1;
static int hf_scsi_osd_collection_fcr		= -1;
static int hf_scsi_osd_collection_object_id	= -1;
static int hf_scsi_osd_requested_collection_object_id	= -1;
static int hf_scsi_osd_partition_created_in	= -1;
static int hf_scsi_osd_partition_removed_in	= -1;
static int hf_scsi_osd_flush_scope		= -1;
static int hf_scsi_osd_flush_collection_scope	= -1;
static int hf_scsi_osd_flush_partition_scope	= -1;
static int hf_scsi_osd_flush_osd_scope		= -1;
static int hf_scsi_osd_attributes_list_type	= -1;
static int hf_scsi_osd_attributes_list_length	= -1;
static int hf_scsi_osd_attributes_page		= -1;
static int hf_scsi_osd_attribute_number		= -1;
static int hf_scsi_osd_attribute_length		= -1;
static int hf_scsi_osd_user_object_logical_length	= -1;

static gint ett_osd_option		= -1;
static gint ett_osd_partition		= -1;
static gint ett_osd_attribute_parameters= -1;
static gint ett_osd_capability		= -1;
static gint ett_osd_permission_bitmask	= -1;
static gint ett_osd_security_parameters	= -1;


#define PAGE_NUMBER_PARTITION		0x30000000
#define PAGE_NUMBER_COLLECTION		0x60000000
#define PAGE_NUMBER_ROOT		0x90000000

#define AP_USER_OBJECT_INFO		0x00000001

/* There will be one such structure create for each conversation ontop of which
 * there is an OSD session
 */
typedef struct _scsi_osd_conv_info_t {
	emem_tree_t *luns;
} scsi_osd_conv_info_t;

/* there will be one such structure created for each lun for each conversation
 * that is handled by the OSD dissector
 */
typedef struct _scsi_osd_lun_info_t {
	emem_tree_t *partitions;
} scsi_osd_lun_info_t;

typedef void (*scsi_osd_dissector_t)(tvbuff_t *tvb, packet_info *pinfo,
		proto_tree *tree, guint offset,
		gboolean isreq, gboolean iscdb,
                guint32 payload_len, scsi_task_data_t *cdata,
		scsi_osd_conv_info_t *conv_info,
		scsi_osd_lun_info_t *lun_info
		);

/* One such structure is created per conversation/lun/partition to
 * keep track of when partitions are created/used/destroyed
 */
typedef struct _partition_info_t {
	int created_in;
	int removed_in;
} partition_info_t;


/* This is a set of extra data specific to OSD that we need to attach to every
 * task.
 */
typedef struct _scsi_osd_extra_data_t {
	guint16 svcaction;
	guint8  gsatype;
	union {
		struct {	/* gsatype: attribute list */
			guint32 get_list_length;
			guint32 get_list_offset;
			guint32 get_list_allocation_length;
			guint32 retrieved_list_offset;
			guint32 set_list_length;
			guint32 set_list_offset;
		} al;
	} u;
} scsi_osd_extra_data_t;

static void
dissect_osd_user_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* user object id */
	proto_tree_add_item(tree, hf_scsi_osd_user_object_id, tvb, offset, 8, 0);
	offset+=8;
}



static void
attribute_1_82(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset=0;

	/* user object id */
	proto_tree_add_item(tree, hf_scsi_osd_user_object_logical_length, tvb, offset, 8, 0);
	offset+=8;
}



typedef void (*attribute_dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

typedef struct _attribute_page_numbers_t {
    guint32	number;
    const char	*name;
    attribute_dissector dissector;
} attribute_page_numbers_t;
static const attribute_page_numbers_t user_object_info_attributes[] = {
    {0x82,	"User object logical length", attribute_1_82},
    {0, NULL, NULL}
};

typedef struct _attribute_pages_t {
    guint32	page;
    const attribute_page_numbers_t *attributes;
} attribute_pages_t;
static const attribute_pages_t attribute_pages[] = {
    {AP_USER_OBJECT_INFO,	user_object_info_attributes},
    {0,NULL}
};

static const value_string attributes_page_vals[] = {
    {AP_USER_OBJECT_INFO,		"User Object Information"},
    {0, NULL}
};


static const value_string attributes_list_type_vals[] = {
    {0x01,	"Retrieve attributes for this OSD object"},
    {0x09,	"Retrieve/Set attributes for this OSD object"},
    {0x0f,	"Retrieve attributes for a CREATE command"},
    {0,NULL}
};

/* 7.1.3.1 */
static void
dissect_osd_attributes_list(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint8 type;
	guint16 length, attribute_length;
	guint32 page, number;
	int start_offset=offset;
	proto_item *item;
	const attribute_pages_t *ap;
	const attribute_page_numbers_t *apn;
	tvbuff_t *next_tvb;

	/* list type */
	type=tvb_get_guint8(tvb, offset)&0x0f;
	proto_tree_add_item(tree, hf_scsi_osd_attributes_list_type, tvb, offset, 1, 0);
	offset++;

	/* a reserved byte */
	offset++;

	/* length */
	length=tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_scsi_osd_attributes_list_length, tvb, offset, 2, 0);
	offset+=2;

	/* if type is 1 length will be zero and we have to cycle over
	 * all remaining bytes.   7.1.3.1 
	 */
	if(type==1){
		length=tvb_length_remaining(tvb, offset);
	}

	while( (offset-start_offset)<(length+4) ){
		switch(type){
		case 0x01: /* retrieving attributes 7.1.3.2 */
			/* attributes page */
			page=tvb_get_ntohl(tvb, offset);
			proto_tree_add_item(tree, hf_scsi_osd_attributes_page, tvb, offset, 4, 0);
			offset+=4;

			/* attribute number */
			number=tvb_get_ntohl(tvb, offset);
			item=proto_tree_add_item(tree, hf_scsi_osd_attribute_number, tvb, offset, 4, 0);
			offset+=4;

			/* find the proper attributes page */
			apn=NULL;
			for(ap=attribute_pages;ap->attributes;ap++){
				if(ap->page==page){
					apn=ap->attributes;
					break;
				}
			}
			if(!apn){
				proto_tree_add_text(tree, tvb, offset, length, "Unknown attribute page. can not decode attribute value");
				break;
			}
			/* find the specific attribute */
			for(;apn->name;apn++){
				if(apn->number==number){
					break;
				}
			}
			if(!apn->name){
				proto_tree_add_text(tree, tvb, offset, length, "Unknown attribute. can not decode attribute value");
				break;
			}
			/* found it */
			proto_item_append_text(item, " (%s)", apn->name);

			break;
		case 0x0f: /* create attributes 7.1.3.4 */
			/* user object id */
			dissect_osd_user_object_id(tvb, offset, tree);
			offset+=8;

			/* fallthrough to the next case */
		case 0x09: /* retrieved/set attributes 7.1.3.3 */
			/* attributes page */
			page=tvb_get_ntohl(tvb, offset);
			proto_tree_add_item(tree, hf_scsi_osd_attributes_page, tvb, offset, 4, 0);
			offset+=4;

			/* attribute number */
			number=tvb_get_ntohl(tvb, offset);
			item=proto_tree_add_item(tree, hf_scsi_osd_attribute_number, tvb, offset, 4, 0);
			offset+=4;

			/* attribute length */
			attribute_length=tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(tree, hf_scsi_osd_attribute_length, tvb, offset, 2, 0);
			offset+=2;

			/* find the proper attributes page */
			apn=NULL;
			for(ap=attribute_pages;ap->attributes;ap++){
				if(ap->page==page){
					apn=ap->attributes;
					break;
				}
			}
			if(!apn){
				proto_tree_add_text(tree, tvb, offset, length, "Unknown attribute page. can not decode attribute value");
				offset+=attribute_length;
				break;
			}
			/* find the specific attribute */
			for(;apn->name;apn++){
				if(apn->number==number){
					break;
				}
			}
			if(!apn->name){
				proto_tree_add_text(tree, tvb, offset, length, "Unknown attribute. can not decode attribute value");
				offset+=attribute_length;
				break;
			}
			/* found it */
			proto_item_append_text(item, " (%s)", apn->name);
			if(attribute_length==0){
				/* nothing to dissect */
				offset+=attribute_length;
				break;
			}
			next_tvb=tvb_new_subset(tvb, offset, attribute_length, attribute_length);
			apn->dissector(next_tvb, pinfo, tree);

			offset+=attribute_length;
			break;
		default:
			proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "Don't know how to decode this attribute list type:0x%02x",type);
			return;
		}
	}
}

static const true_false_string option_dpo_tfs = {
	"DPO is SET",
	"Dpo is NOT set"
};
static const true_false_string option_fua_tfs = {
	"FUA is SET",
	"Fua is NOT set"
};

/* OSD2 5.2.4 */
static void
dissect_osd_option(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
	proto_tree *tree=NULL;
	proto_item *it=NULL;
	guint8 option;

	option=tvb_get_guint8(tvb, offset);

	if(parent_tree){
		it=proto_tree_add_item(parent_tree, hf_scsi_osd_option, tvb, offset, 1, 0);
		tree = proto_item_add_subtree(it, ett_osd_option);
	}

	proto_tree_add_item(tree, hf_scsi_osd_option_dpo, tvb, offset, 1, 0);
	if(option&0x10){
		proto_item_append_text(tree, " DPO");
	}

	proto_tree_add_item(tree, hf_scsi_osd_option_fua, tvb, offset, 1, 0);
	if(option&0x08){
		proto_item_append_text(tree, " FUA");
	}
}


static const value_string scsi_osd_getsetattrib_vals[] = {
    {2,		"Get an attributes page and set an attribute value"},
    {3,		"Get and set attributes using a list"},
    {0, NULL},
};
/* OSD2 5.2.2.1 */
static void
dissect_osd_getsetattrib(tvbuff_t *tvb, int offset, proto_tree *tree, scsi_task_data_t *cdata)
{
	if(cdata && cdata->itlq && cdata->itlq->extra_data){
		scsi_osd_extra_data_t *extra_data=cdata->itlq->extra_data;
		extra_data->gsatype=(tvb_get_guint8(tvb, offset)>>4)&0x03;
	}
	proto_tree_add_item(tree, hf_scsi_osd_getsetattrib, tvb, offset, 1, 0);
}


static const value_string scsi_osd_timestamps_control_vals[] = {
    {0x00,	"Timestamps shall be updated"},
    {0x7f,	"Timestamps shall not be updated"},
    {0, NULL},
};
/* OSD2 5.2.8 */
static void
dissect_osd_timestamps_control(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_scsi_osd_timestamps_control, tvb, offset, 1, 0);
}


static void
dissect_osd_formatted_capacity(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_scsi_osd_formatted_capacity, tvb, offset, 8, 0);
}


static void
dissect_osd_attribute_parameters(tvbuff_t *tvb, int offset, proto_tree *parent_tree, scsi_task_data_t *cdata)
{
	guint8 gsatype=0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	scsi_osd_extra_data_t *extra_data=NULL;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 28,
		    "Attribute Parameters");
		tree = proto_item_add_subtree(item, ett_osd_attribute_parameters);
	}
		
	if(cdata && cdata->itlq && cdata->itlq->extra_data){
		extra_data=cdata->itlq->extra_data;
		gsatype=extra_data->gsatype;
	} else {
		return;
	}

	switch(gsatype){
	case 2: /* 5.2.2.2  attribute page */
		proto_tree_add_item(tree, hf_scsi_osd_get_attributes_page, tvb, offset, 4, 0);
		offset+=4;
		proto_tree_add_item(tree, hf_scsi_osd_get_attributes_allocation_length, tvb, offset, 4, 0);
		offset+=4;
		proto_tree_add_item(tree, hf_scsi_osd_retrieved_attributes_offset, tvb, offset, 4, 0);
		offset+=4;
		proto_tree_add_item(tree, hf_scsi_osd_set_attributes_page, tvb, offset, 4, 0);
		offset+=4;
		proto_tree_add_item(tree, hf_scsi_osd_set_attribute_number, tvb, offset, 4, 0);
		offset+=4;
		proto_tree_add_item(tree, hf_scsi_osd_set_attribute_length, tvb, offset, 4, 0);
		offset+=4;
		proto_tree_add_item(tree, hf_scsi_osd_set_attributes_offset, tvb, offset, 4, 0);
		offset+=4;
		break;
	case 3: /* 5.2.2.3  attribute list */
		proto_tree_add_item(tree, hf_scsi_osd_get_attributes_list_length, tvb, offset, 4, 0);
		extra_data->u.al.get_list_length=tvb_get_ntohl(tvb, offset);
		offset+=4;

		/* 4.12.5 */
		extra_data->u.al.get_list_offset=tvb_get_ntohl(tvb, offset);
		extra_data->u.al.get_list_offset=(extra_data->u.al.get_list_offset&0x0fffffff)<<((extra_data->u.al.get_list_offset>>28)&0x0f);
		extra_data->u.al.get_list_offset<<=8;
		proto_tree_add_uint(tree, hf_scsi_osd_get_attributes_list_offset, tvb, offset, 4, extra_data->u.al.get_list_offset);
		offset+=4;

		proto_tree_add_item(tree, hf_scsi_osd_get_attributes_allocation_length, tvb, offset, 4, 0);
		extra_data->u.al.get_list_allocation_length=tvb_get_ntohl(tvb, offset);
		offset+=4;

		/* 4.12.5 */
		extra_data->u.al.retrieved_list_offset=tvb_get_ntohl(tvb, offset);
		extra_data->u.al.retrieved_list_offset=(extra_data->u.al.retrieved_list_offset&0x0fffffff)<<((extra_data->u.al.retrieved_list_offset>>28)&0x0f);
		extra_data->u.al.retrieved_list_offset<<=8;
		proto_tree_add_uint(tree, hf_scsi_osd_retrieved_attributes_offset, tvb, offset, 4, extra_data->u.al.retrieved_list_offset);
		offset+=4;

		proto_tree_add_item(tree, hf_scsi_osd_set_attributes_list_length, tvb, offset, 4, 0);
		extra_data->u.al.set_list_length=tvb_get_ntohl(tvb, offset);
		offset+=4;

		proto_tree_add_item(tree, hf_scsi_osd_set_attributes_list_offset, tvb, offset, 4, 0);
		extra_data->u.al.set_list_offset=tvb_get_ntohl(tvb, offset);
		offset+=4;

		/* 4 reserved bytes */
		offset+=4;

		break;
	}
}


static void
dissect_osd_attribute_data_out(packet_info *pinfo, tvbuff_t *tvb, int offset _U_, proto_tree *tree, scsi_task_data_t *cdata)
{
	guint8 gsatype=0;
	scsi_osd_extra_data_t *extra_data=NULL;

	if(cdata && cdata->itlq && cdata->itlq->extra_data){
		extra_data=cdata->itlq->extra_data;
		gsatype=extra_data->gsatype;
	} else {
		return;
	}

	switch(gsatype){
	case 2: /* 5.2.2.2  attribute page */
/*qqq*/
		break;
	case 3: /* 5.2.2.3  attribute list */
		if(extra_data->u.al.get_list_length){
			dissect_osd_attributes_list(pinfo, tvb, extra_data->u.al.get_list_offset, tree);
		}
		if(extra_data->u.al.set_list_length){
			proto_tree_add_text(tree, tvb, extra_data->u.al.set_list_offset, extra_data->u.al.set_list_length, "Set Attributes Data");
		}
		break;
	}
}


static void
dissect_osd_attribute_data_in(packet_info *pinfo, tvbuff_t *tvb, int offset _U_, proto_tree *tree, scsi_task_data_t *cdata)
{
	guint8 gsatype=0;
	scsi_osd_extra_data_t *extra_data=NULL;

	if(cdata && cdata->itlq && cdata->itlq->extra_data){
		extra_data=cdata->itlq->extra_data;
		gsatype=extra_data->gsatype;
	} else {
		return;
	}

	switch(gsatype){
	case 2: /* 5.2.2.2  attribute page */
/*qqq*/
		break;
	case 3: /* 5.2.2.3  attribute list */
		if(extra_data->u.al.get_list_allocation_length){
			dissect_osd_attributes_list(pinfo, tvb, extra_data->u.al.retrieved_list_offset, tree);
		}
		break;
	}
}


static const value_string scsi_osd_capability_format_vals[] = {
    {0x00,	"No Capability"},
    {0x01,	"SCSI OSD Capabilities"},
    {0, NULL},
};
static const value_string scsi_osd_object_type_vals[] = {
    {0x01,	"ROOT"},
    {0x02,	"PARTITION"},
    {0x40,	"COLLECTION"},
    {0x80,	"USER"},
    {0, NULL},
};
static const value_string scsi_osd_object_descriptor_type_vals[] = {
    {0, "NONE: the object descriptor field shall be ignored"},
    {1, "U/C: a single collection or user object"},
    {2, "PAR: a single partition, including partition zero"},
    {0, NULL},
};

static const true_false_string permissions_read_tfs = {
	"READ is SET",
	"Read is NOT set"
};
static const true_false_string permissions_write_tfs = {
	"WRITE is SET",
	"Write is NOT set"
};
static const true_false_string permissions_get_attr_tfs = {
	"GET_ATTR is SET",
	"Get_attr is NOT set"
};
static const true_false_string permissions_set_attr_tfs = {
	"SET_ATTR is SET",
	"Set_attr is NOT set"
};
static const true_false_string permissions_create_tfs = {
	"CREATE is SET",
	"Create is NOT set"
};
static const true_false_string permissions_remove_tfs = {
	"REMOVE is SET",
	"Remove is NOT set"
};
static const true_false_string permissions_obj_mgmt_tfs = {
	"OBJ_MGMT is SET",
	"Obj_mgmt is NOT set"
};
static const true_false_string permissions_append_tfs = {
	"APPEND is SET",
	"Append is NOT set"
};
static const true_false_string permissions_dev_mgmt_tfs = {
	"DEV_MGMT is SET",
	"Dev_mgmt is NOT set"
};
static const true_false_string permissions_global_tfs = {
	"GLOBAL is SET",
	"Global is NOT set"
};
static const true_false_string permissions_pol_sec_tfs = {
	"POL/SEC is SET",
	"Pol/sec is NOT set"
};
/* OSD 4.9.2.2.1 */
static void
dissect_osd_permissions(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
	proto_tree *tree=NULL;
	proto_item *it=NULL;
	guint16 permissions;

	permissions=tvb_get_ntohs(tvb, offset); 

	if(parent_tree){
		it=proto_tree_add_item(parent_tree, hf_scsi_osd_permissions, tvb, offset, 2, 0);
		tree = proto_item_add_subtree(it, ett_osd_permission_bitmask);
	}

	proto_tree_add_item(tree, hf_scsi_osd_permissions_read, tvb, offset, 2, 0);
	if(permissions&0x8000){
		proto_item_append_text(tree, " READ");
	}
	proto_tree_add_item(tree, hf_scsi_osd_permissions_write, tvb, offset, 2, 0);
	if(permissions&0x4000){
		proto_item_append_text(tree, " WRITE");
	}
	proto_tree_add_item(tree, hf_scsi_osd_permissions_get_attr, tvb, offset, 2, 0);
	if(permissions&0x2000){
		proto_item_append_text(tree, " GET_ATTR");
	}
	proto_tree_add_item(tree, hf_scsi_osd_permissions_set_attr, tvb, offset, 2, 0);
	if(permissions&0x1000){
		proto_item_append_text(tree, " SET_ATTR");
	}
	proto_tree_add_item(tree, hf_scsi_osd_permissions_create, tvb, offset, 2, 0);
	if(permissions&0x0800){
		proto_item_append_text(tree, " CREATE");
	}
	proto_tree_add_item(tree, hf_scsi_osd_permissions_remove, tvb, offset, 2, 0);
	if(permissions&0x0400){
		proto_item_append_text(tree, " REMOVE");
	}
	proto_tree_add_item(tree, hf_scsi_osd_permissions_obj_mgmt, tvb, offset, 2, 0);
	if(permissions&0x0200){
		proto_item_append_text(tree, " OBJ_MGMT");
	}
	proto_tree_add_item(tree, hf_scsi_osd_permissions_append, tvb, offset, 2, 0);
	if(permissions&0x0100){
		proto_item_append_text(tree, " APPEND");
	}
	proto_tree_add_item(tree, hf_scsi_osd_permissions_dev_mgmt, tvb, offset, 2, 0);
	if(permissions&0x0080){
		proto_item_append_text(tree, " DEV_MGMT");
	}
	proto_tree_add_item(tree, hf_scsi_osd_permissions_global, tvb, offset, 2, 0);
	if(permissions&0x0040){
		proto_item_append_text(tree, " GLOBAL");
	}
	proto_tree_add_item(tree, hf_scsi_osd_permissions_pol_sec, tvb, offset, 2, 0);
	if(permissions&0x0020){
		proto_item_append_text(tree, " POL/SEC");
	}
}

/* 4.9.2.2 */
static void
dissect_osd_capability(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 80,
		    "Capability");
		tree = proto_item_add_subtree(item, ett_osd_capability);
	}
		
	/* capability format */
	proto_tree_add_item(tree, hf_scsi_osd_capability_format, tvb, offset, 1, 0);
	offset++;

	/* key version and icva */
	proto_tree_add_item(tree, hf_scsi_osd_key_version, tvb, offset, 1, 0);
	proto_tree_add_item(tree, hf_scsi_osd_icva, tvb, offset, 1, 0);
	offset++;

	/* security method */
	proto_tree_add_item(tree, hf_scsi_osd_security_method, tvb, offset, 1, 0);
	offset++;

	/* a reserved byte */
	offset++;

	/* capability expiration time */
	proto_tree_add_item(tree, hf_scsi_osd_capability_expiration_time, tvb, offset, 6, 0);
	offset+=6;

	/* audit */
	proto_tree_add_item(tree, hf_scsi_osd_audit, tvb, offset, 20, 0);
	offset+=20;

	/* capability discriminator */
	proto_tree_add_item(tree, hf_scsi_osd_capability_discriminator, tvb, offset, 12, 0);
	offset+=12;

	/* object created time */
	proto_tree_add_item(tree, hf_scsi_osd_object_created_time, tvb, offset, 6, 0);
	offset+=6;

	/* object type */
	proto_tree_add_item(tree, hf_scsi_osd_object_type, tvb, offset, 1, 0);
	offset++;

	/* permission bitmask */
	dissect_osd_permissions(tvb, offset, tree);
	offset+=5;

	/* a reserved byte */
	offset++;

	/* object descriptor type */
	proto_tree_add_item(tree, hf_scsi_osd_object_descriptor_type, tvb, offset, 1, 0);
	offset++;

	/* object descriptor */
	proto_tree_add_item(tree, hf_scsi_osd_object_descriptor, tvb, offset, 24, 0);
	offset+=24;
}



/* 5.2.6 */
static void
dissect_osd_security_parameters(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 40,
		    "Security Parameters");
		tree = proto_item_add_subtree(item, ett_osd_security_parameters);
	}
		
	/* request integrity check value */
	proto_tree_add_item(tree, hf_scsi_osd_ricv, tvb, offset, 20, 0);
	offset+=20;

	/* request nonce */
	proto_tree_add_item(tree, hf_scsi_osd_request_nonce, tvb, offset, 12, 0);
	offset+=12;

	/* data in integrity check value offset */
	proto_tree_add_item(tree, hf_scsi_osd_diicvo, tvb, offset, 4, 0);
	offset+=4;

	/* data out integrity check value offset */
	proto_tree_add_item(tree, hf_scsi_osd_doicvo, tvb, offset, 4, 0);
	offset+=4;
}

static void
dissect_osd_format_osd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info _U_)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 23 reserved bytes */
		offset+=23;

		/* formatted capacity */
		dissect_osd_formatted_capacity(tvb, offset, tree);
		offset+=8;

		/* 8 reserved bytes */
		offset+=8;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for format osd */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for format osd */
	}
	
}


static void
dissect_osd_partition_id(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree, int hf_index, scsi_osd_lun_info_t *lun_info, gboolean is_created, gboolean is_removed)
{
	proto_item *item=NULL;
	guint32 partition_id[2];

	/* partition id */
	item=proto_tree_add_item(tree, hf_index, tvb, offset, 8, 0);
	partition_id[0]=tvb_get_ntohl(tvb, offset);
	partition_id[1]=tvb_get_ntohl(tvb, offset+4);
	if(!partition_id[0] && !partition_id[1]){
		proto_item_append_text(item, " (ROOT partition)");
	} else {
		partition_info_t *part_info;
		emem_tree_key_t pikey[2];
		proto_tree *partition_tree=NULL;

		pikey[0].length=2;
		pikey[0].key=partition_id;
		pikey[1].length=0;
		part_info=se_tree_lookup32_array(lun_info->partitions, &pikey[0]);
		if(!part_info){
			part_info=se_alloc(sizeof(partition_info_t));
			part_info->created_in=0;
			part_info->removed_in=0;

			pikey[0].length=2;
			pikey[0].key=partition_id;
			pikey[1].length=0;
			se_tree_insert32_array(lun_info->partitions, &pikey[0], part_info);
		}
		if(is_created){
			part_info->created_in=pinfo->fd->num;
		}
		if(is_removed){
			part_info->removed_in=pinfo->fd->num;
		}
		if(item){
			partition_tree=proto_item_add_subtree(item, ett_osd_partition);
		}
		if(part_info->created_in){
			proto_item *tmp_item;
			tmp_item=proto_tree_add_uint(partition_tree, hf_scsi_osd_partition_created_in, tvb, 0, 0, part_info->created_in);
			PROTO_ITEM_SET_GENERATED(tmp_item);
		}
		if(part_info->removed_in){
			proto_item *tmp_item;
			tmp_item=proto_tree_add_uint(partition_tree, hf_scsi_osd_partition_removed_in, tvb, 0, 0, part_info->removed_in);
			PROTO_ITEM_SET_GENERATED(tmp_item);
		}
	}
	offset+=8;
}



static void
dissect_osd_create_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* requested partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_requested_partition_id, lun_info, TRUE, FALSE);
		offset+=8;

		/* 28 reserved bytes */
		offset+=28;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for create partition */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for create partition */
	}
	
}

static const value_string scsi_osd_sort_order_vals[] = {
    {0x00,	"Ascending numeric value"},
    {0, NULL},
};
static void
dissect_osd_sortorder(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* sort order */
	proto_tree_add_item(tree, hf_scsi_osd_sortorder, tvb, offset, 1, 0);
	offset++;
}

static void
dissect_osd_list_identifier(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* list identifier */
	proto_tree_add_item(tree, hf_scsi_osd_list_identifier, tvb, offset, 4, 0);
	offset+=4;
}

static void
dissect_osd_allocation_length(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* allocation length */
	proto_tree_add_item(tree, hf_scsi_osd_allocation_length, tvb, offset, 8, 0);
	offset+=8;
}

static void
dissect_osd_initial_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* initial object id */
	proto_tree_add_item(tree, hf_scsi_osd_initial_object_id, tvb, offset, 8, 0);
	offset+=8;
}

static void
dissect_osd_additional_length(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* additional length */
	proto_tree_add_item(tree, hf_scsi_osd_additional_length, tvb, offset, 8, 0);
	offset+=8;
}


static void
dissect_osd_continuation_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* continuation object id */
	proto_tree_add_item(tree, hf_scsi_osd_continuation_object_id, tvb, offset, 8, 0);
	offset+=8;
}

static const true_false_string list_lstchg_tfs = {
	"List has CHANGED since the first List command",
	"List has NOT changed since first command"
};
static const true_false_string list_root_tfs = {
	"Objects are from root and are PARTITION IDs",
	"Objects are from a partition and are USER OBJECTs"
};


static void
dissect_osd_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte / sort order */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		dissect_osd_sortorder(tvb, offset, tree);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* 8 reserved bytes */
		offset+=8;

		/* list identifier */
		dissect_osd_list_identifier(tvb, offset, tree);
		offset+=4;

		/* allocation length */
		dissect_osd_allocation_length(tvb, offset, tree);
		offset+=8;

		/* initial object id */
		dissect_osd_initial_object_id(tvb, offset, tree);
		offset+=8;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for LIST */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		guint64 additional_length;
		gboolean is_root;

		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* dissection of the LIST DATA-IN */
		/* additional length */
		additional_length=tvb_get_ntoh64(tvb, offset);
		dissect_osd_additional_length(tvb, offset, tree);
		offset+=8;

		/* continuation object id */
		dissect_osd_continuation_object_id(tvb, offset, tree);
		offset+=8;

		/* list identifier */
		dissect_osd_list_identifier(tvb, offset, tree);
		offset+=4;

		/* 3 reserved bytes */
		offset+=3;

		/* LSTCHG and ROOT flags */
		proto_tree_add_item(tree, hf_scsi_osd_list_flags_lstchg, tvb, offset, 1, 0);
		proto_tree_add_item(tree, hf_scsi_osd_list_flags_root, tvb, offset, 1, 0);
		is_root=tvb_get_guint8(tvb, offset)&0x01;
		offset++;


		/* list of user object ids or partition ids */
		while(additional_length > (offset-8)){
			if(is_root){
				dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
			} else {
				dissect_osd_user_object_id(tvb, offset, tree);
			}
			offset+=8;
		}
	}
	
}

static void
dissect_osd_requested_user_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* request user object id */
	proto_tree_add_item(tree, hf_scsi_osd_requested_user_object_id, tvb, offset, 8, 0);
	offset+=8;
}

static void
dissect_osd_number_of_user_objects(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* number_of_user_objects */
	proto_tree_add_item(tree, hf_scsi_osd_number_of_user_objects, tvb, offset, 2, 0);
	offset+=2;
}

static void
dissect_osd_create(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* requested user_object id */
		dissect_osd_requested_user_object_id(tvb, offset, tree);
		offset+=8;

		/* 4 reserved bytes */
		offset+=4;

		/* number of user objects */
		dissect_osd_number_of_user_objects(tvb, offset, tree);
		offset+=2;

		/* 14 reserved bytes */
		offset+=14;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for create */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for create */
	}
	
}


static void
dissect_osd_remove_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, TRUE);
		offset+=8;

		/* 28 reserved bytes */
		offset+=28;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for remove partition */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for remove partition */
	}
	
}

static const value_string key_to_set_vals[] = {
    {1,	"Root"},
    {2,	"Partition"},
    {3,	"Working"},
    {0, NULL},
};
static void
dissect_osd_key_to_set(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_scsi_osd_key_to_set, tvb, offset, 1, 0);
}

static void
dissect_osd_set_key_version(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_scsi_osd_set_key_version, tvb, offset, 1, 0);
}

static void
dissect_osd_key_identifier(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_scsi_osd_key_identifier, tvb, offset, 7, 0);
}

static void
dissect_osd_seed(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_scsi_osd_seed, tvb, offset, 20, 0);
}

static void
dissect_osd_set_key(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* a reserved byte */
		offset++;

		/* getset attributes byte and key to set*/
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		dissect_osd_key_to_set(tvb, offset, tree);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* key version */
		dissect_osd_set_key_version(tvb, offset, tree);
		offset++;

		/* key identifier */
		dissect_osd_key_identifier(tvb, offset, tree);
		offset+=7;

		/* seed */
		dissect_osd_seed(tvb, offset, tree);
		offset+=20;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for set key */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for set key */
	}
	
}

static void
dissect_osd_remove(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* user object id */
		dissect_osd_user_object_id(tvb, offset, tree);
		offset+=8;

		/* 20 reserved bytes */
		offset+=20;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for remove */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for remove */
	}
	
}

static const true_false_string collection_fcr_tfs = {
	"FCR is SET",
	"Fcr is NOR set"
};
static void
dissect_osd_collection_fcr(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_scsi_osd_collection_fcr, tvb, offset, 1, 0);
}

static void
dissect_osd_collection_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* collection object id */
	proto_tree_add_item(tree, hf_scsi_osd_collection_object_id, tvb, offset, 8, 0);
	offset+=8;
}


static void
dissect_osd_remove_collection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		dissect_osd_collection_fcr(tvb, offset, tree);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* collection object id */
		dissect_osd_collection_object_id(tvb, offset, tree);
		offset+=8;

		/* 20 reserved bytes */
		offset+=20;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for remove collection */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for remove collection */
	}
	
}


static void
dissect_osd_length(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* length */
	proto_tree_add_item(tree, hf_scsi_osd_length, tvb, offset, 8, 0);
	offset+=8;
}

static void
dissect_osd_starting_byte_address(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* starting_byte_address */
	proto_tree_add_item(tree, hf_scsi_osd_starting_byte_address, tvb, offset, 8, 0);
	offset+=8;
}


static void
dissect_osd_write(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte / sort order */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* user object id */
		dissect_osd_user_object_id(tvb, offset, tree);
		offset+=8;

		/* 4 reserved bytes */
		offset+=4;

		/* length */
		dissect_osd_length(tvb, offset, tree);
		offset+=8;

		/* starting byte address */
		dissect_osd_starting_byte_address(tvb, offset, tree);
		offset+=8;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* xxx should dissect the data ? */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for WRITE */
	}
	
}


static void
dissect_osd_requested_collection_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* requested collection object id */
	proto_tree_add_item(tree, hf_scsi_osd_requested_collection_object_id, tvb, offset, 8, 0);
	offset+=8;
}


static void
dissect_osd_create_collection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		dissect_osd_collection_fcr(tvb, offset, tree);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* requested collection object id */
		dissect_osd_requested_collection_object_id(tvb, offset, tree);
		offset+=8;

		/* 20 reserved bytes */
		offset+=20;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for create collection */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for create collection */
	}
	
}


static const value_string flush_scope_vals[] = {
	{0,	"User object data and attributes"},
	{1,	"User object attributes only"},
	{0, NULL}
};

static void
dissect_osd_flush_scope(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* flush scope */
	proto_tree_add_item(tree, hf_scsi_osd_flush_scope, tvb, offset, 1, 0);
	offset++;
}

static void
dissect_osd_flush(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_flush_scope(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* user object id */
		dissect_osd_user_object_id(tvb, offset, tree);
		offset+=8;

		/* 20 reserved bytes */
		offset+=20;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for flush */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for flush */
	}
	
}


static const value_string flush_collection_scope_vals[] = {
	{0,	"List of user objects contained in the collection"},
	{1,	"Collection attributes only"},
	{2,	"List of user objects and collection attributes"},
	{0, NULL}
};

static void
dissect_osd_flush_collection_scope(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* flush collection scope */
	proto_tree_add_item(tree, hf_scsi_osd_flush_collection_scope, tvb, offset, 1, 0);
	offset++;
}

static void
dissect_osd_flush_collection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_flush_collection_scope(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		dissect_osd_collection_fcr(tvb, offset, tree);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* collection object id */
		dissect_osd_collection_object_id(tvb, offset, tree);
		offset+=8;

		/* 20 reserved bytes */
		offset+=20;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for flush collection */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for flush collection */
	}
	
}


static void
dissect_osd_append(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* user object id */
		dissect_osd_user_object_id(tvb, offset, tree);
		offset+=8;

		/* 4 reserved bytes */
		offset+=4;

		/* length */
		dissect_osd_length(tvb, offset, tree);
		offset+=8;

		/* 8 reserved bytes */
		offset+=8;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* xxx should dissect the data ? */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for append */
	}
	
}

static void
dissect_osd_create_and_write(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* requested user_object id */
		dissect_osd_requested_user_object_id(tvb, offset, tree);
		offset+=8;

		/* 4 reserved bytes */
		offset+=4;

		/* length */
		dissect_osd_length(tvb, offset, tree);
		offset+=8;

		/* starting byte address */
		dissect_osd_starting_byte_address(tvb, offset, tree);
		offset+=8;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* should we dissect the data? */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for create and write*/
	}
	
}


static const value_string flush_osd_scope_vals[] = {
	{0,	"List of partitions contained in the OSD logical unit"},
	{1,	"Root object attributes only"},
	{2,	"Everything"},
	{0, NULL}
};

static void
dissect_osd_flush_osd_scope(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* flush osd scope */
	proto_tree_add_item(tree, hf_scsi_osd_flush_osd_scope, tvb, offset, 1, 0);
	offset++;
}

static void
dissect_osd_flush_osd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info _U_)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_flush_osd_scope(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 39 reserved bytes */
		offset+=39;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for flush osd */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for flush osd */
	}
	
}


static const value_string flush_partition_scope_vals[] = {
	{0,	"List of user objects and collections in the partition"},
	{1,	"Partition attributes only"},
	{2,	"Everything"},
	{0, NULL}
};

static void
dissect_osd_flush_partition_scope(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* flush partition scope */
	proto_tree_add_item(tree, hf_scsi_osd_flush_partition_scope, tvb, offset, 1, 0);
	offset++;
}


static void
dissect_osd_flush_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_flush_partition_scope(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* 28 reserved bytes */
		offset+=28;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for flush partition */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for flush partition */
	}
	
}


static void
dissect_osd_get_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, TRUE);
		offset+=8;

		/* user_object id */
		dissect_osd_user_object_id(tvb, offset, tree);
		offset+=8;

		/* 20 reserved bytes */
		offset+=20;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for get attributes */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for get attributes */
	}
	
}


static void
dissect_osd_list_collection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* one reserved byte */
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* collection object id */
		dissect_osd_collection_object_id(tvb, offset, tree);
		offset+=8;

		/* list identifier */
		dissect_osd_list_identifier(tvb, offset, tree);
		offset+=4;

		/* allocation length */
		dissect_osd_allocation_length(tvb, offset, tree);
		offset+=8;

		/* initial object id */
		dissect_osd_initial_object_id(tvb, offset, tree);
		offset+=8;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for list collection */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

/* XXX dissect the data */
	}
	
}



static void
dissect_osd_read(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte / sort order */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
		offset+=8;

		/* user object id */
		dissect_osd_user_object_id(tvb, offset, tree);
		offset+=8;

		/* 4 reserved bytes */
		offset+=4;

		/* length */
		dissect_osd_length(tvb, offset, tree);
		offset+=8;

		/* starting byte address */
		dissect_osd_starting_byte_address(tvb, offset, tree);
		offset+=8;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for READ */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

/* xxx should dissect the data ? */
	}
	
}


static void
dissect_osd_set_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
			scsi_osd_conv_info_t *conv_info _U_,
			scsi_osd_lun_info_t *lun_info)
{
	/* dissecting the CDB   dissection starts at byte 10 of the CDB */
	if(isreq && iscdb){
		/* options byte */
		dissect_osd_option(tvb, offset, tree);
		offset++;

		/* getset attributes byte */
		dissect_osd_getsetattrib(tvb, offset, tree, cdata);
		offset++;

		/* timestamps control */
		dissect_osd_timestamps_control(tvb, offset, tree);
		offset++;

		/* 3 reserved bytes */
		offset+=3;

		/* partiton id */
		dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, TRUE);
		offset+=8;

		/* user_object id */
		dissect_osd_user_object_id(tvb, offset, tree);
		offset+=8;

		/* 20 reserved bytes */
		offset+=20;

		/* attribute parameters */
		dissect_osd_attribute_parameters(tvb, offset, tree, cdata);
		offset+=28;

		/* capability */
		dissect_osd_capability(tvb, offset, tree);
		offset+=80;

		/* security parameters */
		dissect_osd_security_parameters(tvb, offset, tree);
		offset+=40;
	}

	/* dissecting the DATA OUT */
	if(isreq && !iscdb){
		/* attribute data out */
		dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata);

		/* no data out for set attributes */
	}

	/* dissecting the DATA IN */
	if(!isreq && !iscdb){
		/* attribute data in */
		dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata);

		/* no data in for set attributes */
	}
	
}

/* OSD Service Actions */
#define OSD_FORMAT_OSD		0x8801
#define OSD_CREATE		0x8802
#define OSD_LIST		0x8803
#define OSD_READ		0x8805
#define OSD_WRITE		0x8806
#define OSD_APPEND		0x8807
#define OSD_FLUSH		0x8808
#define OSD_REMOVE		0x880a
#define OSD_CREATE_PARTITION	0x880b
#define OSD_REMOVE_PARTITION	0x880c
#define OSD_GET_ATTRIBUTES	0x880e
#define OSD_SET_ATTRIBUTES	0x880f
#define OSD_CREATE_AND_WRITE	0x8812
#define OSD_CREATE_COLLECTION	0x8815
#define OSD_REMOVE_COLLECTION	0x8816
#define OSD_LIST_COLLECTION	0x8817
#define OSD_SET_KEY		0x8818
#define OSD_FLUSH_COLLECTION	0x881a
#define OSD_FLUSH_PARTITION	0x881b
#define OSD_FLUSH_OSD		0x881c
static const value_string scsi_osd_svcaction_vals[] = {
    {OSD_FORMAT_OSD,		"Format OSD"},
    {OSD_CREATE,		"Create"},
    {OSD_LIST,			"List"},
    {OSD_READ,			"Read"},
    {OSD_WRITE,			"Write"},
    {OSD_APPEND,		"Append"},
    {OSD_FLUSH,			"Flush"},
    {OSD_REMOVE,		"Remove"},
    {OSD_CREATE_PARTITION,	"Create Partition"},
    {OSD_REMOVE_PARTITION,	"Remove Partition"},
    {OSD_GET_ATTRIBUTES,	"Get Attributes"},
    {OSD_SET_ATTRIBUTES,	"Set Attributes"},
    {OSD_CREATE_AND_WRITE,	"Create And Write"},
    {OSD_CREATE_COLLECTION,	"Create Collection"},
    {OSD_REMOVE_COLLECTION,	"Remove Collection"},
    {OSD_LIST_COLLECTION,	"List Collection"},
    {OSD_SET_KEY,		"Set Key"},
    {OSD_FLUSH_COLLECTION,	"Flush Collection"},
    {OSD_FLUSH_PARTITION,	"Flush Partition"},
    {OSD_FLUSH_OSD,		"Flush OSD"},
    {0, NULL},
};

/* OSD Service Action dissectors */
typedef struct _scsi_osd_svcaction_t {
	guint16 svcaction;
	scsi_osd_dissector_t dissector;
} scsi_osd_svcaction_t;
static const scsi_osd_svcaction_t scsi_osd_svcaction[] = {
    {OSD_FORMAT_OSD, 		dissect_osd_format_osd},
    {OSD_CREATE,		dissect_osd_create},
    {OSD_LIST,			dissect_osd_list},
    {OSD_READ,			dissect_osd_read},
    {OSD_WRITE,			dissect_osd_write},
    {OSD_APPEND,		dissect_osd_append},
    {OSD_FLUSH,			dissect_osd_flush},
    {OSD_REMOVE,		dissect_osd_remove},
    {OSD_CREATE_PARTITION,	dissect_osd_create_partition},
    {OSD_REMOVE_PARTITION,	dissect_osd_remove_partition},
    {OSD_GET_ATTRIBUTES,	dissect_osd_get_attributes},
    {OSD_SET_ATTRIBUTES,	dissect_osd_set_attributes},
    {OSD_CREATE_AND_WRITE,	dissect_osd_create_and_write},
    {OSD_CREATE_COLLECTION,	dissect_osd_create_collection},
    {OSD_REMOVE_COLLECTION,	dissect_osd_remove_collection},
    {OSD_LIST_COLLECTION,	dissect_osd_list_collection},
    {OSD_SET_KEY,		dissect_osd_set_key},
    {OSD_FLUSH_COLLECTION,	dissect_osd_flush_collection},
    {OSD_FLUSH_PARTITION,	dissect_osd_flush_partition},
    {OSD_FLUSH_OSD,		dissect_osd_flush_osd},
    {0, NULL},
};

static scsi_osd_dissector_t
find_svcaction_dissector(guint16 svcaction)
{
	const scsi_osd_svcaction_t *sa=scsi_osd_svcaction;

	while(sa&&sa->dissector){
		if(sa->svcaction==svcaction){
			return sa->dissector;
		}
		sa++;
	}
	return NULL;
}



static void
dissect_osd_opcode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len, scsi_task_data_t *cdata)
{
	guint16 svcaction=0;
	scsi_osd_dissector_t dissector;
	scsi_osd_conv_info_t *conv_info=NULL;
	scsi_osd_lun_info_t *lun_info=NULL;

	if(!tree) {
		return;
	}

	/* We must have an itl an itlq and a conversation */
	if(!cdata || !cdata->itl || !cdata->itl->conversation || !cdata->itlq){
		return;
	}
	/* make sure we have a conversation info for this */
	conv_info=conversation_get_proto_data(cdata->itl->conversation, proto_scsi_osd);
	if(!conv_info){
		conv_info=se_alloc(sizeof(scsi_osd_conv_info_t));
		conv_info->luns=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "SCSI OSD luns tree");
		conversation_add_proto_data(cdata->itl->conversation, proto_scsi_osd, conv_info);
	}
	/* make sure we have a lun_info structure for this */
	lun_info=se_tree_lookup32(conv_info->luns, cdata->itlq->lun);
	if(!lun_info){
		lun_info=se_alloc(sizeof(scsi_osd_lun_info_t));
		lun_info->partitions=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "SCSI OSD partitions tree");
		se_tree_insert32(conv_info->luns, cdata->itlq->lun, (void *)lun_info);
	}

	/* dissecting the CDB */
	if (isreq && iscdb) {
		proto_tree_add_item (tree, hf_scsi_control, tvb, offset, 1, 0);
		offset++;

		/* 5 reserved bytes */
		offset+=5;

		proto_tree_add_item (tree, hf_scsi_osd_add_cdblen, tvb, offset, 1, 0);
		offset++;

		svcaction=tvb_get_ntohs(tvb, offset);
		if(cdata && cdata->itlq){
			/* We must store the service action for this itlq
			 * so we can indentify what the data contains
			 */
			if((!pinfo->fd->flags.visited) && (!cdata->itlq->extra_data)){
				scsi_osd_extra_data_t *extra_data;

				extra_data=se_alloc(sizeof(scsi_osd_extra_data_t));
				extra_data->svcaction=svcaction;
				extra_data->gsatype=0;
				cdata->itlq->extra_data=extra_data;
			}
		}
		proto_tree_add_item (tree, hf_scsi_osd_svcaction, tvb, offset, 2, 0);
		offset+=2;


		if(check_col(pinfo->cinfo, COL_INFO)){
			col_append_str(pinfo->cinfo, COL_INFO, 
				val_to_str(svcaction, scsi_osd_svcaction_vals, "Unknown OSD Serviceaction"));
		}
		dissector=find_svcaction_dissector(svcaction);
		if(dissector){
			(*dissector)(tvb, pinfo, tree, offset, isreq, iscdb, payload_len, cdata, conv_info, lun_info);
		}
		return;
	}

	/* If it was not a CDB, try to find the service action and pass it
	 * off to the service action dissector
	 */
	if(cdata && cdata->itlq && cdata->itlq->extra_data){
		scsi_osd_extra_data_t *extra_data=cdata->itlq->extra_data;
		svcaction=extra_data->svcaction;
	}
	if(check_col(pinfo->cinfo, COL_INFO)){
		col_append_str(pinfo->cinfo, COL_INFO, 
			val_to_str(svcaction, scsi_osd_svcaction_vals, "Unknown OSD Serviceaction"));
	}
	if(svcaction){
		proto_item *it;
		it=proto_tree_add_uint_format(tree, hf_scsi_osd_svcaction, tvb, 0, 0, svcaction, "Service Action: 0x%04x", svcaction);
		PROTO_ITEM_SET_GENERATED(it);
	}
	dissector=find_svcaction_dissector(svcaction);
	if(dissector){
		(*dissector)(tvb, pinfo, tree, offset, isreq, iscdb, payload_len, cdata, conv_info, lun_info);
	}

}


/* OSD Commands */
const value_string scsi_osd_vals[] = {
    {SCSI_SPC_INQUIRY			, "Inquiry"},
    {SCSI_SPC_LOGSELECT			, "Log Select"},
    {SCSI_SPC_LOGSENSE			, "Log Sense"},
    {SCSI_SPC_MODESELECT10		, "Mode Select(10)"},
    {SCSI_SPC_MODESENSE10		, "Mode Sense(10)"},
    {SCSI_SPC_PERSRESVIN		, "Persistent Reserve In"},
    {SCSI_SPC_PERSRESVOUT		, "Persistent Reserve Out"},
    {SCSI_SPC_REPORTLUNS		, "Report LUNs"},
    {SCSI_OSD_OPCODE			, "OSD Command" },
    {0, NULL},
};



scsi_cdb_table_t scsi_osd_table[256] = {
/*OSD 0x00*/{NULL},
/*OSD 0x01*/{NULL},
/*OSD 0x02*/{NULL},
/*OSD 0x03*/{NULL},
/*OSD 0x04*/{NULL},
/*OSD 0x05*/{NULL},
/*OSD 0x06*/{NULL},
/*OSD 0x07*/{NULL},
/*OSD 0x08*/{NULL},
/*OSD 0x09*/{NULL},
/*OSD 0x0a*/{NULL},
/*OSD 0x0b*/{NULL},
/*OSD 0x0c*/{NULL},
/*OSD 0x0d*/{NULL},
/*OSD 0x0e*/{NULL},
/*OSD 0x0f*/{NULL},
/*OSD 0x10*/{NULL},
/*OSD 0x11*/{NULL},
/*OSD 0x12*/{dissect_spc_inquiry},
/*OSD 0x13*/{NULL},
/*OSD 0x14*/{NULL},
/*OSD 0x15*/{NULL},
/*OSD 0x16*/{NULL},
/*OSD 0x17*/{NULL},
/*OSD 0x18*/{NULL},
/*OSD 0x19*/{NULL},
/*OSD 0x1a*/{NULL},
/*OSD 0x1b*/{NULL},
/*OSD 0x1c*/{NULL},
/*OSD 0x1d*/{NULL},
/*OSD 0x1e*/{NULL},
/*OSD 0x1f*/{NULL},
/*OSD 0x20*/{NULL},
/*OSD 0x21*/{NULL},
/*OSD 0x22*/{NULL},
/*OSD 0x23*/{NULL},
/*OSD 0x24*/{NULL},
/*OSD 0x25*/{NULL},
/*OSD 0x26*/{NULL},
/*OSD 0x27*/{NULL},
/*OSD 0x28*/{NULL},
/*OSD 0x29*/{NULL},
/*OSD 0x2a*/{NULL},
/*OSD 0x2b*/{NULL},
/*OSD 0x2c*/{NULL},
/*OSD 0x2d*/{NULL},
/*OSD 0x2e*/{NULL},
/*OSD 0x2f*/{NULL},
/*OSD 0x30*/{NULL},
/*OSD 0x31*/{NULL},
/*OSD 0x32*/{NULL},
/*OSD 0x33*/{NULL},
/*OSD 0x34*/{NULL},
/*OSD 0x35*/{NULL},
/*OSD 0x36*/{NULL},
/*OSD 0x37*/{NULL},
/*OSD 0x38*/{NULL},
/*OSD 0x39*/{NULL},
/*OSD 0x3a*/{NULL},
/*OSD 0x3b*/{NULL},
/*OSD 0x3c*/{NULL},
/*OSD 0x3d*/{NULL},
/*OSD 0x3e*/{NULL},
/*OSD 0x3f*/{NULL},
/*OSD 0x40*/{NULL},
/*OSD 0x41*/{NULL},
/*OSD 0x42*/{NULL},
/*OSD 0x43*/{NULL},
/*OSD 0x44*/{NULL},
/*OSD 0x45*/{NULL},
/*OSD 0x46*/{NULL},
/*OSD 0x47*/{NULL},
/*OSD 0x48*/{NULL},
/*OSD 0x49*/{NULL},
/*OSD 0x4a*/{NULL},
/*OSD 0x4b*/{NULL},
/*OSD 0x4c*/{dissect_spc_logselect},
/*OSD 0x4d*/{dissect_spc_logsense},
/*OSD 0x4e*/{NULL},
/*OSD 0x4f*/{NULL},
/*OSD 0x50*/{NULL},
/*OSD 0x51*/{NULL},
/*OSD 0x52*/{NULL},
/*OSD 0x53*/{NULL},
/*OSD 0x54*/{NULL},
/*OSD 0x55*/{dissect_spc_modeselect10},
/*OSD 0x56*/{NULL},
/*OSD 0x57*/{NULL},
/*OSD 0x58*/{NULL},
/*OSD 0x59*/{NULL},
/*OSD 0x5a*/{dissect_spc_modesense10},
/*OSD 0x5b*/{NULL},
/*OSD 0x5c*/{NULL},
/*OSD 0x5d*/{NULL},
/*OSD 0x5e*/{dissect_spc_persistentreservein},
/*OSD 0x5f*/{dissect_spc_persistentreserveout},
/*OSD 0x60*/{NULL},
/*OSD 0x61*/{NULL},
/*OSD 0x62*/{NULL},
/*OSD 0x63*/{NULL},
/*OSD 0x64*/{NULL},
/*OSD 0x65*/{NULL},
/*OSD 0x66*/{NULL},
/*OSD 0x67*/{NULL},
/*OSD 0x68*/{NULL},
/*OSD 0x69*/{NULL},
/*OSD 0x6a*/{NULL},
/*OSD 0x6b*/{NULL},
/*OSD 0x6c*/{NULL},
/*OSD 0x6d*/{NULL},
/*OSD 0x6e*/{NULL},
/*OSD 0x6f*/{NULL},
/*OSD 0x70*/{NULL},
/*OSD 0x71*/{NULL},
/*OSD 0x72*/{NULL},
/*OSD 0x73*/{NULL},
/*OSD 0x74*/{NULL},
/*OSD 0x75*/{NULL},
/*OSD 0x76*/{NULL},
/*OSD 0x77*/{NULL},
/*OSD 0x78*/{NULL},
/*OSD 0x79*/{NULL},
/*OSD 0x7a*/{NULL},
/*OSD 0x7b*/{NULL},
/*OSD 0x7c*/{NULL},
/*OSD 0x7d*/{NULL},
/*OSD 0x7e*/{NULL},
/*OSD 0x7f*/{dissect_osd_opcode},
/*OSD 0x80*/{NULL},
/*OSD 0x81*/{NULL},
/*OSD 0x82*/{NULL},
/*OSD 0x83*/{NULL},
/*OSD 0x84*/{NULL},
/*OSD 0x85*/{NULL},
/*OSD 0x86*/{NULL},
/*OSD 0x87*/{NULL},
/*OSD 0x88*/{NULL},
/*OSD 0x89*/{NULL},
/*OSD 0x8a*/{NULL},
/*OSD 0x8b*/{NULL},
/*OSD 0x8c*/{NULL},
/*OSD 0x8d*/{NULL},
/*OSD 0x8e*/{NULL},
/*OSD 0x8f*/{NULL},
/*OSD 0x90*/{NULL},
/*OSD 0x91*/{NULL},
/*OSD 0x92*/{NULL},
/*OSD 0x93*/{NULL},
/*OSD 0x94*/{NULL},
/*OSD 0x95*/{NULL},
/*OSD 0x96*/{NULL},
/*OSD 0x97*/{NULL},
/*OSD 0x98*/{NULL},
/*OSD 0x99*/{NULL},
/*OSD 0x9a*/{NULL},
/*OSD 0x9b*/{NULL},
/*OSD 0x9c*/{NULL},
/*OSD 0x9d*/{NULL},
/*OSD 0x9e*/{NULL},
/*OSD 0x9f*/{NULL},
/*OSD 0xa0*/{dissect_spc_reportluns},
/*OSD 0xa1*/{NULL},
/*OSD 0xa2*/{NULL},
/*OSD 0xa3*/{NULL},
/*OSD 0xa4*/{NULL},
/*OSD 0xa5*/{NULL},
/*OSD 0xa6*/{NULL},
/*OSD 0xa7*/{NULL},
/*OSD 0xa8*/{NULL},
/*OSD 0xa9*/{NULL},
/*OSD 0xaa*/{NULL},
/*OSD 0xab*/{NULL},
/*OSD 0xac*/{NULL},
/*OSD 0xad*/{NULL},
/*OSD 0xae*/{NULL},
/*OSD 0xaf*/{NULL},
/*OSD 0xb0*/{NULL},
/*OSD 0xb1*/{NULL},
/*OSD 0xb2*/{NULL},
/*OSD 0xb3*/{NULL},
/*OSD 0xb4*/{NULL},
/*OSD 0xb5*/{NULL},
/*OSD 0xb6*/{NULL},
/*OSD 0xb7*/{NULL},
/*OSD 0xb8*/{NULL},
/*OSD 0xb9*/{NULL},
/*OSD 0xba*/{NULL},
/*OSD 0xbb*/{NULL},
/*OSD 0xbc*/{NULL},
/*OSD 0xbd*/{NULL},
/*OSD 0xbe*/{NULL},
/*OSD 0xbf*/{NULL},
/*OSD 0xc0*/{NULL},
/*OSD 0xc1*/{NULL},
/*OSD 0xc2*/{NULL},
/*OSD 0xc3*/{NULL},
/*OSD 0xc4*/{NULL},
/*OSD 0xc5*/{NULL},
/*OSD 0xc6*/{NULL},
/*OSD 0xc7*/{NULL},
/*OSD 0xc8*/{NULL},
/*OSD 0xc9*/{NULL},
/*OSD 0xca*/{NULL},
/*OSD 0xcb*/{NULL},
/*OSD 0xcc*/{NULL},
/*OSD 0xcd*/{NULL},
/*OSD 0xce*/{NULL},
/*OSD 0xcf*/{NULL},
/*OSD 0xd0*/{NULL},
/*OSD 0xd1*/{NULL},
/*OSD 0xd2*/{NULL},
/*OSD 0xd3*/{NULL},
/*OSD 0xd4*/{NULL},
/*OSD 0xd5*/{NULL},
/*OSD 0xd6*/{NULL},
/*OSD 0xd7*/{NULL},
/*OSD 0xd8*/{NULL},
/*OSD 0xd9*/{NULL},
/*OSD 0xda*/{NULL},
/*OSD 0xdb*/{NULL},
/*OSD 0xdc*/{NULL},
/*OSD 0xdd*/{NULL},
/*OSD 0xde*/{NULL},
/*OSD 0xdf*/{NULL},
/*OSD 0xe0*/{NULL},
/*OSD 0xe1*/{NULL},
/*OSD 0xe2*/{NULL},
/*OSD 0xe3*/{NULL},
/*OSD 0xe4*/{NULL},
/*OSD 0xe5*/{NULL},
/*OSD 0xe6*/{NULL},
/*OSD 0xe7*/{NULL},
/*OSD 0xe8*/{NULL},
/*OSD 0xe9*/{NULL},
/*OSD 0xea*/{NULL},
/*OSD 0xeb*/{NULL},
/*OSD 0xec*/{NULL},
/*OSD 0xed*/{NULL},
/*OSD 0xee*/{NULL},
/*OSD 0xef*/{NULL},
/*OSD 0xf0*/{NULL},
/*OSD 0xf1*/{NULL},
/*OSD 0xf2*/{NULL},
/*OSD 0xf3*/{NULL},
/*OSD 0xf4*/{NULL},
/*OSD 0xf5*/{NULL},
/*OSD 0xf6*/{NULL},
/*OSD 0xf7*/{NULL},
/*OSD 0xf8*/{NULL},
/*OSD 0xf9*/{NULL},
/*OSD 0xfa*/{NULL},
/*OSD 0xfb*/{NULL},
/*OSD 0xfc*/{NULL},
/*OSD 0xfd*/{NULL},
/*OSD 0xfe*/{NULL},
/*OSD 0xff*/{NULL}
};




void
proto_register_scsi_osd(void)
{
	static hf_register_info hf[] = {
        { &hf_scsi_osd_opcode,
          {"OSD Opcode", "scsi.osd.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_osd_vals), 0x0, NULL, HFILL}},
        { &hf_scsi_osd_add_cdblen,
          {"Additional CDB Length", "scsi.osd.addcdblen", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_svcaction,
          {"Service Action", "scsi.osd.svcaction", FT_UINT16, BASE_HEX,
           VALS(scsi_osd_svcaction_vals), 0x0, NULL, HFILL}},
        { &hf_scsi_osd_option,
          {"Options Byte", "scsi.osd.option", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_option_dpo,
          {"DPO", "scsi.osd.option.dpo", FT_BOOLEAN, 8,
           TFS(&option_dpo_tfs), 0x10, NULL, HFILL}},
        { &hf_scsi_osd_option_fua,
          {"FUA", "scsi.osd.option.fua", FT_BOOLEAN, 8,
           TFS(&option_fua_tfs), 0x08, NULL, HFILL}},
        { &hf_scsi_osd_getsetattrib,
          {"GET/SET CDBFMT", "scsi.osd.getset", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_getsetattrib_vals), 0x30, NULL, HFILL}},
        { &hf_scsi_osd_timestamps_control,
          {"Timestamps Control", "scsi.osd.timestamps_control", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_timestamps_control_vals), 0x0, NULL, HFILL}},
        { &hf_scsi_osd_formatted_capacity,
          {"Formatted Capacity", "scsi.osd.formatted_capacity", FT_UINT64, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_get_attributes_page,
          {"Get Attributes Page", "scsi.osd.get_attributes_page", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_get_attributes_list_length,
          {"Get Attributes List Length", "scsi.osd.get_attributes_list_length", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_get_attributes_list_offset,
          {"Get Attributes List Offset", "scsi.osd.get_attributes_list_offset", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_set_attributes_list_length,
          {"Set Attributes List Length", "scsi.osd.set_attributes_list_length", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_set_attributes_list_offset,
          {"Set Attributes List Offset", "scsi.osd.set_attributes_list_offset", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_get_attributes_allocation_length,
          {"Get Attributes Allocation Length", "scsi.osd.get_attributes_allocation_length", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_retrieved_attributes_offset,
          {"Retrieved Attributes Offset", "scsi.osd.retrieved_attributes_offset", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_set_attributes_page,
          {"Set Attributes Page", "scsi.osd.set_attributes_page", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_set_attribute_length,
          {"Set Attribute Length", "scsi.osd.set_attribute_length", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_set_attribute_number,
          {"Set Attribute Number", "scsi.osd.set_attribute_number", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_set_attributes_offset,
          {"Set Attributes Offset", "scsi.osd.set_attributes_offset", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_capability_format,
          {"Capability Format", "scsi.osd.capability_format", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_capability_format_vals), 0x0f, NULL, HFILL}},
        { &hf_scsi_osd_key_version,
          {"Key Version", "scsi.osd.key_version", FT_UINT8, BASE_HEX,
           NULL, 0xf0, NULL, HFILL}},
        { &hf_scsi_osd_icva,
          {"Integrity Check Value Algorithm", "scsi.osd.icva", FT_UINT8, BASE_HEX,
           NULL, 0x0f, NULL, HFILL}},
        { &hf_scsi_osd_security_method,
          {"Security Method", "scsi.osd.security_method", FT_UINT8, BASE_HEX,
           NULL, 0x0f, NULL, HFILL}},
        { &hf_scsi_osd_capability_expiration_time,
          {"Capability Expiration Time", "scsi.osd.capability_expiration_time", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_audit,
          {"Audit", "scsi.osd.audit", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_capability_discriminator,
          {"Capability Discriminator", "scsi.osd.capability_descriminator", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_object_created_time,
          {"Object Created Time", "scsi.osd.object_created_time", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_object_type,
          {"Object Type", "scsi.osd.object_type", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_object_type_vals), 0, NULL, HFILL}},
        { &hf_scsi_osd_permissions,
          {"Permissions", "scsi.osd.permissions", FT_UINT16, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_permissions_read,
          {"READ", "scsi.osd.permissions.read", FT_BOOLEAN, 16,
           TFS(&permissions_read_tfs), 0x8000, NULL, HFILL}},
        { &hf_scsi_osd_permissions_write,
          {"WRITE", "scsi.osd.permissions.write", FT_BOOLEAN, 16,
           TFS(&permissions_write_tfs), 0x4000, NULL, HFILL}},
        { &hf_scsi_osd_permissions_get_attr,
          {"GET_ATTR", "scsi.osd.permissions.get_attr", FT_BOOLEAN, 16,
           TFS(&permissions_get_attr_tfs), 0x2000, NULL, HFILL}},
        { &hf_scsi_osd_permissions_set_attr,
          {"SET_ATTR", "scsi.osd.permissions.set_attr", FT_BOOLEAN, 16,
           TFS(&permissions_set_attr_tfs), 0x1000, NULL, HFILL}},
        { &hf_scsi_osd_permissions_create,
          {"CREATE", "scsi.osd.permissions.create", FT_BOOLEAN, 16,
           TFS(&permissions_create_tfs), 0x0800, NULL, HFILL}},
        { &hf_scsi_osd_permissions_remove,
          {"REMOVE", "scsi.osd.permissions.remove", FT_BOOLEAN, 16,
           TFS(&permissions_remove_tfs), 0x0400, NULL, HFILL}},
        { &hf_scsi_osd_permissions_obj_mgmt,
          {"OBJ_MGMT", "scsi.osd.permissions.obj_mgmt", FT_BOOLEAN, 16,
           TFS(&permissions_obj_mgmt_tfs), 0x0200, NULL, HFILL}},
        { &hf_scsi_osd_permissions_append,
          {"APPEND", "scsi.osd.permissions.append", FT_BOOLEAN, 16,
           TFS(&permissions_append_tfs), 0x0100, NULL, HFILL}},
        { &hf_scsi_osd_permissions_dev_mgmt,
          {"DEV_MGMT", "scsi.osd.permissions.dev_mgmt", FT_BOOLEAN, 16,
           TFS(&permissions_dev_mgmt_tfs), 0x0080, NULL, HFILL}},
        { &hf_scsi_osd_permissions_global,
          {"GLOBAL", "scsi.osd.permissions.global", FT_BOOLEAN, 16,
           TFS(&permissions_global_tfs), 0x0040, NULL, HFILL}},
        { &hf_scsi_osd_permissions_pol_sec,
          {"POL/SEC", "scsi.osd.permissions.pol_sec", FT_BOOLEAN, 16,
           TFS(&permissions_pol_sec_tfs), 0x0020, NULL, HFILL}},

        { &hf_scsi_osd_object_descriptor_type,
          {"Object Descriptor Type", "scsi.osd.object_descriptor_type", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_object_descriptor_type_vals), 0xf0, NULL, HFILL}},
        { &hf_scsi_osd_object_descriptor,
          {"Object Descriptor", "scsi.osd.object_descriptor", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_ricv,
          {"Request Integrity Check value", "scsi.osd.ricv", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_request_nonce,
          {"Request Nonce", "scsi.osd.request_nonce", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_diicvo,
          {"Data-In Integrity Check Value Offset", "scsi.osd.diicvo", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_doicvo,
          {"Data-Out Integrity Check Value Offset", "scsi.osd.doicvo", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_requested_partition_id,
          {"Requested Partition Id", "scsi.osd.requested_partition_id", FT_UINT64, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_sortorder,
          {"Sort Order", "scsi.osd.sort_order", FT_UINT8, BASE_DEC,
           VALS(scsi_osd_sort_order_vals), 0x0f, NULL, HFILL}},
        { &hf_scsi_osd_partition_id,
          {"Partition Id", "scsi.osd.partition_id", FT_UINT64, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_list_identifier,
          {"List Identifier", "scsi.osd.list_identifier", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_allocation_length,
          {"Allocation Length", "scsi.osd.allocation_length", FT_UINT64, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_length,
          {"Length", "scsi.osd.length", FT_UINT64, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_starting_byte_address,
          {"Starting Byte Address", "scsi.osd.starting_byte_address", FT_UINT64, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_initial_object_id,
          {"Initial Object Id", "scsi.osd.initial_object_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
	{ &hf_scsi_osd_additional_length,
          {"Additional Length", "scsi.osd.additional_length", FT_UINT64, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_continuation_object_id,
          {"Continuation Object Id", "scsi.osd.continuation_object_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_user_object_id,
          {"User Object Id", "scsi.osd.user_object_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_list_flags_lstchg,
          {"LSTCHG", "scsi.osd.list.lstchg", FT_BOOLEAN, 8,
           TFS(&list_lstchg_tfs), 0x02, NULL, HFILL}},
        { &hf_scsi_osd_list_flags_root,
          {"ROOT", "scsi.osd.list.root", FT_BOOLEAN, 8,
           TFS(&list_root_tfs), 0x01, NULL, HFILL}},
        { &hf_scsi_osd_requested_user_object_id,
          {"Requested User Object Id", "scsi.osd.requested_user_object_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
	{ &hf_scsi_osd_number_of_user_objects,
          {"Number Of User Objects", "scsi.osd.number_of_user_objects", FT_UINT16, BASE_DEC,
           NULL, 0, NULL, HFILL}},
	{ &hf_scsi_osd_key_to_set,
          {"Key to Set", "scsi.osd.key_to_set", FT_UINT8, BASE_DEC,
           VALS(key_to_set_vals), 0x03, NULL, HFILL}},
	{ &hf_scsi_osd_set_key_version,
          {"Key Version", "scsi.osd.set_key_version", FT_UINT8, BASE_DEC,
           NULL, 0x0f, NULL, HFILL}},
	{ &hf_scsi_osd_key_identifier,
          {"Key Identifier", "scsi.osd.key_identifier", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
	{ &hf_scsi_osd_seed,
          {"Seed", "scsi.osd.seed", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_collection_fcr,
          {"FCR", "scsi.osd.collection.fcr", FT_BOOLEAN, 8,
           TFS(&collection_fcr_tfs), 0x01, NULL, HFILL}},
        { &hf_scsi_osd_collection_object_id,
          {"Collection Object Id", "scsi.osd.collection_object_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_requested_collection_object_id,
          {"Requested Collection Object Id", "scsi.osd.requested_collection_object_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_partition_created_in,
          { "Created In", "scsi.osd.partition.created_in", FT_FRAMENUM, BASE_NONE,
          NULL, 0x0, "The frame this partition was created", HFILL }},

        { &hf_scsi_osd_partition_removed_in,
          { "Removed In", "scsi.osd.partition.removed_in", FT_FRAMENUM, BASE_NONE,
          NULL, 0x0, "The frame this partition was removed", HFILL }},

	{ &hf_scsi_osd_flush_scope,
          {"Flush Scope", "scsi.osd.flush.scope", FT_UINT8, BASE_DEC,
           VALS(flush_scope_vals), 0x03, NULL, HFILL}},

	{ &hf_scsi_osd_flush_collection_scope,
          {"Flush Collection Scope", "scsi.osd.flush_collection.scope", FT_UINT8, BASE_DEC,
           VALS(flush_collection_scope_vals), 0x03, NULL, HFILL}},

	{ &hf_scsi_osd_flush_partition_scope,
          {"Flush Partition Scope", "scsi.osd.flush_partition.scope", FT_UINT8, BASE_DEC,
           VALS(flush_partition_scope_vals), 0x03, NULL, HFILL}},

	{ &hf_scsi_osd_flush_osd_scope,
          {"Flush OSD Scope", "scsi.osd.flush_osd.scope", FT_UINT8, BASE_DEC,
           VALS(flush_osd_scope_vals), 0x03, NULL, HFILL}},
	{ &hf_scsi_osd_attributes_list_type,
          {"Attributes List Type", "scsi.osd.attributes_list.type", FT_UINT8, BASE_HEX,
           VALS(attributes_list_type_vals), 0x0f, NULL, HFILL}},
	{ &hf_scsi_osd_attributes_list_length,
          {"Attributes List Length", "scsi.osd.attributes_list.length", FT_UINT16, BASE_DEC,
           NULL, 0, NULL, HFILL}},
	{ &hf_scsi_osd_attributes_page,
	  {"Attributes Page", "scsi.osd.attributes.page", FT_UINT32, BASE_HEX,
	  VALS(attributes_page_vals), 0, NULL, HFILL}},
	{ &hf_scsi_osd_attribute_number,
	  {"Attribute Number", "scsi.osd.attribute.number", FT_UINT32, BASE_HEX,
	  NULL, 0, NULL, HFILL}},
	{ &hf_scsi_osd_attribute_length,
	  {"Attribute Length", "scsi.osd.attribute.length", FT_UINT16, BASE_DEC,
	  NULL, 0, NULL, HFILL}},
	{ &hf_scsi_osd_user_object_logical_length,
	 {"User Object Logical Length", "scsi.osd.user_object.logical_length", FT_UINT64, BASE_DEC,
	  NULL, 0, NULL, HFILL}},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_osd_option,
		&ett_osd_partition,
		&ett_osd_attribute_parameters,
		&ett_osd_capability,
		&ett_osd_permission_bitmask,
		&ett_osd_security_parameters,
	};

	/* Register the protocol name and description */
	proto_scsi_osd = proto_register_protocol("SCSI_OSD", "SCSI_OSD", "scsi_osd");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_scsi_osd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_scsi_osd(void)
{
}

