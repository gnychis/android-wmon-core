/* packet-nfsacl.c
 * Stubs for Sun's NFS ACL RPC service (runs on port 2049, and is presumably
 * handled by the same kernel server code that handles NFS)
 *
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-nfsacl.c 35466 2011-01-10 22:31:05Z sahlberg $
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
#include "config.h"
#endif

#include "packet-rpc.h"
#include "packet-nfs.h"

static int proto_nfsacl = -1;
static int hf_nfsacl_procedure_v1 = -1;
static int hf_nfsacl_procedure_v2 = -1;
static int hf_nfsacl_procedure_v3 = -1;
static int hf_nfsacl_entry = -1;
static int hf_nfsacl_aclcnt = -1;
static int hf_nfsacl_dfaclcnt = -1;
static int hf_nfsacl_aclent = -1;
static int hf_nfsacl_aclent_type = -1;
static int hf_nfsacl_aclent_uid = -1;
static int hf_nfsacl_aclent_perm = -1;
static int hf_nfsacl_create = -1;

static gint ett_nfsacl = -1;
static gint ett_nfsacl_mask = -1;
static gint ett_nfsacl_entry = -1;
static gint ett_nfsacl_aclent = -1;
static gint ett_nfsacl_aclent_perm = -1;
static gint ett_nfsacl_aclent_entries = -1;

#define NFSACL_PROGRAM	100227

#define NFSACLPROC_NULL		0

#define NFSACLPROC2_GETACL	1
#define NFSACLPROC2_SETACL	2
#define NFSACLPROC2_GETATTR	3
#define NFSACLPROC2_ACCESS	4
#define NFSACLPROC2_GETXATTRDIR 5

#define NFSACLPROC3_GETACL	1
#define NFSACLPROC3_SETACL	2
#define NFSACLPROC3_GETXATTRDIR 3

#define ACL2_OK 0
#define ACL3_OK 0

static int
dissect_nfsacl_mask(tvbuff_t *tvb, int offset, proto_tree *tree,
		    const char *name)
{
	guint32 mask;
	proto_item *mask_item = NULL;
	proto_tree *mask_tree = NULL;

	mask = tvb_get_ntohl(tvb, offset + 0);

	if (tree)
	{
		mask_item = proto_tree_add_text(tree, tvb, offset, 4, "%s: 0x%02x",
				name, mask);

		if (mask_item)
			mask_tree = proto_item_add_subtree(mask_item, ett_nfsacl_mask);
	}

	if (mask_tree)
	{
		proto_tree_add_text(mask_tree, tvb, offset, 4, "%s",
				decode_boolean_bitfield(mask, 0x01, 8, "ACL entry",
					"(no ACL entry)"));
		proto_tree_add_text(mask_tree, tvb, offset, 4, "%s",
				decode_boolean_bitfield(mask, 0x02, 8, "ACL count",
					"(no ACL count)"));
		proto_tree_add_text(mask_tree, tvb, offset, 4, "%s",
				decode_boolean_bitfield(mask, 0x04, 8, "default ACL entry",
					"(no default ACL entry)"));
		proto_tree_add_text(mask_tree, tvb, offset, 4, "%s",
				decode_boolean_bitfield(mask, 0x08, 8, "default ACL count",
					"(no default ACL count)"));
	}

	offset += 4;
	return offset;
}

#define NA_READ 0x4
#define NA_WRITE 0x2
#define NA_EXEC 0x1

static const value_string names_nfsacl_aclent_type[] = {
#define NA_USER_OBJ 0x1
	{ NA_USER_OBJ, "NA_USER_OBJ" },
#define NA_USER 0x2
	{ NA_USER, "NA_USER" },
#define NA_GROUP_OBJ 0x4
	{ NA_GROUP_OBJ, "NA_GROUP_OBJ" },
#define NA_GROUP 0x8
	{ NA_GROUP, "NA_GROUP" },
#define NA_CLASS_OBJ 0x10
	{ NA_CLASS_OBJ, "NA_CLASS_OBJ" },
#define NA_OTHER_OBJ 0x20
	{ NA_OTHER_OBJ, "NA_OTHER_OBJ" },
#define NA_ACL_DEFAULT 0x1000
	{ NA_ACL_DEFAULT, "NA_ACL_DEFAULT" },
	{ NA_ACL_DEFAULT | NA_USER_OBJ, "Default NA_USER_OBJ" },
	{ NA_ACL_DEFAULT | NA_USER, "Default NA_USER" },
	{ NA_ACL_DEFAULT | NA_GROUP_OBJ, "Default NA_GROUP_OBJ" },
	{ NA_ACL_DEFAULT | NA_GROUP, "Default NA_GROUP" },
	{ NA_ACL_DEFAULT | NA_CLASS_OBJ, "Default NA_CLASS_OBJ" },
	{ NA_ACL_DEFAULT | NA_OTHER_OBJ, "Default NA_OTHER_OBJ" },
	{ 0, NULL },
};

static int
dissect_nfsacl_aclent(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		      proto_tree* tree)
{
	proto_item *entry_item = NULL;
	proto_tree *entry_tree = NULL;
	guint32 perm;
	proto_item *perm_item = NULL;
	proto_tree *perm_tree = NULL;

	if (tree)
	{
		entry_item = proto_tree_add_item(tree, hf_nfsacl_aclent, tvb,
						 offset + 0, -1, FALSE);
		entry_tree = proto_item_add_subtree(entry_item, ett_nfsacl_aclent);
	}

	offset = dissect_rpc_uint32(tvb, entry_tree, hf_nfsacl_aclent_type, offset);
	offset = dissect_rpc_uint32(tvb, entry_tree, hf_nfsacl_aclent_uid, offset);

	perm = tvb_get_ntohl(tvb, offset);

	perm_item = proto_tree_add_uint(entry_tree, hf_nfsacl_aclent_perm,
					tvb, offset, 4, perm);

	if (perm_item)
		perm_tree = proto_item_add_subtree(perm_item, ett_nfsacl_aclent_perm);

	if (perm_tree)
	{
		proto_tree_add_text(perm_tree, tvb, offset, 4, "%s",
				decode_boolean_bitfield(perm, NA_READ, 4, "READ", "no READ"));

		proto_tree_add_text(perm_tree, tvb, offset, 4, "%s",
				decode_boolean_bitfield(perm, NA_WRITE, 4, "WRITE", "no WRITE"));

		proto_tree_add_text(perm_tree, tvb, offset, 4, "%s",
				decode_boolean_bitfield(perm, NA_EXEC, 4, "EXEC", "no EXEC"));
	}

	offset += 4;

	return offset;
}


static int
dissect_nfsacl_secattr(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		       proto_tree *tree)
{
	guint32 aclcnt, dfaclcnt;
	guint32 i;
	proto_item *entry_item = NULL;
	proto_tree *entry_tree = NULL;

	offset = dissect_nfsacl_mask(tvb, offset, tree, "mask");
	offset = dissect_rpc_uint32(tvb, tree, hf_nfsacl_aclcnt, offset);

	aclcnt = tvb_get_ntohl(tvb, offset);

	entry_item = proto_tree_add_text(tree, tvb, offset, 4,
			"Total ACL entries: %d", aclcnt);

	if (entry_item)
		entry_tree = proto_item_add_subtree(entry_item,
				ett_nfsacl_aclent_entries);

	offset += 4;

	if (aclcnt > 0)
	{
		for (i = 0; i < aclcnt; i++)
			offset = dissect_nfsacl_aclent(tvb, offset, pinfo, entry_tree);
	}

	/* */

	offset = dissect_rpc_uint32(tvb, tree, hf_nfsacl_dfaclcnt, offset);

	dfaclcnt = tvb_get_ntohl(tvb, offset);

	entry_item = proto_tree_add_text(tree, tvb, offset, 4,
			"Total default ACL entries: %d", dfaclcnt);

	if (entry_item)
		entry_tree = proto_item_add_subtree(entry_item,
				ett_nfsacl_aclent_entries);

	offset += 4;

	if (dfaclcnt > 0)
	{
		for (i = 0; i < dfaclcnt; i++)
			offset = dissect_nfsacl_aclent(tvb, offset, pinfo, entry_tree);
	}

	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff nfsacl1_proc[] = {
	{ NFSACLPROC_NULL,	"NULL",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};
static const value_string nfsacl1_proc_vals[] = {
	{ NFSACLPROC_NULL,	"NULL" },
	{ 0,	NULL }
};

static int
dissect_nfsacl2_getacl_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree)
{
	offset = dissect_fhandle(tvb, offset, pinfo, tree, "fhandle", NULL);
	offset = dissect_nfsacl_mask(tvb, offset, tree, "mask");
	return offset;
}

static int
dissect_nfsacl2_getacl_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			     proto_tree *tree)
{
	guint32 status;

	status = tvb_get_ntohl(tvb, offset + 0);

	proto_tree_add_uint(tree, hf_nfs_nfsstat, tvb, offset + 0, 4, status);

	offset += 4;

	if (status == ACL2_OK)
	{
		offset = dissect_fattr(tvb, offset, tree, "attr");
		offset = dissect_nfsacl_secattr(tvb, offset, pinfo, tree);
	}

	return offset;
}

static int
dissect_nfsacl2_setacl_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree)
{
	offset = dissect_fhandle(tvb, offset, pinfo, tree, "fhandle", NULL);
	offset = dissect_nfsacl_secattr(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_nfsacl2_setacl_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			     proto_tree *tree)
{
	guint32 status;

	status = tvb_get_ntohl(tvb, offset + 0);

	proto_tree_add_uint(tree, hf_nfs_nfsstat, tvb, offset + 0, 4, status);

	offset += 4;

	if (status == ACL2_OK)
		offset = dissect_fattr(tvb, offset, tree, "attr");

	return offset;
}

static int
dissect_nfsacl2_getattr_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			     proto_tree *tree)
{
	offset = dissect_fhandle(tvb, offset, pinfo, tree, "fhandle", NULL);

	return offset;
}

static int
dissect_nfsacl2_getattr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			      proto_tree *tree)
{
	offset = dissect_fattr(tvb, offset, tree, "attr");

	return offset;
}

static int
dissect_nfsacl2_access_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree)
{
	guint32 *acc_request, amask;
	rpc_call_info_value *civ;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "fhandle", NULL);

	/* Get access mask to check and save it for comparison to the access reply. */
	amask = tvb_get_ntohl(tvb, offset);
	acc_request = se_memdup( &amask, sizeof(guint32));
	civ = pinfo->private_data;
	civ->private_data = acc_request;

	display_access_items(tvb, offset, pinfo, tree, amask, 'C', 3, NULL, "Check") ;

	offset+=4;
	return offset;
}

static int
dissect_nfsacl2_access_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			     proto_tree *tree)
{
	guint32 status;

	status = tvb_get_ntohl(tvb, offset + 0);

	proto_tree_add_uint(tree, hf_nfs_nfsstat, tvb, offset + 0, 4, status);

	offset += 4;

	if (status == ACL2_OK)
	{
		offset = dissect_fattr(tvb, offset, tree, "attr");
		offset = dissect_access_reply(tvb, offset, pinfo, tree, 3, NULL);
	}

	return offset;
}

static int
dissect_nfsacl2_getxattrdir_call(tvbuff_t *tvb, int offset,
				 packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_fhandle(tvb, offset, pinfo, tree, "fhandle", NULL);
	offset = dissect_rpc_bool(tvb, tree, hf_nfsacl_create, offset);

	return offset;
}

static int
dissect_nfsacl2_getxattrdir_reply(tvbuff_t *tvb, int offset,
				  packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 status;

	status = tvb_get_ntohl(tvb, offset + 0);

	proto_tree_add_uint(tree, hf_nfs_nfsstat, tvb, offset + 0, 4, status);

	offset += 4;

	if (status == ACL2_OK)
	{
		offset = dissect_fhandle(tvb, offset, pinfo, tree, "fhandle", NULL);
		offset = dissect_fattr(tvb, offset, tree, "attr");
	}

	return offset;
}

static const vsff nfsacl2_proc[] = {
	{ NFSACLPROC_NULL,	"NULL",
		NULL,	NULL },
	{ NFSACLPROC2_GETACL,	"GETACL",
		dissect_nfsacl2_getacl_call,	dissect_nfsacl2_getacl_reply },
	{ NFSACLPROC2_SETACL,	"SETACL",
		dissect_nfsacl2_setacl_call,	dissect_nfsacl2_setacl_reply },
	{ NFSACLPROC2_GETATTR,	"GETATTR",
		dissect_nfsacl2_getattr_call,	dissect_nfsacl2_getattr_reply },
	{ NFSACLPROC2_ACCESS,	"ACCESS",
		dissect_nfsacl2_access_call,	dissect_nfsacl2_access_reply },
	{ NFSACLPROC2_GETXATTRDIR,	"GETXATTRDIR",
		dissect_nfsacl2_getxattrdir_call, dissect_nfsacl2_getxattrdir_reply },
	{ 0,	NULL,	NULL,	NULL }
};
static const value_string nfsacl2_proc_vals[] = {
	{ NFSACLPROC_NULL,	"NULL" },
	{ NFSACLPROC2_GETACL,	"GETACL" },
	{ NFSACLPROC2_SETACL,	"SETACL" },
	{ NFSACLPROC2_GETATTR,	"GETATTR" },
	{ NFSACLPROC2_ACCESS,	"ACCESS" },
	{ NFSACLPROC2_GETXATTRDIR, "GETXATTRDIR" },
	{ 0,	NULL }
};

static int
dissect_nfsacl3_getacl_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree)
{
	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "fhandle", NULL);
	offset = dissect_nfsacl_mask(tvb, offset, tree, "mask");

	return offset;
}

static int
dissect_nfsacl3_getacl_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			     proto_tree *tree)
{
	guint32 status;
	proto_item *entry_item = NULL;
	proto_tree *entry_tree = NULL;

	status = tvb_get_ntohl(tvb, offset + 0);

	if (tree)
		proto_tree_add_uint(tree, hf_nfs_nfsstat, tvb, offset + 0, 4,
				status);

	offset += 4;

	if (tree)
	{
		entry_item = proto_tree_add_item(tree, hf_nfsacl_entry, tvb,
				offset + 0, -1, FALSE);
		if (entry_item)
			entry_tree = proto_item_add_subtree(entry_item, ett_nfsacl_entry);
	}

	if (entry_tree)
		offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, entry_tree, "attr");

	if (status != ACL3_OK)
		return offset;

	if (entry_tree)
		offset = dissect_nfsacl_secattr(tvb, offset, pinfo, entry_tree);

	return offset;
}

static int
dissect_nfsacl3_setacl_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree)

{
	proto_item *acl_item = NULL;
	proto_tree *acl_tree = NULL;

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "fhandle", NULL);

	if (tree)
	{
		acl_item = proto_tree_add_item(tree, hf_nfsacl_entry, tvb, offset + 0,
				-1, FALSE);

		if (acl_item)
			acl_tree = proto_item_add_subtree(acl_item, ett_nfsacl_entry);
	}

	if (acl_tree)
		offset = dissect_nfsacl_secattr(tvb, offset, pinfo, acl_tree);

	return offset;
}

static int
dissect_nfsacl3_setacl_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			     proto_tree *tree)
{
	guint32 status = tvb_get_ntohl(tvb, offset + 0);

	if (tree)
		proto_tree_add_uint(tree, hf_nfs_nfsstat, tvb, offset + 0, 4,
				status);

	offset += 4;

	offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree, "attr");

	return offset;
}

static int
dissect_nfsacl3_getxattrdir_call(tvbuff_t *tvb, int offset,
				 packet_info *pinfo _U_, proto_tree *tree)

{
	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "fhandle", NULL);
	offset = dissect_rpc_bool(tvb, tree, hf_nfsacl_create, offset);

	return offset;
}

static int
dissect_nfsacl3_getxattrdir_reply(tvbuff_t *tvb, int offset,
				  packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 status;

	status = tvb_get_ntohl(tvb, offset + 0);

	if (tree)
		proto_tree_add_uint(tree, hf_nfs_nfsstat, tvb, offset + 0, 4,
				    status);

	offset += 4;

	if (status == ACL3_OK)
	{
		offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "fhandle", NULL);
		offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree, "attr");
	}

	return offset;
}

static const vsff nfsacl3_proc[] = {
	{ NFSACLPROC_NULL,	"NULL",
		NULL,	NULL },
	{ NFSACLPROC3_GETACL,	"GETACL",
		dissect_nfsacl3_getacl_call,	dissect_nfsacl3_getacl_reply },
	{ NFSACLPROC3_SETACL,	"SETACL",
		dissect_nfsacl3_setacl_call,	dissect_nfsacl3_setacl_reply },
	{ NFSACLPROC3_GETXATTRDIR,	"GETXATTRDIR",
		dissect_nfsacl3_getxattrdir_call, dissect_nfsacl3_getxattrdir_reply },
	{ 0,	NULL,	NULL,	NULL }
};
static const value_string nfsacl3_proc_vals[] = {
	{ NFSACLPROC_NULL,		 "NULL" },
	{ NFSACLPROC3_GETACL,		 "GETACL" },
	{ NFSACLPROC3_SETACL,		 "SETACL" },
	{ NFSACLPROC3_GETXATTRDIR,	 "GETXATTRDIR" },
	{ 0,	NULL }
};

void
proto_register_nfsacl(void)
{
	static hf_register_info hf[] = {
		{ &hf_nfsacl_procedure_v1, {
			"V1 Procedure", "nfsacl.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(nfsacl1_proc_vals), 0, NULL, HFILL }},
		{ &hf_nfsacl_procedure_v2, {
			"V2 Procedure", "nfsacl.procedure_v2", FT_UINT32, BASE_DEC,
			VALS(nfsacl2_proc_vals), 0, NULL, HFILL }},
		{ &hf_nfsacl_procedure_v3, {
			"V3 Procedure", "nfsacl.procedure_v3", FT_UINT32, BASE_DEC,
			VALS(nfsacl3_proc_vals), 0, NULL, HFILL }},
			/* generic */
		{ &hf_nfsacl_entry, {
			"ACL", "nfsacl.acl", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfsacl_aclcnt, {
			"ACL count", "nfsacl.aclcnt", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfsacl_dfaclcnt, {
			"Default ACL count", "nfsacl.dfaclcnt", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfsacl_aclent, {
			"ACL Entry", "nfsacl.aclent", FT_NONE, BASE_NONE,
			NULL, 0, "ACL", HFILL }},
		{ &hf_nfsacl_aclent_type, {
			"Type", "nfsacl.aclent.type", FT_UINT32, BASE_DEC,
			VALS(names_nfsacl_aclent_type), 0, NULL, HFILL }},
		{ &hf_nfsacl_aclent_uid, {
			"UID", "nfsacl.aclent.uid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfsacl_aclent_perm, {
			"Permissions", "nfsacl.aclent.perm", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
			/* V2 */
		{ &hf_nfsacl_create, {
			"create", "nfsacl.create", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, "Create?", HFILL }},
	};

	static gint *ett[] = {
		&ett_nfsacl,
		&ett_nfsacl_mask,
		&ett_nfsacl_entry,
		&ett_nfsacl_aclent,
		&ett_nfsacl_aclent_perm,
		&ett_nfsacl_aclent_entries
	};

	proto_nfsacl = proto_register_protocol("NFSACL", "NFSACL", "nfsacl");
	proto_register_field_array(proto_nfsacl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nfsacl(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfsacl, NFSACL_PROGRAM, ett_nfsacl);
	/* Register the procedure tables */
	rpc_init_proc_table(NFSACL_PROGRAM, 1, nfsacl1_proc, hf_nfsacl_procedure_v1);
	rpc_init_proc_table(NFSACL_PROGRAM, 2, nfsacl2_proc, hf_nfsacl_procedure_v2);
	rpc_init_proc_table(NFSACL_PROGRAM, 3, nfsacl3_proc, hf_nfsacl_procedure_v3);
}
