/*
 * Copyright (c) 2003 Markus Friedl.  All rights reserved.
 *
 * $Id: packet-enc.c 35224 2010-12-20 05:35:29Z guy $
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/addr_resolv.h>
#include "packet-enc.h"
#include "packet-ip.h"
#include "packet-ipv6.h"

#ifndef offsetof
/* Can't trust stddef.h to be there for us */
# define offsetof(type, member) ((size_t)(&((type *)0)->member))
#endif

/* The header in OpenBSD Encapsulating Interface files. */

struct enchdr {
  guint32 af;
  guint32 spi;
  guint32 flags;
};
#define ENC_HDRLEN    sizeof(struct enchdr)

# define BSD_ENC_INET    2
# define BSD_ENC_INET6   24

# define BSD_ENC_M_CONF          0x0400  /* payload encrypted */
# define BSD_ENC_M_AUTH          0x0800  /* payload authenticated */
# define BSD_ENC_M_COMP          0x1000  /* payload compressed */
# define BSD_ENC_M_AUTH_AH       0x2000  /* header authenticated */

static dissector_handle_t  data_handle, ip_handle, ipv6_handle;

/* header fields */
static int proto_enc = -1;
static int hf_enc_af = -1;
static int hf_enc_spi = -1;
static int hf_enc_flags = -1;

static gint ett_enc = -1;

void
capture_enc(const guchar *pd, int len, packet_counts *ld)
{
  guint32 af;

  if (!BYTES_ARE_IN_FRAME(0, len, (int)ENC_HDRLEN)) {
    ld->other++;
    return;
  }

  af = pntohl(pd + offsetof(struct enchdr, af));
  switch (af) {

  case BSD_ENC_INET:
    capture_ip(pd, ENC_HDRLEN, len, ld);
    break;

  case BSD_ENC_INET6:
    capture_ipv6(pd, ENC_HDRLEN, len, ld);
    break;

  default:
    ld->other++;
    break;
  }
}

static const value_string af_vals[] = {
  { BSD_ENC_INET,  "IPv4" },
  { BSD_ENC_INET6, "IPv6" },
  { 0,            NULL }
};

static void
dissect_enc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct enchdr ench;
  tvbuff_t *next_tvb;
  proto_tree *enc_tree;
  proto_item *ti;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENC");

  /* Copy out the enc header to insure alignment */
  tvb_memcpy(tvb, (guint8 *)&ench, 0, sizeof(ench));

  /* Byteswap the header now */
  ench.spi = g_ntohl(ench.spi);
  /* ench.af = g_ntohl(ench.af); */
  /* ench.flags = g_ntohl(ench.flags); */

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_enc, tvb, 0,
             ENC_HDRLEN,
             "Enc %s, SPI 0x%8.8x, %s%s%s%s",
             val_to_str(ench.af, af_vals, "unknown (%u)"),
             ench.spi,
             ench.flags ? "" : "unprotected",
             ench.flags & BSD_ENC_M_AUTH ? "authentic" : "",
             (ench.flags & (BSD_ENC_M_AUTH|BSD_ENC_M_CONF)) ==
		(BSD_ENC_M_AUTH|BSD_ENC_M_CONF) ? ", " : "",
             ench.flags & BSD_ENC_M_CONF ? "confidential" : ""
	     );
    enc_tree = proto_item_add_subtree(ti, ett_enc);

    proto_tree_add_uint(enc_tree, hf_enc_af, tvb,
             offsetof(struct enchdr, af), sizeof(ench.af),
             ench.af);
    proto_tree_add_uint(enc_tree, hf_enc_spi, tvb,
             offsetof(struct enchdr, spi), sizeof(ench.spi),
             ench.spi);
    proto_tree_add_uint(enc_tree, hf_enc_flags, tvb,
             offsetof(struct enchdr, flags), sizeof(ench.flags),
             ench.flags);
  }

  /* Set the tvbuff for the payload after the header */
  next_tvb = tvb_new_subset_remaining(tvb, ENC_HDRLEN);

  switch (ench.af) {

  case BSD_ENC_INET:
    call_dissector(ip_handle, next_tvb, pinfo, tree);
    break;

  case BSD_ENC_INET6:
    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    break;

  default:
    call_dissector(data_handle, next_tvb, pinfo, tree);
    break;
  }
}

void
proto_register_enc(void)
{
  static hf_register_info hf[] = {
    { &hf_enc_af,
      { "Address Family", "enc.af", FT_UINT32, BASE_DEC, VALS(af_vals), 0x0,
        "Protocol (IPv4 vs IPv6)", HFILL }},
    { &hf_enc_spi,
      { "SPI", "enc.spi", FT_UINT32, BASE_HEX, NULL, 0x0,
        "Security Parameter Index", HFILL }},
    { &hf_enc_flags,
      { "Flags", "enc.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
        "ENC flags", HFILL }},
  };
  static gint *ett[] = { &ett_enc };

  proto_enc = proto_register_protocol("OpenBSD Encapsulating device",
				      "ENC", "enc");
  proto_register_field_array(proto_enc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_enc(void)
{
  dissector_handle_t enc_handle;

  ip_handle = find_dissector("ip");
  ipv6_handle = find_dissector("ipv6");
  data_handle = find_dissector("data");

  enc_handle = create_dissector_handle(dissect_enc, proto_enc);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_ENC, enc_handle);
}
