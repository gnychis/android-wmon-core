/* codec-g729a.c
* Easy codecs stub for EasyG729A
* 2007 Tomas Kukosa
*
* $Id: codec-g729a.c 27401 2009-02-09 12:54:40Z kukosa $
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
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <memory.h>

#include "codec-g729a.h"

#include "EasyG729A/EasyG729A.h"

struct g729a_context {
  CODER_HANDLE handle;
  short speach_buffer[L_G729A_FRAME];
};

void *codec_g729a_init(void) {
  struct g729a_context *ctx = 0;

  ctx = (struct g729a_context*)g_malloc0(sizeof(struct g729a_context));
  ctx->handle = EasyG729A_init_decoder();
  return ctx;
}

void codec_g729a_release(void *context) {
  struct g729a_context *ctx = (struct g729a_context*)context;

  if (!ctx) return;
  EasyG729A_release_decoder(ctx->handle);
  g_free(ctx);
}

int codec_g729a_decode(void *context, const void *input, int inputSizeBytes, void *output, int *outputSizeBytes) {
  struct g729a_context *ctx = (struct g729a_context*)context;
  const unsigned char *bitstream = (const unsigned char*)input;
  short *speech = (short*)output;
  int decodedBytes = 0;

  if (!ctx) return 0;

  if ((inputSizeBytes % L_G729A_FRAME_COMPRESSED) != 0) 
    return 0;

  if (!output)
    return (inputSizeBytes / L_G729A_FRAME_COMPRESSED) * L_G729A_FRAME * sizeof(short);

  while ((inputSizeBytes >= L_G729A_FRAME_COMPRESSED) &&
         ((*outputSizeBytes - decodedBytes) >= L_G729A_FRAME * sizeof(short))) {
    if (EasyG729A_decoder(ctx->handle, (unsigned char*)bitstream, ctx->speach_buffer)) {
      memcpy(speech, ctx->speach_buffer, L_G729A_FRAME * sizeof(short));
      speech += L_G729A_FRAME;
      decodedBytes += L_G729A_FRAME * sizeof(short);
    }
    bitstream += L_G729A_FRAME_COMPRESSED;
    inputSizeBytes -= L_G729A_FRAME_COMPRESSED;
  }

  return decodedBytes;
}

