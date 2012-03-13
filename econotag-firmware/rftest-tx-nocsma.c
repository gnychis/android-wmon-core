/*
 * Copyright (c) 2010, Mariano Alvira <mar@devl.org> and other contributors
 * to the MC1322x project (http://mc1322x.devl.org)
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of libmc1322x: see http://mc1322x.devl.org
 * for details. 
 *
 *
 */

#include <mc1322x.h>
#include <board.h>
#include <stdio.h>

#include "tests.h"
#include "config.h"

#define LED LED_RED

/* 802.15.4 PSDU is 127 MAX */
/* 2 bytes are the FCS */
/* therefore 125 is the max payload length */
#define PAYLOAD_LEN 16
#define DELAY 10000000

void fill_packet(volatile packet_t *p) {
  p->length = 8;
  p->offset = 0;
  p->data[0] = 0x03;
  p->data[1] = 0x08;
  p->data[2] = 0x17;
  p->data[3] = 0xff;
  p->data[4] = 0xff;
  p->data[5] = 0xff;
  p->data[6] = 0xff;
  p->data[7] = 0x07;

}


void main(void) {
	volatile packet_t *p;
	unsigned int cnt=0;

	/* trim the reference osc. to 24MHz */
	trim_xtal();

	uart_init(INC, MOD, SAMP);

	vreg_init();

	maca_init();

	set_channel(1); /* channel 11 */
//	set_power(0x0f); /* 0xf = -1dbm, see 3-22 */
//	set_power(0x11); /* 0x11 = 3dbm, see 3-22 */
	set_power(0x12); /* 0x12 is the highest, not documented */

        /* sets up tx_on, should be a board specific item */
        *GPIO_FUNC_SEL2 = (0x01 << ((44-16*2)*2));
	gpio_pad_dir_set( 1ULL << 44 );

	print_welcome("rftest-tx-gnychis");

	while(1) {		
	    		
		/* call check_maca() periodically --- this works around */
		/* a few lockup conditions */
		check_maca();

		while((p = rx_packet())) {
			if(p) free_packet(p);
		}

		p = get_free_packet();
		if(p) {
			fill_packet(p);

			p->data[3] = cnt & 0xff;
			p->data[2] = (cnt >> 8*1) & 0xff;
			p->data[1] = (cnt >> 8*2) & 0xff;
			p->data[0] = (cnt >> 8*3) & 0xff;
			
			printf("rftest-tx %u--- ", cnt);
			print_packet(p);

			tx_packet(p);
			cnt++;
			
//			for(i=0; i<DELAY; i++) { continue; }
		}
		
	}

}
