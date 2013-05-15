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
#define COUNT_MODE 1      /* use rising edge of primary source */
#define PRIME_SRC  0xf    /* Perip. clock with 128 prescale (for 24Mhz = 187500Hz)*/
#define SEC_SRC    0      /* don't need this */
#define ONCE       0      /* keep counting */
#define LEN        1      /* count until compare then reload with value in LOAD */
#define DIR        0      /* count up */
#define CO_INIT    0      /* other counters cannot force a re-initialization of this counter */
#define OUT_MODE   0      /* OFLAG is asserted while counter is active */

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

int count=0;
unsigned int pkt_cnt=0;

void tmr0_isr(void) {

  if(count%100==0) {
    printf("Packets-per-second: %d\n\r",pkt_cnt*6);
    pkt_cnt=0;
  }

	*TMR0_SCTRL = 0;
	*TMR0_CSCTRL = 0x0040; /* clear compare flag */
	count++;
}

void main(void) {
	volatile packet_t *p;
  int i;

	/* trim the reference osc. to 24MHz */
	trim_xtal();
	uart_init(INC, MOD, SAMP);
	vreg_init();
	maca_init();
	
  ///* Setup the timer */
  *TMR_ENBL     = 0;                    /* tmrs reset to enabled */
	*TMR0_SCTRL   = 0;
	*TMR0_CSCTRL  = 0x0040;
	*TMR0_LOAD    = 0;                    /* reload to zero */
	*TMR0_COMP_UP = 18750;                /* trigger a reload at the end */
	*TMR0_CMPLD1  = 18750;                /* compare 1 triggered reload level, 10HZ maybe? */
	*TMR0_CNTR    = 0;                    /* reset count register */
	*TMR0_CTRL    = (COUNT_MODE<<13) | (PRIME_SRC<<9) | (SEC_SRC<<7) | (ONCE<<6) | (LEN<<5) | (DIR<<4) | (CO_INIT<<3) | (OUT_MODE);
	*TMR_ENBL     = 0xf;                  /* enable all the timers --- why not? */
	enable_irq(TMR);

	set_channel(1); /* channel 11 */
	set_power(0x12); /* 0x12 is the highest, not documented */

  /* sets up tx_on, should be a board specific item */
  *GPIO_FUNC_SEL2 = (0x01 << ((44-16*2)*2));
	gpio_pad_dir_set( 1ULL << 44 );

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

			p->data[3] = pkt_cnt & 0xff;
			p->data[2] = (pkt_cnt >> 8*1) & 0xff;
			p->data[1] = (pkt_cnt >> 8*2) & 0xff;
			p->data[0] = (pkt_cnt >> 8*3) & 0xff;
			
			//printf("rftest-tx %u--- ", pkt_cnt);
			//print_packet(p);

			tx_packet(p);
			pkt_cnt++;
			
			for(i=0; i<DELAY; i++) { continue; }
		}
		
	}

}
