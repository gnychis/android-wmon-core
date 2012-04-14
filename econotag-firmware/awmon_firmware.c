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
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <sys/time.h>

#include "tests.h"
#include "config.h"

#define LED LED_GREEN

#define DELAY 400000

#define CHANGE_CHAN 0x0000
#define TRANSMIT_PACKET 0x0001
#define RECEIVED_PACKET 0x0002
#define INITIALIZED 0x0003
#define TRANSMIT_BEACON 0x0004
#define START_SCAN 0x0005
#define SCAN_DONE 0x0006
#define CHANNEL_IS 0x0007

#define HIGH_CHANNEL 15 // the highest channel, 0->15

void my_set_channel(int tchan);

// Creates a ZigBee beacon which is similar to a probe request in 802.11
// to get ZigBee devices to announce themselves
void create_beacon(volatile packet_t *p) {
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

void maca_rx_callback(volatile packet_t *p) {
	(void)p;
	gpio_data_set(1ULL<< LED);
	gpio_data_reset(1ULL<< LED);
}

void init_dev(void) {
	/* read from the data register instead of the pad */
	/* this is needed because the led clamps the voltage low */
	/* trim the reference osc. to 24MHz */
	gpio_data(0);
	gpio_pad_dir_set( 1ULL << LED );
	gpio_data_sel( 1ULL << LED);
	trim_xtal();
	uart_init(INC, MOD, SAMP);
	vreg_init();
	maca_init();

	/* sets up tx_on, should be a board specific item */
	       *GPIO_FUNC_SEL2 = (0x01 << ((44-16*2)*2));
	gpio_pad_dir_set( 1ULL << 44 );
}

int count=0;
int scan_channel;
int old_chan;
static volatile packet_t pkt;
volatile uint8_t chan;

void tmr0_isr(void) {

	// Every 10 is 1 second
	if(count==3) {

		if(scan_channel!=-1) {
			if(scan_channel>HIGH_CHANNEL) {
				my_set_channel(old_chan);
				scan_channel=-1;
				uart1_putc((char)SCAN_DONE);
			} else {
				my_set_channel(scan_channel);
				memset((char *)&pkt, '\0', sizeof(struct packet));
				create_beacon(&pkt);
				tx_packet(&pkt);
				scan_channel++;
			}
		}
		count=0;
	} else if(count==2) {
		if(scan_channel!=-1 && scan_channel <= HIGH_CHANNEL) {
				memset((char *)&pkt, '\0', sizeof(struct packet));
				create_beacon(&pkt);
				tx_packet(&pkt);
		}
	}

	*TMR0_SCTRL = 0;
	*TMR0_CSCTRL = 0x0040; /* clear compare flag */
	count++;
}

void my_set_channel(int tchan) {
	chan=tchan;
	set_channel(chan);
	uart1_putc(CHANNEL_IS);
	uart1_putc((char)chan);
}

void main(void) {
	volatile packet_t *p;
	int in_cmd,j;
	char tval;
	char initialized_sequence[] = {0x67, 0x65, 0x6f, 0x72, 0x67, 0x65, 0x6e, 0x79, 0x63, 0x68, 0x69, 0x73};

	init_dev();

	scan_channel=-1;
	
	/* timer setup */
	/* CTRL */
#define COUNT_MODE 1      /* use rising edge of primary source */
#define PRIME_SRC  0xf    /* Perip. clock with 128 prescale (for 24Mhz = 187500Hz)*/
#define SEC_SRC    0      /* don't need this */
#define ONCE       0      /* keep counting */
#define LEN        1      /* count until compare then reload with value in LOAD */
#define DIR        0      /* count up */
#define CO_INIT    0      /* other counters cannot force a re-initialization of this counter */
#define OUT_MODE   0      /* OFLAG is asserted while counter is active */

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

	// Initialize the power and channel
	chan = 0;
	set_power(0x12); /* 0x12 is the highest */
	my_set_channel(chan);

	// Send an initialized sequence to the receiver
	for(j=0; j<12; j++)
		uart1_putc(initialized_sequence[j]);
				
	while(1) {		

		/* call check_maca() periodically --- this works around */
		/* a few lockup conditions */
		check_maca();

		// Read the incoming packet and send it over
		if((p = rx_packet())) {
			int i;
			uart1_putc((char)RECEIVED_PACKET);  
			// Now write the channel it was received on (there is no radiotap otherwise)
			uart1_putc((char)chan);
			// First write the lqi (8-bits) and rx time (32-bits)
			uart1_putc((char)p->lqi);
			for(i=0;i<4;i++) 
				 uart1_putc((char)(p->rx_time >> i * CHAR_BIT & 0xff));
			uart1_putc((char)p->length);
			for(i=0;i<p->length;i++) 
				uart1_putc(p->data[i + p->offset]);
			free_packet(p);
		}

		// Look for an incoming command
		if(uart1_can_get()) {
			in_cmd = (int) uart1_getc();

			// If the command is to change the channel, the very next byte
			// will be the channel number (0-15)
			if(in_cmd == CHANGE_CHAN) {
				// Wait for the next byte
				while(!uart1_can_get()) {
				}
				tval = uart1_getc();

				// Only change the channel if we are not scanning
				if(scan_channel == -1) {
					my_set_channel((uint8_t) tval);
				}

				//uart1_putc(tval);  // write back value for testing
			}

			if(in_cmd == TRANSMIT_PACKET) {
			}

			if(in_cmd == TRANSMIT_BEACON) {
				memset((char *)&pkt, '\0', sizeof(struct packet));
				create_beacon(&pkt);
				tx_packet(&pkt);
			}

			// Start a scan, keep the first time, save the old channel
			if(in_cmd == START_SCAN) {
				scan_channel=0;
				old_chan = chan;
			}
		}
	}
}
