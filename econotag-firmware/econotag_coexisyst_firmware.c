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

#include "tests.h"
#include "config.h"

#define LED LED_GREEN

#define CHANGE_CHAN 0x0000
#define TRANSMIT_PACKET 0x0001
#define RECEIVED_PACKET 0x0002

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
	//       *GPIO_FUNC_SEL2 = (0x01 << ((44-16*2)*2));
	gpio_pad_dir_set( 1ULL << 44 );
}

void main(void) {
	volatile packet_t *p;
	volatile uint8_t chan;
	int in_cmd;
	char tval;

	printf("here!");

	init_dev();

	// Initialize the power and channel
	chan = 0;
	set_power(0x0f); /* 0dbm */
	set_channel(chan); /* channel 11 */

	while(1) {		

		/* call check_maca() periodically --- this works around */
		/* a few lockup conditions */
		check_maca();

		// Read the incoming packet and send it over
		if((p = rx_packet())) {
			int i;
			uart1_putc((char)RECEIVED_PACKET);  
			// First write the lqi (8-bits) and rx time (32-bits)
			uart1_putc((char)p->lqi);
			for(i=0;i<4;i++) 
				 uart1_putc((char)(p->rx_time >> i * CHAR_BIT & 0xff));
			uart1_putc((char)p->length);
			for(i=0;i<p->length;i++) 
				uart1_putc(p->data[i]);
			free_packet(p);
		}

		// Look for an incoming command
		if(uart1_can_get()) {
			in_cmd = (int) uart1_getc();

			// If the command is to change the channel, the very next byte
			// will be the channel number (0-15)
			if(in_cmd == CHANGE_CHAN) {
				int chan;
				
				// Wait for the next byte
				while(!uart1_can_get()) {
				}
				tval = uart1_getc();
				chan = (int) tval;
				set_channel(chan);

				uart1_putc(tval);
			}

			if(in_cmd == TRANSMIT_PACKET) {
				printf("Got transmit packet cmd\n\r");
			}
		}
	}
}
