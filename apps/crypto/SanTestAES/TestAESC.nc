/*
* Copyright (c) 2010 Centre for Electronics Design and Technology (CEDT),
*  Indian Institute of Science (IISc) and Laboratory for Cryptologic
*  Algorithms (LACAL), Ecole Polytechnique Federale de Lausanne (EPFL).
*
* Author: Sylvain Pelissier <sylvain.pelissier@gmail.com>
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* - Redistributions of source code must retain the above copyright
*   notice, this list of conditions and the following disclaimer.
* - Redistributions in binary form must reproduce the above copyright
*   notice, this list of conditions and the following disclaimer in the
*   documentation and/or other materials provided with the
*   distribution.
* - Neither the name of INSERT_AFFILIATION_NAME_HERE nor the names of
*   its contributors may be used to endorse or promote products derived
*   from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
* FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL STANFORD
* UNIVERSITY OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
* OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "AES.h"
#include "printfZ1.h"

#define MSG_SIZE 32

module TestAESC{
	uses interface Boot;
	uses interface AES;
    uses interface Timer<TMilli> as TimerBlink;
    uses interface Leds;
}

implementation{

    /* Secret key */
    uint8_t K[KEY_SIZE] =  {0x00, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    // KEY_SIZE = 16 is defined in AES.h

    uint8_t IV[KEY_SIZE] =  {0x01,0x12,0x23,0x34,0x45,0x56,0x67,0x78,0x89,0x98,0x87,0x76,0x65,0x54,0x43,0x32};
    uint8_t i;

    /*
        Array to store the expanded key
    */
	uint8_t exp[240];

	/*
        First plaintext block
    */
    uint8_t in[MSG_SIZE] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5',};

    /*
        Ciphertext blocks.
    */
    uint8_t out[MSG_SIZE];
    uint8_t dec[MSG_SIZE];

	event void Boot.booted()
	{
        printfz1_init();
        printfz1("Starting the program\n");

        /*
            Key expansion.
        */
        call AES.keyExpansion(exp,K);

        call Leds.led2Toggle();
        call TimerBlink.startPeriodic(5000);
	}

    event void TimerBlink.fired()
    {
        uint8_t j;

        printfz1("Round start ------------\n");

        /* Print plain text */
        printfz1("Plain: ");
        for(j = 0; j < MSG_SIZE; j++){
            printfz1("%c",in[j]);
        }
        printfz1("\n\n");

         call Leds.led0Toggle();

        /*
            First block encryption
        */
        call AES.CBC_encrypt(in,exp,out, MSG_SIZE, IV);
        printfz1("Cipher: ");
        for(j = 0; j < MSG_SIZE; j++){
            printfz1("%2x ",out[j]);
        }
        printfz1("\n\n");

        call Leds.led1Toggle();

        /*
            First block decryption
        */
        call AES.CBC_decrypt(out,exp,dec, MSG_SIZE, IV);
        printfz1("Decipher: ");
        for(j = 0; j < MSG_SIZE; j++){
            printfz1("%c",dec[j]);
        }
        printfz1("\n\n");

        printfz1("Round complete ------------\n\n");
        call Leds.led2Toggle();

    }

}
