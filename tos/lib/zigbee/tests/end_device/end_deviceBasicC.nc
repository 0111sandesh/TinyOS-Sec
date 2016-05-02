/*
 * @author Ricardo Severino <rars@isep.ipp.pt>
 * END DEVICE
 *
 */

#include <Timer.h>
#include "printfZ1.h"
#include "log_enable.h"

#define lclPrintf			printfz1
#define lclprintfUART_init		printfz1_init
#define MSG_SIZE 16*7
#define ENCRYPT_ENABLE 0

module end_deviceBasicC 
{
	uses {
		interface Boot;
		interface Leds;
		interface AES;

		interface NLDE_DATA;

		//NLME NWK Management services
		interface NLME_NETWORK_DISCOVERY;
		interface NLME_JOIN;
		interface NLME_LEAVE;
		interface NLME_SYNC;
		interface NLME_RESET;
		interface NLME_GET;
		interface NLME_SET;

		//Timers
		interface Timer<TMilli> as T_init;
		interface Timer<TMilli> as KeepAliveTimer;
		interface Timer<TMilli> as NetAssociationDeferredTimer;

	#if defined(PLATFORM_TELOSB)
		//user button
		interface Get<button_state_t>;
		interface Notify<button_state_t>;
	#endif
	}   
}
implementation
{
	// Depth by configuration
	uint8_t myDepth;
	//boolean variable definig if the device has joined to the PAN
	uint8_t joined;
	// Maximum number of join trials before restart from network discovery
	uint8_t maxJoinTrials;
	uint16_t myParentAddress;

	//sandesh added
	/**************************************************/
	  /* Secret key */
	  uint8_t K[KEY_SIZE] =  {0x00, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	  // KEY_SIZE = 16 is defined in AES.h
	  uint8_t IV[KEY_SIZE] =  {0x01,0x12,0x23,0x34,0x45,0x56,0x67,0x78,0x89,0x98,0x87,0x76,0x65,0x54,0x43,0x32};

	  /* Array to store the expanded key */
	  uint8_t exp[240];

	  /* Ciphertext blocks.*/
	  uint8_t cip[MSG_SIZE];
	  uint8_t dec[MSG_SIZE];

	  uint8_t count = 0;

	/**************************************************/

	task void KeepAlive();


	task void KeepAlive()
	{
		// uint8_t nsdu_pay[6];
		uint8_t j;
		uint8_t msg[16*10] = 	{	'0', '1', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', ' ',
                                  	'0', '2', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', ' ',
                              		'0', '3', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', ' ',
                          			'0', '4', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', ' ',
		                          	'0', '5', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', ' ',
		                      		'0', '6', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', ' ',
		                  			'0', '7', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', ' ',
		              				'0', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', ' ',
		          					'0', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', ' ',
		    						'1', '0', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', ' '};
		uint8_t * nsdu_pay = msg;
		uint8_t * msgToSend;


		
		// Send the message towards the coordinator 
		// (default network address: 0x0000)
		call Leds.led0Toggle();

		if(ENCRYPT_ENABLE){
			lclPrintf("%d: End Device sending encrypted msg to coordinator ----------\n", count);
	        /* First block encryption*/
	        call AES.CBC_encrypt(nsdu_pay,exp,cip, MSG_SIZE, IV);
	        msgToSend = cip;
		}else{
			lclPrintf("%d: End Device sending msg to coordinator ----------\n", count);
			msgToSend = nsdu_pay;
		}

		printfz1("Message: ");
        for(j = 0; j < MSG_SIZE; j++){
            printfz1("%c",nsdu_pay[j]);
        }
        printfz1("\n\n");

        count++;
		
        // printfz1("Cipher: ");
        // for(j = 0; j < MSG_SIZE; j++){
        //     printfz1("%02x ",cip[j]);
        // }
        // printfz1("\n\n");
       
        // /* First block decryption */
        // call AES.CBC_decrypt(cip,exp,dec, MSG_SIZE, IV);
        // printfz1("Decipher: ");
        // for(j = 0; j < MSG_SIZE; j++){
        //     printfz1("%c",dec[j]);
        // }
        // printfz1("\n\n");

      /**************************************************/

		call NLDE_DATA.request(0x0000, MSG_SIZE, msgToSend, 0, 1, 0x00, 0);
		call Leds.led0Toggle();
	}
  
	// This function initializes the variables.
	void initVariables()
	{
		// Depth by configuration (initialize to default)
		myDepth = DEF_DEVICE_DEPTH;  
		//boolean variable definig if the device has joined to the PAN
		joined = 0x00;
		// Maximum number of join trials before restart from network discovery
		maxJoinTrials = MAX_JOIN_TRIALS;
	}

	event void Boot.booted() 
	{
		//printfUART_init();
		printfz1_init();
		call AES.keyExpansion(exp,K);

		initVariables();
		
	#if defined(PLATFORM_TELOSB)
		call Notify.enable();  
	#endif

		// Start the application
		call NLME_RESET.request();
	}


	/*****************************************************
	****************NLDE EVENTS***************************
	******************************************************/

	/*************************NLDE_DATA*****************************/

	event error_t NLDE_DATA.confirm(uint8_t NsduHandle, uint8_t Status)
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("NLDE_DATA.confirm\n", "");
	#endif

		if (joined != 0x00)
			call Leds.led1Toggle();
			
		return SUCCESS;
	}

	event error_t NLDE_DATA.indication(
				uint16_t SrcAddress, 
				uint8_t NsduLength,
				uint8_t Nsdu[120], 
				uint16_t LinkQuality)
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("NLDE_DATA.indication\n", "");
	#endif

		return SUCCESS;
	}

	/*****************************************************
	****************NLME EVENTS***************************
	******************************************************/ 

	/*****************NLME_NETWORK_DISCOVERY**************************/
	// This is not called anymore by the NKWP since it tries to associate 
	// directly to the parent and issuing a JOIN confirm, instead
	event error_t NLME_NETWORK_DISCOVERY.confirm(uint8_t NetworkCount,networkdescriptor networkdescriptorlist[], uint8_t Status)
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("NLME_NETWORK_DISCOVERY.confirm\n", ""); 
	#endif

		return SUCCESS;
	}

	/*************************NLME_JOIN*****************************/
	event error_t NLME_JOIN.indication(uint16_t ShortAddress, uint32_t ExtendedAddress[], uint8_t CapabilityInformation, bool SecureJoin)
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("NLME_JOIN.indication\n", "");
	#endif

		return SUCCESS;
	}

	event error_t NLME_JOIN.confirm(uint16_t PANId, uint8_t Status, uint16_t parentAddress)
	{	
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("NLME_JOIN.confirm\n", "");
	#endif

		switch(Status)
		{
		case NWK_SUCCESS:
			// Join procedure successful
			joined = 0x01;
			myParentAddress=parentAddress;
			call KeepAliveTimer.startPeriodic(10000);

			break;

		case NWK_NOT_PERMITTED:
			joined = 0x00;
			//join failed
			break;

		case NWK_STARTUP_FAILURE:
			joined = 0x00;
			maxJoinTrials--;
			if (maxJoinTrials == 0)
			{
				// Retry restarting from the network discovery phase
				call T_init.startOneShot(5000);
			}
			else
			{
				// Retry after a few seconds
				call NetAssociationDeferredTimer.startOneShot(JOIN_TIMER_RETRY);
			}
			break;

		default:
			//default procedure - join failed
			joined = 0x00;
			break;
		}
		return Status;
	}

	/*************************NLME_LEAVE****************************/
	event error_t NLME_LEAVE.indication(uint64_t DeviceAddress)
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("NLME_LEAVE.indication\n", "");
	#endif

		return SUCCESS;
	}

	event error_t NLME_LEAVE.confirm(uint64_t DeviceAddress, uint8_t Status)
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("NLME_LEAVE.confirm\n", "");
	#endif

		joined=0x00;
		return SUCCESS;
	}

	/*************************NLME_SYNC*****************************/
	event error_t NLME_SYNC.indication()
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("NLME_SYNC.indication\n", "");
	#endif

		// We lost connection with our parent. Automatic rescan is done
		// at the NWK layer, unless it is after a disassociation request
		
		joined=0x00;
		
		// Stop the keep alive timer, if it is still running
		if (call KeepAliveTimer.isRunning())
			call KeepAliveTimer.stop();
		
		// Switch off all leds
		call Leds.led0Off();
		call Leds.led1Off();
		call Leds.led2Off();

		return SUCCESS;
	}

	event error_t NLME_SYNC.confirm(uint8_t Status)
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("NLME_SYNC.confirm\n", "");
	#endif

		return SUCCESS;
	}

	/*****************        NLME-SET     ********************/
	event error_t NLME_SET.confirm(uint8_t Status, uint8_t NIBAttribute)
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("NLME_SET.confirm\n", "");
	#endif

		return SUCCESS;
	}

	/*****************        NLME-GET     ********************/
	event error_t NLME_GET.confirm(uint8_t Status, uint8_t NIBAttribute, uint16_t NIBAttributeLength, uint16_t NIBAttributeValue)
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("NLME_GET.confirm\n", "");
	#endif

		return SUCCESS;
	}

	event error_t NLME_RESET.confirm(uint8_t status)
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("NLME_RESET.confirm\n", "");
	#endif

		call T_init.startOneShot(2000);
		return SUCCESS;
	}

	/*****************************************************
	****************TIMER EVENTS***************************
	******************************************************/ 
	/*******************T_init**************************/
	event void T_init.fired() 
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("I'm NOT the coordinator\n", "");
	#endif

		call NLME_NETWORK_DISCOVERY.request(LOGICAL_CHANNEL, BEACON_ORDER);
		return;
	}

	/*******************NetAssociationDeferredTimer**************************/
	event void NetAssociationDeferredTimer.fired()
	{
	#if (LOG_LEVEL & TRACE_FUNC)
		lclPrintf("go join as end device\n", ""); 
	#endif

		call NLME_JOIN.request(MAC_PANID, FALSE, FALSE, 0, 0, 0, 0, 0);
		return;
	}

	/*******************KeepAlive**************************/
	event void KeepAliveTimer.fired()
	{
		post KeepAlive();
	}

#if defined(PLATFORM_TELOSB)
	event void Notify.notify(button_state_t state)
	{
		if (state == BUTTON_PRESSED && joined) 
		{
			call KeepAliveTimer.stop();
			call NLME_LEAVE.request(0,0,0);
		}
	}
#endif
  
}

