/*********************************************************
 * Module name: ftl_api.c
 *
 * Copyright 2010, 2011. All Rights Reserved, Crane Chu.
 *
 * This file is part of OpenNFM.
 *
 * OpenNFM is free software: you can redistribute it and/or 
 * modify it under the terms of the GNU General Public 
 * License as published by the Free Software Foundation, 
 * either version 3 of the License, or (at your option) any 
 * later version.
 * 
 * OpenNFM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied 
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR 
 * PURPOSE. See the GNU General Public License for more 
 * details.
 *
 * You should have received a copy of the GNU General Public 
 * License along with OpenNFM. If not, see 
 * <http://www.gnu.org/licenses/>.
 *
 * First written on 2010-01-01 by cranechu@gmail.com
 *
 * Module Description:
 *    FTL APIs.
 *
 *********************************************************/

#include <core\inc\cmn.h>
#include <core\inc\ftl.h>
#include <core\inc\ubi.h>
#include <core\inc\mtd.h>
#include <sys\sys.h>
#include "ftl_inc.h"
#include <core\inc\buf.h>

// jdafoe
#include <stdlib.h>
#include <math.h>
#include "init.h"
#include "ecdh.h"
#include "aes.h"
#include "hmac.h"
#include "prp.h"
#define KEY_SIZE 16
UINT32 g_LBAnum = 0;
// end jdafoe
   
/* Advanced Page Mapping FTL:
 * - Block Dirty Table: LOG_BLOCK 0, cache all
 * - ROOT Table: LOG_BLOCK 1, cache all. point to journal blocks.
 * - Page Mapping Table: LOG_BLOCK 2~N, cache x pages with LRU algo.
 * - DATA Journal: commit
 * - Init: read BDT, ROOT, PMT, Journal info, ...
 * - Reclaim
 * - Meta Data Page: in last page in PMT blocks and data blocks.
 * - choose journal block on erase and write, according to die index
 *
 * TODO: advanced features:
 * - sanitizing
 * - bg erase
 * - check wp/trim, ...
 */

// Jdafoe
extern int read_state = 0; // keeps track of the read state. Determines what to do on reads
                            // 0: Regular mode
                            // 1: Audit mode
                            // 2: Parity generation
static uint8_t dh_sharedKey[ECC_PUB_KEY_SIZE];
static uint8_t tempKey[KEY_SIZE];
extern int page_inx = 0; // Used to find offset of data in page read.
static int numBits = 0;  // Number of bits IO for the inverse PRP.
static int genPar = 0;   // Boolean value. Keeps track of whether FTL is in parity generation mode.
                          // 0: Regular mode
                          // 1: Parity generation mode.
static int restricted_area_end = 5000; // TODO: should this be -1??
static int expected_semiRestricted_writes = 0;
static int current_semiRestricted_writes = 0;
static int secretLen = 0;
static int proofLen = 0;
static uint8_t proof[1024];
static int writePartition = 0;

//int read_loops;
// end Jdafoe

// Jdafoe


/* pseudo random number generator with 128 bit internal state... probably not suited for cryptographical usage */
typedef struct
{
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
} prng_t;

static prng_t prng_ctx;

static uint32_t prng_rotate(uint32_t x, uint32_t k)
{
  return (x << k) | (x >> (32 - k)); 
}

static uint32_t prng_next(void)
{
  uint32_t e = prng_ctx.a - prng_rotate(prng_ctx.b, 27); 
  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17); 
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e; 
  prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}

static void prng_init(uint32_t seed)
{
  uint32_t i;
  prng_ctx.a = 0xf1ea5eed;
  prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;

  for (i = 0; i < 31; ++i) 
  {
    (void) prng_next();
  }
}

// Niusen
// Function to encrypt read data
#define NUM1     (1<<24)
#define NUM2     (1<<16)
#define NUM3     (1<<8)
int DecryptData(uint32_t* KEY,void* buffer, int dataLen)
{
   //decrypt after read
    AesCtx ctx;
    unsigned char iv[] = "1234"; // Needs to be same between FTL and SGX
    unsigned char key[16];
    uint8_t i;
    for(i=0;i<4;i++){    
    	key[4*i]=(*(KEY+i))/NUM1;
    	key[(4*i)+1]=((*(KEY+i))/NUM2)%NUM3;
    	key[(4*i)+2]=(*(KEY+i)% NUM2)/NUM3;
    	key[(4*i)+3]=(*(KEY+i)% NUM2)%NUM3;
    }
    
   if( AesCtxIni(&ctx, iv, key, KEY128, EBC) < 0) return -1;

   if (AesDecrypt(&ctx, (unsigned char *)buffer, (unsigned char *)buffer, dataLen) < 0) return -1;

   return 0;
}
int EncryptData(uint32_t* KEY,void* buffer, int dataLen)
{
    //encrypt before writing
    AesCtx ctx;
    unsigned char iv[] = "1234";
    //unsigned char key[] = "876543218765432";
    unsigned char key[16];    
    uint8_t i;
    for(i=0;i<4;i++){    
     key[4*i]=(*(KEY+i))/NUM1;
     key[(4*i)+1]=((*(KEY+i))/NUM2)%NUM3;
     key[(4*i)+2]=(*(KEY+i)% NUM2)/NUM3;
     key[(4*i)+3]=(*(KEY+i)% NUM2)%NUM3;
    }
    for(i=0;i<16;i++){ 
     // uart_printf("EncryptData():the %d byte of key is %x\n\r",i,key[i]); 
    }
    
    //uart_printf("before encrypt: %s\n\r", buffer);
    
   // initialize context and encrypt data at one end    
    if( AesCtxIni(&ctx, iv, key, KEY128, EBC) < 0)
        uart_printf("init error\n");
    
    int flag = 0;
    if ((flag = AesEncrypt(&ctx, (unsigned char *)buffer, (unsigned char *)buffer, dataLen)) < 0) 
      // dataLen needs to be different based on PDP vs ECC. Full 512 byte segment for ECC. KEY_SIZE for PDP.
    {
       uart_printf("error in encryption\n");
       if(flag == -2)
      {
        uart_printf("Data is empty");
        //return -2;
      }
      else if(flag == -3)
      {
        uart_printf("cipher is empty");
      //return -3;
      }
      else if(flag == -4)
      {
        uart_printf("context is empty");
       // return -4;
      }
      else if(flag == -5)
      {
        uart_printf("data length is not a multiple of 16");
      //return -5;
      }
      else
      {
        uart_printf("other error");
      }    
    }else{
      //uart_printf("encryption ok %d\n\r",count_write);
      //uart_printf("after encrypt: %s\n\r", buffer);      
    }
  return 0;
}
// end Niusen
// end Jdafoe



STATUS FTL_Format() {
  STATUS ret;
    
  ret = UBI_Format();
  if (ret == STATUS_SUCCESS) {
    ret = UBI_Init();
  }

  if (ret == STATUS_SUCCESS) {
    ret = DATA_Format();
  }

  if (ret == STATUS_SUCCESS) {
    ret = HDI_Format();
  }

  if (ret == STATUS_SUCCESS) {
    ret = PMT_Format();
  }

  if (ret == STATUS_SUCCESS) {
    ret = BDT_Format();
  }

  if (ret == STATUS_SUCCESS) {
    ret = ROOT_Format();
  }

  return ret;
}

STATUS FTL_Init() {
  STATUS ret;

  ret = UBI_Init();
  if (ret == STATUS_SUCCESS) {
    /* scan tables on UBI, and copy to RAM */
    ret = ROOT_Init();
  }

  if (ret == STATUS_SUCCESS) {
    ret = BDT_Init();
  }

  if (ret == STATUS_SUCCESS) {
    ret = PMT_Init();
  }

  if (ret == STATUS_SUCCESS) {
    ret = HDI_Init();
  }

  if (ret == STATUS_SUCCESS) {
    ret = DATA_Replay(root_table.hot_journal);
  }

  if (ret == STATUS_SUCCESS) {
    ret = DATA_Replay(root_table.cold_journal);
  }

  if (ret == STATUS_SUCCESS) {
    /* handle reclaim PLR: start reclaim again. Some data should
     * be written in the same place, so just rewrite same data in the
     * same page regardless this page is written or not. */

    /* check if hot journal blocks are full */
    if (DATA_IsFull(TRUE) == TRUE) {
      ret = DATA_Reclaim(TRUE);
      if (ret == STATUS_SUCCESS) {
        ret = DATA_Commit();
      }
    }

    /* check if cold journal blocks are full */
    if (DATA_IsFull(FALSE) == TRUE) {
      ret = DATA_Reclaim(FALSE);
      if (ret == STATUS_SUCCESS) {
        ret = DATA_Commit();
      }
    }
  }

  return ret;
}

#define PMT_CURRENT_BLOCK  (PM_NODE_BLOCK(root_table.pmt_current_block))
#define PMT_CURRENT_PAGE   (PM_NODE_PAGE(root_table.pmt_current_block))
#define PMT_RECLAIM_BLOCK  (PM_NODE_BLOCK(root_table.pmt_reclaim_block))
#define PMT_RECLAIM_PAGE   (PM_NODE_PAGE(root_table.pmt_reclaim_block))

extern STATUS pmt_reclaim_blocks();

STATUS FTL_MAPI_restore(){  
  STATUS ret = STATUS_SUCCESS;
  UINT32 iClusterNum;//???
  
  PM_NODE_ADDR iPM_NODE[PM_PER_NODE];//512
  PM_NODE_ADDR* cache_addr = NULL; 
  
  LOG_BLOCK block_stored;
  PAGE_OFF page_stored;  
  SPARE spare; 
  
  PMT_CLUSTER meta_data[PAGE_PER_PHY_BLOCK];//??1?PMT???????
  
  UINT32 i,j; 
  
  PMT_CLUSTER pm_cluster;  
  
  //?PMT???LEB?BDT????63,??,????PMT???
  for (i = PMT_START_BLOCK; i < PMT_START_BLOCK + PMT_BLOCK_COUNT; i++) {
    block_dirty_table[i] = MAX_DIRTY_PAGES;//63 
  }  
  pmt_reclaim_blocks();//?PMT?????????????,??pmt?current?,?????PMT???MAPI
  
  
  //MAPI?8?,????II?8?LEB??   
  iClusterNum=((g_LBAnum + PM_PER_NODE - 1) / PM_PER_NODE);//???471   
  cache_addr = &(iPM_NODE[0]);
  PMT_Init();//?????????
  
  for(i=0;i<iClusterNum;i=i+PAGE_PER_PHY_BLOCK-1){      
      
    for(j=0;j<PAGE_PER_PHY_BLOCK-1;j++){//j<63        
      pm_cluster=i+j; 
      //????MAPI???
      block_stored=(pm_cluster/PAGE_PER_PHY_BLOCK)+PMTRESORE_START_BLOCK;//?LEB46???
      page_stored=pm_cluster % PAGE_PER_PHY_BLOCK;
      
      ret = UBI_Read(block_stored, page_stored, cache_addr, spare);
      
      if (ret == STATUS_SUCCESS) {     
       
        ret = UBI_Write(PMT_CURRENT_BLOCK, PMT_CURRENT_PAGE,cache_addr, spare, FALSE);
        if (ret == STATUS_SUCCESS) {
          meta_data[PMT_CURRENT_PAGE] = pm_cluster;
         
        }                 
        PM_NODE_SET_BLOCKPAGE(root_table.page_mapping_nodes[pm_cluster],PMT_CURRENT_BLOCK, PMT_CURRENT_PAGE);
        PM_NODE_SET_BLOCKPAGE(root_table.pmt_current_block, PMT_CURRENT_BLOCK, PMT_CURRENT_PAGE+1);
      }        
    }
    //??63?MAP I?,?PMT???????????????????
    if (ret == STATUS_SUCCESS) {
      ret = UBI_Write(PMT_CURRENT_BLOCK, PMT_CURRENT_PAGE, meta_data, NULL, FALSE);
      if (ret == STATUS_SUCCESS) {              
        ret = pmt_reclaim_blocks();//??pmt?current?,???PMT?????MAPI
      }       
    }     
  }
  
  //??root_table.pmt_reclaim_block
  if (ret == STATUS_SUCCESS) {
     ret = UBI_Erase(PMT_CURRENT_BLOCK+1, PMT_CURRENT_BLOCK+1);
   }
  if (ret == STATUS_SUCCESS) {
     PM_NODE_SET_BLOCKPAGE(root_table.pmt_reclaim_block, PMT_CURRENT_BLOCK+1, 0);
     block_dirty_table[PMT_CURRENT_BLOCK+1] = 0;
  }
  
  //todo:???????1?PMT?(???)???1??????????  
  
  return ret; 
}

STATUS FTL_Write(PGADDR addr, void* buffer) {
  STATUS ret;
  
  
  // Jdafoe
  
  /*
   * 237846 (951384) - Set writePartition to 1 or 0. 
   * 237847 (951388) - Generate shared key via Diffie-Hellman key exchange.
   * 237848 (951392) - Generate temporary key from shared key, derived from nonce.
   * 237849 (951396) - Recieve page next page number to be read for current audit.
   * 237850 (951400) - Set genPar to 1 or 0. Set numBits to correct number.
   * 237851 (951404) - Restore ALL old mappings! (Up to one).
   * 237852 (951408) - Enable GC on invalidated blocks.
   */
  

  if(addr == 237846) { // 951384
    if(writePartition == 0) {
      writePartition = 1;
    }
    else {
      writePartition = 0;
    }
  }

  // Generate ecc keypair for diffie hellman
  if(addr == 237847) { // 951388
    
    uint8_t sgx_pubKey[ECC_PUB_KEY_SIZE];
    uint8_t dh_privKey[ECC_PRV_KEY_SIZE];
    uint8_t dh_pubKey[ECC_PUB_KEY_SIZE];
    int status = 0;
    
    uint8_t *temp = buffer;
    
    //uart_printf("SGX_PUBKEY: ");
    for(int i = 0; i < ECC_PUB_KEY_SIZE; i++) {
      sgx_pubKey[i] = temp[i];
      //uart_printf("%x", sgx_pubKey[i]);
   }
   //uart_printf("\n\n");
    
    status = gen_ecc_keypair(dh_pubKey, dh_privKey); /* Keypair used in DH keygen. pubKey send to SGX */

    //uart_printf("FTL PRIVATE KEY: ");
    //for(int i = 0; i < ECC_PRV_KEY_SIZE; i++) {
      //uart_printf("%x", dh_privKey[i]);
    //}
    //uart_printf("\n\n");
                
    //uart_printf("FTL PUBLIC KEY: ");
    for(int i = 0; i < ECC_PUB_KEY_SIZE; i++) {
      //uart_printf("%x", dh_pubKey[i]);
      temp[i] = dh_pubKey[i]; /* Send pubKey to SGX by writing to this location */
    }
    //uart_printf("\n\n");
    
    status = gen_shared_dh_key(dh_privKey, sgx_pubKey, dh_sharedKey); /* Generate Diffie-Hellman shared key */
    
  }
  

  if(addr == 237848) { //951392
    // Generate tempKey - derived from nonce.
	size_t keySize = KEY_SIZE;
    uint8_t *temp = buffer;
    hmac_sha1(dh_sharedKey, ECC_PUB_KEY_SIZE, temp, KEY_SIZE, tempKey, &keySize);
    //uart_printf("Challenge number recieved: ");
    //for(int i = 0; i < KEY_SIZE; i++) {
      //uart_printf("%x", temp[i]);
    //}
    //uart_printf("\n");
    //uart_printf("Challenge key generated: ");
    //for(int i = 0; i < KEY_SIZE; i++) {
    //}
    //uart_printf("\n");
    //uart_printf("-------------------------------------------------------\n");
  }
  
  // Writes to 237849 (951396) will be te index for next page to be read during audit
  if(addr == 237849) { // TODO: this can probably be handled better for efficiency.
    uint8_t *temp = buffer;
    //uart_printf("Recieving index: ");
    //for(int i = 0; i < 1; i++) {
    //  uart_printf("%x", temp[i]);
    //}
    
    if(genPar == 1) {
      read_state = 2;

      
    }
    else {
      read_state = 1;
    }
    page_inx = temp[0] % 4;
    //uart_printf("-------------------------------------------------------\n");
  }
  
  // read_state 2 is parity generation mode. Assume read state is set to 0 between operations. When swapping to mode 2, buffer will contain ceil(log_2(numPages))
  if(addr == 237850) { // 951400
    if(genPar != 1) {
      genPar =  1;
      uint8_t *temp = buffer;
      numBits = temp[0];
      //uart_printf("genPar = 1\n");
    } 
    else {
	//	uart_printf("genPar = 0\n");
      genPar = 0;
    }
  }
  
  if(addr == 237851) { // 951404
    ret = FTL_MAPI_restore();
  //  uart_printf("Restore Good! \n");
    return ret;
  }
  
  if(addr == 237852) { // 951408
    for(int i = 0; i < 3991; i++) {
      
      if(block_state[i] == 1) {
        block_state[i] = 2;
      }
  }
  }
  
  if(addr >= 5000 && addr < restricted_area_end) { // TODO: these "ends" should be defined as constants
  	// writes are simply disabled here.
    uart_printf("in fail\n");
	return STATUS_SUCCESS;
  }
  if(addr >= (restricted_area_end) && addr <= 10000) {
    

	  
	  size_t keySize = KEY_SIZE;
	  // very first is to check magic number. if it is "PARITY", then set expected_semiRestricted_writes and current_semiRestricted_writes to 0.
	  uint8_t *temp = buffer;
         

	  int loc = 0;

	  char magicNumber[7] = {0};
	  for(int i = 0; i < 6; i++) {
		magicNumber[i] = temp[i];
	  }
	  if(strcmp("PARITY", magicNumber) == 0) {
   //         uart_printf("found magic number\n");
		loc += 6;
		// generate groupKey... this _should_ be the only tempKey?
		hmac_sha1(dh_sharedKey, KEY_SIZE, temp + loc, KEY_SIZE, tempKey, &keySize);
		loc += KEY_SIZE;
    //            uart_printf("mag sha1 done\n");

		// get expected_semiRestricted_writes
                memcpy(&expected_semiRestricted_writes, temp + loc, sizeof(int));
		loc += sizeof(int);

		// get Proof length and secret length
		memcpy(&proofLen, temp + loc, sizeof(int));
		loc += sizeof(int);
		secretLen = (proofLen / expected_semiRestricted_writes) * 8;
		// get proof
		//if(proof != NULL) {
                //  uart_printf("call free\n");
		//	free(proof);
                //        uart_printf("free done\n");
		//}

		//proof = malloc(proofLen);
		if(proof == NULL) {
			// Handle error
    //              uart_printf("malloc fail\n");
		}

		memcpy(proof, temp + loc, proofLen);
		loc += proofLen;
		uint8_t signature[KEY_SIZE];
    //            uart_printf("mag sha1 2 start\n");
		hmac_sha1(tempKey, KEY_SIZE, temp, loc, signature, &keySize);
  //              uart_printf("mag sha1 2 done\n");

                
		if(memcmp(signature, temp + loc, KEY_SIZE) != 0) {
			// Handle error. signature failed.
			current_semiRestricted_writes = 0;
			expected_semiRestricted_writes = 0;
		}
		//if() // other fail conditions TODO: Think of any additional fail conditions.
		prng_init((uint32_t) tempKey[0]);
   //             uart_printf("Found magic number done.\n");
	  }
	  else if(expected_semiRestricted_writes > current_semiRestricted_writes) {
		// progressively check proof.
		if(restricted_area_end + current_semiRestricted_writes != addr) {
			expected_semiRestricted_writes = 0;
			current_semiRestricted_writes = 0;
                        uart_printf("in fail 2\n");
			return STATUS_SUCCESS; // TODO: think if this is really all that needs to be done on fail. There is an implicit failsafe... no comm with TEE here.
		}
                
    //            uart_printf("checking...\n");


		int randLen = secretLen * log2((2048 * 8) / secretLen);
 //               uart_printf("malloc\n");
		uint8_t *pageRand = (uint8_t *) malloc(secretLen * sizeof(uint8_t));
  //              uart_printf("end malloc\n");
                for(int l = 0; l < secretLen; l++) {
                  pageRand[l] = 0;
                }

		int current = 0;
		int verificationResult = 1;
		for(int j = 0; j < secretLen; j++) {
			pageRand[j] = (uint8_t) prng_next();
			int pageIndex = (current + (int) floor(pageRand[j] / 8));
			int bitIndex = pageRand[j] % 8;
			int proofBit = (current_semiRestricted_writes * secretLen) + j;
			int proofByteIndex = (int) floor(proofBit / 8);
			int proofBitIndex = proofBit % 8;
			if(((temp[pageIndex] >> bitIndex) & 1) != ((proof[proofByteIndex] >> proofBitIndex) & 1)) {
				// proof failed... reset expected_semiRestricted_writes and current_semiRestricted_writes, etc... other important things (so that further writes are rejected). AND, write signed 0 to location for Enclave to read.
                expected_semiRestricted_writes = 0;
				current_semiRestricted_writes = 0;
				verificationResult = 0;
				uint8_t signedVerificationResult[KEY_SIZE + 1];
				hmac_sha1(tempKey, KEY_SIZE, signedVerificationResult, sizeof(int), signedVerificationResult + 1, &keySize);
				signedVerificationResult[0] = verificationResult;
				FTL_Write(1000, signedVerificationResult);
				break;
			}
        current += 2048 / secretLen;
		}
		current_semiRestricted_writes++;
		if(verificationResult == 1) {
			if(current_semiRestricted_writes == expected_semiRestricted_writes) {
				// proof success. Write signed 1 to location for Enclave to read. Reset essential viriables.
				uint8_t signedVerificationResult[KEY_SIZE + 1];
				restricted_area_end += expected_semiRestricted_writes;
				expected_semiRestricted_writes = 0;
				current_semiRestricted_writes = 0;
				hmac_sha1(tempKey, KEY_SIZE, signedVerificationResult, sizeof(int), signedVerificationResult + 1, &keySize);
				signedVerificationResult[0] = verificationResult;
				uart_printf("verification result: %d\n", verificationResult);
				FTL_Write(1000, signedVerificationResult);
			}
		}

	  }

	  // Note: there are a few conditions which comprimize this process explicily:
	  // signature fails
	  // expected_semiRestricted_writes == 0 && addr != restricted_area_end.
	  // restricted_area_end + current_semiRestricted_writes + 1 != addr 
	  

	  // If not first semi-restricted write, then progressively check proof.
	  // If final semi-restricted write, then increase restricted_area_end only if proof passed, and regardless, write signed proof verification results to a certain address, which should be read by the Enclave.
  }

  if(writePartition) {
    if(addr < 237846) {
      addr = feistel_network_prp(tempKey, addr, numBits);
      uint8_t *temp = buffer;
      DecryptData((UINT32 *)tempKey, temp, 2048);
    }
  }
  
  // end Jdafoe
  
  BOOL is_hot = HDI_IsHotPage(addr);
  
  //uart_printf("write\n");
  
  ret = DATA_Write(addr, buffer, is_hot);
  if (ret == STATUS_SUCCESS) {
    if (DATA_IsFull(is_hot) == TRUE) {
      ret = DATA_Reclaim(is_hot);
      if (ret == STATUS_SUCCESS) {
        ret = DATA_Commit();
      }
    }
  }
 // uart_printf("write done\n");
  return ret;
}





STATUS FTL_Read(PGADDR addr, void* buffer) {
  
  uint8_t ckwi[KEY_SIZE];
  
  // Use inverse_feistel_netwrk_prp on the address, with the tempKey. Read and encrypt the data at this location.
  if(read_state == 2 && addr < 237846) {
    
    //FTL_Read(237849, buffer); // the first int (4 bytes) of this will be the page number with correct data.
    //uint8_t *temp = buffer;
    //uint8_t page = temp[0]; // How does this translate to what address to read?
       //   uart_printf("%d\n", addr);
      addr = feistel_network_prp(tempKey, addr, numBits);
     // uart_printf("%d\n", addr);
  }
  
  
  if(read_state == 1 && addr < 237846) {
    // Generate challenge key with index
    FTL_Read(237849, buffer); // the first int (4 bytes) of this will be the index.
    int len = KEY_SIZE;
    uint8_t *temp = buffer;
    hmac_sha1(tempKey, KEY_SIZE, temp, sizeof(uint8_t), ckwi, &len); // !THIS ONLY SUPPORTS UP TO 256 PAGES CURRENTLY!
    //uart_printf("Page CKWI key generated: ");
    //for(int i = 0; i < KEY_SIZE; i++) {
    //  uart_printf("%x", ckwi[i]);
   // }
   // uart_printf("\n");

  }
  
  LOG_BLOCK block;
  PAGE_OFF page; 
  STATUS ret;

  ret = PMT_Search(addr, &block, &page);
  //uart_printf("Addr %d ; Block %d ; Page %d \n", addr, block, page);
  if (ret == STATUS_SUCCESS) {
    ret = UBI_Read(block, page, buffer, NULL);
  }
  // Jdafoe
  
  // Encrypt the data.
  if(read_state == 2 && addr < 237846) {
    uint8_t *temp = buffer;
    EncryptData((UINT32 *)tempKey, temp + (512 * page_inx), 512);
    read_state = 0;
   // uart_printf("The Encrypted data are:\n");
  //  for(int i = 0; i < 512; i++) {
   //   uart_printf("%x", temp[i + (512 * page_inx)]);
  //  }
  //  uart_printf("\n");
    
 //   uart_printf("Got page, and encrypted!\n");
  }

  if(read_state == 1 && addr < 237846/*&& buf_ptr[0] == 'M' && buf_ptr[1] == 'A' && buf_ptr[2] == 'G' && buf_ptr[3] == '2' && buf_ptr[4] == '3'*/ ) {
    // Generate key with HMAC-sha1 from github Akagi201/hmac-sha1, using challenge key, and file page number
    // Next, encrypt first 128 bits using AES (provided by Niusen) 
      // Note this should be random 16 bytes, determined by challenge key maybe? or a new key?
  //  uart_printf("Get Page. Encrypting first 16 bytes\n"); 
      
    uint8_t *temp = buffer;
    
    
    EncryptData((UINT32 *)ckwi, temp + (512 * page_inx), KEY_SIZE);
    
    //uart_printf("The Encrypted data are:\n");
    //for(int i = 0; i < 512; i++) {
    //  uart_printf("%x", temp[i + (512 * page_inx)]);
   // }
   // uart_printf("\n");
    
   // uart_printf("Got page, and encrypted!\n");
   // uart_printf("%d\n", page_inx);
    read_state = 0;
   // uart_printf("-------------------------------------------------------\n");
  }
  // end Jdafoe
  
  return ret;
}

STATUS FTL_Trim(PGADDR start, PGADDR end) {
  PGADDR addr;
  STATUS ret = STATUS_SUCCESS;

  for (addr = start; addr <= end; addr++) {
    ret = FTL_Write(addr, NULL);
    if (ret != STATUS_SUCCESS) {
      break;
    }
  }

  return ret;
}

STATUS FTL_SetWP(PGADDR laddr, BOOL enabled) {
  return STATUS_FAILURE;
}

BOOL FTL_CheckWP(PGADDR laddr) {
  return FALSE;
}

STATUS FTL_BgTasks() {
  return STATUS_SUCCESS;
}

PGADDR FTL_Capacity() {
  LOG_BLOCK block;

  block = UBI_Capacity;//3989
  block -= JOURNAL_BLOCK_COUNT; /* data hot journal *///1
  block -= JOURNAL_BLOCK_COUNT; /* data cold journal *///1
  block -= JOURNAL_BLOCK_COUNT; /* data reclaim journal *///1
  block -= PMT_BLOCK_COUNT; /* pmt blocks *///40
  block -= 2; /* bdt blocks */
  block -= 2; /* root blocks */
  block -= 2; /* hdi reserved */
  block -= block / 100 * OVER_PROVISION_RATE; /* over provision */
  
  uart_printf("%s: UBI_Capacity=%d\r\n",__func__,UBI_Capacity);
  uart_printf("%s: actual user capacity: block=%d\r\n",__func__,block);//3823

  /* last page in every block is reserved for meta data collection */
  return block * (PAGE_PER_PHY_BLOCK - 1);//471
}

STATUS FTL_Flush() {
  STATUS ret;

  ret = DATA_Commit();
  if (ret == STATUS_SUCCESS) {
    ret = UBI_Flush();
  }

  if (ret == STATUS_SUCCESS) {
    ret = UBI_SWL();
  }

  return ret;
}
