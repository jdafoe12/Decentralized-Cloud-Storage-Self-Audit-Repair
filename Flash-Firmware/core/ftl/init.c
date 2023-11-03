// jdafoe

#include "ecdh.h"
#include "init.h"
#include <stdint.h> 
#include <core\inc\cmn.h>
#include <core\inc\ftl.h>
#include <core\inc\ubi.h>
//#include <core\inc\mtd.h>
#include <sys\sys.h>
#include "ftl_inc.h"
#include <core\inc\buf.h>

/* pseudo random number generator with 128 bit internal state... probably not suited for cryptographical usage. Taken from github.com/kokke/tiny-ECDH-c */
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
/*End pseudo RNG */ 


int gen_ecc_keypair(uint8_t *dh_pubKey, uint8_t *dh_privKey) {
  
  // Generate random private key;
  static int initialized = 0;
  if(!initialized) {
    prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 777);
    initialized = 1;
  }
  for(int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    dh_privKey[i] = prng_next();
  }
  
  // Generate public key
  return ecdh_generate_keys(dh_pubKey, dh_privKey);
}

int gen_shared_dh_key(uint8_t *dh_privKey, uint8_t *sgx_pubKey, uint8_t *dh_sharedKey) {
  return ecdh_shared_secret(dh_privKey, sgx_pubKey, dh_sharedKey);
}

// end jdafoe

