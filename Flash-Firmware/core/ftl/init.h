//jdafoe

#ifndef INIT_H
#define INIT_H

#include <stdint.h> 

int gen_ecc_keypair(uint8_t *dh_pubKey, uint8_t *dh_privKey);

int gen_shared_key(uint8_t *dh_privKey, uint8_t *sgx_pubKey, uint8_t *dh_sharedKey);


#endif

// end jdafoe
