#ifndef CPOR_H
#define CPOR_H

#include <stdint.h>
#include <openssl/bn.h>
#include "sharedTypes.h"
#include "enDefs.h"

void prepare_tag(Tag *tag, PorSK porSk);

void decrypt_tag(Tag *tag, PorSK porSk);

void gen_challenge(int totalSegments, uint8_t *indices, uint8_t *coefficients, uint8_t *prime);

//void getRandomByPRF(char* key, int length_key, unsigned char *i, int length_input, BIGNUM *p, BIGNUM *rand);
void generate_random_mod_p(char* prf_key, int key_len, unsigned char *i, int i_len, BIGNUM *p, BIGNUM *result);

// Initialization function. Generate secret key (encKey, macKey).
PorSK por_init(void);


// Prepare file, generate omega for each block, and file tag. (File is recieved via attestation connection with client)

// Generate prfKey, alpha[s].
void gen_file_tag(BIGNUM *prime, Tag *tag);

// Generate Omega for a single block.
//void get_sigma(BIGNUM *sigma, BIGNUM **data, BIGNUM **alpha, uint8_t blockNum, uint8_t *prfKey, BIGNUM *prime);



/*
 * Input: key - The key used in the PRP. 
 * 		  n - number of blocks
 *        k - Number of groups
 * Output: groups - a 2d array representing which blocks are in each group. groups[group][index]
 */
uint64_t** get_groups(const uint8_t *key, int n, int k);


#endif
