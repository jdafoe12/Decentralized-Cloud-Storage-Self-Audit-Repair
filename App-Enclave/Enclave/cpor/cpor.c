
#include "cpor.h"
#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sharedTypes.h"
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/hmac.h>
#include "prp.h"

void generate_random_mod_p(char* prf_key, int key_len, unsigned char *i, int i_len, BIGNUM *p, BIGNUM *result) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    // Compute the PRF value
    HMAC(EVP_sha256(), prf_key, key_len, i, i_len, hash, &hash_len);
    // Convert the PRF value to a BIGNUM
    BIGNUM *bn_prf = BN_new();
    BN_bin2bn(hash, hash_len, bn_prf);

    // Compute the random number modulo p
    BN_CTX *ctx = BN_CTX_new();
    BN_mod(result, bn_prf, p, ctx);

    // Clean up memory
    BN_free(bn_prf);
}

void prepare_tag(Tag *tag, PorSK porSk) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // Define IV for testing purposes only
    const unsigned char iv[] = "0123456789abcdef";
    
    // Encrypt alpha using encKey
    int outlen;
    int len = (PAGE_PER_BLOCK * PRIME_LENGTH / 8) + KEY_SIZE;
    unsigned char *out = malloc(len + EVP_MAX_BLOCK_LENGTH);

    if (out == NULL) {
        // Handle memory allocation error
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, porSk.encKey, iv);
    EVP_EncryptUpdate(ctx, out, &outlen, tag->prfKey, len);
    EVP_EncryptFinal_ex(ctx, out + outlen, &outlen);
    memcpy(tag->prfKey, out, len);

    
    // Compute MAC using macKey
    ctx = EVP_CIPHER_CTX_new();
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha1();
    uint8_t *mac_data[3] = { (uint8_t*)&tag->n, tag->prfKey, (uint8_t*)tag->alpha };
    int mac_data_len[3] = { sizeof(tag->n), KEY_SIZE, (PRIME_LENGTH / 8) * PAGE_PER_BLOCK };
    uint8_t mac[MAC_SIZE];
    int mac_len;
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, porSk.macKey, MAC_SIZE);
    for (int i = 0; i < 3; i++) {
        EVP_DigestUpdate(md_ctx, mac_data[i], mac_data_len[i]);
    }
    EVP_DigestFinal_ex(md_ctx, mac, &mac_len);
    EVP_CIPHER_CTX_free(ctx);
    EVP_MD_CTX_free(md_ctx);

    memcpy(tag->MAC, mac, MAC_SIZE);
}


void decrypt_tag(Tag *tag, PorSK porSk) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const unsigned char iv[] = "0123456789abcdef";

    // Decrypt alpha using encKey
    int outlen;
    int len = (PAGE_PER_BLOCK * PRIME_LENGTH / 8) + KEY_SIZE;
    unsigned char *out = malloc(len + EVP_MAX_BLOCK_LENGTH);

    if (out == NULL) {
        // Handle memory allocation error
    }

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, porSk.encKey, iv);
    EVP_DecryptUpdate(ctx, out, &outlen, tag->prfKey, len);
    EVP_DecryptFinal_ex(ctx, out + outlen, &outlen);
    memcpy(tag->prfKey, out, len);

    EVP_CIPHER_CTX_free(ctx);
    free(out);
    //free(prfKey_out);
}


void gen_challenge(int totalPages, uint8_t *indices, uint8_t *coefficients, uint8_t *prime) {
    BIGNUM *bn_coefficient;
    BIGNUM *bn_prime = BN_bin2bn(prime, PRIME_LENGTH / 8, NULL);
    BN_CTX *ctx = BN_CTX_new();

    int i, j;
    for (i = 0; i < NUM_CHAL_BLOCKS; i++) {
        int bad = 1;
        while(bad == 1) {
            /* Generate a random index between 0 and totalPages - 1 */
            sgx_read_rand(&indices[i], sizeof(uint8_t));
            indices[i] = indices[i] % totalPages;

            /* Generate a random coefficient using OpenSSL BIGNUMs */
            bn_coefficient = BN_new();
            BN_rand_range(bn_coefficient, bn_prime);
            BN_bn2bin(bn_coefficient, coefficients + i * (PRIME_LENGTH / 8));
            BN_free(bn_coefficient);

            /* Check if the index has already been generated */
            bad = 0;
            for(j = 0 ; j < i; j++) {
                if(indices[j] == indices[i] || indices[i] < 1) {
                    bad = 1;
                    break;
                }
            }
        }
    }

    BN_free(bn_prime);
    BN_CTX_free(ctx);
}


PorSK por_init() {
	
	PorSK porSKL;

	if(sgx_read_rand(porSKL.encKey, KEY_SIZE) != SGX_SUCCESS) {
		// handle error
	}

	if(sgx_read_rand(porSKL.sortKey, KEY_SIZE) != SGX_SUCCESS) {
		// handle error
	}

	if(sgx_read_rand(porSKL.macKey, KEY_SIZE) != SGX_SUCCESS) {
		// handle error
	}

	return porSKL;
}

void gen_file_tag(BIGNUM *prime, Tag *tag) {

    // Generate prfKey
    if(sgx_read_rand(tag->prfKey, KEY_SIZE) != SGX_SUCCESS) {
        // handle error
    }


	BIGNUM *alpha_BN[PAGE_PER_BLOCK];

	for(int i = 0; i < PAGE_PER_BLOCK; i++) {
    	alpha_BN[i] = BN_new(); // Allocate memory for a new BIGNUM object

    	if(!BN_rand_range(alpha_BN[i], prime)) { // Will generate random number in range(0, prime - 1)
       		// handle error
    	}

    	BN_bn2bin(alpha_BN[i], tag->alpha[i]);
	}

    return tag;
}


/*
 * Input: key - The key used in the PRP. 
 * 		  n - number of blocks
 *        k - Number of groups
 * Output: groups - a 2d array representing which blocks are in each group. groups[group][index]
 */
uint64_t** get_groups(const uint8_t *key, int n, int k) {

    uint64_t **groups = malloc(k * sizeof(uint64_t*));
	
    for (int i = 0; i < k; i++) {
        groups[i] = malloc(ceil((double) n / k) * sizeof(uint64_t));
    }


	int groupCounters[k]; // Current index for each group
	for(int i = 0; i < k; i++) {
		groupCounters[i] = 0;
	}


	int iter = 0;
	int prevbits = 0;
	int groupNum = 0;
    while (n != 0) {
        int bits = (int)floor(log2(n));
        int temp = n - (int)pow(2, bits);
        for (int i = 0; i < (int)pow(2, bits); i++) {
            int index = feistel_network_prp(key, i, bits);

			if(iter == 0) {
				groupNum = index % k;

			}
			else {
				groupNum = (index + (int) pow(2, prevbits)) % k;
			}
            groups[groupNum][groupCounters[groupNum]] = i + temp + 1;
			groupCounters[groupNum]++;
        }

        n = temp;
		iter++;
		prevbits = bits;
    }

    return groups;
}



// void get_sigma(BIGNUM *sigma, BIGNUM **data, BIGNUM **alpha, uint8_t blockNum, uint8_t *prfKey, BIGNUM *prime) {

// 	BIGNUM *blockRand;
// 	BIGNUM *result;
// 	BIGNUM *sum;
// 	BN_CTX *ctx;

// //	BIGNUM *randAtI = BN_new();
// 	result = BN_new();
// 	sum = BN_new();
// 	ctx = BN_CTX_new();
// 	blockRand = BN_new();

// 	BN_zero(sum);

// 	generate_random_mod_p(prfKey, KEY_SIZE, &blockNum, sizeof(uint8_t), prime, blockRand);

// 	for(int i = 0; i < PAGE_PER_BLOCK; i++) {
// 		BN_mod_mul(result, data[i], alpha[i], prime, ctx);
// 		BN_mod_add(sum, sum, result, prime, ctx);
// 	}

// 	BN_mod_add(sigma, sum, blockRand, prime, ctx);

// 	return;
// }


