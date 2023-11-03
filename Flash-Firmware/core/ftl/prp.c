#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "math.h"

#include "aes.h"

void generate_round_key(const uint8_t *key, int round_num, uint8_t *round_key)
{
    // Generate a unique round key based on the key and the round number
    memcpy(round_key, key, 16);
    round_key[15] ^= round_num;
}




uint64_t round_function(uint64_t data, uint8_t *key)
{
    AesCtx ctx;
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];

    memcpy(plaintext + 8, &data, 8);

    if (AesCtxIni(&ctx, NULL, key, KEY128, EBC) < 0)
    {
        printf("init error\n");
        exit(1);
    }

    if (AesEncrypt(&ctx, plaintext, ciphertext, sizeof(plaintext)) < 0)
    {
        printf("error in encryption\n");
        exit(1);
    }

    uint64_t result = *((uint64_t *)(ciphertext + 8)) & 0xFFFFFFFFFFFFFFFF;
    return result;
}

uint64_t feistel_network_prp(const uint8_t *key, uint64_t input_block, int num_bits)
{
    // Perform a fixed number of rounds (e.g., 4 rounds)
	if(num_bits == 0) {
		return 0;
	}
    int num_rounds = 4;
    int round_num;
    for (round_num = 0; round_num < num_rounds; round_num++)
    {
        // Compute the round key based on the current round number
        uint8_t round_key[16];
        generate_round_key(key, round_num, round_key);

        // Extract the right half of the input
        uint64_t right_half = input_block & ((1ULL << (num_bits / 2)) - 1);

        // Apply the Feistel round function
        uint64_t f_result = round_function(right_half, round_key);

        // XOR the result of the round function with the left half
        input_block ^= (f_result << (num_bits / 2));
    }

    // Return the result
    return input_block << (64 - num_bits) >> (64 - num_bits);
}

