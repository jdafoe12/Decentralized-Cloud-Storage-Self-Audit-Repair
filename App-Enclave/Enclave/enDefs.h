#ifndef ENDEFS_H
#define ENDEFS_H
#include <stdint.h>
#include <openssl/bn.h>
#include "sharedTypes.h"



typedef struct PorSK {
	uint8_t encKey[KEY_SIZE];
	uint8_t macKey[MAC_SIZE];
	uint8_t sortKey[KEY_SIZE]; // Note if used for all files, the same block numbers in different files will be permuted the same.
} PorSK;

// n and k are the erasure code parameters for an (n, k) erasure code.
typedef struct File {
	int inUse;
	int numBlocks;
	int n;
	int k;
	char fileName[FILE_NAME_LEN];
	uint8_t prime[PRIME_LENGTH / 8];
} File;

extern File files[MAX_FILES];

extern PorSK porSK;

extern uint8_t dh_sharedKey[64];

#endif
