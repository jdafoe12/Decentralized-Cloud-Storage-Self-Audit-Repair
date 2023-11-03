#ifndef SHARED_TYPES_H
#define SHARED_TYPES_H


#define KEY_SIZE 16
#define MAC_SIZE 20
#define PRIME_LENGTH 80
#define BLOCK_SIZE 4096
#define PAGE_SIZE 512
#define PAGE_PER_BLOCK (BLOCK_SIZE / PAGE_SIZE)
#define SHA_DIGEST_LENGTH 20
#define FILE_NAME_LEN 512
#define MAX_FILES 10
#define NUM_CHAL_BLOCKS 5
#define NUM_ORIGINAL_SEGMENTS 2 
#define NUM_TOTAL_SEGMENTS 3


typedef struct Tag {
    int n;
    uint8_t prfKey[KEY_SIZE];
	uint8_t alpha[PAGE_PER_BLOCK][PRIME_LENGTH / 8];
	uint8_t MAC[MAC_SIZE];
} Tag;

#endif
