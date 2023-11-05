
#ifndef DEFS_H
#define DEFS_H

#define KEY_SIZE 16
#define MAC_SIZE 20

#define BLOCK_SIZE 4096
#define PAGE_SIZE 2048
#define SEGMENT_SIZE 512
#define PAGE_PER_BLOCK (BLOCK_SIZE / PAGE_SIZE)
#define SEGMENT_PER_BLOCK (BLOCK_SIZE / SEGMENT_SIZE)
#define FILE_NAME_LEN 512
#define PRIME_LENGTH 80

typedef struct Tag {
    int n;
    uint8_t prfKey[KEY_SIZE];
    uint8_t alpha[PRIME_LENGTH / 8][SEGMENT_PER_BLOCK];
    uint8_t MAC[MAC_SIZE];
} Tag;


#endif
