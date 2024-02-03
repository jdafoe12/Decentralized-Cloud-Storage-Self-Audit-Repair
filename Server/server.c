/*
 *
 *
 *
 *
 */

#define _GNU_SOURCE
#define PATH "/dev/sdc"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>

#include "scom.h"
#include "defs.h"
#include <time.h>

void send_ack(int client_fd) {
 char ack[] = "ACK";
 write(client_fd, ack, sizeof(ack));
}

void ftl_initial(uint8_t *sgx_pubKey, uint8_t *ftl_pubKey) 
{

 int fd; 
 if((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 // Write SGX public key to device
 off_t offset = 951388 * 512;
 void *buf;
 if(posix_memalign(&buf, 512, 64) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 memcpy(buf, sgx_pubKey, 64);
 if (pwrite(fd, buf, 512, offset) == -1) {
 perror("[pwrite]");
 free(buf);
 close(fd);
 return 1;
 }

 fdatasync(fd);

 // Read FTL public key from device
 if(lseek(fd, offset, SEEK_SET) == -1) {
 perror("[lseek]");
 close(fd);
 return;
 }

 if(read(fd, buf, 512) == -1) {
 perror("[read]");
 close(fd);
 return;
 }

 fsync(fd);

 memcpy(ftl_pubKey, buf, 64);

 close(fd);
 return;
}

void get_challnum(int server_fd) 
{

 int client_fd;
 uint8_t challnum[KEY_SIZE];

 client_fd = accept_connection(server_fd);
 read(client_fd, challnum, KEY_SIZE);
 send_ack(client_fd);
 close(client_fd);
 // for(int i = 0; i < KEY_SIZE; i++) {
 // printf("%X", challnum[i]);
 // }
 // printf("\n");

 int fd; 
 if((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 // Write challenge number to device
 off_t offset = 951392 * 512;
 void *buf;
 if(posix_memalign(&buf, 512, KEY_SIZE) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }


 memcpy(buf, challnum, KEY_SIZE);
 if (pwrite(fd, buf, 512, offset) == -1) { 
 perror("[pwrite]");
 free(buf);
 close(fd);
 return -1;
 }

 fdatasync(fd);


}

void get_segment(int server_fd) 
{
usleep(200000);
 int client_fd;
 uint8_t segData[SEGMENT_SIZE];
 uint8_t buffer[BUFFER_SIZE];

 /* Recieve fileName */
 client_fd = accept_connection(server_fd);
 int fileNameLen = read(client_fd, buffer, FILE_NAME_LEN);
 send_ack(client_fd);
 close(client_fd);

 char fileName[fileNameLen+1];
 strncpy(fileName, buffer, fileNameLen);
 fileName[fileNameLen] = '\0';

 /* Recieve segNum */
 int segNum;
 client_fd = accept_connection(server_fd);
 read(client_fd, &segNum, sizeof(int));
 send_ack(client_fd);
 close(client_fd);
 //printf("Segment number recieved: %d\n", segNum);
 /* Open device */
 int fd;
 if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 off_t offset = segNum * SEGMENT_SIZE; /* Segment offset */
 void *buf;
 if (posix_memalign(&buf, SEGMENT_SIZE, SEGMENT_SIZE) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 int type;
 client_fd = accept_connection(server_fd);
 read(client_fd, &type, sizeof(int));
 send_ack(client_fd);
 close(client_fd);

 if(type == 0) {
 /* Write segNum to address 951396 */ // TODO: THIS BAD. ONLY DO THIS DURING AUDIT and parity generation.
 if (lseek(fd, 951396 * SEGMENT_SIZE, SEEK_SET) == -1) {
 perror("[lseek]");
 close(fd);
 return;
 }
 
//printf("segNum: %d\n", segNum);
 memcpy(buf, &segNum, sizeof(segNum));
 if (write(fd, buf, SEGMENT_SIZE) == -1) {
 perror("[write]");
 close(fd);
 return;
 }

 fsync(fd);
 }




 if (pread(fd, buf, SEGMENT_SIZE, offset) == -1) { 
 perror("[pread]");
 free(buf);
 close(fd);
 return -1;
 }

 fsync(fd);
 close(fd);
 

 memcpy(segData, buf, SEGMENT_SIZE);

 // printf("Segment data encrypted??\n");
 // for(int i = 0; i < SEGMENT_SIZE; i++) {
 // printf("%x", segData[i]);
 // }
 // printf("\n");



 /* Send data at segNum */
 client_fd = accept_connection(server_fd);
 size_t total_sent = 0;
 while (total_sent < SEGMENT_SIZE) {
 size_t sent = write(client_fd, segData + total_sent, SEGMENT_SIZE - total_sent);
 if (sent == -1) {
 // handle error
 break;
 }
 total_sent += sent;
 }
 char ack[4];
 read(client_fd, ack, 4);
 close(client_fd);

}

void file_init(int server_fd) 
{
 int client_fd;
 uint8_t buffer[8192];
 


 // Open storage device. ASSUME 1 File for now
 int fd; 
 if((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) { // For now do not do O_DIRECT. This is not in reserved area. A simple write
 perror("[open]");
 return;
 }

void *buf;
 if (posix_memalign(&buf, SEGMENT_SIZE, BLOCK_SIZE) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }
 
 // Receive file name
 client_fd = accept_connection(server_fd);
 int fileNameLen = read(client_fd, buffer, FILE_NAME_LEN);
 send_ack(client_fd);
 close(client_fd);

 char fileName[fileNameLen+1];
 strncpy(fileName, buffer, fileNameLen);
 fileName[fileNameLen] = '\0';

 printf("File name: %s\n", fileName);

 // Receive number of blocks
 int numParityBlocks;

 client_fd = accept_connection(server_fd);
 read(client_fd, &numParityBlocks, sizeof(numParityBlocks));
 send_ack(client_fd);
 close(client_fd);
 printf("Number of blocks: %d\n", numParityBlocks);


 // Receive each block
 uint8_t blockData[BLOCK_SIZE];
 for (int i = 0; i < numParityBlocks; i++) {


 for (int j = 0; j < 8; j++) {
 client_fd = accept_connection(server_fd);
 ssize_t total_read = 0;
 ssize_t bytes_read;
 char* buffer_ptr = blockData + (SEGMENT_SIZE * j);

 while (total_read < SEGMENT_SIZE) {
 bytes_read = read(client_fd, buffer_ptr + total_read, SEGMENT_SIZE - total_read);
 if (bytes_read <= 0) {
 if (bytes_read == 0) {
 printf("Client disconnected, segment %d partially received\n", j);
 } else {
 perror("Read error");
 }
 close(client_fd);
 exit(EXIT_FAILURE); // Or handle the error as appropriate
 }
 total_read += bytes_read;
 }
 printf("Segment %d received successfully\n", j);

 // Send acknowledgment to client
 send_ack(client_fd);

 close(client_fd);
 }


 
 printf("Block %d received successfully\n", i);

 // Write block to storage device 
 memset(buf, 0, BLOCK_SIZE);
 memcpy(buf, blockData, BLOCK_SIZE); // not sure this is right
 if(write(fd, buf, BLOCK_SIZE) == -1) {
 perror("[write]");
 close(fd);
 return;
 }
 
 }

printf("Blocks written successfully\n");

 // Receive each sigma
 uint8_t sigma[numParityBlocks][PRIME_LENGTH / 8];
 const int bytesPerSeg = 512;
 const int sigPerSeg = (bytesPerSeg) / (PRIME_LENGTH / 8);
 int sigCount = 0;
for (int i = 0; i < numParityBlocks; i++) {
 client_fd = accept_connection(server_fd);

 ssize_t total_read = 0;
 ssize_t bytes_read;
 while (total_read < PRIME_LENGTH / 8) {
 bytes_read = read(client_fd, sigma[i] + total_read, (PRIME_LENGTH / 8) - total_read);
 if (bytes_read <= 0) {
 if (bytes_read == 0) {
 printf("Client disconnected before sending complete data\n");
 } else {
 perror("failed to read sigma");
 }
 close(client_fd);
 exit(EXIT_FAILURE); // Or handle the error as appropriate
 }
 total_read += bytes_read;
 }

 // Send acknowledgment to client
 send_ack(client_fd);
 printf("Sigma %d received successfully\n", i);

 close(client_fd);
 sigCount++;
}


for(int i = 0; i < ceil((double) sigCount / sigPerSeg); i++) {
int sigIndex = 0;

memset(buf, 0, SEGMENT_SIZE);
while (sigIndex < sigCount) {
// Load sigmas into buf
for (int i = 0; i < sigPerSeg; i++) {
 if (sigIndex >= sigCount) {
 break;
 }
 
 memcpy(buf + (i * (PRIME_LENGTH / 8)), sigma[sigIndex], PRIME_LENGTH / 8);
 sigIndex++;
}

// Write segment from buf
//printf("Writing segment %d\n", i);
if (write(fd, buf, bytesPerSeg) == -1) {
 perror("[write]");
 close(fd);
 return;
}
fdatasync(fd);
//printf("Done writing segment %d\n", i);

}


}

 // Receive the tag
 Tag tag;
 
 client_fd = accept_connection(server_fd);

 if (read(client_fd, &tag, sizeof(Tag)) != sizeof(Tag)) {
 perror("failed to read tag");
 exit(EXIT_FAILURE);
 }
 send_ack(client_fd);
 close(client_fd);
 printf("Tag received successfully\n");
 printf("tag size: %d\n", sizeof(Tag));
 memset(buf, 0, BLOCK_SIZE);

 memcpy(buf, &tag, sizeof(Tag));

 for(int i = 0; i < sizeof(Tag); i++) {
 uint8_t *byte = buf;
 printf("%X", byte[i]);
 }
 printf("\n");
 printf("\n");

for(int i = 0; i < SEGMENT_PER_BLOCK; i ++) {
 for(int j = 0; j < PRIME_LENGTH / 8; j++)
 printf("%X", tag.alpha[i][j]);
}
 //printf("Tag copied to buffer\n");
 // Write tag to storage device.

 if (write(fd, buf, SEGMENT_SIZE) == -1) {
 perror("[write]");
 close(fd);
 return;
 }
 //printf("Tag written successfully\n");
 fdatasync(fd);

 return 0;
}

void ftl_init(int server_fd) 
{
 int client_fd;
 uint8_t sgx_pubKey[64] = {0};
 uint8_t *ftl_pubKey = malloc(sizeof(uint8_t) * 64);
 
 /* Read SGX public key from server*/
 client_fd = accept_connection(server_fd);
 read(client_fd, sgx_pubKey, sizeof(uint8_t) * 64);
 send_ack(client_fd);
 close(client_fd);


 /* Send SGX public key to FTL, and recieve FTL public key */
 ftl_initial(sgx_pubKey, ftl_pubKey);

 client_fd = accept_connection(server_fd);
 write(client_fd, ftl_pubKey, sizeof(uint8_t) * 64);
 uint8_t ack[4];
 read(client_fd, ack, 4);
 close(client_fd);


 free(ftl_pubKey);
}

void state_2(int server_fd) 
{
 int client_fd;

 int numBits = 0;

 client_fd = accept_connection(server_fd);
 int len = read(client_fd, &numBits, sizeof(int));
 send_ack(client_fd);
 close(client_fd);

 int fd;
 if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 off_t offset = 951400 * SEGMENT_SIZE; /* Segment offset */
 void *buf;
 if (posix_memalign(&buf, SEGMENT_SIZE, SEGMENT_SIZE) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 /* Write segNum to address 951396 */
 if (lseek(fd, 951400 * SEGMENT_SIZE, SEEK_SET) == -1) {
 perror("[lseek]");
 close(fd);
 return;
 }

 memcpy(buf, &numBits, sizeof(numBits));
 if (write(fd, buf, SEGMENT_SIZE) == -1) {
 perror("[write]");
 close(fd);
 return;
 }
 

}

void receive_parity(int server_fd) {
 //printf("here?\n");

 // Open storage device. ASSUME 1 File for now
 int fd;
 if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 // Receive size
 size_t size = 0;
 int client_fd = accept_connection(server_fd);
 if (read(client_fd, &size, sizeof(size)) != sizeof(size)) {
 perror("[read size]");
 close(client_fd);
 close(fd);
 return;
 }
 send_ack(client_fd);
 close(client_fd);

 // Align buffer to 2048 bytes
 uint8_t *buffer;
 if (posix_memalign((void **)&buffer, 2048, size) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 // Receive startPage
 int startPage = 0;
 client_fd = accept_connection(server_fd);
 if (read(client_fd, &startPage, sizeof(startPage)) != sizeof(startPage)) {
 perror("[read startPage]");
 free(buffer);
 close(client_fd);
 close(fd);
 return;
 }
 send_ack(client_fd);
 close(client_fd);

 //printf("start page: %d\n", startPage);
 //printf("size: %zu\n", size);

 // Receive page into buffer
 client_fd = accept_connection(server_fd);
 int bytes_received = 0;
 while (bytes_received < size) {
 int bytes_read = read(client_fd, buffer + bytes_received, size - bytes_received);
 if (bytes_read <= 0) {
 perror("[read page]");
 free(buffer);
 close(client_fd);
 close(fd);
 return;
 }
 bytes_received += bytes_read;
 }
 send_ack(client_fd);
 close(client_fd);

 if (lseek(fd, (startPage) * 2048, SEEK_SET) == -1) {
 perror("[lseek]");
 free(buffer);
 close(fd);
 return;
 }

 if (write(fd, buffer, 2048) == -1) {
 perror("[write]");
 free(buffer);
 close(fd);
 return;
 }
 fdatasync(fd);

 if (lseek(fd, (startPage) * 2048, SEEK_SET) == -1) {
 perror("[lseek]");
 free(buffer);
 close(fd);
 return;
 }

 // Loop for writing the data in segments
 
 for (int i = 0; i < (size / 4096) - 1; i++) {
 for (int j = 0; j < 2; j++) {
 //usleep(1000000);
 size_t offset = 4096 + (4096 * i) + (2048 * j);
 if (offset + 2048 <= size) {
 if (write(fd, buffer + offset, 2048) == -1) {
 perror("[write]");
 free(buffer);
 close(fd);
 return;
 }
 fdatasync(fd);
 }
 }
 }

 free(buffer);
 close(fd);
}

void end_genPar(int server_fd) {
 int client_fd;

 int fd;
 if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 off_t offset = 951384 * SEGMENT_SIZE; /* Segment offset */
 void *buf;
 if (posix_memalign(&buf, SEGMENT_SIZE, SEGMENT_SIZE) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 /* Write segNum to address 951396 */
 if (lseek(fd, offset, SEEK_SET) == -1) {
 perror("[lseek]");
 close(fd);
 return;
 }
 int temp = 0;
 memcpy(buf, &temp, sizeof(temp));
 if (write(fd, buf, SEGMENT_SIZE) == -1) {
 perror("[write]");
 close(fd);
 return;
 }
 fdatasync(fd);
 
}

void write_partition(int server_fd) {
 int client_fd;

 int numBits = 0;

 client_fd = accept_connection(server_fd);
 int len = read(client_fd, &numBits, sizeof(int));
 send_ack(client_fd);
 close(client_fd);

 int fd;
 if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 off_t offset = 951384 * SEGMENT_SIZE; /* Segment offset */
 void *buf;
 if (posix_memalign(&buf, SEGMENT_SIZE, SEGMENT_SIZE) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 /* Write segNum to address 951396 */
 if (lseek(fd, 951384 * SEGMENT_SIZE, SEEK_SET) == -1) {
 perror("[lseek]");
 close(fd);
 return;
 }

 memcpy(buf, &numBits, sizeof(numBits));
 if (write(fd, buf, SEGMENT_SIZE) == -1) {
 perror("[write]");
 close(fd);
 return;
 }
 fdatasync(fd);

}

void write_page(int server_fd) {
 int fd;
 if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 // Align buffer to 2048 bytes
 uint8_t *buffer;
 if (posix_memalign((void **)&buffer, 2048, 2048) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 // Receive startPage
 int pageNum = 0;
 int client_fd = accept_connection(server_fd);
 if (read(client_fd, &pageNum, sizeof(pageNum)) != sizeof(pageNum)) {
 perror("[read startPage]");
 free(buffer);
 close(client_fd);
 close(fd);
 return;
 }
 send_ack(client_fd);
 close(client_fd);

 //printf("start page: %d\n", startPage);
 //printf("size: %zu\n", size);

 // Receive page into buffer
 client_fd = accept_connection(server_fd);
 int bytes_received = 0;
 while (bytes_received < 2048) {
 int bytes_read = read(client_fd, buffer + bytes_received, 2048 - bytes_received);
 if (bytes_read <= 0) {
 perror("[read page]");
 free(buffer);
 close(client_fd);
 close(fd);
 return;
 }
 bytes_received += bytes_read;
 }
 send_ack(client_fd);
 close(client_fd);

 if (lseek(fd, (pageNum) * 2048, SEEK_SET) == -1) {
 perror("[lseek]");
 free(buffer);
 close(fd);
 return;
 }

 if (write(fd, buffer, 2048) == -1) {
 perror("[write]");
 free(buffer);
 close(fd);
 return;
 }
 fdatasync(fd);

}


main() 
{
 int server_fd, client_fd;
 server_fd = create_socket();
 uint8_t buffer[BUFFER_SIZE];

 while(1) {
 client_fd = accept_connection(server_fd);
 int stringLen = read(client_fd, buffer, FILE_NAME_LEN);
 send_ack(client_fd);
 close(client_fd);
 char command[stringLen+1];
 strncpy(command, buffer, stringLen);
 command[stringLen] = '\0';

 if(strcmp(command, "ftl_init") == 0) {
 printf("ftl init\n");
 ftl_init(server_fd);
 }
 else if(strcmp(command, "file_init") == 0) {
 printf("file_init\n");
 file_init(server_fd);
 }
 else if(strcmp(command, "get_segment") == 0) {
 printf("get segment\n");
 get_segment(server_fd);
 }
 else if(strcmp(command, "get_nonce") == 0 ) {
 printf("get nonce\n");
 get_challnum(server_fd);
 }
 else if(strcmp(command, "send_parity") == 0 ) {
 printf("recieve_parity\n");
 receive_parity(server_fd);

 }
 else if(strcmp(command, "state_2") == 0) { // TODO: should be changed to writing a signed magic number.
 // State transitions need to be better defined in FTL, in general.
 printf("enter state 2\n");
 state_2(server_fd);
 }
 else if(strcmp(command, "end_genPar") == 0) {
 printf("end genpar\n");
 end_genPar(server_fd);
 }
 else if(strcmp(command, "write_partition") == 0) {
 printf("write_partition");
 write_partition(server_fd);
 }
 else if(strcmp(command, "write_page") == 0) {
 printf("write_page");
 write_page(server_fd);
 }
 else exit(1);
 }
}