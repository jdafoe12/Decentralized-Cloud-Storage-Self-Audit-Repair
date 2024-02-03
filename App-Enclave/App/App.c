/*
 * Application side function for interaction between the trusted application running in an Enclave,
 * and the server which interacts directly with the storage device.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

#include "sgx_urts.h"
#include "sharedTypes.h"
#include "Enclave_u.h"
#include "ccom.h"
#include <time.h>

#include <string.h>

//static long double waitTime = 0;

void ocall_get_time(uint64_t *outTime) {
    struct timespec currentTime;
    clock_gettime(CLOCK_MONOTONIC, &currentTime);
    *outTime = (uint64_t)currentTime.tv_nsec; // Cast to uint64_t to match the type
}

void ocall_send_parity(int startPage, uint8_t *parityData, size_t size)
{
    send_data_to_server("send_parity", 12);
	send_data_to_server(&size, sizeof(size_t));
	send_data_to_server(&startPage, sizeof(int));
    send_data_to_server(parityData, sizeof(uint8_t) * size);
    //usleep(10000000);
   // waitTime += (100000 * 4);
   // waitTime +=  10000000;
}

void ocall_init_parity(int numBits) 
{
	send_data_to_server("state_2", 8);
	send_data_to_server(&numBits, sizeof(int)); // TODO: write response on server side in VM.
}

void ocall_write_partition(int numBits)
{
    send_data_to_server("write_partition", 16);
    send_data_to_server(&numBits, sizeof(int));
   // waitTime += (100000 * 2);
}

void ocall_write_page(int pageNum, uint8_t *pageData) 
{
    send_data_to_server("write_page", 11);
    send_data_to_server(&pageNum, sizeof(int));
    send_data_to_server(pageData, sizeof(uint8_t) * PAGE_SIZE);
    //waitTime += (100000 * 3);
}

void ocall_end_genPar() 
{
	send_data_to_server("end_genPar", 11);
   // waitTime += (100000 * 1);
}



/*
 * Sends the public challenge number to the server, which passes it to the storage device.
 * Simply establish a connection and send the number.
 *
 * No returns
 */
void ocall_send_nonce(uint8_t *nonce) 
{


	/* Call server function get_nonce*/
	send_data_to_server("get_nonce", 12); // TODO: Change this on server side to nonce.

	/* Send nonce to server */
	send_data_to_server(nonce, sizeof(uint8_t) * KEY_SIZE);
  //  waitTime += (100000 * 2);
}

void ocall_get_segment(const char *fileName, int segNum, uint8_t *segData, int type) //TODO: make it clear when pages vs segments need to be read.
{

    /* Call server function get_segment */
    send_data_to_server("get_segment", 11);

    /* Send fileName to server*/
    send_data_to_server(fileName, strlen(fileName));

    /* Send segNum to server*/
    send_data_to_server(&segNum, sizeof(int));

    send_data_to_server(&type, sizeof(int));

    /* Recieve segData from server */
    uint8_t *temp = malloc(SEGMENT_SIZE);
    temp = (uint8_t *) receive_data_from_server(SEGMENT_SIZE);
    //waitTime += (100000 * 5);
    //send_data_to_server("ack", 4);

    // printf("Segment %d received\n", segNum);
    // printf("Segment data: ");
    // for(int i = 0; i < SEGMENT_SIZE; i++) {
    //     printf("%X", temp[i]);
    // }

    if (temp != NULL) {
        memcpy(segData, temp, SEGMENT_SIZE);
        free(temp);
    } else {
        // handle error
    }

    //printf("segment data: ");
}

/*
 * Gets the data from the referenced block, in the specified file.
 *
 * Implicit return : Populate uint8_t data with the data from the requested block in the specified file.
 */
void ocall_get_block(uint8_t *data, size_t segSize, int segPerBlock, int blockNum, char *fileName) 
{

    // Open the necessary file for reading
    int fd = open(fileName, O_RDONLY);
    if (fd < 0) {
        printf("Error: cannot open file %s\n", fileName);
        exit(1);
    }

    // Go to block offset
    off_t offset = blockNum * (off_t) segSize * segPerBlock;
    if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
        printf("Error: cannot seek to offset %lld in file %s\n", (long long) offset, fileName);
        close(fd);
        exit(1);
    }

    // Read data into buffer
    uint8_t buffer[segSize * segPerBlock];
    ssize_t bytesRead = read(fd, buffer, segSize * segPerBlock);
    if (bytesRead < 0) {
        printf("Error: cannot read file %s\n", fileName);
        close(fd);
        exit(1);
    }
    close(fd);

    // Copy buffer into data arr

    memcpy(data, buffer, segSize * segPerBlock);

}


/*
 * Send the sgx public ecc key to the storage device at address 951388. 
 * The storage device will use this for generating the shared ecc Diffie-Hellman key
 * and write its public ecc key to address 951388 (in reserved area).
 * We can then read from this location to pass the storage device public key into SGX,
 * which can be used to generate the shared Diffie-Hellman key in SGX.
 *
 * Implicit return : Populates ftl_pubkey with the storage device public ecc key.
 */
void ocall_ftl_init(uint8_t *sgx_pubKey, uint8_t *ftl_pubKey) 
{
    /* Call server function ftl_init */
    send_data_to_server("ftl_init", 8);

    /* Provide input to ftl_init */

    send_data_to_server(ftl_pubKey, 64); /* Send FTL public key to server */

    /* Recieve the output of ftl_init */
    ftl_pubKey = (uint8_t *)receive_data_from_server(64);

}

/* Used for debugging purposes, to print a value within the enclave */
void ocall_printf(unsigned char *buffer, size_t size, int type) 
{
	if(type == 1) {
		for(int i = 0; i < (int)size; i++) {
			printf("%X", buffer[i]);
		}
		printf("\n");
	}
	else if(type == 2) {
		for(int i = 0; i < (int)size; i++) {
			printf("%d%",buffer[i]);
		}
		printf("\n");
	}
	else if (type == 0) {
		for(int i = 0; i < (int)size; i++) {
			printf("%c", buffer[i]);
		}
		printf("\n");
	}
	

}

void ocall_printint(int *buffer) 
{

	printf("%d\n",*buffer);

	

}



/*  
 * Perform the initialization steps for a file. Generates all data necessary to perform file integrity auditing.
 *
 * Implicit returns : Writes the file and POR data to the storage device. Calls ecall_file_init,
 * Which initializes many values in the enclave.
 */
void app_file_init(sgx_enclave_id_t eid, const char *fileName,  int numBlocks) 
{

    sgx_status_t status;

	/* Check input values */
    if (fileName == NULL) {
        printf("Error: filename is NULL\n");
        return;
    }

    if (numBlocks <= 0) {
        printf("Error: numBlocks must be positive\n");
        return;
    }

	Tag *tag = malloc(sizeof(Tag));

	// Allocate memory for sigma
	uint8_t **sigma = malloc(numBlocks * sizeof(uint8_t *));
	uint8_t *sigma_mem = malloc(numBlocks * (PRIME_LENGTH / 8) * sizeof(uint8_t));
	for (int i = 0; i < numBlocks; i++) {
    	sigma[i] = sigma_mem + i * (PRIME_LENGTH / 8);
    	memset(sigma[i], 0, (PRIME_LENGTH / 8) * sizeof(uint8_t)); /* Initialize all sigma to 0 */
	}

    /* Call ecall_file_init to initialize tag and sigma */

	//printf("call ecall\n");
	int fileNum = 0;
    status = ecall_file_init(eid, &fileNum, fileName, tag, *sigma, numBlocks); // make sure the change to returning fileNum works properly.
    if (status != SGX_SUCCESS) {
        printf("Error calling enclave function: %d\n", status);
        return;
    }


    /* Open the file for reading */
    FILE *file = fopen(fileName, "rb");
    if (!file) {
        fprintf(stderr, "Error: failed to open file %s\n", fileName);
        return;
    }

    /* 
	 * Now, store the data back in FTL. Since no filesystem, we need to know start and end location of each file. This will be managed on FTL server side.
     * Store file in FTL as ( block1 || ... || blockN || sigma1 || ... || sigmaN || Tag ).
     * Send file name, numBlocks, then full data stream in order to server. (Open file, send blocks one at a time, send sigmas one at a time, send tag).
	 */

    /* Allocate buffer to recieve block data */
    uint8_t blockData[BLOCK_SIZE];
	int client_fd;


	/* Call file initialization function on server */

    send_data_to_server("file_init", 9);


    send_data_to_server(fileName, strlen(fileName)); /* Send file Name */

    send_data_to_server(&numBlocks, sizeof(int)); /* Send file number */


    /* Send each block data to the server */
    for (int i = 0; i < numBlocks; i++) {
        /* Read the i-th block from the file into blockData */
        if (fread(blockData, BLOCK_SIZE, 1, file) != 1) {
            fprintf(stderr, "Error: failed to read block %d from file %s\n", i, fileName);
            fclose(file);
            close(client_fd);
            return;
        }

        /* Send the i-th block to the server */
 for (int j = 0; j < 8; j++) {
        client_fd = create_client_socket();
        connect_to_server(client_fd);

        int out = write(client_fd, blockData + (j * SEGMENT_SIZE), SEGMENT_SIZE);
        if (out < 0) {
            perror("Write error");
            exit(EXIT_FAILURE);
        }
        //printf("Segment %d sent\n", j);

        // Wait for acknowledgment from server
        char ack[4];
        read(client_fd, ack, sizeof(ack));

        close(client_fd);
    }
	//	printf("Sent block %d\n", i);
    }
	/* All blocks sent to server */


    /* Send each sigma to the server */
for (int i = 0; i < numBlocks; i++) {
    client_fd = create_client_socket();
    connect_to_server(client_fd);

    write(client_fd, sigma[i], PRIME_LENGTH / 8);

    // Wait for acknowledgment from server
    char ack[4];
    read(client_fd, ack, sizeof(ack));

    close(client_fd);
}

	/* All sigma sent to server */

    /* Send the tag to the server */

    send_data_to_server(tag, sizeof(Tag));

    fclose(file);
	/* server function file_init has now completed execution, it does not require any more data */
	printf("generate parity!\n");
    ecall_generate_file_parity(eid, fileNum); // Note: The convention for this call is slightly different than the rest of the file initialization.
                                         // Above, the gennerated data is directly retrurned, rather than written via an ocall, as is done here.
}





int main(void) 
{

    sgx_enclave_id_t eid;
    sgx_status_t ret;

    // Initialize the Intel SGX runtime
    ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Error creating enclave: %d\n", ret);
        return 1;
    }

    // Call Enclave initialization function.
    //int result;


    printf("Call FTL init\n");
    ret = ecall_init(eid);
    

    if (ret != SGX_SUCCESS) {
        printf("Error calling enclave function: %d\n", ret);
        return 1;
    }

    // Data for initialization provided by local file at the filePath of fileName
    char fileName[512];
    strcpy(fileName, "/home/jdafoe/Decentralized-Cloud-Storage-Self-Audit-Repair/App-Enclave/testFile");
    int numBlocks = FILE_SIZE;

    // Perform file initialization in SGX

    printf("Call file init\n");

    app_file_init(eid, fileName, numBlocks);


    int status = 1;

    printf("Call audit file\n");

    ecall_audit_file(eid, fileName, &status);


    printf("Press enter to repair <enter>\n");
    getchar();

    printf("Call decode partition\n");

    ecall_decode_partition(eid, fileName, 3);


    if(status == 0) {
        printf("SUCCESS!!!\n");
    }

    // Destroy the enclave
    ret = sgx_destroy_enclave(eid);
    if (ret != SGX_SUCCESS) {
        printf("Error destroying enclave: %d\n", ret);
        return 1;
    }

    return 0;
}
