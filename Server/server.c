#define _GNU_SOURCE

#define PATH "/dev/sdb"
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

void ftl_initial(uint8_t *sgx_pubKey, uint8_t *ftl_pubKey) {

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

    //printf("start KS\n");
    //struct timeval start_time, end_time;
    //gettimeofday(&start_time, NULL);
    memcpy(buf, sgx_pubKey, 64);
    if (pwrite(fd, buf, 512, offset) == -1) {
        perror("[pwrite]");
        free(buf);
        close(fd);
        return 1;
    }

    fdatasync(fd);
    //printf("end KS\n");

    //gettimeofday(&end_time, NULL);
    //long int elapsed_time_KS_sec = end_time.tv_sec - start_time.tv_sec;
    //long int elapsed_time_KS_micro = end_time.tv_usec - start_time.tv_usec;
    //if (elapsed_time_KS_micro < 0) {
    //    elapsed_time_KS_micro += 1000000;
    //    elapsed_time_KS_sec--;
    //}
 //printf("Elapsed time: %ld.%06ld seconds\n", elapsed_time_KS_sec, elapsed_time_KS_micro);


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

    memcpy(ftl_pubKey, buf, 64);

    close(fd);
    return;
}

void get_challnum(int server_fd) {

    int client_fd;
    uint8_t challnum[KEY_SIZE];

    client_fd = accept_connection(server_fd);
    read(client_fd, challnum, KEY_SIZE);
    close(client_fd);
 //   for(int i = 0; i < KEY_SIZE; i++) {
   //     printf("%X", challnum[i]);
  //  }
   // printf("\n");

    int fd; 
    if((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
        perror("[open]");
        return;
    }

    // Write  challenge number to device
    off_t offset = 951392 * 512;
    void *buf;
    if(posix_memalign(&buf, 512, KEY_SIZE) != 0) {
        perror("[posix_memalign]");
        close(fd);
        return;
    }

    //struct timeval start, end;
    //gettimeofday(&start, NULL);
    memcpy(buf, challnum, KEY_SIZE);
    if (pwrite(fd, buf, 512, offset) == -1) { 
        perror("[pwrite]");
        free(buf);
        close(fd);
        return -1;
    }

    fsync(fd);

    //gettimeofday(&end, NULL);
    //long seconds = end.tv_sec - start.tv_sec;
    //long micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);

    //printf("Time elapsed Give challNum: %ld.%06ld seconds\n", seconds, micros);

}

void get_page(int server_fd) {

    int client_fd;
    uint8_t pageData[PAGE_SIZE];
    uint8_t buffer[BUFFER_SIZE];

    /* Recieve fileName */
    client_fd = accept_connection(server_fd);
    int fileNameLen = read(client_fd, buffer, FILE_NAME_LEN);
    close(client_fd);

    char fileName[fileNameLen+1];
    strncpy(fileName, buffer, fileNameLen);
    fileName[fileNameLen] = '\0';

    /* Recieve pageNum */
    int pageNum;
    client_fd = accept_connection(server_fd);
    read(client_fd, &pageNum, sizeof(int));
    close(client_fd);
    printf("Page number recieved: %d\n", pageNum);
    /* Open device */
    int fd;
    if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
        perror("[open]");
        return;
    }

    off_t offset = pageNum * PAGE_SIZE; /* Page offset */
    void *buf;
    if (posix_memalign(&buf, PAGE_SIZE, PAGE_SIZE) != 0) {
        perror("[posix_memalign]");
        close(fd);
        return;
    }

    /* Write pageNum to address 951396 */ // TODO: THIS BAD. ONLY DO THIS DURING AUDIT, ?? maybe good now????
    if (lseek(fd, 951396 * PAGE_SIZE, SEEK_SET) == -1) {
        perror("[lseek]");
        close(fd);
        return;
    }

    memcpy(buf, &pageNum, sizeof(pageNum));
    if (write(fd, buf, PAGE_SIZE) == -1) {
        perror("[write]");
        close(fd);
        return;
    }

  //struct timeval start, end;
    //gettimeofday(&start, NULL);

    if (pread(fd, buf, PAGE_SIZE, offset) == -1) { 
        perror("[pread]");
        free(buf);
        close(fd);
        return -1;
    }

    fsync(fd);

    //gettimeofday(&end, NULL);
    //long seconds = end.tv_sec - start.tv_sec;
    //long micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);

    //printf("Time elapsed Get page: %ld.%06ld seconds\n", seconds, micros);


    memcpy(pageData, buf, PAGE_SIZE);

    // printf("Page data encrypted??\n");
    // for(int i = 0; i < PAGE_SIZE; i++) {
    //     printf("%x", pageData[i]);
    // }
    // printf("\n");

    close(fd);

    /* Send data at pageNum */
    client_fd = accept_connection(server_fd);
    ssize_t total_sent = 0;
    while (total_sent < PAGE_SIZE) {
        ssize_t sent = write(client_fd, pageData + total_sent, PAGE_SIZE - total_sent);
        if (sent == -1) {
            // handle error
            break;
        }
        total_sent += sent;
    }
    close(client_fd);

}

void file_init(int server_fd) {
    int client_fd;
    uint8_t buffer[8192];
    


    // Open storage device. ASSUME 1 File for now
    int fd; 
    if((fd = open(PATH, O_RDWR)) == -1) { // For now do not do O_DIRECT. This is not in reserved area. A simple write
        perror("[open]");
        return;
    }

    
    // Receive file name
    client_fd = accept_connection(server_fd);
    int fileNameLen = read(client_fd, buffer, FILE_NAME_LEN);
    close(client_fd);

    char fileName[fileNameLen+1];
    strncpy(fileName, buffer, fileNameLen);
    fileName[fileNameLen] = '\0';

    // Receive number of blocks
    int numBlocks;

    client_fd = accept_connection(server_fd);
    read(client_fd, &numBlocks, sizeof(numBlocks));
    close(client_fd);


    // Receive each block
    uint8_t blockData[BLOCK_SIZE];
    for (int i = 0; i < numBlocks; i++) {

	    client_fd = accept_connection(server_fd);
        int bytes_received = 0;
	    int bytes_left = BLOCK_SIZE;
	    while (bytes_left > 0) {
    	    int bytes_read = read(client_fd, blockData + bytes_received, bytes_left);
    	    if (bytes_read < 0) {
        	// handle error
    	    } else if (bytes_read == 0) {
                // handle disconnection
            } else {
                bytes_received += bytes_read;
                bytes_left -= bytes_read;
            }
        }
     //   printf("Block %d received successfully\n", i);

	    close(client_fd);
    
        // Write block to storage device
	    if(write(fd, blockData, BLOCK_SIZE) == -1) {
	        perror("[write]");
	        close(fd);
	        return;
	    }
    }

    // Receive each sigma
    uint8_t sigma[numBlocks][PRIME_LENGTH / 8];
    const int bytesPerPage = 512;
    const int sigPerPage = (bytesPerPage) / (PRIME_LENGTH / 8);
    int sigCount = 0;
    for (int i = 0; i < numBlocks; i++) {
        
        client_fd = accept_connection(server_fd);

        if (read(client_fd, sigma[i], PRIME_LENGTH / 8) != PRIME_LENGTH / 8) {
            perror("failed to read sigma");
            exit(EXIT_FAILURE);
        }
        close(client_fd);

        /* Write sigma to storage device */
        if (write(fd, sigma[i], PRIME_LENGTH / 8) == -1) {
            perror("[write]");
            close(fd);
            return;
        }
        sigCount++;

        if (sigCount % sigPerPage == 0) {
            // Calculate the number of bytes to write to fill the current page
            int bytesWritten = (sigCount * (PRIME_LENGTH / 8));
            int bytesToFillPage = bytesPerPage - (bytesWritten % bytesPerPage);
            if (bytesToFillPage != bytesPerPage) {
                uint8_t buffer[bytesToFillPage];
                memset(buffer, 0, bytesToFillPage);
                if (write(fd, buffer, bytesToFillPage) == -1) {
                    perror("[write]");
                    close(fd);
                    return;
                }
            }
        }
    }

    // Seek to next 512 byte page
    off_t pos = lseek(fd, 0, SEEK_CUR);
    if (pos == -1) {
        perror("[lseek]");
        close(fd);
        return;
    }
    off_t nextPageStart = ((pos / bytesPerPage) + 1) * bytesPerPage;
    off_t bytesToSkip = nextPageStart - pos;
    if (lseek(fd, bytesToSkip, SEEK_CUR) == -1) {
        perror("[lseek]");
        close(fd);
        return;
    }


    // Receive the tag
    Tag tag;
    
    client_fd = accept_connection(server_fd);

    if (read(client_fd, &tag, sizeof(Tag)) != sizeof(Tag)) {
        perror("failed to read tag");
        exit(EXIT_FAILURE);
    }
    close(client_fd);
    
    // Write tag to storage device.
    if (write(fd, &tag, sizeof(tag)) == -1) {
        perror("[write]");
        close(fd);
        return;
    }

    return 0;
}

void ftl_init(int server_fd) {
    int client_fd;
    uint8_t sgx_pubKey[64] = {0};
    uint8_t *ftl_pubKey = malloc(sizeof(uint8_t) * 64);
    
    /* Read SGX public key from server*/
    client_fd = accept_connection(server_fd);
    read(client_fd, sgx_pubKey, sizeof(uint8_t) * 64);
    close(client_fd);


    /* Send SGX public key to FTL, and recieve FTL public key */
    ftl_initial(sgx_pubKey, ftl_pubKey);

    client_fd = accept_connection(server_fd);
    write(client_fd, ftl_pubKey, sizeof(uint8_t) * 64);
    close(client_fd);

    free(ftl_pubKey);
}

void state_2(int server_fd) {
    int client_fd;

    int numBits = 0;

    client_fd = accept_connection(server_fd);
    int len = read(client_fd, &numBits, sizeof(int));
    close(client_fd);

    int fd;
    if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
        perror("[open]");
        return;
    }

    off_t offset = 951400 * PAGE_SIZE; /* Page offset */
    void *buf;
    if (posix_memalign(&buf, PAGE_SIZE, PAGE_SIZE) != 0) {
        perror("[posix_memalign]");
        close(fd);
        return;
    }

    /* Write pageNum to address 951396 */
    if (lseek(fd, 951400 * PAGE_SIZE, SEEK_SET) == -1) {
        perror("[lseek]");
        close(fd);
        return;
    }

    memcpy(buf, &numBits, sizeof(numBits));
    if (write(fd, buf, PAGE_SIZE) == -1) {
        perror("[write]");
        close(fd);
        return;
    }
    

}

void write_parity(int server_fd) {

    int client_fd;
    uint8_t buffer[8192];
    


    // Open storage device. ASSUME 1 File for now
    int fd; 
    if((fd = open(PATH, O_RDWR)) == -1) { // For now do not do O_DIRECT. This is not in reserved area. A simple write
        perror("[open]");
        return;
    }



    int groupNum = 0;
    // Receive file name
    client_fd = accept_connection(server_fd);
    int fileNameLen = read(client_fd, groupNum, sizeof(groupNum));
    close(client_fd);

    // Receive number of blocks
    int numBlocks;

    client_fd = accept_connection(server_fd);
    read(client_fd, &numBlocks, sizeof(numBlocks));
    close(client_fd);

    lseek(fd, 230000 + (numBlocks * groupNum), SEEK_SET);

    // Receive each block
    uint8_t blockData[BLOCK_SIZE];
    for (int i = 0; i < numBlocks; i++) {

	    client_fd = accept_connection(server_fd);
        int bytes_received = 0;
	    int bytes_left = BLOCK_SIZE;
	    while (bytes_left > 0) {
    	    int bytes_read = read(client_fd, blockData + (bytes_received / 2) , bytes_left);
    	    if (bytes_read < 0) {
        	// handle error
    	    } else if (bytes_read == 0) {
                // handle disconnection
            } else {
                bytes_received += bytes_read;
                bytes_left -= bytes_read;
            }
        }
     //   printf("Block %d received successfully\n", i);

	    close(client_fd);
    
        // Write block to storage device
	    if(write(fd, blockData, BLOCK_SIZE) == -1) {
	        perror("[write]");
	        close(fd);
	        return;
	    }
    }

}

main() {

    int server_fd, client_fd;
    server_fd = create_socket();
    uint8_t buffer[BUFFER_SIZE];

    while(1) {
        client_fd = accept_connection(server_fd);
        int stringLen = read(client_fd, buffer, FILE_NAME_LEN);
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
        else if(strcmp(command, "get_page") == 0) {
            printf("get page\n");
            get_page(server_fd);
        }
        else if(strcmp(command, "get_nonce") == 0 ) {
            printf("get nonce\n");
            get_challnum(server_fd);
        }
        else if(strcmp(command, "write_parity") == 0 ) {
            printf("write parity\n");
            write_parity(server_fd);

        }
	else if(strcmp(command, "state_2") == 0) {
	    printf("enter state 2\n");
	    state_2(server_fd);
	}
        else exit(1);
    }
}
