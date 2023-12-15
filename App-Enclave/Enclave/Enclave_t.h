#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sharedTypes.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_init(void);
int ecall_file_init(const char* fileName, Tag* tag, uint8_t* sigma, int numBlocks);
void ecall_audit_file(const char* fileName, int* ret);
void ecall_generate_file_parity(int fileNum);

sgx_status_t SGX_CDECL ocall_ftl_init(uint8_t* sgx_pubKey, uint8_t* ftl_pubKey);
sgx_status_t SGX_CDECL ocall_get_block(uint8_t* data, size_t segSize, int segPerBlock, int blockNum, char* fileName);
sgx_status_t SGX_CDECL ocall_printf(unsigned char* buffer, size_t size, int type);
sgx_status_t SGX_CDECL ocall_send_nonce(uint8_t* nonce);
sgx_status_t SGX_CDECL ocall_get_segment(const char* fileName, int segNum, uint8_t* segData);
sgx_status_t SGX_CDECL ocall_init_parity(int numBits);
sgx_status_t SGX_CDECL ocall_send_parity(int startPage, uint8_t* parityData, size_t size);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
