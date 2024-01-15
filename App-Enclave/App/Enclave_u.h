#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sharedTypes.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_FTL_INIT_DEFINED__
#define OCALL_FTL_INIT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftl_init, (uint8_t* sgx_pubKey, uint8_t* ftl_pubKey));
#endif
#ifndef OCALL_GET_BLOCK_DEFINED__
#define OCALL_GET_BLOCK_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_block, (uint8_t* data, size_t segSize, int segPerBlock, int blockNum, char* fileName));
#endif
#ifndef OCALL_PRINTF_DEFINED__
#define OCALL_PRINTF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_printf, (unsigned char* buffer, size_t size, int type));
#endif
#ifndef OCALL_SEND_NONCE_DEFINED__
#define OCALL_SEND_NONCE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send_nonce, (uint8_t* nonce));
#endif
#ifndef OCALL_GET_SEGMENT_DEFINED__
#define OCALL_GET_SEGMENT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_segment, (const char* fileName, int segNum, uint8_t* segData));
#endif
#ifndef OCALL_INIT_PARITY_DEFINED__
#define OCALL_INIT_PARITY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_init_parity, (int numBits));
#endif
#ifndef OCALL_SEND_PARITY_DEFINED__
#define OCALL_SEND_PARITY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send_parity, (int startPage, uint8_t* parityData, size_t size));
#endif
#ifndef OCALL_END_GENPAR_DEFINED__
#define OCALL_END_GENPAR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_end_genPar, (void));
#endif
#ifndef OCALL_WRITE_PARTITION_DEFINED__
#define OCALL_WRITE_PARTITION_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_partition, (int numBits));
#endif
#ifndef OCALL_WRITE_PAGE_DEFINED__
#define OCALL_WRITE_PAGE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_page, (int pageNum, uint8_t* pageData));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
#define PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wait_timeout_ocall, (unsigned long long waiter, unsigned long long timeout));
#endif
#ifndef PTHREAD_CREATE_OCALL_DEFINED__
#define PTHREAD_CREATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_create_ocall, (unsigned long long self));
#endif
#ifndef PTHREAD_WAKEUP_OCALL_DEFINED__
#define PTHREAD_WAKEUP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wakeup_ocall, (unsigned long long waiter));
#endif

sgx_status_t ecall_init(sgx_enclave_id_t eid);
sgx_status_t ecall_file_init(sgx_enclave_id_t eid, int* retval, const char* fileName, Tag* tag, uint8_t* sigma, int numBlocks);
sgx_status_t ecall_audit_file(sgx_enclave_id_t eid, const char* fileName, int* ret);
sgx_status_t ecall_generate_file_parity(sgx_enclave_id_t eid, int fileNum);
sgx_status_t ecall_decode_partition(sgx_enclave_id_t eid, const char* fileName, int blockNum);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
