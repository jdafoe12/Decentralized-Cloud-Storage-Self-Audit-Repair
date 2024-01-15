#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_file_init_t {
	int ms_retval;
	const char* ms_fileName;
	size_t ms_fileName_len;
	Tag* ms_tag;
	uint8_t* ms_sigma;
	int ms_numBlocks;
} ms_ecall_file_init_t;

typedef struct ms_ecall_audit_file_t {
	const char* ms_fileName;
	size_t ms_fileName_len;
	int* ms_ret;
} ms_ecall_audit_file_t;

typedef struct ms_ecall_generate_file_parity_t {
	int ms_fileNum;
} ms_ecall_generate_file_parity_t;

typedef struct ms_ecall_decode_partition_t {
	const char* ms_fileName;
	size_t ms_fileName_len;
	int ms_blockNum;
} ms_ecall_decode_partition_t;

typedef struct ms_ocall_ftl_init_t {
	uint8_t* ms_sgx_pubKey;
	uint8_t* ms_ftl_pubKey;
} ms_ocall_ftl_init_t;

typedef struct ms_ocall_get_block_t {
	uint8_t* ms_data;
	size_t ms_segSize;
	int ms_segPerBlock;
	int ms_blockNum;
	char* ms_fileName;
} ms_ocall_get_block_t;

typedef struct ms_ocall_printf_t {
	unsigned char* ms_buffer;
	size_t ms_size;
	int ms_type;
} ms_ocall_printf_t;

typedef struct ms_ocall_send_nonce_t {
	uint8_t* ms_nonce;
} ms_ocall_send_nonce_t;

typedef struct ms_ocall_get_segment_t {
	const char* ms_fileName;
	int ms_segNum;
	uint8_t* ms_segData;
} ms_ocall_get_segment_t;

typedef struct ms_ocall_init_parity_t {
	int ms_numBits;
} ms_ocall_init_parity_t;

typedef struct ms_ocall_send_parity_t {
	int ms_startPage;
	uint8_t* ms_parityData;
	size_t ms_size;
} ms_ocall_send_parity_t;

typedef struct ms_ocall_write_partition_t {
	int ms_numBits;
} ms_ocall_write_partition_t;

typedef struct ms_ocall_write_page_t {
	int ms_pageNum;
	uint8_t* ms_pageData;
} ms_ocall_write_page_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_ftl_init(void* pms)
{
	ms_ocall_ftl_init_t* ms = SGX_CAST(ms_ocall_ftl_init_t*, pms);
	ocall_ftl_init(ms->ms_sgx_pubKey, ms->ms_ftl_pubKey);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_block(void* pms)
{
	ms_ocall_get_block_t* ms = SGX_CAST(ms_ocall_get_block_t*, pms);
	ocall_get_block(ms->ms_data, ms->ms_segSize, ms->ms_segPerBlock, ms->ms_blockNum, ms->ms_fileName);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_printf(void* pms)
{
	ms_ocall_printf_t* ms = SGX_CAST(ms_ocall_printf_t*, pms);
	ocall_printf(ms->ms_buffer, ms->ms_size, ms->ms_type);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_send_nonce(void* pms)
{
	ms_ocall_send_nonce_t* ms = SGX_CAST(ms_ocall_send_nonce_t*, pms);
	ocall_send_nonce(ms->ms_nonce);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_segment(void* pms)
{
	ms_ocall_get_segment_t* ms = SGX_CAST(ms_ocall_get_segment_t*, pms);
	ocall_get_segment(ms->ms_fileName, ms->ms_segNum, ms->ms_segData);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_init_parity(void* pms)
{
	ms_ocall_init_parity_t* ms = SGX_CAST(ms_ocall_init_parity_t*, pms);
	ocall_init_parity(ms->ms_numBits);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_send_parity(void* pms)
{
	ms_ocall_send_parity_t* ms = SGX_CAST(ms_ocall_send_parity_t*, pms);
	ocall_send_parity(ms->ms_startPage, ms->ms_parityData, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_end_genPar(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_end_genPar();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write_partition(void* pms)
{
	ms_ocall_write_partition_t* ms = SGX_CAST(ms_ocall_write_partition_t*, pms);
	ocall_write_partition(ms->ms_numBits);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write_page(void* pms)
{
	ms_ocall_write_page_t* ms = SGX_CAST(ms_ocall_write_page_t*, pms);
	ocall_write_page(ms->ms_pageNum, ms->ms_pageData);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[18];
} ocall_table_Enclave = {
	18,
	{
		(void*)Enclave_ocall_ftl_init,
		(void*)Enclave_ocall_get_block,
		(void*)Enclave_ocall_printf,
		(void*)Enclave_ocall_send_nonce,
		(void*)Enclave_ocall_get_segment,
		(void*)Enclave_ocall_init_parity,
		(void*)Enclave_ocall_send_parity,
		(void*)Enclave_ocall_end_genPar,
		(void*)Enclave_ocall_write_partition,
		(void*)Enclave_ocall_write_page,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_pthread_wait_timeout_ocall,
		(void*)Enclave_pthread_create_ocall,
		(void*)Enclave_pthread_wakeup_ocall,
	}
};
sgx_status_t ecall_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_file_init(sgx_enclave_id_t eid, int* retval, const char* fileName, Tag* tag, uint8_t* sigma, int numBlocks)
{
	sgx_status_t status;
	ms_ecall_file_init_t ms;
	ms.ms_fileName = fileName;
	ms.ms_fileName_len = fileName ? strlen(fileName) + 1 : 0;
	ms.ms_tag = tag;
	ms.ms_sigma = sigma;
	ms.ms_numBlocks = numBlocks;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_audit_file(sgx_enclave_id_t eid, const char* fileName, int* ret)
{
	sgx_status_t status;
	ms_ecall_audit_file_t ms;
	ms.ms_fileName = fileName;
	ms.ms_fileName_len = fileName ? strlen(fileName) + 1 : 0;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_generate_file_parity(sgx_enclave_id_t eid, int fileNum)
{
	sgx_status_t status;
	ms_ecall_generate_file_parity_t ms;
	ms.ms_fileNum = fileNum;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_decode_partition(sgx_enclave_id_t eid, const char* fileName, int blockNum)
{
	sgx_status_t status;
	ms_ecall_decode_partition_t ms;
	ms.ms_fileName = fileName;
	ms.ms_fileName_len = fileName ? strlen(fileName) + 1 : 0;
	ms.ms_blockNum = blockNum;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

