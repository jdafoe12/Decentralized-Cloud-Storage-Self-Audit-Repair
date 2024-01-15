#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_init(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_init();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_file_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_file_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_file_init_t* ms = SGX_CAST(ms_ecall_file_init_t*, pms);
	ms_ecall_file_init_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_file_init_t), ms, sizeof(ms_ecall_file_init_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_fileName = __in_ms.ms_fileName;
	size_t _len_fileName = __in_ms.ms_fileName_len ;
	char* _in_fileName = NULL;
	Tag* _tmp_tag = __in_ms.ms_tag;
	size_t _len_tag = sizeof(Tag);
	Tag* _in_tag = NULL;
	uint8_t* _tmp_sigma = __in_ms.ms_sigma;
	size_t _len_sigma = 10 * 10;
	uint8_t* _in_sigma = NULL;
	int _in_retval;

	if (10 != 0 &&
		10 > (SIZE_MAX / 10)) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_fileName, _len_fileName);
	CHECK_UNIQUE_POINTER(_tmp_tag, _len_tag);
	CHECK_UNIQUE_POINTER(_tmp_sigma, _len_sigma);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_fileName != NULL && _len_fileName != 0) {
		_in_fileName = (char*)malloc(_len_fileName);
		if (_in_fileName == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_fileName, _len_fileName, _tmp_fileName, _len_fileName)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_fileName[_len_fileName - 1] = '\0';
		if (_len_fileName != strlen(_in_fileName) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_tag != NULL && _len_tag != 0) {
		if ((_in_tag = (Tag*)malloc(_len_tag)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_tag, 0, _len_tag);
	}
	if (_tmp_sigma != NULL && _len_sigma != 0) {
		if ( _len_sigma % sizeof(*_tmp_sigma) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sigma = (uint8_t*)malloc(_len_sigma)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sigma, 0, _len_sigma);
	}
	_in_retval = ecall_file_init((const char*)_in_fileName, _in_tag, _in_sigma, __in_ms.ms_numBlocks);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_tag) {
		if (memcpy_verw_s(_tmp_tag, _len_tag, _in_tag, _len_tag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sigma) {
		if (memcpy_verw_s(_tmp_sigma, _len_sigma, _in_sigma, _len_sigma)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_fileName) free(_in_fileName);
	if (_in_tag) free(_in_tag);
	if (_in_sigma) free(_in_sigma);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_audit_file(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_audit_file_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_audit_file_t* ms = SGX_CAST(ms_ecall_audit_file_t*, pms);
	ms_ecall_audit_file_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_audit_file_t), ms, sizeof(ms_ecall_audit_file_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_fileName = __in_ms.ms_fileName;
	size_t _len_fileName = __in_ms.ms_fileName_len ;
	char* _in_fileName = NULL;
	int* _tmp_ret = __in_ms.ms_ret;
	size_t _len_ret = sizeof(int);
	int* _in_ret = NULL;

	CHECK_UNIQUE_POINTER(_tmp_fileName, _len_fileName);
	CHECK_UNIQUE_POINTER(_tmp_ret, _len_ret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_fileName != NULL && _len_fileName != 0) {
		_in_fileName = (char*)malloc(_len_fileName);
		if (_in_fileName == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_fileName, _len_fileName, _tmp_fileName, _len_fileName)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_fileName[_len_fileName - 1] = '\0';
		if (_len_fileName != strlen(_in_fileName) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_ret != NULL && _len_ret != 0) {
		if ( _len_ret % sizeof(*_tmp_ret) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ret = (int*)malloc(_len_ret)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret, 0, _len_ret);
	}
	ecall_audit_file((const char*)_in_fileName, _in_ret);
	if (_in_ret) {
		if (memcpy_verw_s(_tmp_ret, _len_ret, _in_ret, _len_ret)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_fileName) free(_in_fileName);
	if (_in_ret) free(_in_ret);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_generate_file_parity(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_file_parity_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_file_parity_t* ms = SGX_CAST(ms_ecall_generate_file_parity_t*, pms);
	ms_ecall_generate_file_parity_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_generate_file_parity_t), ms, sizeof(ms_ecall_generate_file_parity_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_generate_file_parity(__in_ms.ms_fileNum);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_decode_partition(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_decode_partition_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_decode_partition_t* ms = SGX_CAST(ms_ecall_decode_partition_t*, pms);
	ms_ecall_decode_partition_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_decode_partition_t), ms, sizeof(ms_ecall_decode_partition_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_fileName = __in_ms.ms_fileName;
	size_t _len_fileName = __in_ms.ms_fileName_len ;
	char* _in_fileName = NULL;

	CHECK_UNIQUE_POINTER(_tmp_fileName, _len_fileName);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_fileName != NULL && _len_fileName != 0) {
		_in_fileName = (char*)malloc(_len_fileName);
		if (_in_fileName == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_fileName, _len_fileName, _tmp_fileName, _len_fileName)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_fileName[_len_fileName - 1] = '\0';
		if (_len_fileName != strlen(_in_fileName) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	ecall_decode_partition((const char*)_in_fileName, __in_ms.ms_blockNum);

err:
	if (_in_fileName) free(_in_fileName);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_ecall_init, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_file_init, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_audit_file, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_generate_file_parity, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_decode_partition, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[18][5];
} g_dyn_entry_table = {
	18,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_ftl_init(uint8_t* sgx_pubKey, uint8_t* ftl_pubKey)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sgx_pubKey = 64 * sizeof(uint8_t);
	size_t _len_ftl_pubKey = 64 * sizeof(uint8_t);

	ms_ocall_ftl_init_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ftl_init_t);
	void *__tmp = NULL;

	void *__tmp_ftl_pubKey = NULL;

	CHECK_ENCLAVE_POINTER(sgx_pubKey, _len_sgx_pubKey);
	CHECK_ENCLAVE_POINTER(ftl_pubKey, _len_ftl_pubKey);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sgx_pubKey != NULL) ? _len_sgx_pubKey : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ftl_pubKey != NULL) ? _len_ftl_pubKey : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ftl_init_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ftl_init_t));
	ocalloc_size -= sizeof(ms_ocall_ftl_init_t);

	if (sgx_pubKey != NULL) {
		if (memcpy_verw_s(&ms->ms_sgx_pubKey, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_sgx_pubKey % sizeof(*sgx_pubKey) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, sgx_pubKey, _len_sgx_pubKey)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sgx_pubKey);
		ocalloc_size -= _len_sgx_pubKey;
	} else {
		ms->ms_sgx_pubKey = NULL;
	}

	if (ftl_pubKey != NULL) {
		if (memcpy_verw_s(&ms->ms_ftl_pubKey, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_ftl_pubKey = __tmp;
		if (_len_ftl_pubKey % sizeof(*ftl_pubKey) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_ftl_pubKey, 0, _len_ftl_pubKey);
		__tmp = (void *)((size_t)__tmp + _len_ftl_pubKey);
		ocalloc_size -= _len_ftl_pubKey;
	} else {
		ms->ms_ftl_pubKey = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (ftl_pubKey) {
			if (memcpy_s((void*)ftl_pubKey, _len_ftl_pubKey, __tmp_ftl_pubKey, _len_ftl_pubKey)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_block(uint8_t* data, size_t segSize, int segPerBlock, int blockNum, char* fileName)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = 4096 * sizeof(uint8_t);
	size_t _len_fileName = 1024;

	ms_ocall_get_block_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_block_t);
	void *__tmp = NULL;

	void *__tmp_data = NULL;

	CHECK_ENCLAVE_POINTER(data, _len_data);
	CHECK_ENCLAVE_POINTER(fileName, _len_fileName);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (data != NULL) ? _len_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fileName != NULL) ? _len_fileName : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_block_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_block_t));
	ocalloc_size -= sizeof(ms_ocall_get_block_t);

	if (data != NULL) {
		if (memcpy_verw_s(&ms->ms_data, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_data = __tmp;
		if (_len_data % sizeof(*data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_data, 0, _len_data);
		__tmp = (void *)((size_t)__tmp + _len_data);
		ocalloc_size -= _len_data;
	} else {
		ms->ms_data = NULL;
	}

	if (memcpy_verw_s(&ms->ms_segSize, sizeof(ms->ms_segSize), &segSize, sizeof(segSize))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_segPerBlock, sizeof(ms->ms_segPerBlock), &segPerBlock, sizeof(segPerBlock))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_blockNum, sizeof(ms->ms_blockNum), &blockNum, sizeof(blockNum))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (fileName != NULL) {
		if (memcpy_verw_s(&ms->ms_fileName, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_fileName % sizeof(*fileName) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, fileName, _len_fileName)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_fileName);
		ocalloc_size -= _len_fileName;
	} else {
		ms->ms_fileName = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (data) {
			if (memcpy_s((void*)data, _len_data, __tmp_data, _len_data)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_printf(unsigned char* buffer, size_t size, int type)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = size * sizeof(unsigned char);

	ms_ocall_printf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_printf_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_printf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_printf_t));
	ocalloc_size -= sizeof(ms_ocall_printf_t);

	if (buffer != NULL) {
		if (memcpy_verw_s(&ms->ms_buffer, sizeof(unsigned char*), &__tmp, sizeof(unsigned char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buffer, _len_buffer)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}

	if (memcpy_verw_s(&ms->ms_size, sizeof(ms->ms_size), &size, sizeof(size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_type, sizeof(ms->ms_type), &type, sizeof(type))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_send_nonce(uint8_t* nonce)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_nonce = 16 * sizeof(uint8_t);

	ms_ocall_send_nonce_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_send_nonce_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(nonce, _len_nonce);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (nonce != NULL) ? _len_nonce : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_send_nonce_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_send_nonce_t));
	ocalloc_size -= sizeof(ms_ocall_send_nonce_t);

	if (nonce != NULL) {
		if (memcpy_verw_s(&ms->ms_nonce, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_nonce % sizeof(*nonce) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, nonce, _len_nonce)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_nonce);
		ocalloc_size -= _len_nonce;
	} else {
		ms->ms_nonce = NULL;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_segment(const char* fileName, int segNum, uint8_t* segData)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fileName = fileName ? strlen(fileName) + 1 : 0;
	size_t _len_segData = SEGMENT_SIZE;

	ms_ocall_get_segment_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_segment_t);
	void *__tmp = NULL;

	void *__tmp_segData = NULL;

	CHECK_ENCLAVE_POINTER(fileName, _len_fileName);
	CHECK_ENCLAVE_POINTER(segData, _len_segData);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fileName != NULL) ? _len_fileName : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (segData != NULL) ? _len_segData : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_segment_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_segment_t));
	ocalloc_size -= sizeof(ms_ocall_get_segment_t);

	if (fileName != NULL) {
		if (memcpy_verw_s(&ms->ms_fileName, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_fileName % sizeof(*fileName) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, fileName, _len_fileName)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_fileName);
		ocalloc_size -= _len_fileName;
	} else {
		ms->ms_fileName = NULL;
	}

	if (memcpy_verw_s(&ms->ms_segNum, sizeof(ms->ms_segNum), &segNum, sizeof(segNum))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (segData != NULL) {
		if (memcpy_verw_s(&ms->ms_segData, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_segData = __tmp;
		if (_len_segData % sizeof(*segData) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_segData, 0, _len_segData);
		__tmp = (void *)((size_t)__tmp + _len_segData);
		ocalloc_size -= _len_segData;
	} else {
		ms->ms_segData = NULL;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (segData) {
			if (memcpy_s((void*)segData, _len_segData, __tmp_segData, _len_segData)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_init_parity(int numBits)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_init_parity_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_init_parity_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_init_parity_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_init_parity_t));
	ocalloc_size -= sizeof(ms_ocall_init_parity_t);

	if (memcpy_verw_s(&ms->ms_numBits, sizeof(ms->ms_numBits), &numBits, sizeof(numBits))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_send_parity(int startPage, uint8_t* parityData, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_parityData = size;

	ms_ocall_send_parity_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_send_parity_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(parityData, _len_parityData);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (parityData != NULL) ? _len_parityData : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_send_parity_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_send_parity_t));
	ocalloc_size -= sizeof(ms_ocall_send_parity_t);

	if (memcpy_verw_s(&ms->ms_startPage, sizeof(ms->ms_startPage), &startPage, sizeof(startPage))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (parityData != NULL) {
		if (memcpy_verw_s(&ms->ms_parityData, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_parityData % sizeof(*parityData) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, parityData, _len_parityData)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_parityData);
		ocalloc_size -= _len_parityData;
	} else {
		ms->ms_parityData = NULL;
	}

	if (memcpy_verw_s(&ms->ms_size, sizeof(ms->ms_size), &size, sizeof(size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_end_genPar(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(7, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_write_partition(int numBits)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_write_partition_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_partition_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_partition_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_partition_t));
	ocalloc_size -= sizeof(ms_ocall_write_partition_t);

	if (memcpy_verw_s(&ms->ms_numBits, sizeof(ms->ms_numBits), &numBits, sizeof(numBits))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write_page(int pageNum, uint8_t* pageData)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pageData = 2048;

	ms_ocall_write_page_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_page_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pageData, _len_pageData);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pageData != NULL) ? _len_pageData : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_page_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_page_t));
	ocalloc_size -= sizeof(ms_ocall_write_page_t);

	if (memcpy_verw_s(&ms->ms_pageNum, sizeof(ms->ms_pageNum), &pageNum, sizeof(pageNum))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (pageData != NULL) {
		if (memcpy_verw_s(&ms->ms_pageData, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pageData % sizeof(*pageData) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pageData, _len_pageData)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pageData);
		ocalloc_size -= _len_pageData;
	} else {
		ms->ms_pageData = NULL;
	}

	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wait_timeout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wait_timeout_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wait_timeout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wait_timeout_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wait_timeout_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_create_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_create_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_create_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_create_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_create_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wakeup_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wakeup_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wakeup_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wakeup_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wakeup_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

