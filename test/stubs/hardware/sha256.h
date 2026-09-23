#pragma once
#include "hardware/structs/sha256.h"

#define SHA256_CSR_START_BITS             0x00000001u
#define SHA256_CSR_WDATA_RDY_BITS         0x00000002u
#define SHA256_CSR_SUM_VLD_BITS           0x00000004u
#define SHA256_CSR_ERR_WDATA_NOT_RDY_BITS 0x00000010u
#define SHA256_CSR_DMA_SIZE_LSB           8u
#define SHA256_CSR_DMA_SIZE_VALUE_32BIT   0x2u
#define SHA256_CSR_BSWAP_BITS             0x00001000u

void sha_emul_set_bswap(bool b);
void sha_emul_err_clear(void);
bool sha_emul_err(void);

static inline void sha256_set_bswap(bool b)        { sha_emul_set_bswap(b); }
static inline void sha256_err_not_ready_clear(void){ sha_emul_err_clear(); }
static inline bool sha256_err_not_ready(void)      { return sha_emul_err(); }
