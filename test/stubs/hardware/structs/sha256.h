#pragma once
#include "pico.h"

// Host emulation hooks implemented in sha_emul.cpp
void     sha_emul_csr_write(uint32_t v);
uint32_t sha_emul_csr_read(void);
void     sha_emul_wdata(uint32_t v);
uint32_t sha_emul_sum(int i);

struct RegWO { void operator=(uint32_t v) const { sha_emul_wdata(v); } };
struct RegRW {
    void operator=(uint32_t v) const { sha_emul_csr_write(v); }
    operator uint32_t() const { return sha_emul_csr_read(); }
};
struct RegRO { operator uint32_t() const; };

typedef RegRW io_rw_32;
typedef RegWO io_wo_32;
typedef RegRO io_ro_32;

typedef struct { io_rw_32 csr; io_wo_32 wdata; io_ro_32 sum[8]; } sha256_hw_t;
extern sha256_hw_t sha256_hw_obj;
#define sha256_hw (&sha256_hw_obj)
