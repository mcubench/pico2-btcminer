#pragma once
#include "pico.h"
#define DREQ_SHA256 54
typedef enum { DMA_SIZE_8=0, DMA_SIZE_16=1, DMA_SIZE_32=2 } enum_dma_transfer_size;
typedef struct { int dummy; } dma_channel_config;

int  dma_claim_unused_channel(bool required);
dma_channel_config dma_channel_get_default_config(uint ch);
void channel_config_set_transfer_data_size(dma_channel_config *c, enum_dma_transfer_size s);
void channel_config_set_read_increment(dma_channel_config *c, bool v);
void channel_config_set_write_increment(dma_channel_config *c, bool v);
void channel_config_set_dreq(dma_channel_config *c, uint d);
void dma_channel_configure(uint ch, const dma_channel_config *c, volatile void *w,
                           const volatile void *r, uint count, bool trigger);
void dma_channel_set_trans_count(uint ch, uint32_t count, bool trigger);
void dma_channel_set_read_addr(uint ch, const volatile void *addr, bool trigger);
void dma_channel_wait_for_finish_blocking(uint ch);
