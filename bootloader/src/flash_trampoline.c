#include "flash_trampoline.h"
#include <stdint.h>

#include "uart.h"

__attribute__((section(".data"))) void current_hash(uint8_t* out, uint8_t* start, uint32_t size) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, 0x5800, (uint32_t)start - 0x5800);
    sha256_update(&ctx, start + size, 0x40000 - (uint32_t)(start + size));
    sha256_final(&ctx, out);
}

__attribute__((section(".data"))) __attribute__ ((noreturn)) void panic(void) {
    // infinite loop
    while(1) {
        // Let host tools know what happened
        uart_writeb(HOST_UART, 'P');
        // Block on waiting
        uart_readb(HOST_UART);
    }       
}

