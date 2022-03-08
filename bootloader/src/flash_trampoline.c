#include "flash_trampoline.h"
#include <stdint.h>

#include "uart.h"

__attribute__((section(".data"))) void current_hash(uint8_t* out, uint8_t* start, uint32_t size) {
    /*
    struct tc_sha256_state_struct hash;
    tc_sha256_init(&hash);
    tc_sha256_update(&hash, (uint8_t*)0x4, (uint32_t)start - 0x4); // 0x4, start
    tc_sha256_update(&hash, start + size, 0x40000 - (uint32_t)(start + size)); // start+size, 0x40000
    tc_sha256_final(out, &hash);
    */
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, 0, (uint32_t)start);
    // sha256_update(&ctx, start + size, 0x40000 - (uint32_t)(start + size));
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

