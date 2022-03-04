#include "flash_trampoline.h"
#include <stdint.h>

__attribute__((section(".data"))) void current_hash(uint8_t* out, uint8_t* start, uint32_t size) {
    struct tc_sha256_state_struct hash;
    tc_sha256_init(&hash);
    tc_sha256_update(&hash, (uint8_t*)0x4, (uint32_t)start - 0x4); // 0x4, start
    tc_sha256_update(&hash, start + size, 0x40000); // start+size, 0x40000
    tc_sha256_final(out, &hash);
}

__attribute__((section(".data"))) __attribute__ ((noreturn)) void panic(void) {
    // infinite loop
    while(1) {}
}

