#include "cfg_decrypt.h"
#include "flash.h"
#include "flash_trampoline.h"

__attribute__((section(".data"))) void cfg_decrypt(uint8_t* configuration_storage, uint8_t* iv, uint32_t size, struct AES_ctx* ctx) {
    uint8_t hash[TC_SHA256_DIGEST_SIZE];
    uint8_t hash2[TC_SHA256_DIGEST_SIZE];

    // Flash check!
    current_hash(hash, (uint8_t*)configuration_storage, size);

    uint8_t inbuf[32];
    // Padded to 32 before
    uint32_t iterations = size / 32;
    AES_ctx_set_iv(ctx, iv);
    for(uint32_t m = 0; m < iterations; m++) {
        for(uint32_t n = 0; n < 32; n++) {
            inbuf[n] = *((uint8_t*)configuration_storage+32*m+n);
        }
        AES_CBC_decrypt_buffer(ctx, inbuf, 32);
        flash_write_unsafe((uint32_t*)inbuf, (uint32_t)configuration_storage+32*m, 32/4);
    }

    current_hash(hash2, (uint8_t*)configuration_storage, size);
    for(int i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
        if(hash[i] != hash2[i]) panic();
    }
}
