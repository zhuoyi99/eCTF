#include "cfg_decrypt.h"
#include "flash.h"
#include "flash_trampoline.h"
#include "rand.h"

__attribute__((section(".data"))) void cfg_decrypt(uint8_t* configuration_storage, uint32_t size, struct AES_ctx* ctx) {
    uint8_t hash[TC_SHA256_DIGEST_SIZE];
    uint8_t hash2[TC_SHA256_DIGEST_SIZE];
    
    // Pad size to FLASH_PAGE_SIZE (note, already padded to AES block size)
    uint32_t padded_size = size;
    if(padded_size % FLASH_PAGE_SIZE != 0)
        padded_size += FLASH_PAGE_SIZE - size % FLASH_PAGE_SIZE;

    // Flash check!
    current_hash(hash, (uint8_t*)configuration_storage, padded_size);

    // We need to buffer full pages because we erase pages as we go
    // Similar to load_data
    uint8_t inbuf[FLASH_PAGE_SIZE];
    uint8_t mask[RAND_BUF_LEN + 4];
    rand_buf(mask);
    uint32_t mask_ofs = 0;
    uint32_t cur_size;
    while(size > 0) {
        if(size < FLASH_PAGE_SIZE) {
            cur_size = size;
            // Pad out
            for(uint32_t i = cur_size; i < FLASH_PAGE_SIZE; i++)
                inbuf[i] = 0xFF;
        } else {
            cur_size = FLASH_PAGE_SIZE;
        }

        for(uint32_t n = 0; n < cur_size; n++) {
            inbuf[n] = *((uint8_t*)configuration_storage+n);
        }
        
        AES_CBC_decrypt_buffer(ctx, inbuf, cur_size, mask + mask_ofs);
        mask_ofs += 2;
        mask_ofs %= (RAND_BUF_LEN - 6);

        flash_erase_page_unsafe((uint32_t)configuration_storage);
        flash_write_unsafe((uint32_t*)inbuf, (uint32_t)configuration_storage, FLASH_PAGE_SIZE/4);
        configuration_storage += FLASH_PAGE_SIZE;
        size -= cur_size;
    }

    current_hash(hash2, (uint8_t*)configuration_storage - padded_size, padded_size);
    for(int i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
        if(hash[i] != hash2[i]) panic();
    }
}
