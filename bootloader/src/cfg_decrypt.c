#include <stdbool.h>

#include "aes.h"
#include "cfg_decrypt.h"
#include "driverlib/eeprom.h"
#include "flash.h"
#include "rand.h"
#include "uart.h"

/**
 * @brief Read configuration data from a UART interface and program to flash memory.
 * This function is unsafe to call directly.
 * 
 * @param interface is the base address of the UART interface to read from.
 * @param dst is the starting page address to store the data.
 * @param size is the number of bytes to load.
 */
__attribute__((section(".data"))) void load_cfg_unsafe(uint32_t interface, uint32_t dst, uint32_t size, const uint32_t max_size) {
    int i;
    uint32_t frame_size;
    uint8_t page_buffer[FLASH_PAGE_SIZE];

    // Clear whole flash region at once
    // assert: max_size % FLASH_PAGE_SIZE == 0
    for(i = 0; i < max_size; i += FLASH_PAGE_SIZE) {
        flash_erase_page_unsafe(dst + i);
    }

    // Initialize AES
    struct AES_ctx ctx;
    unsigned char ENC_KEY[32];
    EEPROMRead((uint32_t*)&ENC_KEY, ED_ENCRYPTION_KEY_LOCATION, 32);
    AES_init_ctx(&ctx, ENC_KEY);
    // We're done with this in memory
    for(uint32_t i = 0; i < (sizeof(ENC_KEY) / sizeof(uint32_t)); i++) {
        *((uint32_t*)ENC_KEY + i) = 0x00000000;
    }
    AES_ctx_set_iv(&ctx, (uint8_t*)CONFIGURATION_IV_PTR);
    // We need an extra 4 bytes for the mask buffer because of the expectations of AES_CBC_decrypt_buffer
    uint8_t mask[RAND_BUF_LEN + 4];
    rand_buf(mask);
    // Attempt to "spread" mask randomness
    uint32_t mask_ofs = 0;

    while(size > 0) {
        // calculate frame size
        frame_size = size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : size;
        // read frame into buffer
        uart_read(HOST_UART, page_buffer, frame_size);
        // pad buffer if frame is smaller than the page
        // assert: frame_size % 16 == 0
        for(i = frame_size; i < FLASH_PAGE_SIZE; i++) {
            page_buffer[i] = 0xff;
        }
        // decrypt buffer
        for(i = 0; i < frame_size; i += 16) {
            AES_CBC_decrypt_buffer(&ctx, (uint8_t*)page_buffer + i, 16, mask + mask_ofs);
            mask_ofs++;
            mask_ofs %= (RAND_BUF_LEN - 6);
        }
        // write flash page
        flash_write_unsafe((uint32_t *)page_buffer, dst, FLASH_PAGE_SIZE >> 2);
        // next page and decrease size
        dst += FLASH_PAGE_SIZE;
        size -= frame_size;
        // send frame ok
        uart_writeb(HOST_UART, FRAME_OK);
    }

    // Zero sensitive round keys in memory
    for(uint32_t i = 0; i < (sizeof(struct AES_ctx) / sizeof(uint32_t)); i++) {
        *((uint32_t*)&ctx + i) = 0x00000000;
    }
}
