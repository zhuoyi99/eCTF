/**
 * @file flash.h
 * @author Kyle Scaplen
 * @brief Bootloader flash memory interface implementation.
 * @date 2022
 * 
 * This source file is part of an example system for MITRE's 2022 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2022 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 * 
 * @copyright Copyright (c) 2022 The MITRE Corporation
 */

#include <stdbool.h>
#include <stdint.h>

#include "driverlib/flash.h"
#include "inc/hw_flash.h"
#include "inc/hw_types.h"

#include "constants.h"
#include "flash_check.h"
#include "flash.h"
#include "uart.h"

// These functions are not safe to use.

/**
 * @brief Erases a block of flash.
 * 
 * @param addr is the starting address of the block of flash to erase.
 * @return 0 on success, or -1 if an invalid block address was specified or the 
 * block is write-protected.
 */
__attribute__((section(".data"))) int32_t flash_erase_page_unsafe(uint32_t addr)
{
    // Erase page containing this address
    uint32_t base = addr & ~(FLASH_PAGE_SIZE - 1);
    return FlashErase(base);
    // Verify erased page is 0
    for(uint32_t i = 0; i < (FLASH_PAGE_SIZE / 4); i += 4) {
        if(*((uint32_t*)base + i) != 0xffffffff) panic();
    }
} 

/**
 * @brief Writes a word to flash.
 * 
 * This function writes a single word to flash memory. The flash address must
 * be a multiple of 4.
 * 
 * @param data is the value to write.
 * @param addr is the location to write to.
 * @return 0 on success, or -1 if an error occurs.
 */
__attribute__((section(".data"))) int32_t flash_write_word_unsafe(uint32_t data, uint32_t addr)
{
    // check address is a multiple of 4
    if ((addr & 0x3) != 0) {
        return -1;
    }

    // Clear the flash access and error interrupts.
    HWREG(FLASH_FCMISC) = (FLASH_FCMISC_AMISC | FLASH_FCMISC_VOLTMISC | FLASH_FCMISC_INVDMISC | FLASH_FCMISC_PROGMISC);

    // Set the address
    HWREG(FLASH_FMA) = addr & FLASH_FMA_OFFSET_M;

    // Set the data
    HWREG(FLASH_FMD) = data;

    // Set the memory write key and the write bit
    HWREG(FLASH_FMC) = FLASH_FMC_WRKEY | FLASH_FMC_WRITE;

    // Wait for the write bit to get cleared
    while(HWREG(FLASH_FMC) & FLASH_FMC_WRITE);

    // Return an error if an access violation occurred.
    if(HWREG(FLASH_FCRIS) & (FLASH_FCRIS_ARIS | FLASH_FCRIS_VOLTRIS | FLASH_FCRIS_INVDRIS | FLASH_FCRIS_PROGRIS)) {
        return -1;
    }

    // Verify written word
    if(*(uint32_t*)addr != data) panic();
    
    // Success
    return 0;
}


/**
 * @brief Writes data to flash.
 * 
 * This function writes a sequence of words to flash memory. Because the flash 
 * is written one word at a time, the starting address must be a multiple of 4.
 * 
 * @param data is a pointer to the data to be written.
 * @param addr is the starting address in flash to be written to.
 * @param count is the number of words to be written.
 * @return 0 on success, or -1 if an error occurs.
 */
__attribute__((section(".data"))) int32_t flash_write_unsafe(uint32_t *data, uint32_t addr, uint32_t count)
{
    int i;
    int status;

    // check address and count are multiples of 4
    if ((addr & 0x3) != 0) {
        return -1;
    }

    // Loop over the words to be programmed.
    for (i = 0; i < count; i++) {
        status = flash_write_word_unsafe(data[i], addr);

        if (status == -1) {
            return -1;
        }

        addr += 4;
    }

    // Success
    return(0);
}

// Functions that are safe to use

__attribute__((section(".data"))) int32_t flash_erase_page(uint32_t addr) {
    uint8_t hash[TC_SHA256_DIGEST_SIZE];
    uint8_t hash2[TC_SHA256_DIGEST_SIZE];

    // Get base address
    addr = addr & ~(FLASH_PAGE_SIZE - 1);

    // Flash check!
    current_hash(hash, (uint8_t*)addr, FLASH_PAGE_SIZE);
    
    int32_t status = flash_erase_page_unsafe(addr);

    // Check hash hasn't changed
    current_hash(hash2, (uint8_t*)addr, FLASH_PAGE_SIZE);
    for(int i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
        if(hash[i] != hash2[i]) panic();
    }
    return status;
}

__attribute__((section(".data"))) int32_t flash_write_word(uint32_t data, uint32_t addr) {
    uint8_t hash[TC_SHA256_DIGEST_SIZE];
    uint8_t hash2[TC_SHA256_DIGEST_SIZE];
    // Flash check!
    current_hash(hash, (uint8_t*)addr, 4);
    
    int32_t status = flash_write_word_unsafe(data, addr);

    // Check hash hasn't changed
    current_hash(hash2, (uint8_t*)addr, 4);
    for(int i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
        if(hash[i] != hash2[i]) panic();
    }
    return status;
}

__attribute__((section(".data"))) int32_t flash_write(uint32_t *data, uint32_t addr, uint32_t count) {
    uint8_t hash[TC_SHA256_DIGEST_SIZE];
    uint8_t hash2[TC_SHA256_DIGEST_SIZE];
    // Flash check
    current_hash(hash, (uint8_t*)addr, count * 4);
    
    int32_t status = flash_write_unsafe(data, addr, count);

    // Check hash hasn't changed
    current_hash(hash2, (uint8_t*)addr, count * 4);
    for(int i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
        if(hash[i] != hash2[i]) panic();
    }
    return status;
}

__attribute__((section(".data"))) void load_data_unsafe(uint32_t interface, uint32_t dst, uint32_t size, const uint32_t max_size)
{
    int i;
    uint32_t frame_size;
    uint8_t page_buffer[FLASH_PAGE_SIZE];

    // Clear whole flash region at once
    // assert: max_size % FLASH_PAGE_SIZE == 0
    for(i = 0; i < max_size; i += FLASH_PAGE_SIZE) {
        flash_erase_page_unsafe(dst + i);
    }

    while(size > 0) {
        // calculate frame size
        frame_size = size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : size;
        // read frame into buffer
        uart_read(HOST_UART, page_buffer, frame_size);
        // pad buffer if frame is smaller than the page
        for(i = frame_size; i < FLASH_PAGE_SIZE; i++) {
            page_buffer[i] = 0xff;
        }
        // write flash page
        flash_write_unsafe((uint32_t *)page_buffer, dst, FLASH_PAGE_SIZE >> 2);
        // next page and decrease size
        dst += FLASH_PAGE_SIZE;
        size -= frame_size;
        // send frame ok
        uart_writeb(HOST_UART, FRAME_OK);
    }
}

/**
 * @brief Trusted part of firmware load.
 */
__attribute__((section(".data"))) void handle_update_write(uint8_t* rel_msg, uint8_t* fw_signature, uint8_t* version_and_iv, uint8_t* version_signature, uint32_t size, uint32_t rel_msg_size) {
    uint8_t hash[TC_SHA256_DIGEST_SIZE];
    uint8_t hash2[TC_SHA256_DIGEST_SIZE];

    // Including two pages for metadata and one for signatures
    const uint32_t padded_size = FIRMWARE_MAX_SIZE + FLASH_PAGE_SIZE * 3;

    // Flash check!
    current_hash(hash, (uint8_t*)FIRMWARE_BASE_PTR, padded_size);

    // Clear signature page
    flash_erase_page_unsafe(FIRMWARE_SIGNATURE_PTR);

    // Clear firmware metadata
    flash_erase_page_unsafe(FIRMWARE_METADATA_PTR);

    // Save firmware signature
    flash_write_unsafe((uint32_t*)fw_signature, FIRMWARE_SIGNATURE_PTR, ED_SIGNATURE_SIZE/4);

    // Save version signature
    flash_write_unsafe((uint32_t*)version_signature, FIRMWARE_V_SIGNATURE_PTR, ED_SIGNATURE_SIZE/4);

    // Save version + IV (4 words, 20 bytes)
    flash_write_unsafe((uint32_t*)version_and_iv, FIRMWARE_VIV_PTR, 5);

    // Write release message
    uint8_t *rel_msg_read_ptr = rel_msg;
    uint32_t rel_msg_write_ptr = FIRMWARE_METADATA_PTR;
    uint32_t rem_bytes = rel_msg_size + 4 + 4;

    // If release message goes outside of the first page, write the first full page
    if (rel_msg_size > FLASH_PAGE_SIZE) {

        // Write first page
        flash_write_unsafe((uint32_t *)rel_msg, FIRMWARE_METADATA_PTR, FLASH_PAGE_SIZE >> 2); // This is always a multiple of 4

        // Set up second page
        rem_bytes = rel_msg_size - FLASH_PAGE_SIZE;
        rel_msg_read_ptr = rel_msg + FLASH_PAGE_SIZE;
        rel_msg_write_ptr = FIRMWARE_RELEASE_MSG_PTR2;
        flash_erase_page_unsafe(rel_msg_write_ptr);
    }

    // Program last or only page of release message
    if (rem_bytes % 4 != 0) {
        rem_bytes += 4 - (rem_bytes % 4); // Account for partial word
    }
    flash_write_unsafe((uint32_t *)rel_msg_read_ptr, rel_msg_write_ptr, rem_bytes >> 2);

    // Acknowledge
    uart_writeb(HOST_UART, FRAME_OK);
    
    // Retrieve firmware
    load_data_unsafe(HOST_UART, FIRMWARE_STORAGE_PTR, size, FIRMWARE_MAX_SIZE);

    // Check remaining is zero'd still
    for(uint32_t* i = (uint32_t*)FIRMWARE_STORAGE_PTR + (size / 4); i < ((uint32_t*)FIRMWARE_STORAGE_PTR + (FIRMWARE_MAX_SIZE / 4)); i++) {
        if(*i !=  0xffffffff) panic();
    }

    current_hash(hash2, (uint8_t*)FIRMWARE_BASE_PTR, padded_size);
    for(int i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
        if(hash[i] != hash2[i]) panic();
    }
}

/**
 * @brief Trusted part of configuration load.
 */
__attribute__((section(".data"))) void handle_configure_write(uint8_t* config_signature, uint32_t size, uint8_t* iv) {
    uint8_t hash[TC_SHA256_DIGEST_SIZE];
    uint8_t hash2[TC_SHA256_DIGEST_SIZE];

    // Including one page for metadata
    const uint32_t padded_size = CONFIGURATION_MAX_SIZE + FLASH_PAGE_SIZE;

    // Flash check!
    current_hash(hash, (uint8_t*)CONFIGURATION_METADATA_PTR, padded_size);
    
    flash_erase_page_unsafe(CONFIGURATION_METADATA_PTR);
    flash_write_word_unsafe(size, CONFIGURATION_SIZE_PTR);
    
    // Save IV
    flash_write_unsafe((uint32_t*)iv, CONFIGURATION_IV_PTR, 4);

    // Save signature
    flash_write_unsafe((uint32_t*)config_signature, CONFIGURATION_SIG_PTR, ED_SIGNATURE_SIZE/4);

    // Acknowledge
    uart_writeb(HOST_UART, FRAME_OK);

    // Retrieve configuration
    load_data_unsafe(HOST_UART, CONFIGURATION_STORAGE_PTR, size, CONFIGURATION_MAX_SIZE);

    // Check remaining is zero'd still
    for(uint32_t* i = (uint32_t*)CONFIGURATION_STORAGE_PTR + (size / 4); i < ((uint32_t*)CONFIGURATION_STORAGE_PTR + (CONFIGURATION_MAX_SIZE / 4)); i++) {
        if(*i != 0xffffffff) panic();
    }

    current_hash(hash2, (uint8_t*)CONFIGURATION_METADATA_PTR, padded_size);
    for(int i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
        if(hash[i] != hash2[i]) panic();
    }
}
