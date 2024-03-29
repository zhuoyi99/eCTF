#include "flash_check.h"
#include <stdbool.h>
#include <stdint.h>

#include "constants.h"
#include "driverlib/eeprom.h"
#include "uart.h"

/*
 * @brief Returns the hash of all flash memory OUTSIDE the region start, start+size.
 * out must be at least TC_SHA256_DIGEST_SIZE bytes.
 */
__attribute__((section(".data"))) void current_hash(uint8_t* out, uint8_t* start, uint32_t size) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (uint8_t*)0x5800, (uint32_t)start - 0x5800);
    sha256_update(&ctx, start + size, 0x40000 - (uint32_t)(start + size));
    sha256_final(&ctx, out);
}

/*
 * @brief A function that prevents the device from leaking secrets without returning to flash.
 * Sends the byte 'P' over UART repeatedly.
 */
__attribute__((section(".data"), noreturn)) void panic(void) {
    uint8_t buf[EEPROM_BLOCK];
    for(uint32_t i = 0; i < EEPROM_BLOCK; i++)
        buf[i] = 0;
    // Clear secrets
    EEPROMProgram((uint32_t*)buf, ED_ENCRYPTION_KEY_LOCATION, EEPROM_BLOCK);
    EEPROMProgram((uint32_t*)buf, AUTH_EEPROM_BLOCK, EEPROM_BLOCK);
    EEPROMProgram((uint32_t*)buf, RAND_SEED, EEPROM_BLOCK);
    // Set "panicking" bit
    EEPROMProgram((uint32_t*)buf, PANIC_BIT_LOC, 4);
    // infinite loop
    while(1) {
        // Let host tools know what happened
        uart_writeb(HOST_UART, 'P');
        // Block on waiting
        uart_readb(HOST_UART);
    }       
}

