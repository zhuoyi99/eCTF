#ifndef FLASH_CHECK_H
#define FLASH_CHECK_H

#include <sha256.h>
#include <stdint.h>
#define TC_SHA256_DIGEST_SIZE 32

/*
 * @brief Returns the hash of all flash memory OUTSIDE the region start, start+size.
 * out must be at least TC_SHA256_DIGEST_SIZE bytes.
 */
void current_hash(uint8_t* out, uint8_t* start, uint32_t size);

/*
 * @brief A function that prevents the device from leaking secrets without returning to flash.
 * Sends the byte 'P' over UART repeatedly.
 */
__attribute__ ((noreturn)) void panic(void);

#endif
