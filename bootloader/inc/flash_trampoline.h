#ifndef FLASH_TRAMPOLINE_H
#define FLASH_TRAMPOLINE_H

#include <tinycrypt/sha256.h>

/*
 * Returns the hash of all flash memory OUTSIDE the region start, start+size.
 * out must be at least TC_SHA256_DIGEST_SIZE bytes.
 */
void current_hash(uint8_t* out, uint8_t* start, uint32_t size);

/*
 * A function that bricks the device without returning to flash.
 */
__attribute__ ((noreturn)) void panic(void);

#endif
