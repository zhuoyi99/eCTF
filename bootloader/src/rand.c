#include "rand.h"
#include "sha256.h"
#include "inc/hw_eeprom.h"
#include "driverlib/eeprom.h"

/**
 * @brief Increment a counter variable stored on EEPROM.
 */
__attribute__((section(".data"))) void inc_counter (uint8_t *counter) {
    uint8_t *loc = counter + RAND_CTR_LEN - 1;
    while (loc != counter - 1) {
	(*loc)++;
	if (*loc != 0x0) {
            break;
	}
        --loc;
    }

    EEPROMProgram((uint32_t *) counter, RAND_CTR, RAND_CTR_LEN);
}

__attribute__((section(".data"))) void rand_buf(uint8_t* buf) {
    // create random 32B value by basically doing buf = SHA(counter + seed); counter++;

    uint8_t counter[RAND_CTR_LEN];
    uint8_t seed[RAND_SEED_LEN];
    EEPROMRead((uint32_t *) counter, RAND_CTR, RAND_CTR_LEN);
    EEPROMRead((uint32_t *) seed, RAND_SEED, RAND_SEED_LEN);

    SHA256_CTX chal_ctx;
    sha256_init(&chal_ctx);
    sha256_update(&chal_ctx, counter, RAND_CTR_LEN);
    sha256_update(&chal_ctx, seed, RAND_SEED_LEN);
    sha256_final(&chal_ctx, buf);
    inc_counter(counter);
}
