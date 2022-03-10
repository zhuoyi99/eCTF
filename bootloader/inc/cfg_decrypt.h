#ifndef CFG_DECRYPT_H
#define CFG_DECRYPT_H

#include "aes.h"

/**
 * @brief Decrypts the configuration in place.
 */
void cfg_decrypt(uint8_t* configuration_storage, uint8_t* iv, uint32_t size, struct AES_ctx* ctx);

#endif
