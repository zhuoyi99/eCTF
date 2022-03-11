#ifndef CFG_DECRYPT_H
#define CFG_DECRYPT_H

#include "aes.h"

/**
 * @brief Decrypts the configuration in place. Assumes ctx has been initialized with key and IV.
 */
void cfg_decrypt(uint8_t* configuration_storage, uint32_t size, struct AES_ctx* ctx);

#endif
