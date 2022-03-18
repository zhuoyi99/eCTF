#ifndef CFG_DECRYPT_H
#define CFG_DECRYPT_H

#include "aes.h"

/**
 * @brief Encrypts/decrypts the configuration in place. Assumes ctx has been initialized with key and IV.
 */
void cfg_crypt(uint8_t* configuration_storage, uint32_t size, struct AES_ctx* ctx, const _Bool encrypt);

#endif
