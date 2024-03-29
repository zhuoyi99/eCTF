#ifndef CONSTANTS_H
#define CONSTANTS_H

// Storage layout

/*
 * Firmware:
 *      Reserved:0x0002B000 : 0x0002B300 (768B)
 *      FW Sig:  0x0002B300 : 0x0002B340 (64B, ED_SIGNATURE_SIZE)
 *      Ver Sig: 0x0002B340 : 0x0002B380 (64B, ED_SIGNATURE_SIZE)
 *      SV+IV:   0x0002B380 : 0x0002B394 (4+16B)
 *      Padding: 0x0002B394 : 0x0002B400
 *      Size:    0x0002B400 : 0x0002B404 (4B)
 *      Version: 0x0002B404 : 0x0002B408 (4B)
 *      Msg:     0x0002B408 : 0x0002BC00 (~2KB = 1KB + 1B + pad)
 *      Fw:      0x0002BC00 : 0x0002FC00 (16KB)
 * Configuration:
 *      Size:    0x0002FC00 : 0x0002FC40 (1KB = 4B + 60B of padding)
 *      Sig:     0x0002FC40 : 0x0002FC80 (64B, ED_SIGNATURE_SIZE)
 *      IV:      0x0002FC80 : 0x0002FC90 (16B)
 *      Padding: 0x0002FC94 : 0x00030000 (880B)
 *      Cfg:     0x00030000 : 0x00040000 (64KB)
 */
#define FIRMWARE_BASE_PTR          ((uint32_t)(FLASH_START + 0x0002B000))
#define FIRMWARE_SIGNATURE_PTR     ((uint32_t)(FLASH_START + 0x0002B300))
#define FIRMWARE_V_SIGNATURE_PTR   ((uint32_t)(FLASH_START + 0x0002B340))
#define FIRMWARE_VIV_PTR            ((uint32_t)(FLASH_START + 0x0002B380))

#define FIRMWARE_METADATA_PTR      ((uint32_t)(FLASH_START + 0x0002B400))
#define FIRMWARE_SIZE_PTR          ((uint32_t)(FIRMWARE_METADATA_PTR + 0))
#define FIRMWARE_VERSION_PTR       ((uint32_t)(FIRMWARE_METADATA_PTR + 4))
#define FIRMWARE_RELEASE_MSG_PTR   ((uint32_t)(FIRMWARE_METADATA_PTR + 8))
#define FIRMWARE_RELEASE_MSG_PTR2  ((uint32_t)(FIRMWARE_METADATA_PTR + FLASH_PAGE_SIZE))

#define FIRMWARE_STORAGE_PTR       ((uint32_t)(FIRMWARE_METADATA_PTR + (FLASH_PAGE_SIZE*2)))
#define FIRMWARE_BOOT_PTR          ((uint32_t)0x20004000)

#define CONFIGURATION_METADATA_PTR ((uint32_t)(FIRMWARE_STORAGE_PTR + (FLASH_PAGE_SIZE*16)))
#define CONFIGURATION_SIZE_PTR     ((uint32_t)(CONFIGURATION_METADATA_PTR + 0))
#define CONFIGURATION_SIG_PTR      ((uint32_t)(CONFIGURATION_METADATA_PTR + 0x40))
#define CONFIGURATION_IV_PTR       ((uint32_t)(CONFIGURATION_METADATA_PTR + 0x80))
#define CONFIGURATION_STORAGE_PTR  ((uint32_t)(CONFIGURATION_METADATA_PTR + FLASH_PAGE_SIZE))

// Maximum sizes
#define FIRMWARE_MAX_SIZE       0x4000
#define CONFIGURATION_MAX_SIZE  0x10000

#define EEPROM_BLOCK 64

// Digital signature related
#define ED_SIGNATURE_SIZE 64
// Location of public key on EEPROM
#define ED_PUBLIC_KEY_LOCATION 0
#define DEFAULT_VERSION_SIGNATURE_LOCATION (1 * EEPROM_BLOCK)

// Location of Encryption/Decryption key on EEPROM
#define ED_ENCRYPTION_KEY_LOCATION (2 * EEPROM_BLOCK)

// Authentication constants
#define AUTH_KEY_LEN 32           // assume 32 byte key
#define AUTH_CH_LEN 32            // challenge is a 32B SHA256 digest 
#define AUTH_DIGEST_LEN 32        // SHA256 

#define AUTH_EEPROM_BLOCK (3 * EEPROM_BLOCK) // base addr for 64B auth block
#define AUTH_KEY (AUTH_EEPROM_BLOCK + 0x0)

// Randomness constants
#define RAND_BUF_LEN 32            // challenge is a 32B SHA256 digest 
#define RAND_CTR_LEN 32 
#define RAND_SEED_LEN 64
#define RAND_CTR (AUTH_EEPROM_BLOCK + AUTH_KEY_LEN)
#define RAND_SEED (4 * EEPROM_BLOCK)

// Panic bit on EEPROM
#define PANIC_BIT_LOC (5 * EEPROM_BLOCK)

// Booted bit on EEPROM
#define BOOTED_BIT_LOC (6 * EEPROM_BLOCK)

// Firmware update constants
#define FRAME_OK 0x00
#define FRAME_BAD 0x01

#endif
