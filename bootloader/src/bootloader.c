/**
 * @file bootloader.c
 * @author Kyle Scaplen
 * @brief Bootloader implementation
 * @date 2022
 * 
 * This source file is part of an example system for MITRE's 2022 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2022 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 * 
 * @copyright Copyright (c) 2022 The MITRE Corporation
 */

// DUMMY FW/CFG ENCRYPTION KEY ***** REMOVE IN THE SUBMISSSION*******
char DUMMY_ENC_KEY[32] = {0x97,0xf1,0xe7,0x1a,0x7b,0xf9,0x69,0x94,0xb5,0x68,0x20,0x59,0x94,0xf8,
    0xb8,0x57,0x92,0xe3,0xc5,0x62,0xe3,0x7a,0x1e,0xae,0x41,0xa0,0x51,0xbe,0x26,0xbe,0x11,0xc8};

#include <stdint.h>
#include <stdbool.h>

#include "driverlib/interrupt.h"
#include "driverlib/sysctl.h"
#include "driverlib/eeprom.h"

#include "constants.h"
#include "flash.h"
#include "uart.h"

#include "tinycrypt/aes.h"
#include "tinycrypt/cbc_mode.h"
// this will run if EXAMPLE_AES is defined in the Makefile (see line 54)
#ifdef EXAMPLE_AES
#include "aes.h"
#endif

// ED25519 Signatures
#include "ed25519.h"
// SRAM variable (TODO: Move this?)
unsigned char ED_PUBLIC_KEY[32];
// Helper to verify signatures
#define signature_verify(signature, storage, size) ed25519_verify(signature, storage, size, ED_PUBLIC_KEY)

// KEY, IV and schedule struct for firmware decryption
unsigned char ENC_KEY[32];
unsigned char ENC_IV[16];
struct tc_aes_key_sched_struct sched;

// SHA512 from the ED25519 library
#include "sha512.h"

// Storage layout

/*
    Decrypt Fimrware/configuration before boot/update
*/
void Decrypt(uint8_t * out, const uint8_t * in, unsigned int len)
{
    tc_cbc_mode_decrypt(out, len, in, len, ENC_IV, &sched);
}

/**
 * @brief Boot the firmware.
 */
void handle_boot(void)
{
    uint32_t size;
    uint32_t i = 0;
    uint8_t *rel_msg;

    // Acknowledge the host
    uart_writeb(HOST_UART, 'B');

    // Find the metadata
    size = *((uint32_t *)FIRMWARE_SIZE_PTR);

    uint8_t fbuf[size];
    Decrypt(fbuf, (uint8_t*)(FIRMWARE_STORAGE_PTR), size);
    // Copy the firmware into the Boot RAM section
    for (i = 0; i < size; i++) {
        *((uint8_t *)(FIRMWARE_BOOT_PTR + i)) = fbuf[i];
    }

    // Probably not needed, but verify signature of version
    if(!signature_verify((uint8_t*)FIRMWARE_V_SIGNATURE_PTR, (uint8_t*)FIRMWARE_VERSION_PTR, sizeof(uint32_t))) {
        uart_writeb(HOST_UART, 'S');
        return;
    }

    // Verify firmware signature
    if(!signature_verify((uint8_t*)FIRMWARE_SIGNATURE_PTR, fbuf, size)) {
        uart_writeb(HOST_UART, 'S');
        return;
    }

    // TODO Decrypt configuration in-place
    
    // Verify configuration signature
    if(!signature_verify((uint8_t*)CONFIGURATION_SIG_PTR, (uint8_t*)CONFIGURATION_STORAGE_PTR, *(uint32_t*)CONFIGURATION_SIZE_PTR)) {
        uart_writeb(HOST_UART, 'S');
        return;
    }

    uart_writeb(HOST_UART, 'M');

    // Print the release message
    rel_msg = (uint8_t *)FIRMWARE_RELEASE_MSG_PTR;
    while (*rel_msg != 0) {
        uart_writeb(HOST_UART, *rel_msg);
        rel_msg++;
    }
    uart_writeb(HOST_UART, '\0');

    // Execute the firmware
    void (*firmware)(void) = (void (*)(void))(FIRMWARE_BOOT_PTR + 1);
    firmware();
}


/**
 * @brief Send the firmware data over the host interface.
 */
void handle_readback(void)
{
    uint8_t region;
    uint8_t *address;
    uint8_t *signature;
    uint32_t size = 0;
    
    // Acknowledge the host
    uart_writeb(HOST_UART, 'R');

    // Receive region identifier
    region = (uint32_t)uart_readb(HOST_UART);

    if (region == 'F') {
        // Set the base address for the readback
        address = (uint8_t *)FIRMWARE_STORAGE_PTR;
        size = *((uint32_t *)FIRMWARE_SIZE_PTR);
        signature = (uint8_t *)FIRMWARE_SIGNATURE_PTR;
        // Acknowledge the host
        uart_writeb(HOST_UART, 'F');
    } else if (region == 'C') {
        // Set the base address for the readback
        address = (uint8_t *)CONFIGURATION_STORAGE_PTR;
        size = *((uint32_t *)CONFIGURATION_SIZE_PTR);
        signature = (uint8_t *)CONFIGURATION_SIG_PTR;
        // Acknowledge the host
        uart_writeb(HOST_UART, 'C');
    } else {
        return;
    }
    
    // Read out size
    uart_write(HOST_UART, &size, sizeof(size));

    // Read out signature
    uart_write(HOST_UART, signature, ED_SIGNATURE_SIZE);
    
    
    // Wait for host to be ready
    uart_readb(HOST_UART);

    // Read out the memory
    uart_write(HOST_UART, address, size);
}

// load_data was moved to flash.c since it sits in SRAM now

/**
 * @brief Update the firmware.
 */
void handle_update(void)
{
    // metadata
    uint32_t current_version;
    uint32_t version = 0;
    uint32_t size = 0;
    uint32_t rel_msg_size = 0;
    uint8_t rel_msg[1024 + 1 + 4 + 4]; // 1024 + terminator + version + size

    // Acknowledge the host
    uart_writeb(HOST_UART, 'U');

    // Receive version
    version = ((uint32_t)uart_readb(HOST_UART)) << 8;
    version |= (uint32_t)uart_readb(HOST_UART);

    // Receive size
    size = ((uint32_t)uart_readb(HOST_UART)) << 24;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 16;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 8;
    size |= (uint32_t)uart_readb(HOST_UART);
    // Validate this is sensible (within 16kb limit)
    if(size > FIRMWARE_MAX_SIZE) {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }
    
    // Receive digital signature of firmware
    uint8_t fw_signature[ED_SIGNATURE_SIZE];
    uart_read(HOST_UART, fw_signature, ED_SIGNATURE_SIZE);

    // Receive digital signature of version number
    uint8_t version_signature[ED_SIGNATURE_SIZE];
    uart_read(HOST_UART, version_signature, ED_SIGNATURE_SIZE);
    
    // Receive release message
    rel_msg_size = uart_readline(HOST_UART, rel_msg + 8, 1024) + 1; // Include terminator

    // Check the version signature (done after just so bytes read is constant)
    if(!signature_verify(version_signature, (uint8_t*)&version, sizeof(version))) {
        uart_writeb(HOST_UART, 'S');
        return;
    }
    
    // Check the version
    current_version = *((uint32_t *)FIRMWARE_VERSION_PTR);

    // Just in case...
    // Default version is signed
    if(!signature_verify((uint8_t*)FIRMWARE_V_SIGNATURE_PTR, (uint8_t*)FIRMWARE_VERSION_PTR, sizeof(uint32_t))) {
        uart_writeb(HOST_UART, 'S');
        return;
    }

    if (current_version == 0xFFFFFFFF) {
        current_version = (uint32_t)OLDEST_VERSION;
    }

    if ((version != 0) && (version < current_version)) {
        // Version is not acceptable
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }

    // Writes have been merged to save time in writing

    // Only save new version if it is not 0
    if (version != 0) {
        // flash_write_word(version, FIRMWARE_VERSION_PTR);
        *(uint32_t*)(rel_msg+4) = version;
    } else {
        // flash_write_word(current_version, FIRMWARE_VERSION_PTR);
        *(uint32_t*)(rel_msg+4) = current_version;
    }

    // Save size
    // flash_write_word(size, FIRMWARE_SIZE_PTR);
    *(uint32_t*)rel_msg = size;

    handle_update_write(rel_msg, fw_signature, version_signature, size, rel_msg_size);
}

/**
 * @brief Load configuration data.
 */
void handle_configure(void)
{
    uint32_t size = 0;

    // Acknowledge the host
    uart_writeb(HOST_UART, 'C');

    // Receive size
    size = (((uint32_t)uart_readb(HOST_UART)) << 24);
    size |= (((uint32_t)uart_readb(HOST_UART)) << 16);
    size |= (((uint32_t)uart_readb(HOST_UART)) << 8);
    size |= ((uint32_t)uart_readb(HOST_UART));
    // Validate this is sensible (within limit)
    if(size > CONFIGURATION_MAX_SIZE) {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }
    uart_writeb(HOST_UART, FRAME_OK);

    // Receive digital signature of firmware
    uint8_t config_signature[ED_SIGNATURE_SIZE];
    uart_read(HOST_UART, config_signature, ED_SIGNATURE_SIZE);
 
    // Perform writes on SRAM
    handle_configure_write(config_signature, size);
}

/**
 * @brief Handle an integrity challenge of itself.
 */
void handle_integrity_challenge(void) {
    sha512_context hash;
    unsigned char challenge[12];
    unsigned char out[64];

    uart_writeb(HOST_UART, 'R');

    unsigned char* start;
    uint32_t size;
    uart_read(HOST_UART, (unsigned char*)&start, sizeof(start));
    uart_read(HOST_UART, (unsigned char*)&size, sizeof(size));
    // Sanity check, sorry for all the casts...
    if(start > (unsigned char*)0x40000 ||
            size > 0x40000 || (start + size) > (unsigned char*)0x40000) return;
    uart_read(HOST_UART, challenge, 12);
    sha512_init(&hash); // If it fails at any step, final hash is bad so whatever
    sha512_update(&hash, challenge, 12);
    sha512_update(&hash, start, size);
    sha512_final(&hash, out);
    uart_write(HOST_UART, out, 64);
}



/**
 * @brief Host interface polling loop to receive configure, update, readback,
 * and boot commands.
 * 
 * @return int
 */
int main(void) {

    uint8_t cmd = 0;

#ifdef EXAMPLE_AES
    // -------------------------------------------------------------------------
    // example encryption using tiny-AES-c
    // -------------------------------------------------------------------------
    struct AES_ctx ctx;
    uint8_t key[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 
                        0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
    uint8_t plaintext[16] = "0123456789abcdef";

    // initialize context
    AES_init_ctx(&ctx, key);

    // encrypt buffer (encryption happens in place)
    AES_ECB_encrypt(&ctx, plaintext);

    // decrypt buffer (decryption happens in place)
    AES_ECB_decrypt(&ctx, plaintext);
    // -------------------------------------------------------------------------
    // end example
    // -------------------------------------------------------------------------
#endif

    // Initialize IO components
    uart_init();

    // Initialize EEPROM
    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    EEPROMInit();

    // Read signature public key from EEPROM - this block cannot be hidden
    EEPROMRead((uint32_t*)&ED_PUBLIC_KEY, ED_PUBLIC_KEY_LOCATION, 32);
    EEPROMRead((uint32_t*)&ENC_KEY, ED_ENCRYPTION_KEY_LOCATION, 32);
    EEPROMRead((uint32_t*)&ENC_IV, ED_ENCRYPTION_IV_LOCATION, 16);

    // Set up the decryption key

    tc_aes128_set_decrypt_key(&sched, ENC_KEY);

    { // Anonymous block
        uint8_t default_version_signature[ED_SIGNATURE_SIZE];
        EEPROMRead((uint32_t*)default_version_signature, DEFAULT_VERSION_SIGNATURE_LOCATION, ED_SIGNATURE_SIZE);
        EEPROMBlockHide(EEPROMBlockFromAddr(DEFAULT_VERSION_SIGNATURE_LOCATION));
        flash_write((uint32_t*)default_version_signature, FIRMWARE_V_SIGNATURE_PTR, ED_SIGNATURE_SIZE/4);
    }

    // Handle host commands
    while (1) {
        cmd = uart_readb(HOST_UART);

        switch (cmd) {
        case 'I':
            handle_integrity_challenge();
            break;
        case 'C':
            handle_configure();
            break;
        case 'U':
            handle_update();
            break;
        case 'R':
            handle_readback();
            break;
        case 'B':
            handle_boot();
            break;
        default:
            break;
        }
    }
}
