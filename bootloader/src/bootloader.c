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

#include <stdint.h>
#include <stdbool.h>

#include "driverlib/interrupt.h"
#include "driverlib/sysctl.h"
#include "driverlib/eeprom.h"
#include "inc/hw_eeprom.h"
#include "inc/hw_types.h"

#include "constants.h"
#include "flash.h"
#include "mpu.h"
#include "uart.h"

// #include "tinycrypt/aes.h"
// #include "tinycrypt/cbc_mode.h"
#include "aes.h"

// ED25519 Signatures
#include "ed25519.h"
// SRAM variable
unsigned char ED_PUBLIC_KEY[32];
// Helper to verify signatures
#define signature_verify(signature, storage, size) ed25519_verify(signature, storage, size, ED_PUBLIC_KEY)

// SHA512 from the ED25519 library
#include "sha512.h"

// Authentication uses SHA256
#include "sha256.h" // same sha256 include as flash_trampoline.h

/**
 * @brief Increment a counter variable stored on EEPROM.
 */
void inc_counter (uint8_t *counter) {
    uint8_t *loc = counter + AUTH_CTR_LEN - 1;
    while (loc != counter - 1) {
	(*loc)++;
	if (*loc != 0x0) {
            break;
	}
        --loc;
    }

    EEPROMProgram((uint32_t *) counter, AUTH_CTR, AUTH_CTR_LEN);
}

/**
 * @brief Device side authentication, issue challenge, validate response, respond to challenge
 * 
 * @return true if mutual authentication succeeded, false if some step failed
 */
// bool auth (uint8_t *counter, uint8_t *seed) {
bool auth (void) {
    // secrets should be created with generate_secrets in host_tools (for the host computer) 
    //     and with Dockerfile 1 (for the bootloader) (use bootloader/eeprom.bin, which gets used in Dockerfile 2) 

    // create random 32B value by basically doing challenge = SHA(counter + seed); counter++;
    uint8_t counter[AUTH_CTR_LEN];
    uint8_t seed[AUTH_SEED_LEN];
    EEPROMRead((uint32_t *) counter, AUTH_CTR, AUTH_CTR_LEN);
    EEPROMRead((uint32_t *) seed, AUTH_SEED, AUTH_SEED_LEN);
    
    uint8_t challenge[AUTH_CH_LEN]; 
    SHA256_CTX chal_ctx;
    sha256_init(&chal_ctx);
    sha256_update(&chal_ctx, counter, AUTH_CTR_LEN);
    sha256_update(&chal_ctx, seed, AUTH_SEED_LEN);
    sha256_final(&chal_ctx, challenge);
    inc_counter(counter);

    // get symmetric key from EEPROM
    uint8_t sym_key[AUTH_KEY_LEN];
    // 2nd arg = address, 3rd arg = number bytes; both must be multiples of 4
    EEPROMRead((uint32_t *) sym_key, AUTH_KEY, AUTH_KEY_LEN);

    // issue challenge
    uart_write(HOST_UART, challenge, AUTH_CH_LEN);

    // compute expected digest, basically SHA256(challenge + key) 
    uint8_t expected_digest[AUTH_DIGEST_LEN];
    SHA256_CTX auth_ctx;
    sha256_init(&auth_ctx);
    sha256_update(&auth_ctx, challenge, AUTH_CH_LEN);
    sha256_update(&auth_ctx, sym_key, AUTH_KEY_LEN);
    sha256_final(&auth_ctx, expected_digest);

    // receive challenge response, SHA256 digest is 256b = 32B
    uint8_t host_ans[AUTH_DIGEST_LEN];
    uart_read(HOST_UART, host_ans, AUTH_DIGEST_LEN);

    // verify response byte-by-byte
    uint32_t index;
    for (index = 0; index < AUTH_DIGEST_LEN; ++index) {
        if (expected_digest[index] != host_ans[index]) {
            uart_writeb(HOST_UART, FRAME_BAD);
            return false;
        }   
    }

    // send authentication OK to host_tools 
    uart_writeb(HOST_UART, FRAME_OK);
    return true;
}

/**
 * @brief Boot the firmware.
 */
void handle_boot(void)
{
    uint32_t size, cfg_size;
    uint8_t *rel_msg;
    struct AES_ctx ctx;
    unsigned char ENC_KEY[32];

    // Acknowledge the host
    uart_writeb(HOST_UART, 'B');

    // Probably not needed, but verify signature of version
    uint8_t version_and_iv[20];
    for(uint32_t i = 0; i < 5; i++)
        *((uint32_t*)version_and_iv + i) = *((uint32_t*)FIRMWARE_VIV_PTR + i);

    if(!signature_verify((uint8_t*)FIRMWARE_V_SIGNATURE_PTR, (uint8_t*)version_and_iv, sizeof(version_and_iv))) {
        uart_writeb(HOST_UART, 'Z');
        return;
    }


    // Find the metadata
    size = *((uint32_t *)FIRMWARE_SIZE_PTR);
    // Unitialized firmware - just return
    if(size > FIRMWARE_MAX_SIZE) {
        uart_writeb(HOST_UART, 'I');
        return;
    }

    cfg_size = *(uint32_t*)CONFIGURATION_SIZE_PTR;
    // Unitialized configuration - just return
    if(cfg_size > CONFIGURATION_MAX_SIZE) {
        uart_writeb(HOST_UART, 'J');
        return;
    }

    EEPROMRead((uint32_t*)&ENC_KEY, ED_ENCRYPTION_KEY_LOCATION, 32);
    AES_init_ctx(&ctx, ENC_KEY);
    AES_ctx_set_iv(&ctx, (uint8_t*)FIRMWARE_VIV_PTR+4);
    for(uint32_t i = 0; i < size; i++) {
        *((uint8_t*)FIRMWARE_BOOT_PTR + i) = *((uint8_t*)FIRMWARE_STORAGE_PTR + i);
    }
    AES_CBC_decrypt_buffer(&ctx, (uint8_t*)FIRMWARE_BOOT_PTR, size);

    // Verify firmware signature
    if(!signature_verify((uint8_t*)FIRMWARE_SIGNATURE_PTR, (uint8_t*)FIRMWARE_BOOT_PTR, size)) {
        uart_writeb(HOST_UART, 'S');
        return;
    }

    // TODO Decrypt config
    // cfg_decrypt(CONFIGURATION_STORAGE_PTR, (uint8_t*)CONFIGURATION_IV_PTR, cfg_size, &ctx);
    
    // Verify configuration signature
    if(!signature_verify((uint8_t*)CONFIGURATION_SIG_PTR, (uint8_t*)CONFIGURATION_STORAGE_PTR, cfg_size)) {
        // We don't have to re-encrypt the config since if it was a valid fw in the first palce we would have booted
        uart_writeb(HOST_UART, 'C');
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
    uint8_t *iv;
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
        iv = (uint8_t *)FIRMWARE_VIV_PTR;
        // Acknowledge the host
        uart_writeb(HOST_UART, 'F');
    } else if (region == 'C') {
        // Set the base address for the readback
        address = (uint8_t *)CONFIGURATION_STORAGE_PTR;
        size = *((uint32_t *)CONFIGURATION_SIZE_PTR);
        signature = (uint8_t *)CONFIGURATION_SIG_PTR;
        iv = (uint8_t *)CONFIGURATION_IV_PTR;
        // Acknowledge the host
        uart_writeb(HOST_UART, 'C');
    } else {
        return;
    }
    
    // Read out size
    uart_write(HOST_UART, (uint8_t*)&size, sizeof(size));

    // Read out signature
    uart_write(HOST_UART, signature, ED_SIGNATURE_SIZE);
    
    // Read out signed ver, IV
    uart_write(HOST_UART, iv, 20);
    
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
    uint8_t version_and_iv[20];

    // Acknowledge the host
    uart_writeb(HOST_UART, 'U');

    // Receive version
    version = ((uint32_t)uart_readb(HOST_UART)) << 8;
    version |= (uint32_t)uart_readb(HOST_UART);

    *(uint32_t*)version_and_iv = version;

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

    // Receive IV
    uart_read(HOST_UART, version_and_iv+4, 16);

    // Receive digital signature of firmware
    uint8_t fw_signature[ED_SIGNATURE_SIZE];
    uart_read(HOST_UART, fw_signature, ED_SIGNATURE_SIZE);

    // Receive digital signature of version number
    uint8_t version_signature[ED_SIGNATURE_SIZE];
    uart_read(HOST_UART, version_signature, ED_SIGNATURE_SIZE);
    
    // Receive release message
    rel_msg_size = uart_readline(HOST_UART, rel_msg + 8, 1024) + 1; // Include terminator

    // Check the version signature (done after just so bytes read is constant)
    if(!signature_verify(version_signature, (uint8_t*)version_and_iv, sizeof(version_and_iv))) {
        uart_writeb(HOST_UART, 'S');
        return;
    }
    
    // Check the version
    current_version = *((uint32_t *)FIRMWARE_VERSION_PTR);

    uint8_t version_and_iv_old[20];
    // Just in case...
    // Default version is signed with default IV in storage 0xff...
    for(uint32_t i = 0; i < 5; i++)
        *((uint32_t*)version_and_iv_old + i) = *((uint32_t*)FIRMWARE_VIV_PTR + i);

    if(!signature_verify((uint8_t*)FIRMWARE_V_SIGNATURE_PTR, (uint8_t*)version_and_iv_old, sizeof(version_and_iv_old))) {
        uart_writeb(HOST_UART, 'Z');
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

    // Only save new version to permanent area if it is not 0
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

    handle_update_write(rel_msg, fw_signature, version_and_iv, version_signature, size, rel_msg_size);
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

// Linker segment definitions
extern uint32_t _data;
extern uint32_t _edata;
extern uint32_t _ldata;

/**
 * @brief Handle an integrity challenge of itself.
 */
void handle_integrity_challenge(void) {
    sha512_context hash;
    unsigned char challenge[12];
    unsigned char out[64];

    uart_writeb(HOST_UART, 'R');

    uart_read(HOST_UART, challenge, 12);
    sha512_init(&hash); // If it fails at any step, final hash is bad so whatever
    sha512_update(&hash, challenge, 12);
    // Flash
    uint8_t* start = (uint8_t*)0x5800;
    uint32_t size = 0x2B000 - 0x5800;
    sha512_update(&hash, start, size);
    // SRAM .data section
    start = (uint8_t*)&_data;
    size = (uint8_t*)&_edata - (uint8_t*)&_data;
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
    // Stack space collision causes problems after a soft reset here.
    // I am not sure why it's not properly restored by Bootloader_Startup, but the instructions get clobbered - likely a bug with the stack after resets. We get to do this ourselves.
    uint32_t* source = &_ldata;
    for(uint32_t* start = &_data; start < &_edata;)
        *start++ = *source++;

    // Enable MPU
    mpu_setup();

    // If we need to set up permissions, do so.
    uint32_t control_reg;
    // This inline assembly just loads the CONTROL register into a variable.
    __asm ("mrs %[result], CONTROL" : [result] "=r" (control_reg));
    if((control_reg & 1) == 0) {
        // No need for interrupts for us
        IntMasterDisable();
        // Enter unpriviledged mode
        __asm volatile ("mov r0, #1\nmsr CONTROL, r0" : : : "r0");
    }

    // Initialize IO components
    uart_init();

    // Initialize EEPROM
    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    EEPROMInit();

    // Read signature public key from EEPROM
    EEPROMRead((uint32_t*)&ED_PUBLIC_KEY, ED_PUBLIC_KEY_LOCATION, 32);

    // Only read this if needed
    if((HWREG(EEPROM_EEHIDE) & (1 << EEPROMBlockFromAddr(DEFAULT_VERSION_SIGNATURE_LOCATION))) == 0) {
        uint8_t default_version_signature[ED_SIGNATURE_SIZE];
        EEPROMRead((uint32_t*)default_version_signature, DEFAULT_VERSION_SIGNATURE_LOCATION, ED_SIGNATURE_SIZE);
        EEPROMBlockHide(EEPROMBlockFromAddr(DEFAULT_VERSION_SIGNATURE_LOCATION));
        flash_write((uint32_t*)default_version_signature, FIRMWARE_V_SIGNATURE_PTR, ED_SIGNATURE_SIZE/4);
    }

    uint8_t cmd = 0;

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
            // CHAP Authentication
            if (auth()) {
                handle_readback();
            }
            break;
        case 'B':
            handle_boot();
            break;
        default:
            break;
        }
    }
}
