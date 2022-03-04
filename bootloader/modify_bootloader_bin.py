# Append random data to the bootloader to fill up space, which is checked by the integrity checking process

import secrets

FLASH_START = 0x5800
USABLE_FLASH_SIZE = 0x40000 - FLASH_START
FIRMWARE_VERSION_PTR = 0x0002B400 + 4 - FLASH_START

with open("/bl_build/gcc/bootloader.bin", "rb") as f:
    bootloader = f.read()

bootloader = bytearray(bootloader + secrets.token_bytes(USABLE_FLASH_SIZE - len(bootloader)))

# Default version number should be set to this
bootloader[FIRMWARE_VERSION_PTR:FIRMWARE_VERSION_PTR+4] = b"\xff\xff\xff\xff"

# Back to bytes
bootloader = bytes(bootloader)

with open("/bl_build/gcc/bootloader.bin", "wb") as f:
    f.write(bootloader)
