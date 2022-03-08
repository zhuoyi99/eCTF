# Append random data to the bootloader to fill up space, which is checked by the integrity checking process

import secrets

FLASH_START = 0x5800
USABLE_FLASH_SIZE = 115 * 1024

with open("/bl_build/gcc/bootloader.bin", "rb") as f:
    bootloader = f.read()

bootloader = bootloader + secrets.token_bytes(USABLE_FLASH_SIZE - len(bootloader))

with open("/bl_build/gcc/bootloader.bin", "wb") as f:
    f.write(bootloader)
