# Encryption
Encryption is done using AES-256 in CBC mode and keys are stored in EEPROM and SRAM.

Keys are generated using /dev/urandom and encryption on the client side uses pyca's cryptography library. Decryption on the bootloader side is done via masked-AES-c, a fork of tiny-AES-c that performs random masking.
