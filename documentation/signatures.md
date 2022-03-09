# Digital Signatures

Digital signatures have been implemented with the ED25519 signature scheme.

To sign data on the host tools, use the `sign` function in the `utils` module. This requires access to secrets.

```python
from utils import sign

sign(data) # type: bytes, length: 64
```

To verify a signature on the device, use the `signature_verify` macro. The signature requires `ED_SIGNATURE_SIZE` bytes, which is defined to be 64.

```c
if(!signature_verify((uint8_t*)SIGNATURE_PTR, (uint8_t*)DATA_PTR, size)) {
    // Failure case
    uart_writeb(HOST_UART, 'S');
    return;
}
```

## Details

The signing key is generated in the `generate_secrets` host tool and stored in the `secrets` volume.

What is currently signed:
- Plaintext firmware data at 0x2B300
- Firmware version number concatenated with the IV at 0x2B340
- Plaintext configuration data at 0x2B380

The public key is copied to EEPROM currently at position 0. A signature of the default version number and an invalid `b"\xff"*16` IV is also copied to EEPROM at block 1.
