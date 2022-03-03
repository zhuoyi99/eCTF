# Digital Signatures

Digital signatures have been implemented with the ED25519 signature scheme.

To sign data on the host tools, use the `sign` function in the `utils` module. This requires access to secrets.

```python
from utils import sign

sign(data) # type: bytes, length: 64
```

To verify a signature on the device, use the `signature_verify` macro. The signature requires `ED_SIGNATURE_SIZE` bytes, which is defined to be 64. Currently signatures are stored at 0x2B300.

```c
if(!signature_verify((uint8_t*)SIGNATURE_PTR, (uint8_t*)DATA_PTR, size)) {
    // Failure case
    uart_writeb(HOST_UART, 'S');
    return;
}
```

## Details

The signing key is generated in the `generate_secrets` host tool and stored in the `secrets` volume.

The public key is copied to EEPROM currently at position 0.

