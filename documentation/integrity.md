# Integrity Challenge

Whenever interacting with the device, first use the `integrity_challenge` function in the `utils` module to attempt to ensure the trojan has not overwritten anything. The function will immediately exit if the check fails.

```python
from utils import integrity_challenge

# ...

integrity_challenge(sock, checkWholeRegion=False)
```

Areas not used for storage are filled with random data so they cannot be used by the trojan easily.

This check fails by default if any region of flash is changed, including after updating the firmware and configuration. If the checkWholeRegion argument is set to False, only the regions not used for storage are checked - current defined as up to `0x2B000`. The rest should be read off and have signatures verified during readback.

Currently it is done on a firmware update, but there should be another place to put it that is only on a boot...

TODO ideas:
- Load signed empty FW and config by default, always verify non-storage sections and then signatures in the rest
