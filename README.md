# 2022 MITRE eCTF Challenge: Secure Avionics Flight Firmware Installation Routine (SAFFIRe)
This repository contains our implementation of the SAFFIRe bootloader with security features. Documentation can be seen in the [design document](design_document.pdf) and in the documentation folder.

Here is a listing of added security features:
- [Authentication](documentation/authentication.md) - the board authenticates host tools before allowing readback
- [Encryption](documentation/encryption.md) - the firmware and configuration file are encrypted with AES
- [Flash Security](documentation/flash_trampoline.md) - all flash writes are done with code execution in SRAM, and flash memory is hashed before/after the write
- [Integrity Checking](documentation/integrity.md) - all host tools attempt to verify integrity of bootloader before communicating further
- [Memory Protection](documentation/mpu.md) - no-execute memory protection is applied to flash regions
- [Layout Randomization](documentation/randomization.md) - memory layout is randomized on boot
- [Signing](documentation/signatures.md) - sensitive data is digitally signed

Use this code at your own risk!

## Getting Started
Please see the [Getting Started Guide](getting_started.md).
Make sure you pull submodules!

## Project Structure
The example code is structured as follows

* `bootloader/` - Contains everything to build the SAFFIRE bootloader. See [Bootloader README](bootloader/README.md).
* `configuration/` - Directory to hold raw and protected configuration images. The repo comes with an example unprotected configuration binary.
* `dockerfiles/` - Contains all Dockerfiles to build system.
* `firmware/` - Directory to contain raw and protected firmware images. The repo comes with an example unprotected firmware binary.
* `host-tools/` - Contains the host tools.
* `platform/` - Contains everything to run the avionic device.
* `tools/` - Miscellaneous tools to run and interract with SAFFIRe.
* `saffire.cfg` - An example option config file for running SAFFIRe

