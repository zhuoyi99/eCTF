# Memory Protection Unit
On a launch, the memory protection unit of the Cortex-M4 processor is set up. It defines restrictions on how flash memory can be used and then drops the bootloader into unprivedged mode, so that these protections cannot easily be disabled.

# Details
3 effective regions are defined on memory:

- `0x05800 - 0x20000`: Bootloader code. Cannot be written but can be executed.
- `0x20000 - 0x2B000`: Unused data. Cannot be written or executed.
- `0x2B000 - 0x40000`: Storage. Cannot be executed, can be written.
