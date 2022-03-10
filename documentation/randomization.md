# Layout Randomization
Some layout randomization is performed at the linking step by a wrapper script for `ld` located at `bootloader/arm-none-eabi-ld-wrapper`. It randomizes the order of the arguments of object files such that they are placed in different location each build.
