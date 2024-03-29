# 2022 eCTF
# Host-Tools and Bootloader Creation Dockerfile
# Andrew Mirghassemi
#
# (c) 2022 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2022 Embedded System
# CTF (eCTF). This code is being provided only for educational purposes for the
# 2022 MITRE eCTF competition, and may not meet MITRE standards for quality.
# Use this code at your own risk!

FROM ubuntu:focal

# Add environment customizations here
# NOTE: do this first so Docker can used cached containers to skip reinstalling everything
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y python3 python3-pip \
    binutils-arm-none-eabi gcc-arm-none-eabi make

# Install python package(s)
RUN python3 -m pip install ed25519
# After installing pip, install cryptography library
RUN python3 -m pip install cryptography

# Create bootloader binary folder
RUN mkdir /bootloader

# Add any system-wide secrets here
RUN mkdir /secrets

# Add host tools and bootloader source to container
ADD host_tools/ /host_tools
ADD bootloader /bl_build

# Copy linker wrapper
RUN cp /bl_build/arm-none-eabi-ld-wrapper /bin/arm-none-eabi-ld-wrapper

# Generate Secrets
RUN python3 /host_tools/generate_secrets

# Create EEPROM contents
# Example: RUN echo "Bootloader Data" > /bootloader/eeprom.bin
RUN cat /secrets/ed_public_key.bin > /bootloader/eeprom.bin
#RUN cat /secrets/aes_key_bootloader.bin >> /bootloader/eeprom.bin
RUN cat /secrets/default_ver_signature.bin >> /bootloader/eeprom.bin
RUN cat /secrets/encryption_key.bin >> /bootloader/eeprom.bin
# 32 byte symmetric key for auth
RUN cat /secrets/auth_key.bin >> /bootloader/eeprom.bin
# 32 bytes for auth counter 
RUN head -c 32 /dev/random >> /bootloader/eeprom.bin
# 64 bytes for auth seed
RUN head -c 64 /dev/random >> /bootloader/eeprom.bin

# Compile bootloader
WORKDIR /bl_build

ARG OLDEST_VERSION
RUN make OLDEST_VERSION=${OLDEST_VERSION}
RUN python3 /bl_build/modify_bootloader_bin.py
RUN mv /bl_build/gcc/bootloader.bin /bootloader/bootloader.bin
RUN mv /bl_build/gcc/bootloader.axf /bootloader/bootloader.elf
