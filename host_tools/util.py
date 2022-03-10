# 2022 eCTF
# Host Tool Utility File
# Kyle Scaplen
#
# (c) 2022 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2022 Embedded System
# CTF (eCTF). This code is being provided only for educational purposes for the
# 2022 MITRE eCTF competition, and may not meet MITRE standards for quality.
# Use this code at your own risk!

import logging
from pathlib import Path
import socket
from sys import stderr

LOG_FORMAT = "%(asctime)s:%(name)-12s%(levelname)-8s %(message)s"
log = logging.getLogger(Path(__file__).name)

CONFIGURATION_ROOT = Path("/configuration")
FIRMWARE_ROOT = Path("/firmware")
RELEASE_MESSAGES_ROOT = Path("/messages")

RESP_OK = b"\x00"


def print_banner(s: str) -> None:
    """Print an underlined string to stdout

    Args:
        s (str): the string to print
    """
    width = len(s)
    line = "-" * width
    banner = f"\n{line}\n{s}\n{line}"
    print(banner, file=stderr)


class PacketIterator:
    BLOCK_SIZE = 0x400

    def __init__(self, data: bytes):
        self.data = data
        self.index = 0
        self.size = len(data)

    def __iter__(self):
        return [
            self.data[i : i + self.BLOCK_SIZE]
            for i in range(0, len(self.data), self.BLOCK_SIZE)
        ].__iter__()


def send_packets(sock: socket.socket, data: bytes):
    packets = PacketIterator(data)

    for num, packet in enumerate(packets):
        log.debug(f"Sending Packet {num} ({len(packet)} bytes)...")
        sock.sendall(packet)
        resp = sock.recv(1)  # Wait for an OK from the bootloader

        if resp != RESP_OK:
            exit(f"ERROR: Bootloader responded with {repr(resp)}")

import ed25519

def sign(msg: bytes) -> bytes:
    with open("/secrets/ed_private_key.bin", "rb") as f:
        SIGNING_KEY = ed25519.SigningKey(f.read())
    return SIGNING_KEY.sign(msg)

def verify(msg: bytes, sig: bytes) -> bool:
    with open("/secrets/ed_public_key.bin", "rb") as f:
        VERIFYING_KEY = ed25519.VerifyingKey(f.read()[:32])
    try:
        VERIFYING_KEY.verify(sig, msg)
    except ed25519.BadSignatureError:
        return False
    return True

from secrets import token_bytes
from hashlib import sha512
import struct
import subprocess

def integrity_challenge(sock: socket.socket) -> None:
    """
    Checks the integrity of the bootloader and exits on failure.
    """

    with open("/bootloader/bootloader.bin", "rb") as f:
        fw_data = f.read()
    start = 0x5800
    end = 0x2B000
    fw_data = fw_data.ljust(end - start, b"\xff")

    # Add .data section
    data, edata, ldata = None, None, None
    sections = subprocess.run(["nm", "/bootloader/bootloader.elf"], capture_output=True).stdout
    for section in sections.split(b"\n"):
        if section == b"":
            continue
        addr, _, name = section.split(b" ")
        if name == b"_data":
            data = int(addr.decode(), 16)
        if name == b"_edata":
            edata = int(addr.decode(), 16)
        if name == b"_ldata":
            ldata = int(addr.decode(), 16)
    start = ldata-start
    end = start + (edata - data)
    fw_data += fw_data[start:end]

    sock.sendall(b"I");
    recv = sock.recv(1)
    if recv != b"R":
        if recv == b"P":
            log.error("[INTEGRITY CHECK] Bootloader previously detected integrity violation!")
            exit(-1)
        log.error("[INTEGRITY CHECK] Failed to start integrity challenge")
        exit(1)

    challenge = token_bytes(12)
    import time
    start_time = time.time()
    sock.sendall(challenge)

    computed_hash = sha512(challenge + fw_data).digest()
    log.info(f"[INTEGRITY CHECK] Challenge: {challenge.hex()[:16]}...")
    log.info(f"[INTEGRITY CHECK] Computed:  {computed_hash.hex()[:16]}...")

    recv = b""
    while len(recv) != 512//8:
        recv_chunk = sock.recv(512//8 - len(recv))
        if recv_chunk == b"": break # Forcefully in case of closed
        recv += recv_chunk
    log.info(f"[INTEGRITY CHECK] Recieved:  {recv.hex()[:16]}...")
    log.info(f"[INTEGRITY CHECK] Time: {time.time() - start_time} sec")

    if recv != computed_hash:
        log.error("Could not verify integrity of bootloader!")
        exit(-1)

    log.info("[INTEGRITY CHECK] Looks good.")
