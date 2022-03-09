from email.policy import default
import os
#! /usr/bin/env/python3
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pathlib import Path
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
e = cipher.encryptor()
file = Path(os.getcwd()+"/example_fw.bin")
all_bytes = file.read_bytes()
padding = 32 + (32 -len(all_bytes)%32)
all_bytes+= b'\xFF'*padding
text = e.update(all_bytes) + e.finalize()
with open ("test_key", "wb") as f:
    f.write(key)
with open ("test_iv", "wb") as f:
    f.write(iv)
with open("test_fw.prot", "wb") as f:
    f.write(text)

