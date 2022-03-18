# Flash Security

All Flash writes done by the bootloader are done through the helper functions in flash.c.

These functions compute a SHA256 hash of non-written Flash memory before and after writes to ensure the trojan has not done anything funny. If it detects a change, it panics and erases some sensitive data. 

We make sure to write in blocks if possible, this is VERY expensive!
