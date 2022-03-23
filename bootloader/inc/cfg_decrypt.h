#ifndef CFG_DECRYPT_H
#define CFG_DECRYPT_H

/**
 * @brief Read configuration data from a UART interface and program to flash memory.
 * * 
 * @param interface is the base address of the UART interface to read from.
 * @param dst is the starting page address to store the data.
 * @param size is the number of bytes to load.
 */
void load_cfg_unsafe(uint32_t interface, uint32_t dst, uint32_t size, const uint32_t max_size);

#endif
