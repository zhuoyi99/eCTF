#ifndef RAND_H
#define RAND_H

#include <stdint.h>
#include <stdbool.h>
#include "constants.h"

/**
 * @brief Increment a counter variable stored on EEPROM.
 */
void inc_counter(uint8_t* counter);

/**
 * @brief Fill a random buffer of size RAND_BUF_LEN
 */
void rand_buf(uint8_t* buf);

#endif
