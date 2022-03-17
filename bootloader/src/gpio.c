#include "gpio.h"

#include <stdbool.h>
#include <stdint.h>
#include "inc/hw_gpio.h"
#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "driverlib/gpio.h"
#include "driverlib/rom.h"
#include "driverlib/rom_map.h"
#include "driverlib/sysctl.h"

void gpio_lock() {
    // This code is mostly taken from the examples:
    // https://github.com/yuvadm/tiva-c/blob/master/boards/dk-tm4c129x/gpio_jtag/gpio_jtag.c#L134

    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOC);
    while(!(SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOC)));
    HWREG(GPIO_PORTC_BASE + GPIO_O_LOCK) = GPIO_LOCK_KEY;
    HWREG(GPIO_PORTC_BASE + GPIO_O_CR) = 0x0F;

    //
    // Now modifiy the configuration of the pins that we unlocked.
    // Set pins to be GPIO and then disable them.
    //
    HWREG(GPIO_PORTC_BASE + GPIO_O_AFSEL) &= 0xf0;
    HWREG(GPIO_PORTC_BASE + GPIO_O_DEN) = 0x00;

    //
    // Finally, clear the commit register and the lock to prevent
    // the pin configuration from being changed accidentally later.
    // Note that the lock is closed whenever we write to the GPIO_O_CR
    // register so we need to reopen it here.
    //
    HWREG(GPIO_PORTC_BASE + GPIO_O_LOCK) = GPIO_LOCK_KEY;
    HWREG(GPIO_PORTC_BASE + GPIO_O_CR) = 0x00;
    HWREG(GPIO_PORTC_BASE + GPIO_O_LOCK) = 0;

    SysCtlPeripheralDisable(SYSCTL_PERIPH_GPIOC);
}
