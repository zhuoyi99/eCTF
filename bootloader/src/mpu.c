#include <stdint.h>

#include "mpu.h"
#include "inc/hw_nvic.h"
#include "inc/hw_types.h"
#include "driverlib/mpu.h"

/**
 * @brief Set up memory protection if neccessary.
 */
void mpu_setup() {
    // Check we didn't already do this
    if((HWREG(NVIC_MPU_CTRL) & NVIC_MPU_CTRL_ENABLE) == 1) return;

    // Bootstrapper is forbidden to modify bootstrapper, IVT

    // Default region (0)
    MPURegionSet(0, 0, MPU_RGN_SIZE_4G | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RW_USR_RW | MPU_RGN_ENABLE);

    // Region 1: Bootloader 0x5800-0x6000
    MPURegionSet(1, 0x5800, MPU_RGN_SIZE_2K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RO_USR_RO | MPU_RGN_ENABLE);
    // Region 2: Bootloader 0x6000-0x10000 by excluding regions
    MPURegionSet(2, 0x0000, MPU_RGN_SIZE_64K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RO_USR_RO | MPU_RGN_ENABLE | MPU_SUB_RGN_DISABLE_0 | MPU_SUB_RGN_DISABLE_1 | MPU_SUB_RGN_DISABLE_2);
    // Region 3: Bootloader 0x10000-0x20000
    MPURegionSet(3, 0x10000, MPU_RGN_SIZE_64K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RO_USR_RO | MPU_RGN_ENABLE);

    // Region 4: Unused 0x20000-0x28000
    MPURegionSet(4, 0x20000, MPU_RGN_SIZE_32K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RO_USR_RO | MPU_RGN_ENABLE);
    // Region 5: Unused 0x28000-0x30000, disable subregions 3-7
    MPURegionSet(5, 0x28000, MPU_RGN_SIZE_32K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RO_USR_RO | MPU_RGN_ENABLE | MPU_SUB_RGN_DISABLE_3 | MPU_SUB_RGN_DISABLE_4 | MPU_SUB_RGN_DISABLE_5 | MPU_SUB_RGN_DISABLE_6 | MPU_SUB_RGN_DISABLE_7);

    // Region 6: NX 0x28000-0x30000, disable subregions 0-2
    MPURegionSet(6, 0x28000, MPU_RGN_SIZE_32K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW | MPU_RGN_ENABLE | MPU_SUB_RGN_DISABLE_0 | MPU_SUB_RGN_DISABLE_1 | MPU_SUB_RGN_DISABLE_2);
    // Region 7: NX 0x30000-0x40000
    MPURegionSet(7, 0x30000, MPU_RGN_SIZE_64K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW | MPU_RGN_ENABLE);

    // Enable
    MPUEnable(MPU_CONFIG_HARDFLT_NMI);
}
