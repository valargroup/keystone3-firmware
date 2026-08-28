#include "drv_trng.h"
#include "mhscpu.h"
#include "mhscpu_trng.h"
#include "assert.h"
#include "user_memory.h"

static bool TrngReadBlock(uint32_t output[4])
{
    TRNG_Start(TRNG0);

    while (TRNG_Get(output, TRNG0) != 0) {
        if (TRNG_GetITStatus(TRNG_IT_RNG0_ATTACK) == SET) {
            return false;
        }
    }

    // Data-ready and attack can be asserted at the same time.
    return TRNG_GetITStatus(TRNG_IT_RNG0_ATTACK) == RESET;
}

void TrngInit(void)
{
    SYSCTRL_APBPeriphClockCmd(SYSCTRL_APBPeriph_TRNG, ENABLE);
    SYSCTRL_APBPeriphResetCmd(SYSCTRL_APBPeriph_TRNG, ENABLE);
}

void TrngGet(void *buf, uint32_t len)
{
    uint32_t buf4[4] = {0};

    ASSERT(buf != NULL || len == 0);

    for (uint32_t i = 0; i < len; i += 16) {
        if (!TrngReadBlock(buf4)) {
            memset_s(buf4, sizeof(buf4), 0, sizeof(buf4));
            memset_s(buf, len, 0, len);
            ASSERT(false);
            return;
        }

        if (len - i >= 16) {
            memcpy((uint8_t *)buf + i, buf4, 16);
        } else {
            memcpy((uint8_t *)buf + i, buf4, len - i);
        }
    }

    memset_s(buf4, sizeof(buf4), 0, sizeof(buf4));
}
