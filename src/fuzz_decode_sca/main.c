#include <stdlib.h>

#include "analysisd.h"
#include "cleanevent.h"

__AFL_FUZZ_INIT();

void _fuzz_decode_sca(const char* msg)
{
    int res = 0;
    Eventinfo* lf = NULL;
    int socket = -1;

    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);

    if (msg[0] == SCA_MQ)
    {
        if (OS_CleanMSG(msg, lf) < 0)
        {
            Free_Eventinfo(lf);
            return;
        }
        DecodeSCA(lf, &socket);
    }
    w_free_event_info(lf);
}

int main()
{
    unsigned char* afl_input = NULL;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    Config.decoder_order_size = 51;
    SecurityConfigurationAssessmentInit();

    afl_input = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000))
    {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        afl_input[len] = '\0';
        _fuzz_decode_sca(afl_input);
    }

    return 0;
}

__attribute__((noreturn)) void OS_ReadMSG(char* ut_str) {}