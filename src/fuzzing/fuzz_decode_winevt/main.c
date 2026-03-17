#include <stdlib.h>

#include "analysisd.h"
#include "cleanevent.h"

__AFL_FUZZ_INIT();

void _fuzz_decode_winevt(const char* msg)
{
    int res = 0;
    Eventinfo* lf = NULL;

    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);

    if (msg[0] == WIN_EVT_MQ)
    {
        if (OS_CleanMSG(msg, lf) < 0)
        {
            Free_Eventinfo(lf);
            return;
        }
        DecodeWinevt(lf);
    }
    w_free_event_info(lf);
}

int main()
{
    unsigned char* afl_input = NULL;
    OSDecoderInfo* NULL_Decoder_tmp = NULL;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    Config.decoder_order_size = 51;

    os_calloc(1, sizeof(OSDecoderInfo), NULL_Decoder_tmp);
    NULL_Decoder_tmp->id = 0;
    NULL_Decoder_tmp->type = SYSLOG;
    NULL_Decoder_tmp->name = NULL;
    NULL_Decoder_tmp->fts = 0;
    NULL_Decoder = NULL_Decoder_tmp;

    WinevtInit();

    afl_input = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000))
    {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        afl_input[len] = '\0';
        _fuzz_decode_winevt(afl_input);
    }

    return 0;
}

__attribute__((noreturn)) void OS_ReadMSG(char* ut_str) {}
