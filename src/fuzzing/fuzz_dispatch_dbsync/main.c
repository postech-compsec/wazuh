#include <stdio.h>
#include <stdlib.h>

#include "analysisd.h"
#include "cleanevent.h"
#include "wazuhdb_op.h"

__AFL_FUZZ_INIT();

int wdbc_query_ex(int* sock, const char* query, char* response, const int len)
{
    snprintf(response, 19, "ok not found");
    return 0;
}

int wdbc_parse_result(char* result, char** payload)
{
    return WDBC_OK;
}

void _fuzz_dispatch_dbsync(const char* msg)
{
    Eventinfo* lf = NULL;
    dbsync_context_t ctx = { .db_sock = -1, .ar_sock = -1 };
    

    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);

    Zero_Eventinfo(lf);

    if (msg[0] == DBSYNC_MQ) {
        if (OS_CleanMSG(msg, lf) < 0)
        {
            Free_Eventinfo(lf);
            return;
        }
        DispatchDBSync(&ctx, lf);
    }
    
    Free_Eventinfo(lf);
}

int main()
{
    unsigned char* afl_input = NULL;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    Config.decoder_order_size = 51;

    afl_input = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000000000))
    {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        afl_input[len] = '\0';
        _fuzz_dispatch_dbsync(afl_input);
    }

    return 0;
}

__attribute__((noreturn)) void OS_ReadMSG(char* ut_str) {}