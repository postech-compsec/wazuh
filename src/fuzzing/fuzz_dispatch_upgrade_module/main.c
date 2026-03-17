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

void _fuzz_dispatch_upgrade_module(const char* msg)
{
    Eventinfo* lf = NULL;
    
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);

    Zero_Eventinfo(lf);

    if (msg[0] == UPGRADE_MQ) {
        if (OS_CleanMSG(msg, lf) < 0)
        {
            Free_Eventinfo(lf);
            return;
        }
        cJSON *message_obj = cJSON_Parse(lf->log);

        if (message_obj) {
            cJSON *message_params = cJSON_GetObjectItem(message_obj, "parameters");

            if (message_params) {
                // int sock = OS_ConnectUnixDomain(WM_UPGRADE_SOCK, SOCK_STREAM, OS_MAXSTR);
                // if (sock == OS_SOCKTERR) {
                //     merror("Could not connect to upgrade module socket at '%s'. Error: %s", WM_UPGRADE_SOCK, strerror(errno));
                // } else {
                int agent = atoi(lf->agent_id);
                cJSON* agents = cJSON_CreateIntArray(&agent, 1);
                cJSON_AddItemToObject(message_params, "agents", agents);

                char *message = cJSON_PrintUnformatted(message_obj);
                // OS_SendSecureTCP(sock, strlen(message), message);
                os_free(message);
                // close(sock);
                // }
            } else {
                merror("Could not get parameters from upgrade message: %s", lf->log);
            }
            cJSON_Delete(message_obj);
        } else {
            merror("Could not parse upgrade message: %s", lf->log);
        }
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
        _fuzz_dispatch_upgrade_module(afl_input);
    }

    return 0;
}

__attribute__((noreturn)) void OS_ReadMSG(char* ut_str) {}