#include <stdlib.h>

#include "analysisd.h"
#include "cleanevent.h"
#include "wazuhdb_op.h"

static OSDecoderInfo *sca_json_dec = NULL;

void SecurityConfigurationAssessmentInit()
{

    os_calloc(1, sizeof(OSDecoderInfo), sca_json_dec);
    sca_json_dec->id = getDecoderfromlist(SCA_MOD, &os_analysisd_decoder_store);
    sca_json_dec->type = OSSEC_RL;
    sca_json_dec->name = SCA_MOD;
    sca_json_dec->fts = 0;

/*
 *     request_queue = queue_init(1024);
 * 
 *     w_create_thread(RequestDBThread,NULL);
 */

    mdebug1("SecurityConfigurationAssessmentInit completed.");
}

static void PushDumpRequest(char * agent_id, char * policy_id, int first_scan) {
    assert(agent_id);
    assert(policy_id);

    int result;
    char request_db[OS_SIZE_4096 + 1] = {0};

    mdebug1("Requesting dump for policy: %s", policy_id);

    snprintf(request_db,OS_SIZE_4096,"%s:sca-dump:%s:%d",agent_id,policy_id,first_scan);
    char *msg = NULL;

/*
 *     os_strdup(request_db,msg);
 * 
 *     result = queue_push_ex(request_queue,msg);
 * 
 *     if (result < 0) {
 *         mwarn("SCA request queue is full.");
 *         free(msg);
 *     }
 */
}

int wdbc_query_ex(int *sock, const char *query, char *response, const int len) {
  return 0;
}

int wdbc_parse_result(char *result, char **payload) {
  return WDBC_OK;
}


__AFL_FUZZ_INIT();

void _fuzz_decode_sca(const char* msg)
{
    int res = 0;
    Eventinfo* lf = NULL;
    int socket = -1;

    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Config.g_rules_hash = OSHash_Create();
    
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
