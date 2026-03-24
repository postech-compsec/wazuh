#include <stdlib.h>

#include "analysisd.h"
#include "cleanevent.h"
#include "wazuhdb_op.h"
#include "getloglocation.h"

int wdbc_query_ex(int* sock, const char* query, char* response, const int len)
{
    snprintf(response, 19, "xx not found");
    return 0;
}

int wdbc_parse_result(char* result, char** payload)
{
    return WDBC_OK;
}


__AFL_FUZZ_INIT();


void _fuzz_writer_log(const char* msg)
{
    int res = 0;
    Eventinfo* lf = NULL;
    Eventinfo* lf_cpy = NULL;
    OSDecoderNode* node;
    regex_matching decoder_match;
    memset(&decoder_match, 0, sizeof(regex_matching));
    int sock = -1;

    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Config.g_rules_hash = OSHash_Create();

    Zero_Eventinfo(lf);

    if (OS_CleanMSG(msg, lf) < 0)
    {
        Free_Eventinfo(lf);
        return;
    }

    
    if (msg[0] == CISCAT_MQ)
    {
        if (!DecodeCiscat(lf, &sock))
        {
            w_free_event_info(lf);
            return;
        }
    }
    else
    {
        if (msg[0] == SYSLOG_MQ)
        {
        }
        else if (msg[0] == LOCALFILE_MQ)
        {
            extract_module_from_location(lf->location);
        }
        node = OS_GetFirstOSDecoder(lf->program_name);
        DecodeEvent(lf, Config.g_rules_hash, &decoder_match, node);
    }
    os_calloc(1, sizeof(Eventinfo), lf_cpy);
    w_copy_event_for_log(lf, lf_cpy);
    if (Config.custom_alert_output) {
        set_global_alert_second_id(ftell(_aflog));
        OS_CustomLog(lf, Config.custom_alert_output_format);
    } else if (Config.alerts_log) {
        set_global_alert_second_id(ftell(_aflog));
        OS_Log(lf, _aflog);
    } else if (Config.jsonout_output) {
        set_global_alert_second_id(ftell(_jflog));
    }

    // if (Config.jsonout_output) {
    //     jsonout_output_event(lf);

    //     if (Config.forwarders_list) {
    char* json_msg = Eventinfo_to_jsonstr(lf, false, NULL);
    //         SendJSONtoSCK(json_msg, Config.socket_list);
    //     }
    // }

    Free_Eventinfo(lf);
}

int main()
{
    unsigned char* afl_input = NULL;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    // decoder_order_size default value @ etc/internal_options.conf:L29-30
    // Maximum number of fields in a decoder (order tag) [32..1024]
    // analysisd.decoder_order_size=256
    Config.decoder_order_size = 256;

    /* Load decoders from main_analysisd.
        Omitted all error handling codes, as loading default decoders doesn't generate any errors.
    */
    {
        char* msg;
        OSList* list_msg = OSList_Create();
        OSList_SetMaxSize(list_msg, ERRORLIST_MAXSIZE);

        /* Initialize the decoders list */
        OS_CreateOSDecoderList();

        /* If we haven't specified a decoders directory, load default */
        if (!Config.decoders)
        {
            /* Legacy loading */
            /* Read default decoders */
            Read_Rules(NULL, &Config, NULL);
        }

        {
            char** decodersfiles;
            decodersfiles = Config.decoders;
            while (decodersfiles && *decodersfiles)
            {
                ReadDecodeXML(*decodersfiles,
                              &os_analysisd_decoderlist_pn,
                              &os_analysisd_decoderlist_nopn,
                              &os_analysisd_decoder_store,
                              list_msg);

                decodersfiles++;
            }
        }

        /* Load decoders */
        SetDecodeXML(
            list_msg, &os_analysisd_decoder_store, &os_analysisd_decoderlist_nopn, &os_analysisd_decoderlist_pn);

        os_free(list_msg);
    }

    CiscatInit();

    afl_input = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000000000))
    {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        afl_input[len] = '\0';
        _fuzz_writer_log(afl_input);
    }

    return 0;
}

__attribute__((noreturn)) void OS_ReadMSG(char* ut_str) {}
