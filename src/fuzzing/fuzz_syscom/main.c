#include <stdio.h>
#include <stdlib.h>

#include "syscheckd/include/syscheck.h"

__AFL_FUZZ_INIT();

size_t syscom_dispatch(char * command, char ** output){
    assert(command != NULL);
    assert(output != NULL);

    if (strncmp(command, HC_FIM_FILE, strlen(HC_FIM_FILE)) == 0
        || strncmp(command, HC_FIM_REGISTRY, strlen(HC_FIM_REGISTRY)) == 0
        || strncmp(command, HC_FIM_REGISTRY_KEY, strlen(HC_FIM_REGISTRY_KEY)) == 0
        || strncmp(command, HC_FIM_REGISTRY_VALUE, strlen(HC_FIM_REGISTRY_VALUE)) == 0) {

        // fim_sync_push_msg(command); COMMENT OUT FOR FUZZ (prevent DB operations)
        return 0;
    } else if (strncmp(command, HC_SK, strlen(HC_SK)) == 0 ||
               strncmp(command, HC_GETCONFIG, strlen(HC_GETCONFIG)) == 0 ||
               strncmp(command, HC_RESTART, strlen(HC_RESTART)) == 0) {
        char *rcv_comm = NULL;
        char *rcv_args = NULL;

        if (strncmp(command, HC_SK, strlen(HC_SK)) == 0) {
            rcv_comm = command + strlen(HC_SK);
        } else {
            rcv_comm = command;
        }

        if ((rcv_args = strchr(rcv_comm, ' '))){
            *rcv_args = '\0';
            rcv_args++;
        }

        if (strcmp(rcv_comm, "getconfig") == 0){
            // getconfig section
            if (!rcv_args){
                mdebug1(FIM_SYSCOM_ARGUMENTS, "getconfig");
                os_strdup("err SYSCOM getconfig needs arguments", *output);
                return strlen(*output);
            }
            return syscom_getconfig(rcv_args, output);
        } else if (strcmp(rcv_comm, "restart") == 0) {
            os_set_restart_syscheck();
            return 0;
        }
    }

    mdebug1(FIM_SYSCOM_UNRECOGNIZED_COMMAND, command);
    os_strdup("err Unrecognized command", *output);
    return strlen(*output);
}


void _fuzz_syscom_main(const char* msg)
{
    ssize_t length;
    char *response = NULL;

    length = syscom_dispatch(msg, &response);
    os_free(response);
}

int main()
{
    int r;
    unsigned char* afl_input = NULL;
    const char *cfg = OSSECCONF;
    int test_config = 0, run_foreground = 0;

    /* Read syscheck config */
    if ((r = Read_Syscheck_Config(cfg)) < 0) {
        mwarn(RCONFIG_ERROR, SYSCHECK, cfg);
        syscheck.disabled = 1;
    } else if ((r == 1) || (syscheck.disabled == 1)) {
        if (syscheck.directories == NULL || OSList_GetFirstNode(syscheck.directories) == NULL) {
            if (!test_config) {
                minfo(FIM_DIRECTORY_NOPROVIDED);
            }
        }

        if (!syscheck.ignore) {
            os_calloc(1, sizeof(char *), syscheck.ignore);
        } else {
            os_free(syscheck.ignore[0]);
        }

        if (!test_config) {
            minfo(FIM_DISABLED);
        }
    }

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    afl_input = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000000000))
    {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        afl_input[len] = '\0';
        _fuzz_syscom_main(afl_input);
    }

    return 0;
}
