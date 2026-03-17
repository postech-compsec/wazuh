#include <stdio.h>
#include <stdlib.h>

#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_parsing.h"
#include "wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_tasks.h"

__AFL_FUZZ_INIT();
void _fuzz_main(const char* msg)
{
    void* task = NULL;
    int* agent_ids = NULL;
    char* message = NULL;
    int ret = wm_agent_upgrade_parse_message(msg, &task, &agent_ids, &message);
    printf("%d %s\n", ret, message ? message : "no error");
}

int main()
{
    unsigned char* afl_input = NULL;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    afl_input = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000000000))
    {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        afl_input[len] = '\0';
        _fuzz_main(afl_input);
    }

    return 0;
}
