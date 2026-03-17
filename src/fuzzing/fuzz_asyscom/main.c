#include <stdio.h>
#include <stdlib.h>

#include "analysisd.h"
#include "cleanevent.h"

__AFL_FUZZ_INIT();


void _fuzz_asyscom_main(const char* msg)
{
    ssize_t length;
    char *response = NULL;

    length = asyscom_dispatch(msg, &response);
    printf("response: %s\n", response);
    os_free(response);
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
        _fuzz_asyscom_main(afl_input);
    }

    return 0;
}

__attribute__((noreturn)) void OS_ReadMSG(char* ut_str) {}
