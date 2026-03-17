#include <stdio.h>
#include <stdlib.h>

#include "remoted.h"

__AFL_FUZZ_INIT();

void _fuzz_ar_forward(const char* msg)
{
    int ar_location = 0;
    char *msg_to_send;
    os_calloc(OS_MAXSTR, sizeof(char), msg_to_send);
    char *ar_agent_id = NULL;
    char *tmp_str = NULL;


    mdebug2("Active response request received: %s", msg);

    /* Always zero the location */
    ar_location = 0;

    /* Location */
    tmp_str = strchr(msg, ')');
    if (!tmp_str) {
        mwarn(EXECD_INV_MSG, msg);
        return;
    }
    tmp_str += 2;

    /* Source IP */
    tmp_str = strchr(tmp_str, ']');
    if (!tmp_str) {
        mwarn(EXECD_INV_MSG, msg);
        return;
    }
    tmp_str += 2;

    /* AR location */
    if (*tmp_str == ALL_AGENTS_C) {
        ar_location |= ALL_AGENTS;
    }
    tmp_str++;
    if (*tmp_str == REMOTE_AGENT_C) {
        ar_location |= REMOTE_AGENT;
    } else if (*tmp_str == NO_AR_C) {
        ar_location |= NO_AR_MSG;
    }
    tmp_str++;
    if (*tmp_str == SPECIFIC_AGENT_C) {
        ar_location |= SPECIFIC_AGENT;
    }
    tmp_str += 2;

    /* Extract the agent id */
    ar_agent_id = tmp_str;
    tmp_str = strchr(tmp_str, ' ');
    if (!tmp_str) {
        mwarn(EXECD_INV_MSG, msg);
        return;
    }
    *tmp_str = '\0';
    tmp_str++;

    /* Create the new message */
    if (ar_location & NO_AR_MSG) {
        snprintf(msg_to_send, OS_MAXSTR, "%s%s",
                    CONTROL_HEADER,
                    tmp_str);
    } else {
        snprintf(msg_to_send, OS_MAXSTR, "%s%s%s",
                    CONTROL_HEADER,
                    EXECD_HEADER,
                    tmp_str);
    }

    mdebug2("Active response sent: %s", msg_to_send);

    /* Send to ALL agents */
    if (ar_location & ALL_AGENTS) {
        char agent_id[KEYSIZE + 1] = "";

        /* Lock use of keys */
        key_lock_read();

        for (unsigned int i = 0; i < keys.keysize; i++) {
            if (keys.keyentries[i]->rcvd >= (time(0) - logr.global.agents_disconnection_time)) {
                strncpy(agent_id, keys.keyentries[i]->id, KEYSIZE);
                key_unlock();
                // if (send_msg(agent_id, msg_to_send, -1) >= 0) {
                //     rem_inc_send_ar(agent_id);
                // }
                key_lock_read();
            }
        }

        key_unlock();
    }

    /* Send to the remote agent that generated the event or to a pre-defined agent */
    else if (ar_location & (REMOTE_AGENT | SPECIFIC_AGENT)) {
        // if (send_msg(ar_agent_id, msg_to_send, -1) >= 0) {
        //     rem_inc_send_ar(ar_agent_id);
        // }
    }
}

int main()
{
    unsigned char* afl_input = NULL;
    OS_ReadKeys(&keys, W_ENCRYPTION_KEY, 0);
    // OS_StartCounter(&keys);
    keys.keyentries[0]->crypto_method = W_METH_AES;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    afl_input = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000000000))
    {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        afl_input[len] = '\0';
        _fuzz_ar_forward(afl_input);
    }

    return 0;
}
