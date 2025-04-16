#include <stdlib.h>

#include "shared.h"
#include "../os_net/os_net.h"
#include "remoted.h"
#include "state.h"
#include "router.h"

/* 001 fuzz01 any 7c6e622b906b1fd60dfec2817d237e5f14a9de08b950f3902c830894e93adf77 */

__AFL_FUZZ_INIT();

void __fuzz_HandleSecureMessage(unsigned char* afl_input, int len) {
  int agentid;
  const int protocol = REMOTED_NET_PROTOCOL_UDP;
  char cleartext_msg[OS_MAXSTR + 1];
  char srcmsg[OS_FLSIZE + 1];
  char srcip[IPSIZE + 1] = {0};
  char agname[KEYSIZE + 1] = {0};
  char *agentid_str = NULL;
  char *agent_ip = NULL;
  char *agent_name = NULL;
  char buffer[OS_MAXSTR + 1] = "";
  char *tmp_msg;
  size_t msg_length;
  char ip_found = 0;
  int r;
  int recv_b = len;
  int sock_idle = -1;
  int sock = USING_UDP_NO_CLIENT_SOCKET;

  /* Initialize some variables */
  memset(cleartext_msg, '\0', OS_MAXSTR + 1);
  memset(srcmsg, '\0', OS_FLSIZE + 1);
  tmp_msg = NULL;
  memcpy(buffer, afl_input, recv_b);

  /* Get a valid agent id */
  if (buffer[0] == '!') {
    tmp_msg = buffer;
    tmp_msg++;

    // We need to make sure that we have a valid id
    // and that we reduce the recv buffer size
    while (isdigit((int)*tmp_msg)) {
      tmp_msg++;
      recv_b--;
    }

    if (*tmp_msg != '!') {
      merror(ENCFORMAT_ERROR, "(unknown)", srcip);

      /*
       * if (message->sock >= 0) {
       *   _close_sock(&keys, message->sock);
       * }
       */

      /* rem_inc_recv_unknown(); */
      return;
    }

    *tmp_msg = '\0';
    tmp_msg++;
    recv_b -= 2;

    key_lock_read();
    agentid = OS_IsAllowedDynamicID(&keys, buffer + 1, srcip);

    if (agentid == -1) {
      int id = OS_IsAllowedID(&keys, buffer + 1);

      if (id < 0) {
        snprintf(agname, sizeof(agname), "unknown");
      } else {
        snprintf(agname, sizeof(agname), "%s", keys.keyentries[id]->name);
      }

      key_unlock();

      mwarn(ENC_IP_ERROR, buffer + 1, srcip, agname);

      // Send key request by id
      /* push_request(buffer + 1, "id"); */
      /*
       * if (message->sock >= 0) {
       *   _close_sock(&keys, message->sock);
       * }
       */

      /* rem_inc_recv_unknown(); */
      return;
    }
  } else {
    key_lock_read();

    agentid = OS_IsAllowedIP(&keys, srcip);

    tmp_msg = buffer;
  }
  printf("agentid: %d\n", agentid);

  /* Decrypt the message */
  if (r = ReadSecMSG(&keys, tmp_msg, cleartext_msg, agentid, recv_b - 1, &msg_length, srcip, &tmp_msg), r != KS_VALID) {
    /* If duplicated, a warning was already generated */
    key_unlock();

    if (r == KS_ENCKEY) {
      if (ip_found) {
        /* push_request(srcip, "ip"); */
      } else {
        /* push_request(buffer + 1, "id"); */
      }
    }

    /*
     *     if (message->sock >= 0) {
     *       mwarn("Decrypt the message fail, socket %d", message->sock);
     *       _close_sock(&keys, message->sock);
     *     }
     * 
     *     if (sock_idle >= 0) {
     *       _close_sock(&keys, sock_idle);
     *     }
     */

    /* rem_inc_recv_unknown(); */
    return;
  }

  /* Recieved valid message timestamp updated. */
  keys.keyentries[agentid]->rcvd = time(NULL);

  /* Check if it is a control message */
  if (IsValidHeader(tmp_msg)) {

    return;
  }

  /* Generate srcmsg */

  snprintf(srcmsg, OS_FLSIZE, "[%s] (%s) %s", keys.keyentries[agentid]->id,
      keys.keyentries[agentid]->name, keys.keyentries[agentid]->ip->ip);

  os_strdup(keys.keyentries[agentid]->id, agentid_str);
  os_strdup(keys.keyentries[agentid]->name, agent_name);
  os_strdup(keys.keyentries[agentid]->ip->ip, agent_ip);

  key_unlock();

  /*
   * if (sock_idle >= 0) {
   *   _close_sock(&keys, sock_idle);
   * }
   */

  // If we can't send the message, try to connect to the
  // socket again. If it not exit.
  if (SendMSG(logr.m_queue, tmp_msg, srcmsg, SECURE_MQ) < 0) {
    merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));

    // Try to reconnect infinitely
    logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    minfo("Successfully reconnected to '%s'", DEFAULTQUEUE);

    if (SendMSG(logr.m_queue, tmp_msg, srcmsg, SECURE_MQ) < 0) {
      // Something went wrong sending a message after an immediate reconnection...
      merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
    } else {
      /* rem_inc_recv_evt(agentid_str); */
    }
  } else {
    /* rem_inc_recv_evt(agentid_str); */
  }

  // Forwarding events to subscribers
  router_message_forward(tmp_msg, agentid_str, agent_ip, agent_name);

  os_free(agentid_str);
  os_free(agent_ip);
  os_free(agent_name);
}

int main() {
  unsigned char buf[65535] = "!001!#AES:";

  OS_ReadKeys(&keys, W_ENCRYPTION_KEY, 0);

  const char* replay = getenv("REPLAY");
  if (replay) {
    FILE* fp = fopen(replay, "rb");
    if (fp == NULL) {
      fprintf(stderr, "Cannot open %s\n", replay);
      return EXIT_FAILURE;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
      perror("Error seeking to end of file");
      fclose(fp);
      return EXIT_FAILURE;
    }
    long filesize = ftell(fp);
    if (filesize == -1L) {
      perror("Error determining file size");
      fclose(fp);
      return EXIT_FAILURE;
    }
    rewind(fp);

    char *afl_input = malloc(filesize + 1);
    if (afl_input == NULL) {
      fprintf(stderr, "Error: Memory allocation failed.\n");
      fclose(fp);
      return EXIT_FAILURE;
    }

    /* Read the file contents into the buffer */
    size_t read_size = fread(afl_input, 1, filesize, fp);
    if (read_size != filesize) {
      fprintf(stderr, "Error: Only read %zu of %ld bytes from file.\n", read_size, filesize);
      free(afl_input);
      fclose(fp);
      return EXIT_FAILURE;
    }

    afl_input[filesize] = '\0';  // Null-terminate the buffer

    memcpy(buf + 10, afl_input, filesize);
    __fuzz_HandleSecureMessage(buf, filesize);

    free(afl_input);
    fclose(fp);

    return 0;
  }

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
  /* unsigned char buf[65535] = "!001!#AES:"; */
  unsigned char *afl_input = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(1)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    if (len > 64000) {
      continue;
    }
    memcpy(buf + 10, afl_input, len);

    /* printf("%s %d\n", buf, len); */
    __fuzz_HandleSecureMessage(buf, len);
  }

  return 0;
}
