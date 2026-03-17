#include <stdlib.h>

#include "shared.h"
#include "remoted.h"

/* from client.keys: 001 fuzz01 any 7c6e622b906b1fd60dfec2817d237e5f14a9de08b950f3902c830894e93adf77 */

__AFL_FUZZ_INIT();

void __fuzz_HandleSecureMessage(unsigned char* afl_input, int len) {
  int agentid;
  const int protocol = REMOTED_NET_PROTOCOL_UDP;
  char cleartext_msg[OS_MAXSTR + 1];
  char srcmsg[OS_FLSIZE + 1];
  char srcip[IPSIZE + 1] = {0};
  char agname[KEYSIZE + 1] = {0};
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

      return;
    }

    *tmp_msg = '\0';
    tmp_msg++;
    recv_b -= 2;
  }

  agentid = 0;
  key_lock_read();

  /* Decrypt the message */
  ReadSecMSG(&keys, tmp_msg, cleartext_msg, agentid, recv_b - 1, &msg_length, srcip, &tmp_msg);

  /* Recieved valid message timestamp updated. */
  keys.keyentries[agentid]->rcvd = time(NULL);

  /* Check if it is a control message */
  if (IsValidHeader(tmp_msg)) {
    return;
  }

  key_unlock();
}

int main() {
  OS_ReadKeys(&keys, W_ENCRYPTION_KEY, 0);
  OS_StartCounter(&keys);
  keys.keyentries[0]->crypto_method = W_METH_AES;

  char msg_encrypted[OS_MAXSTR + 1];

  size_t sz_evt_header = 9;

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

    // afl_input should be formatted as an "event"
    // <Queue>:<Location>:<Message>
    // 4:FUZZER:__AFL_FUZZ_TESTCASE_BUF
    char *afl_input = malloc(filesize + 1 + sz_evt_header);
    if (afl_input == NULL) {
      fprintf(stderr, "Error: Memory allocation failed.\n");
      fclose(fp);
      return EXIT_FAILURE;
    }
    strcpy(afl_input, "4:FUZZER:");

    /* Read the file contents into the buffer */
    size_t read_size = fread(afl_input + sz_evt_header, 1, filesize, fp);
    if (read_size != filesize) {
      fprintf(stderr, "Error: Only read %zu of %ld bytes from file.\n", read_size, filesize);
      free(afl_input);
      fclose(fp);
      return EXIT_FAILURE;
    }

    afl_input[filesize + sz_evt_header] = '\0';  // Null-terminate the buffer

    size_t enc_len = CreateSecMSG(&keys, afl_input, filesize + sz_evt_header, msg_encrypted, 0);
    __fuzz_HandleSecureMessage(msg_encrypted, enc_len);

    free(afl_input);
    fclose(fp);

    return 0;
  }

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
  unsigned char buf[65535] = "4:FUZZER:";
  unsigned char *afl_input = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(1)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    if (len > 64000) {
      continue;
    }

    memcpy(buf + sz_evt_header, afl_input, len);
    buf[len + sz_evt_header] = '\0';

    size_t enc_len = CreateSecMSG(&keys, buf, len + sz_evt_header, msg_encrypted, 0);

    __fuzz_HandleSecureMessage(msg_encrypted, enc_len);
  }

  return 0;
}
