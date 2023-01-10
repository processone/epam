/*
 * Copyright (C) 2002-2023 ProcessOne, SARL. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define dec_int16(s) ((((unsigned char *)(s))[0] << 8) | \
                      (((unsigned char *)(s))[1]))

#define enc_int16(i, s)                            \
  {                                                \
    ((unsigned char *)(s))[0] = ((i) >> 8) & 0xff; \
    ((unsigned char *)(s))[1] = (i)&0xff;          \
  }

#define BUFSIZE (1 << 16)
#define CMD_AUTH 0
#define CMD_ACCT 1

typedef unsigned char byte;

typedef struct bin_t
{
  const char *data;
  unsigned int len;
} bin_t;

#ifdef PAM_FAIL_DELAY
static void delay_fn(int retval, unsigned usec_delay, void *appdata_ptr)
{
  /* No delay. However, looks like some PAM modules ignore this */
}
#endif

static int misc_conv(int num_msg,
                     const struct pam_message **msg,
                     struct pam_response **resp,
                     void *password)
{
  int msg_style;
  if (num_msg != 1)
    return PAM_CONV_ERR;
  msg_style = msg[0]->msg_style;
  if ((msg_style != PAM_PROMPT_ECHO_OFF) && (msg_style != PAM_PROMPT_ECHO_ON))
    return PAM_CONV_ERR;
  *resp = malloc(sizeof(struct pam_response));
  (*resp)[0].resp_retcode = 0;
  (*resp)[0].resp = strdup(password);
  return PAM_SUCCESS;
}

static int auth(const char *service, const char *user, const char *password, const char *rhost)
{
  struct pam_conv conv = {misc_conv, (char *)password};
  int retval;
  pam_handle_t *pamh = NULL;
  retval = pam_start(service, user, &conv, &pamh);
  if (retval == PAM_SUCCESS)
    retval = pam_set_item(pamh, PAM_RUSER, user);
  if (retval == PAM_SUCCESS)
    retval = pam_set_item(pamh, PAM_RHOST, rhost);
#ifdef PAM_FAIL_DELAY
  if (retval == PAM_SUCCESS)
    retval = pam_set_item(pamh, PAM_FAIL_DELAY, (void *)delay_fn);
#endif
  if (retval == PAM_SUCCESS)
    retval = pam_authenticate(pamh, 0);
  if (retval == PAM_SUCCESS)
    retval = pam_acct_mgmt(pamh, 0);
  pam_end(pamh, retval);
  return retval;
}

static int acct_mgmt(const char *service, const char *user)
{
  struct pam_conv conv = {misc_conv, NULL};
  int retval;
  pam_handle_t *pamh = NULL;
  retval = pam_start(service, user, &conv, &pamh);
  if (retval == PAM_SUCCESS)
    retval = pam_set_item(pamh, PAM_RUSER, user);
#ifdef PAM_FAIL_DELAY
  if (retval == PAM_SUCCESS)
    retval = pam_set_item(pamh, PAM_FAIL_DELAY, (void *)delay_fn);
#endif
  if (retval == PAM_SUCCESS)
    retval = pam_acct_mgmt(pamh, 0);
  pam_end(pamh, retval);
  return retval;
}

static int read_buf(int fd, byte *buf, int len)
{
  int i, got = 0;
  do
  {
    if ((i = read(fd, buf + got, len - got)) <= 0)
    {
      if (i == 0)
        return got;
      if (errno != EINTR)
        return got;
      i = 0;
    }
    got += i;
  } while (got < len);
  return (len);
}

static int read_cmd(byte *buf)
{
  int len;
  if (read_buf(0, buf, 2) != 2)
    return 0;
  len = dec_int16(buf);
  if (read_buf(0, buf, len) != len)
    return 0;
  return 1;
}

static bin_t read_bin(byte **buf)
{
  bin_t result;
  result.len = dec_int16(*buf);
  result.data = (const char*)(*buf + 2);
  *buf = *buf + 2 + result.len + 1;

  return result;
}

static int write_buf(int fd, const char *buf, int len)
{
  int i, done = 0;
  do
  {
    if ((i = write(fd, buf + done, len - done)) < 0)
    {
      if (errno != EINTR)
        return (i);
      i = 0;
    }
    done += i;
  } while (done < len);
  return (len);
}

static int write_cmd(const char *buf, int len)
{
  byte hd[2];
  enc_int16(len, hd);
  if (write_buf(1, (char *)hd, 2) != 2)
    return 0;
  if (write_buf(1, buf, len) != len)
    return 0;
  return 1;
}

static int process_reply(bin_t pid, int res)
{
  byte hd[3];
  int len;
  const char *errtxt;
  if (res == PAM_SUCCESS)
  {
    enc_int16(pid.len + 2 + 1, hd);
    hd[2] = 1;
    if (write_buf(1, (char *)hd, 3) != 3)
      return 0;
    if (!write_cmd(pid.data, pid.len))
      return 0;
  }
  else
  {
    errtxt = pam_strerror(NULL, res);
    len = strlen(errtxt);
    enc_int16(pid.len + 2 + 1 + len + 2, hd);
    hd[2] = 0;
    if (write_buf(1, (char *)hd, 3) != 3)
      return 0;
    enc_int16(pid.len, hd);
    if (!write_cmd(pid.data, pid.len))
      return 0;
    if (!write_cmd(errtxt, len))
      return 0;
  }
  return 1;
}

static int process_command(byte *buf)
{
  switch (buf[0])
  {
  case CMD_AUTH:
  {
    byte *tmp = buf + 1;
    bin_t pid = read_bin(&tmp);
    bin_t srv = read_bin(&tmp);
    bin_t user = read_bin(&tmp);
    bin_t pass = read_bin(&tmp);
    bin_t rhost = read_bin(&tmp);
    return process_reply(pid, auth(srv.data, user.data, pass.data, rhost.data));
  }
  case CMD_ACCT:
  {
    byte *tmp = buf + 1;
    bin_t pid = read_bin(&tmp);
    bin_t srv = read_bin(&tmp);
    bin_t user = read_bin(&tmp);
    return process_reply(pid, acct_mgmt(srv.data, user.data));
  }
  default:
    return 0;
  };
}

static void loop(void)
{
  byte buf[BUFSIZE];
  int retval = 0;
  do
  {
    if (read_cmd(buf) > 0)
      retval = process_command(buf);
    else
      retval = 0;
  } while (retval);
}

int main(int argc, char *argv[])
{
  loop();
  return 0;
}
