/*
 * Copyright (c) 2014 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pwd.h>

#include "util.h"

static void test_get_user_cfgfile_path(void) {
  char *file;
  struct passwd user;
  int ret;
  user.pw_name = "root";
  user.pw_dir = "/root";
  ret = get_user_cfgfile_path("/foo/bar", "test", &user, &file);
  assert(ret == 1);
  assert(strcmp(file, "/foo/bar/test") == 0);
  free(file);
  ret = get_user_cfgfile_path(NULL, "test", &user, &file);
  assert(ret == 1);
  assert(strcmp(file, "/root/.yubico/test") == 0);
  free(file);
}

static void test_check_user_token(void) {
  char file[] = "/tmp/pamtest.XXXXXX";
  int fd = mkstemp(file);
  FILE *handle;
  int ret;

  assert(fd != -1);
  handle = fdopen(fd, "w");
  fprintf(handle, "# This is a comment containing foobar:foobar\n");
  fprintf(handle, "foobar:hhhvhvhdhbid:hnhbhnhbhnhb:\n");
  fprintf(handle, "# This is a comment in the middle\n");
  fprintf(handle, "kaka:hdhrhbhjhvhu:hihbhdhrhbhj\n");
  fprintf(handle, "# foo2 is a user showing up twice in the file\n");
  fprintf(handle, "foo2:vvvvvvvvvvvv\n");
  fprintf(handle, "bar:hnhbhnhbhnhb\n");
  fprintf(handle, "foo2:cccccccccccc\n");
  fclose(handle);

  ret = check_user_token(file, "foobar", "hhhvhvhdhbid", 1);
  assert(ret == 1);
  ret = check_user_token(file, "foobar", "hnhbhnhbhnhb", 1);
  assert(ret == 1);
  ret = check_user_token(file, "foobar", "hnhbhnhbhnhc", 1);
  assert(ret == -1);
  ret = check_user_token(file, "kaka", "hihbhdhrhbhj", 1);
  assert(ret == 1);
  ret = check_user_token(file, "bar", "hnhbhnhbhnhb", 1);
  assert(ret == 1);
  ret = check_user_token(file, "foo", "hdhrhbhjhvhu", 1);
  assert(ret == -2);
  ret = check_user_token(file, "foo2", "cccccccccccc", 1);
  assert(ret == 1);
  ret = check_user_token(file, "foo2", "vvvvvvvvvvvv", 1);
  assert(ret == 1);
  ret = check_user_token(file, "foo2", "vvvvvvvvvvcc", 1);
  assert(ret == -1);
  ret = check_user_token(file, "foo2", "", 1);
  assert(ret == -1);
  ret = check_user_token(file, "foo", "", 1);
  assert(ret == -2);
  remove(file);
}

#if HAVE_CR

#define CHALLENGE1 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define RESPONSE1 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define SALT1 "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define CHALLENGE2 "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
#define RESPONSE2 "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

static void test_load_chalresp_state(void) {
  int ret;
  FILE *file = tmpfile();
  CR_STATE state;

  memset(&state, 0, sizeof(state));
  fprintf(file, "v2:%s:%s:%s:%d:%d\n", CHALLENGE1, RESPONSE1, SALT1, 1000, 2);
  rewind(file);
  ret = load_chalresp_state(file, &state, true);
  assert(ret == 1);
  assert(state.iterations == 1000);
  assert(state.slot == 2);
  assert(state.challenge_len == CR_CHALLENGE_SIZE);
  assert(state.response_len == CR_RESPONSE_SIZE);
  assert(state.salt_len == CR_SALT_SIZE);
  rewind(file);

  memset(&state, 0, sizeof(state));
  fprintf(file, "v1:%s:%s:%d\n", CHALLENGE2, RESPONSE2, 1);
  rewind(file);
  ret = load_chalresp_state(file, &state, true);
  assert(ret == 1);
  assert(state.iterations == CR_DEFAULT_ITERATIONS);
  assert(state.slot == 1);
  assert(state.challenge_len == CR_CHALLENGE_SIZE);
  assert(state.response_len == CR_RESPONSE_SIZE);
  assert(state.salt_len == 0);
  rewind(file);

  /* slot 3 should fail.. */
  fprintf(file, "v2:%s:%s:%s:%d:%d\n", CHALLENGE1, RESPONSE1, SALT1, 1000, 3);
  rewind(file);
  ret = load_chalresp_state(file, &state, true);
  assert(ret == 0);
  fclose(file);
}

#endif /* HAVE_CR */

static void test_filter_printf(void) {
    assert(filter_result_len("meno %u", "doof", NULL) == 10);
    assert(filter_result_len("meno %u %u", "doof", NULL) == 15);
    assert(filter_result_len("%u meno %u", "doof", NULL) == 15);
    assert(filter_result_len("%u me %u no %u", "doof", NULL) == 21);
    assert(filter_result_len("meno %w %%u", "doof", NULL) == 14);
    assert(filter_result_len("meno %w %%u meno", "doof", NULL) == 19);
    assert(filter_result_len("meno ", "doof", NULL) == 6);

    assert(!strcmp(filter_printf("meno %u", "doof"), "meno doof"));
    assert(!strcmp(filter_printf("meno %u %u", "doof"), "meno doof doof"));
    assert(!strcmp(filter_printf("%u meno %u", "doof"), "doof meno doof"));
    assert(!strcmp(filter_printf("%u me %u no %u", "doof"), "doof me doof no doof"));
    assert(!strcmp(filter_printf("meno %w %%u", "doof"), "meno %w %doof"));
    assert(!strcmp(filter_printf("meno %w %%u meno", "doof"), "meno %w %doof meno"));
    assert(!strcmp(filter_printf("meno ", "doof"), "meno "));
    printf("test_filter_printf OK\n");
}

int main (void) {
  test_filter_printf();
  test_get_user_cfgfile_path();
  test_check_user_token();
#if HAVE_CR
  test_load_chalresp_state();
#endif /* HAVE_CR */
  return 0;
}
