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
#include <unistd.h>

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

  ret = check_user_token(file, "foobar", "hhhvhvhdhbid", 1, stdout);
  assert(ret == AUTH_FOUND);
  ret = check_user_token(file, "foobar", "hnhbhnhbhnhb", 1, stdout);
  assert(ret == AUTH_FOUND);
  ret = check_user_token(file, "foobar", "hnhbhnhbhnhc", 1, stdout);
  assert(ret == AUTH_NOT_FOUND);
  ret = check_user_token(file, "kaka", "hihbhdhrhbhj", 1, stdout);
  assert(ret == AUTH_FOUND);
  ret = check_user_token(file, "bar", "hnhbhnhbhnhb", 1, stdout);
  assert(ret == AUTH_FOUND);
  ret = check_user_token(file, "foo", "hdhrhbhjhvhu", 1, stdout);
  assert(ret == AUTH_NO_TOKENS);
  ret = check_user_token(file, "foo2", "cccccccccccc", 1, stdout);
  assert(ret == AUTH_FOUND);
  ret = check_user_token(file, "foo2", "vvvvvvvvvvvv", 1, stdout);
  assert(ret == AUTH_FOUND);
  ret = check_user_token(file, "foo2", "vvvvvvvvvvcc", 1, stdout);
  assert(ret == AUTH_NOT_FOUND);
  ret = check_user_token(file, "foo2", "", 1, stdout);
  assert(ret == AUTH_NOT_FOUND);
  ret = check_user_token(file, "foo", "", 1, stdout);
  assert(ret == AUTH_NO_TOKENS);
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
  ret = load_chalresp_state(file, &state, true, stdout);
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
  ret = load_chalresp_state(file, &state, true, stdout);
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
  ret = load_chalresp_state(file, &state, true, stdout);
  assert(ret == 0);
  fclose(file);
}

static void test_check_user_challenge_file(void) {
  int ret;
  char * tmpdir_path;
  char * buf;
  FILE * file;
  struct passwd user;

  buf = malloc(256);

#define create_tmpdir_dir(path) \
  strcpy(buf, tmpdir_path); \
  strcat(buf, "/"); \
  strcat(buf, path); \
  mkdir(buf, 0755);

#define remove_tmpdir_dir(path) \
  strcpy(buf, tmpdir_path); \
  strcat(buf, "/"); \
  strcat(buf, path); \
  rmdir(buf);

#define create_tmpdir_file(path) \
  strcpy(buf, tmpdir_path); \
  strcat(buf, "/"); \
  strcat(buf, path); \
  file = fopen(buf, "w"); \
  fclose(file);

#define remove_tmpdir_file(path) \
  strcpy(buf, tmpdir_path); \
  strcat(buf, "/"); \
  strcat(buf, path); \
  unlink(buf);

  /* create temporary directory */
  char template[] = "/tmp/pamtest.XXXXXX";
  tmpdir_path = mkdtemp(template);
  assert(tmpdir_path != NULL);

  /* set user data */
  user.pw_name = "tester";
  user.pw_dir = tmpdir_path;

  /* execute tests */
  /* no asserts here as we have directory to remove */

  int case_001_empty_chalresp_dir;
  case_001_empty_chalresp_dir = check_user_challenge_file(tmpdir_path, &user, stdout);

  int case_002_one_challenge_file;
  create_tmpdir_file("tester");
  case_002_one_challenge_file = check_user_challenge_file(tmpdir_path, &user, stdout);
  remove_tmpdir_file("tester");

  int case_003_multiple_challenge_files;
  create_tmpdir_file("tester-001");
  create_tmpdir_file("tester-002");
  case_003_multiple_challenge_files = check_user_challenge_file(tmpdir_path, &user, stdout);
  remove_tmpdir_file("tester-002");
  remove_tmpdir_file("tester-001");

  int case_004_other_users_files;
  create_tmpdir_file("tester1");
  create_tmpdir_file("tester1-001");
  case_004_other_users_files = check_user_challenge_file(tmpdir_path, &user, stdout);
  remove_tmpdir_file("tester1-001");
  remove_tmpdir_file("tester1");

  int case_005_no_chalresp_no_yubico;
  case_005_no_chalresp_no_yubico = check_user_challenge_file(NULL, &user, stdout);

  int case_006_no_chalresp_empty_yubico;
  create_tmpdir_dir(".yubico");
  case_006_no_chalresp_empty_yubico = check_user_challenge_file(NULL, &user, stdout);
  remove_tmpdir_dir(".yubico");

  int case_007_no_chalresp_one_challenge_file;
  create_tmpdir_dir(".yubico");
  create_tmpdir_file(".yubico/challenge");
  case_007_no_chalresp_one_challenge_file = check_user_challenge_file(NULL, &user, stdout);
  remove_tmpdir_file(".yubico/challenge");
  remove_tmpdir_dir(".yubico");

  int case_008_no_chalresp_multiple_challenge_files;
  create_tmpdir_dir(".yubico");
  create_tmpdir_file(".yubico/challenge-001");
  create_tmpdir_file(".yubico/challenge-002");
  case_008_no_chalresp_multiple_challenge_files = check_user_challenge_file(NULL, &user, stdout);
  remove_tmpdir_file(".yubico/challenge-002");
  remove_tmpdir_file(".yubico/challenge-001");
  remove_tmpdir_dir(".yubico");

  /* remove temporary directory */
  ret = rmdir(tmpdir_path);
  assert(ret == 0);
  free(tmpdir_path);
  free(buf);

  /* check test results */
  assert(case_001_empty_chalresp_dir == AUTH_NOT_FOUND);
  assert(case_002_one_challenge_file == AUTH_FOUND);
  assert(case_003_multiple_challenge_files == AUTH_FOUND);
  assert(case_004_other_users_files == AUTH_NOT_FOUND);
  assert(case_005_no_chalresp_no_yubico == AUTH_NOT_FOUND);
  assert(case_006_no_chalresp_empty_yubico == AUTH_NOT_FOUND);
  assert(case_007_no_chalresp_one_challenge_file == AUTH_FOUND);
  assert(case_008_no_chalresp_multiple_challenge_files == AUTH_FOUND);

#undef create_tmpdir_dir
#undef remove_tmpdir_dir
#undef create_tmpdir_file
#undef remove_tmpdir_file
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
  test_check_user_challenge_file();
#endif /* HAVE_CR */
  return 0;
}
