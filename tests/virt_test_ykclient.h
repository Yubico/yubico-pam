

ykclient_rc test_ykclient_init (ykclient_t ** ykc) {
  return YKCLIENT_OK;
}

void test_ykclient_done (ykclient_t ** ykc) {
}

ykclient_rc test_ykclient_request (ykclient_t * ykc, const char *yubikey_otp) {
  if (!strcmp("ccccccdhuvvvijehidgthrhtglegiiijdktvgrhgukci", yubikey_otp)) {
    return YKCLIENT_OK;
  }
  return YKCLIENT_BAD_OTP;
}

const char *test_ykclient_strerror (ykclient_rc ret) {
  return ykclient_strerror(ret);
}

ykclient_rc test_ykclient_set_client_b64 (ykclient_t * ykc, unsigned int client_id, const char *key) {
  return YKCLIENT_OK;
}

void test_ykclient_set_verify_signature (ykclient_t * ykc, int value) {
}

void test_ykclient_set_ca_path (ykclient_t * ykc, const char *ca_path) {
}

ykclient_rc test_ykclient_set_url_template (ykclient_t * ykc, const char *url_template) {
  return YKCLIENT_BAD_INPUT;
}

ykclient_rc test_ykclient_set_url_bases (ykclient_t * ykc, size_t num_templates, const char **url_templates) {
  return YKCLIENT_BAD_INPUT;
}

ykclient_rc test_ykclient_global_init () {
  return YKCLIENT_OK;
}

void test_ykclient_global_done () {
}

static VirtYkClient test_ykclient = {
  &test_ykclient_init,
  &test_ykclient_done,
  &test_ykclient_request,
  &test_ykclient_strerror,
  &test_ykclient_set_client_b64,
  &test_ykclient_set_verify_signature,
  &test_ykclient_set_ca_path,
  &test_ykclient_set_url_template,
  &test_ykclient_set_url_bases,
  &test_ykclient_global_init,
  &test_ykclient_global_done,
};

