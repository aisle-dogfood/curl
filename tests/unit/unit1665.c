/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "unitcheck.h"

#include "urldata.h"
#include "curl_setup.h"

#include "memdebug.h" /* LAST include file */

static CURLcode t1665_setup(void)
{
  CURLcode res = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  return res;
}

static void t1665_test_haproxy_client_ip(
  const char *input_ip,
  CURLcode exp_rc)
{
  CURL *easy;
  CURLcode rc;

  easy = curl_easy_init();
  fail_unless(easy != NULL, "curl_easy_init() failed");

  rc = curl_easy_setopt(easy, CURLOPT_HAPROXY_CLIENT_IP, input_ip);
  fail_unless(rc == exp_rc, "curl_easy_setopt(CURLOPT_HAPROXY_CLIENT_IP) "
              "returned unexpected code");

  curl_easy_cleanup(easy);
}

static CURLcode test_unit1665(const char *arg)
{
  (void)arg;
  UNITTEST_BEGIN(t1665_setup())

  /* Valid IPv4 addresses should be accepted */
  t1665_test_haproxy_client_ip("192.168.1.1", CURLE_OK);
  t1665_test_haproxy_client_ip("127.0.0.1", CURLE_OK);
  t1665_test_haproxy_client_ip("0.0.0.0", CURLE_OK);
  t1665_test_haproxy_client_ip("255.255.255.255", CURLE_OK);
  t1665_test_haproxy_client_ip("10.0.0.1", CURLE_OK);

  /* Valid IPv6 addresses should be accepted */
  t1665_test_haproxy_client_ip("::1", CURLE_OK);
  t1665_test_haproxy_client_ip("fe80::1", CURLE_OK);
  t1665_test_haproxy_client_ip("2001:db8::1", CURLE_OK);
  t1665_test_haproxy_client_ip("::ffff:192.168.1.1", CURLE_OK);

  /* Invalid addresses with CRLF injection should be rejected */
  t1665_test_haproxy_client_ip("192.168.1.1\r\n", CURLE_BAD_FUNCTION_ARGUMENT);
  t1665_test_haproxy_client_ip("192.168.1.1\nGET / HTTP/1.1\r\n",
                               CURLE_BAD_FUNCTION_ARGUMENT);
  t1665_test_haproxy_client_ip("127.0.0.1\r\nPROXY UNKNOWN\r\n",
                               CURLE_BAD_FUNCTION_ARGUMENT);

  /* Other invalid addresses should be rejected */
  t1665_test_haproxy_client_ip("not-an-ip", CURLE_BAD_FUNCTION_ARGUMENT);
  t1665_test_haproxy_client_ip("999.999.999.999",
                               CURLE_BAD_FUNCTION_ARGUMENT);
  t1665_test_haproxy_client_ip("example.com", CURLE_BAD_FUNCTION_ARGUMENT);
  t1665_test_haproxy_client_ip("192.168.1.1:8080",
                               CURLE_BAD_FUNCTION_ARGUMENT);

  /* NULL should be accepted (clears the option) */
  t1665_test_haproxy_client_ip(NULL, CURLE_OK);

  UNITTEST_END()
  return CURLE_OK;
}
