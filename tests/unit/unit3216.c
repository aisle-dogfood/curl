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

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "urldata.h"
#include "curl_krb5.h"

#if defined(HAVE_GSSAPI) && !defined(CURL_DISABLE_FTP)

struct krb5_len_case {
  uint32_t netlen;
  CURLcode result;
  size_t decoded_len;
};

static CURLcode test_unit3216(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  const struct krb5_len_case cases[] = {
    { 0U, CURLE_RECV_ERROR, 0 },
    { htonl(1U), CURLE_OK, 1 },
    { htonl((uint32_t)CURL_MAX_INPUT_LENGTH), CURLE_OK,
      CURL_MAX_INPUT_LENGTH },
    { htonl((uint32_t)CURL_MAX_INPUT_LENGTH + 1U), CURLE_TOO_LARGE, 0 },
    { 0xffffffffU, CURLE_TOO_LARGE, 0 }
  };
  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(cases); ++i) {
    size_t decoded_len = 0;
    CURLcode result = Curl_krb5_decode_len(cases[i].netlen, &decoded_len);

    if(result != cases[i].result) {
      curl_mfprintf(stderr, "test %zu: expected result %d, got %d\n",
                    i, cases[i].result, result);
      unitfail++;
    }
    if(!result && decoded_len != cases[i].decoded_len) {
      curl_mfprintf(stderr, "test %zu: expected length %zu, got %zu\n",
                    i, cases[i].decoded_len, decoded_len);
      unitfail++;
    }
  }

  UNITTEST_END_SIMPLE
}

#else

static CURLcode test_unit3216(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("not tested since FTP GSS-API support is not built in");
  UNITTEST_END_SIMPLE
}

#endif
