#ifndef HEADER_CURL_MD4_H
#define HEADER_CURL_MD4_H
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

#include "curl_setup.h"
#include <curl/curl.h>

#ifdef USE_CURL_NTLM_CORE

/*
 * SECURITY WARNING: MD4 is a cryptographically broken hash algorithm that
 * provides insufficient computational effort for secure password hashing.
 * MD4 should not be used for new applications.
 *
 * This implementation exists solely for NTLM authentication protocol
 * compatibility, as the NTLM specification mandates the use of MD4.
 *
 * Applications should migrate away from NTLM to more secure authentication
 * methods such as Kerberos, OAuth, or other modern mechanisms.
 */

#define MD4_DIGEST_LENGTH 16

/*
 * Curl_md4it() - Compute MD4 hash (INSECURE - for NTLM compatibility only)
 *
 * This function computes the MD4 hash of input data. MD4 is cryptographically
 * broken and should only be used for NTLM protocol compatibility.
 *
 * Parameters:
 *   output - Buffer to store the 16-byte MD4 hash (must be at least
 *            MD4_DIGEST_LENGTH bytes)
 *   input  - Input data to hash
 *   len    - Length of input data in bytes
 *
 * Returns:
 *   CURLE_OK on success
 *   CURLE_FAILED_INIT if MD4 initialization fails
 */
CURLcode Curl_md4it(unsigned char *output, const unsigned char *input,
                    const size_t len);

#endif /* USE_CURL_NTLM_CORE */

#endif /* HEADER_CURL_MD4_H */
