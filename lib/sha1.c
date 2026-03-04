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

#ifndef CURL_DISABLE_WEBSOCKETS

#include "curlx/warnless.h"
#include "curl_sha1.h"

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#elif defined(USE_GNUTLS)
#include <nettle/sha.h>
#elif defined(USE_MBEDTLS)
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER < 0x03020000
  #error "mbedTLS 3.2.0 or later required"
#endif
#include <mbedtls/sha1.h>
#elif (defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && \
              (__MAC_OS_X_VERSION_MAX_ALLOWED >= 1040)) || \
      (defined(__IPHONE_OS_VERSION_MAX_ALLOWED) && \
              (__IPHONE_OS_VERSION_MAX_ALLOWED >= 20000))
#include <CommonCrypto/CommonDigest.h>
#define AN_APPLE_OS
#elif defined(USE_WIN32_CRYPTO)
#include <wincrypt.h>
#endif

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* Please keep the SSL backend-specific #if branches in this order:
 *
 * 1. USE_OPENSSL
 * 2. USE_GNUTLS
 * 3. USE_MBEDTLS
 * 4. USE_COMMON_CRYPTO
 * 5. USE_WIN32_CRYPTO
 *
 * This ensures that the same SSL branch gets activated throughout this source
 * file even if multiple backends are enabled at the same time.
 */

#ifdef USE_OPENSSL

struct ossl_sha1_ctx {
  EVP_MD_CTX *openssl_ctx;
};
typedef struct ossl_sha1_ctx my_sha1_ctx;

static CURLcode my_sha1_init(void *in)
{
  my_sha1_ctx *ctx = (my_sha1_ctx *)in;
  ctx->openssl_ctx = EVP_MD_CTX_create();
  if(!ctx->openssl_ctx)
    return CURLE_OUT_OF_MEMORY;

  if(!EVP_DigestInit_ex(ctx->openssl_ctx, EVP_sha1(), NULL)) {
    EVP_MD_CTX_destroy(ctx->openssl_ctx);
    return CURLE_FAILED_INIT;
  }
  return CURLE_OK;
}

static void my_sha1_update(void *in,
                           const unsigned char *data,
                           unsigned int length)
{
  my_sha1_ctx *ctx = (my_sha1_ctx *)in;
  EVP_DigestUpdate(ctx->openssl_ctx, data, length);
}

static void my_sha1_final(unsigned char *digest, void *in)
{
  my_sha1_ctx *ctx = (my_sha1_ctx *)in;
  EVP_DigestFinal_ex(ctx->openssl_ctx, digest, NULL);
  EVP_MD_CTX_destroy(ctx->openssl_ctx);
}

#elif defined(USE_GNUTLS)

typedef struct sha1_ctx my_sha1_ctx;

static CURLcode my_sha1_init(void *ctx)
{
  sha1_init(ctx);
  return CURLE_OK;
}

static void my_sha1_update(void *ctx,
                           const unsigned char *data,
                           unsigned int length)
{
  sha1_update(ctx, length, data);
}

static void my_sha1_final(unsigned char *digest, void *ctx)
{
  sha1_digest(ctx, SHA1_DIGEST_SIZE, digest);
}

#elif defined(USE_MBEDTLS)

typedef mbedtls_sha1_context my_sha1_ctx;

static CURLcode my_sha1_init(void *ctx)
{
  (void)mbedtls_sha1_starts(ctx);
  return CURLE_OK;
}

static void my_sha1_update(void *ctx,
                           const unsigned char *data,
                           unsigned int length)
{
  (void)mbedtls_sha1_update(ctx, data, length);
}

static void my_sha1_final(unsigned char *digest, void *ctx)
{
  (void)mbedtls_sha1_finish(ctx, digest);
}

#elif defined(AN_APPLE_OS)
typedef CC_SHA1_CTX my_sha1_ctx;

static CURLcode my_sha1_init(void *ctx)
{
  (void)CC_SHA1_Init(ctx);
  return CURLE_OK;
}

static void my_sha1_update(void *ctx,
                           const unsigned char *data,
                           unsigned int length)
{
  (void)CC_SHA1_Update(ctx, data, length);
}

static void my_sha1_final(unsigned char *digest, void *ctx)
{
  (void)CC_SHA1_Final(digest, ctx);
}

#elif defined(USE_WIN32_CRYPTO)

struct sha1_ctx {
  HCRYPTPROV hCryptProv;
  HCRYPTHASH hHash;
};
typedef struct sha1_ctx my_sha1_ctx;

static CURLcode my_sha1_init(void *in)
{
  my_sha1_ctx *ctx = (my_sha1_ctx *)in;
  if(!CryptAcquireContext(&ctx->hCryptProv, NULL, NULL, PROV_RSA_FULL,
                         CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    return CURLE_OUT_OF_MEMORY;

  if(!CryptCreateHash(ctx->hCryptProv, CALG_SHA1, 0, 0, &ctx->hHash)) {
    CryptReleaseContext(ctx->hCryptProv, 0);
    ctx->hCryptProv = 0;
    return CURLE_FAILED_INIT;
  }

  return CURLE_OK;
}

static void my_sha1_update(void *in,
                           const unsigned char *data,
                           unsigned int length)
{
  my_sha1_ctx *ctx = (my_sha1_ctx *)in;
#ifdef __MINGW32CE__
  CryptHashData(ctx->hHash, (BYTE *)CURL_UNCONST(data), length, 0);
#else
  CryptHashData(ctx->hHash, (const BYTE *)data, length, 0);
#endif
}

static void my_sha1_final(unsigned char *digest, void *in)
{
  my_sha1_ctx *ctx = (my_sha1_ctx *)in;
  unsigned long length = 0;

  CryptGetHashParam(ctx->hHash, HP_HASHVAL, NULL, &length, 0);
  if(length == CURL_SHA1_DIGEST_LENGTH)
    CryptGetHashParam(ctx->hHash, HP_HASHVAL, digest, &length, 0);

  if(ctx->hHash)
    CryptDestroyHash(ctx->hHash);

  if(ctx->hCryptProv)
    CryptReleaseContext(ctx->hCryptProv, 0);
}

#else

#error "No SHA1 implementation available"

#endif /* CRYPTO LIBS */

/*
 * Curl_sha1it()
 *
 * Generates a SHA1 hash for the given input data.
 *
 * Parameters:
 *
 * output [in/out] - The output buffer.
 * input  [in]     - The input data.
 * length [in]     - The input length.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sha1it(unsigned char *output, const unsigned char *input,
                     const size_t length)
{
  CURLcode result;
  my_sha1_ctx ctx;

  result = my_sha1_init(&ctx);
  if(!result) {
    my_sha1_update(&ctx, input, curlx_uztoui(length));
    my_sha1_final(output, &ctx);
  }
  return result;
}

#endif /* !CURL_DISABLE_WEBSOCKETS */
