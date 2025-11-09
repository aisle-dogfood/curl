/* File: report_openssl_version.c
 *
 * This file dynamically loads the OpenSSL shared image to report the
 * version string.
 *
 * It will optionally place that version string in a DCL symbol.
 *
 * Usage:  report_openssl_version <shared_image> [<dcl_symbol>]
 *
 * Copyright (C) John Malmberg
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * SPDX-License-Identifier: ISC
 *
 */

#include <dlfcn.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#include <string.h>
#include <descrip.h>
#include <libclidef.h>
#include <stsdef.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>

unsigned long LIB$SET_SYMBOL(
  const struct dsc$descriptor_s * symbol,
  const struct dsc$descriptor_s * value,
  const unsigned long *table_type);

/* Validate that the library path is safe to load */
static int validate_library_path(const char *path)
{
  struct stat st;
  char resolved_path[PATH_MAX];
  
  /* Check if file exists and get its properties */
  if(stat(path, &st) != 0) {
    fprintf(stderr, "Error: Cannot access file %s: %s\n", path, strerror(errno));
    return 0;
  }
  
  /* Ensure it's a regular file */
  if(!S_ISREG(st.st_mode)) {
    fprintf(stderr, "Error: %s is not a regular file\n", path);
    return 0;
  }
  
  /* Resolve the real path to prevent directory traversal attacks */
  if(realpath(path, resolved_path) == NULL) {
    fprintf(stderr, "Error: Cannot resolve path %s: %s\n", path, strerror(errno));
    return 0;
  }
  
  /* Check that the resolved path is in a trusted location */
  /* On VMS, OpenSSL libraries are typically in SYS$SHARE or similar system directories */
  if(strncmp(resolved_path, "/sys$share/", 11) != 0 &&
     strncmp(resolved_path, "/usr/lib/", 9) != 0 &&
     strncmp(resolved_path, "/opt/", 5) != 0) {
    fprintf(stderr, "Error: Library %s is not in a trusted location\n", resolved_path);
    return 0;
  }
  
  /* Check file permissions - should not be world-writable */
  if(st.st_mode & S_IWOTH) {
    fprintf(stderr, "Error: Library %s is world-writable, potential security risk\n", path);
    return 0;
  }
  
  return 1;
}

int main(int argc, char **argv)
{
  void *libptr;
  const char * (*ssl_version)(int t);
  const char *version;

  if(argc < 2) {
    puts("report_openssl_version filename");
    return 1;
  }

  /* Validate the library path before loading */
  if(!validate_library_path(argv[1])) {
    return 1;
  }

  libptr = dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
  if(!libptr) {
    fprintf(stderr, "Error: Failed to load library %s: %s\n", argv[1], dlerror());
    return 1;
  }

  ssl_version = (const char * (*)(int))dlsym(libptr, "SSLeay_version");
  if(!ssl_version) {
    ssl_version = (const char * (*)(int))dlsym(libptr, "ssleay_version");
    if(!ssl_version) {
      ssl_version = (const char * (*)(int))dlsym(libptr, "SSLEAY_VERSION");
    }
  }

  if(!ssl_version) {
    fprintf(stderr, "Error: Unable to lookup version function in OpenSSL library\n");
    dlclose(libptr);
    return 1;
  }

  version = ssl_version(SSLEAY_VERSION);
  
  /* Close the library after getting the version string */
  dlclose(libptr);

  puts(version);

  /* Was a symbol argument given? */
  if(argc > 2) {
    int status;
    struct dsc$descriptor_s symbol_dsc;
    struct dsc$descriptor_s value_dsc;
    const unsigned long table_type = LIB$K_CLI_LOCAL_SYM;

    symbol_dsc.dsc$a_pointer = argv[2];
    symbol_dsc.dsc$w_length = strlen(argv[2]);
    symbol_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
    symbol_dsc.dsc$b_class = DSC$K_CLASS_S;

    value_dsc.dsc$a_pointer = (char *)version; /* Cast ok */
    value_dsc.dsc$w_length = strlen(version);
    value_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
    value_dsc.dsc$b_class = DSC$K_CLASS_S;

    status = LIB$SET_SYMBOL(&symbol_dsc, &value_dsc, &table_type);
    if(!$VMS_STATUS_SUCCESS(status)) {
      return status;
    }
  }

  return 0;
}
