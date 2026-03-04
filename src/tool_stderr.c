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

#include "tool_setup.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_IO_H
#include <io.h>
#endif

#include "tool_stderr.h"
#include "tool_msgs.h"

#include "memdebug.h" /* keep this as LAST include */

FILE *tool_stderr;

void tool_init_stderr(void)
{
  /* !checksrc! disable STDERR 1 */
  tool_stderr = stderr;
}

void tool_set_stderr_file(const char *filename)
{
  FILE *fp;
  int fd = -1;

  if(!filename)
    return;

  if(!strcmp(filename, "-")) {
    tool_stderr = stdout;
    return;
  }

  /* Create file with restrictive permissions (0600) to prevent information
     leakage in multi-user environments. This protects sensitive data that
     may be written to stderr (credentials, headers, verbose output). */
#ifdef _WIN32
  /* On Windows, use _open with _S_IREAD | _S_IWRITE for user-only access.
     Note: Windows ACLs provide the real security; these permission bits
     primarily affect file mode for compatibility. */
  fd = _open(filename, _O_WRONLY | _O_CREAT | _O_TRUNC | CURL_O_BINARY,
             _S_IREAD | _S_IWRITE);
#else
  /* On Unix-like systems, use open with mode 0600 for user read/write only.
     This ensures the file is created with restrictive permissions regardless
     of the process umask. */
  fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | CURL_O_BINARY, 0600);
#endif

  if(fd == -1) {
    warnf("Warning: Failed to open %s", filename);
    return;
  }

  /* Convert file descriptor to FILE* */
  fp = fdopen(fd, FOPEN_WRITETEXT);
  if(!fp) {
    warnf("Warning: Failed to fdopen %s", filename);
#ifdef _WIN32
    _close(fd);
#else
    close(fd);
#endif
    return;
  }
  fclose(fp);

  /* freopen the actual stderr (stdio.h stderr) instead of tool_stderr since
     the latter may be set to stdout. */
  /* !checksrc! disable STDERR 1 */
  fp = freopen(filename, FOPEN_WRITETEXT, stderr);
  if(!fp) {
    /* stderr may have been closed by freopen. there is nothing to be done. */
    DEBUGASSERT(0);
    return;
  }
  /* !checksrc! disable STDERR 1 */
  tool_stderr = stderr;
}
