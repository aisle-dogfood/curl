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
/* for open() */
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
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

  if(!filename)
    return;

  if(!strcmp(filename, "-")) {
    tool_stderr = stdout;
    return;
  }

#if defined(HAVE_FCNTL_H) && defined(HAVE_SYS_STAT_H) && !defined(_WIN32)
  /* On Unix-like systems, create the file with restrictive permissions (0600)
     to prevent leakage of sensitive information that may be written to stderr.
     This protects against insecure umask settings. */
  {
    int fd;
    int flags = O_CREAT | O_WRONLY | O_TRUNC;
    mode_t mode = S_IRUSR | S_IWUSR; /* 0600 */

    /* precheck that filename is accessible to lessen the chance that the
       subsequent freopen will fail. */
    fd = open(filename, flags, mode);
    if(fd == -1) {
      warnf("Warning: Failed to open %s", filename);
      return;
    }

    /* Convert file descriptor to FILE* */
    fp = fdopen(fd, FOPEN_WRITETEXT);
    if(!fp) {
      close(fd);
      warnf("Warning: Failed to open %s", filename);
      return;
    }
    fclose(fp);
  }
#else
  /* On Windows and other systems, use fopen.
     Windows does not use Unix permissions. */
  /* precheck that filename is accessible to lessen the chance that the
     subsequent freopen will fail. */
  fp = fopen(filename, FOPEN_WRITETEXT);
  if(!fp) {
    warnf("Warning: Failed to open %s", filename);
    return;
  }
  fclose(fp);
#endif

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
