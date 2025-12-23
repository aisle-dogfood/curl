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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_IO_H
#include <io.h>
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

/* !checksrc! disable STDERR all */
void tool_set_stderr_file(const char *filename)
{
  FILE *fp;
  int fd;

  if(!filename)
    return;

  if(!strcmp(filename, "-")) {
    tool_stderr = stdout;
    return;
  }

#if defined(HAVE_FCNTL_H) && defined(HAVE_UNISTD_H)
  /* On POSIX systems, open the file with restrictive permissions (0600)
     to prevent group/world-readable logs that may contain sensitive data.
     Then redirect stderr to this file descriptor. */
  fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | CURL_O_BINARY,
            S_IRUSR | S_IWUSR);
  if(fd == -1) {
    warnf("Warning: Failed to open %s", filename);
    return;
  }

  /* Convert file descriptor to FILE* */
  fp = fdopen(fd, FOPEN_WRITETEXT);
  if(!fp) {
    close(fd);
    warnf("Warning: Failed to fdopen %s", filename);
    return;
  }

  /* Redirect stderr to the new file descriptor */
  if(dup2(fd, STDERR_FILENO) == -1) {
    fclose(fp);
    warnf("Warning: Failed to redirect stderr to %s", filename);
    return;
  }

  /* Close the original file pointer since stderr now points to the same fd */
  fclose(fp);

  /* Update tool_stderr to point to the redirected stderr */
  tool_stderr = stderr;

#elif defined(_WIN32)
  /* On Windows, use _sopen_s with restrictive permissions.
     _S_IREAD | _S_IWRITE restricts access to the current user. */
#ifdef _MSC_VER
  if(_sopen_s(&fd, filename, _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY,
              _SH_DENYRW, _S_IREAD | _S_IWRITE) != 0) {
    warnf("Warning: Failed to open %s", filename);
    return;
  }
#else
  /* MinGW and other Windows compilers */
  fd = _open(filename, _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY,
             _S_IREAD | _S_IWRITE);
  if(fd == -1) {
    warnf("Warning: Failed to open %s", filename);
    return;
  }
#endif

  /* Convert file descriptor to FILE* */
  fp = _fdopen(fd, FOPEN_WRITETEXT);
  if(!fp) {
    _close(fd);
    warnf("Warning: Failed to fdopen %s", filename);
    return;
  }

  /* Redirect stderr to the new file descriptor */
  if(_dup2(fd, _fileno(stderr)) == -1) {
    fclose(fp);
    warnf("Warning: Failed to redirect stderr to %s", filename);
    return;
  }

  /* Close the original file pointer since stderr now points to the same fd */
  fclose(fp);

  /* Update tool_stderr to point to the redirected stderr */
  tool_stderr = stderr;

#else
  /* Fallback for platforms without secure file opening support.
     NOTE: This creates files with default umask permissions, which may be
     group/world-readable. Users on such platforms should ensure their umask
     is set appropriately (e.g., 077) if stderr logs may contain sensitive
     information. */

  /* precheck that filename is accessible to lessen the chance that the
     subsequent freopen will fail. */
  fp = fopen(filename, FOPEN_WRITETEXT);
  if(!fp) {
    warnf("Warning: Failed to open %s", filename);
    return;
  }
  fclose(fp);

  /* freopen the actual stderr (stdio.h stderr) instead of tool_stderr since
     the latter may be set to stdout. */
  fp = freopen(filename, FOPEN_WRITETEXT, stderr);
  if(!fp) {
    /* stderr may have been closed by freopen. there is nothing to be done. */
    DEBUGASSERT(0);
    return;
  }
  tool_stderr = stderr;
#endif
}
/* !checksrc! enable STDERR */
