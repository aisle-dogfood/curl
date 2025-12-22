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

#include "tool_util.h"
#include "memdebug.h" /* keep this as LAST include */

#ifdef _WIN32

struct timeval tvrealnow(void)
{
  /* UNIX EPOCH (1970-01-01) in FILETIME (1601-01-01) as 64-bit value */
  static const curl_uint64_t EPOCH = (curl_uint64_t)116444736000000000ULL;
  SYSTEMTIME systime;
  FILETIME ftime; /* 100ns since 1601-01-01, as double 32-bit value */
  curl_uint64_t time; /* 100ns since 1601-01-01, as 64-bit value */
  struct timeval now;

  GetSystemTime(&systime);
  SystemTimeToFileTime(&systime, &ftime);
  time = ((curl_uint64_t)ftime.dwLowDateTime);
  time += ((curl_uint64_t)ftime.dwHighDateTime) << 32;

  now.tv_sec  = (long)((time - EPOCH) / 10000000L); /* unit is 100ns */
  now.tv_usec = (long)(systime.wMilliseconds * 1000);
  return now;
}

#else

struct timeval tvrealnow(void)
{
  struct timeval now;
#ifdef HAVE_GETTIMEOFDAY
  (void)gettimeofday(&now, NULL);
#else
  now.tv_sec = time(NULL);
  now.tv_usec = 0;
#endif
  return now;
}

#endif

/* Case insensitive compare. Accept NULL pointers. */
int struplocompare(const char *p1, const char *p2)
{
  if(!p1)
    return p2 ? -1 : 0;
  if(!p2)
    return 1;
  return CURL_STRICMP(p1, p2);
}

/* Indirect version to use as qsort callback. */
int struplocompare4sort(const void *p1, const void *p2)
{
  return struplocompare(* (char * const *) p1, * (char * const *) p2);
}

/*
 * Open a file with restrictive permissions for writing sensitive data.
 * On POSIX systems, creates the file with mode 0600 (owner read/write only).
 * On Windows, uses default permissions (could be enhanced with ACLs).
 * Returns FILE pointer on success, NULL on failure.
 */
FILE *tool_fopen_secure(const char *filename, const char *mode)
{
#if defined(_WIN32)
  /* On Windows, use _sopen_s with restricted sharing mode if available */
#if defined(_MSC_VER) && (_MSC_VER >= 1400)
  /* Use secure file opening on Windows with MSVC 2005+ */
  int fd;
  FILE *fp = NULL;

  /* _SH_DENYRW denies read and write sharing, but this doesn't restrict
   * other users on multi-user systems. For better security on Windows,
   * we would need to set explicit ACLs, but that's complex.
   * For now, we at least prevent other processes from opening the file
   * while we have it open.
   */
  if(_sopen_s(&fd, filename, _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY,
              _SH_DENYRW, _S_IREAD | _S_IWRITE) == 0) {
    fp = _fdopen(fd, mode);
    if(!fp)
      _close(fd);
  }
  return fp;
#else
  /* Fallback for older Windows compilers or non-MSVC */
  return fopen(filename, mode);
#endif
#else
  /* POSIX: use open() with restrictive mode, then fdopen() */
  int fd;
  FILE *fp = NULL;
  int flags = O_WRONLY | O_CREAT | O_TRUNC;

#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif

  /* Create with mode 0600 - only owner can read/write */
  fd = open(filename, flags, S_IRUSR | S_IWUSR);
  if(fd != -1) {
    fp = fdopen(fd, mode);
    if(!fp)
      close(fd);
  }
  return fp;
#endif
}

#ifdef USE_TOOL_FTRUNCATE

#ifdef UNDER_CE
/* 64-bit lseek-like function unavailable */
#  undef _lseeki64
#  define _lseeki64(hnd,ofs,whence) lseek(hnd,ofs,whence)
#endif

/*
 * Truncate a file handle at a 64-bit position 'where'.
 */

int tool_ftruncate64(int fd, curl_off_t where)
{
  intptr_t handle = _get_osfhandle(fd);

  if(_lseeki64(fd, where, SEEK_SET) < 0)
    return -1;

  if(!SetEndOfFile((HANDLE)handle))
    return -1;

  return 0;
}

#endif /* USE_TOOL_FTRUNCATE */

#if defined(_WIN32) && !defined(UNDER_CE)
FILE *tool_execpath(const char *filename, char **pathp)
{
  static char filebuffer[512];
  unsigned long len;
  /* Get the filename of our executable. GetModuleFileName is already declared
   * via inclusions done in setup header file. We assume that we are using
   * the ASCII version here.
   */
  len = GetModuleFileNameA(0, filebuffer, sizeof(filebuffer));
  if(len > 0 && len < sizeof(filebuffer)) {
    /* We got a valid filename - get the directory part */
    char *lastdirchar = strrchr(filebuffer, DIR_CHAR[0]);
    if(lastdirchar) {
      size_t remaining;
      *lastdirchar = 0;
      /* If we have enough space, build the RC filename */
      remaining = sizeof(filebuffer) - strlen(filebuffer);
      if(strlen(filename) < remaining - 1) {
        curl_msnprintf(lastdirchar, remaining, "%s%s", DIR_CHAR, filename);
        *pathp = filebuffer;
        return fopen(filebuffer, FOPEN_READTEXT);
      }
    }
  }

  return NULL;
}
#endif
