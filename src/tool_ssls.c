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

#ifdef _WIN32
#include <aclapi.h>
#endif

#include "tool_cfgable.h"
#include "tool_cb_dbg.h"
#include "tool_msgs.h"
#include "tool_setopt.h"
#include "tool_ssls.h"
#include "tool_parsecfg.h"
#include "tool_util.h"
#include "curlx/multibyte.h"

#include "memdebug.h" /* keep this as LAST include */

/* The maximum line length for an ecoded session ticket */
#define MAX_SSLS_LINE (64 * 1024)

#ifdef _WIN32
#define PATHSEP "\\"
#define IS_SEP(x) (((x) == '/') || ((x) == '\\'))
#elif defined(MSDOS) || defined(OS2)
#define PATHSEP "\\"
#define IS_SEP(x) ((x) == '\\')
#else
#define PATHSEP "/"
#define IS_SEP(x) ((x) == '/')
#endif

static char *tool_ssls_dirslash(const char *path)
{
  size_t n;
  struct dynbuf out;

  DEBUGASSERT(path);
  curlx_dyn_init(&out, CURL_MAX_INPUT_LENGTH);
  n = strlen(path);
  if(n) {
    /* find the rightmost path separator, if any */
    while(n && !IS_SEP(path[n - 1]))
      --n;
    /* skip over all the path separators, if any */
    while(n && IS_SEP(path[n - 1]))
      --n;
  }
  if(curlx_dyn_addn(&out, path, n))
    return NULL;
  /* if there was a directory, append a single trailing slash */
  if(n && curlx_dyn_addn(&out, PATHSEP, 1))
    return NULL;
  return curlx_dyn_ptr(&out);
}

#ifdef _WIN32
static PSID tool_ssls_win32_sid(void)
{
  HANDLE token = NULL;
  TOKEN_USER *user = NULL;
  PSID sid = NULL;
  DWORD needed = 0;

  if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    return NULL;

  if(!GetTokenInformation(token, TokenUser, NULL, 0, &needed) &&
     (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
    user = malloc(needed);
  if(user && GetTokenInformation(token, TokenUser, user, needed, &needed)) {
    DWORD sidlen = GetLengthSid(user->User.Sid);
    sid = malloc(sidlen);
    if(!sid || !CopySid(sidlen, sid, user->User.Sid)) {
      free(sid);
      sid = NULL;
    }
  }
  free(user);
  CloseHandle(token);
  return sid;
}

static bool tool_ssls_win32_owner(HANDLE hfile, PSID sid)
{
  bool match = FALSE;
  PSECURITY_DESCRIPTOR sd = NULL;
  PSID owner = NULL;

  if(GetSecurityInfo(hfile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                     &owner, NULL, NULL, NULL, &sd) == ERROR_SUCCESS &&
     owner && sid && EqualSid(owner, sid))
    match = TRUE;
  if(sd)
    LocalFree(sd);
  return match;
}

static bool tool_ssls_win32_safe_dacl(HANDLE hfile, PSID sid)
{
  bool result = FALSE;
  PSECURITY_DESCRIPTOR sd = NULL;
  PACL dacl = NULL;
  BOOL present;
  BOOL defd;
  ACL_SIZE_INFORMATION aclinfo;
  ACCESS_ALLOWED_ACE *ace;

  if(!sid)
    return FALSE;

  if((GetSecurityInfo(hfile, SE_FILE_OBJECT,
                      DACL_SECURITY_INFORMATION |
                      PROTECTED_DACL_SECURITY_INFORMATION,
                      NULL, NULL, &dacl, NULL, &sd) != ERROR_SUCCESS) ||
     !GetSecurityDescriptorDacl(sd, &present, &dacl, &defd) ||
     !present || !dacl ||
     !GetAclInformation(dacl, &aclinfo, sizeof(aclinfo),
                        AclSizeInformation) ||
     (aclinfo.AceCount != 1) ||
     !GetAce(dacl, 0, (LPVOID *)&ace) ||
     (((ACE_HEADER *)ace)->AceType != ACCESS_ALLOWED_ACE_TYPE) ||
     !EqualSid((PSID)&ace->SidStart, sid))
    goto out;

  result = TRUE;
out:
  if(sd)
    LocalFree(sd);
  return result;
}

static bool tool_ssls_restrict_win32_file(HANDLE hfile, PSID sid)
{
  bool result = FALSE;
  EXPLICIT_ACCESS ea;
  PACL dacl = NULL;

  if(!sid)
    return FALSE;

  memset(&ea, 0, sizeof(ea));
  ea.grfAccessPermissions = GENERIC_ALL;
  ea.grfAccessMode = SET_ACCESS;
  ea.grfInheritance = NO_INHERITANCE;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
  ea.Trustee.ptstrName = (LPTSTR)sid;

  if((SetEntriesInAcl(1, &ea, NULL, &dacl) == ERROR_SUCCESS) &&
     (SetSecurityInfo(hfile, SE_FILE_OBJECT,
                      DACL_SECURITY_INFORMATION |
                      PROTECTED_DACL_SECURITY_INFORMATION,
                      NULL, NULL, dacl, NULL) == ERROR_SUCCESS))
    result = TRUE;

  if(dacl)
    LocalFree(dacl);
  return result;
}

static void tool_ssls_win32_unlock_dirs(HANDLE *dirs, size_t count)
{
  size_t i;
  for(i = 0; i < count; ++i)
    CloseHandle(dirs[i]);
  free(dirs);
}

static bool tool_ssls_win32_lock_dirs(TCHAR *path, HANDLE **dirsp,
                                      size_t *countp)
{
  bool result = FALSE;
  size_t count = 0;
  size_t i;
  size_t len = (size_t)lstrlen(path);
  HANDLE *dirs = calloc(len ? len : 1, sizeof(*dirs));

  *dirsp = NULL;
  *countp = 0;
  if(!dirs)
    return FALSE;

  if((len > 3) && IS_SEP(path[0]) && IS_SEP(path[1]) &&
     ((path[2] == '?') || (path[2] == '.')))
    goto out;
  if((len > 1) && IS_SEP(path[0]) && IS_SEP(path[1]))
    goto out;

  i = 0;
  if((len > 1) && ISALPHA(path[0]) && (path[1] == ':')) {
    i = 2;
    if((i < len) && IS_SEP(path[i]))
      ++i;
  }
  else if(len && IS_SEP(path[0]))
    i = 1;

  for(; i < len; ++i) {
    HANDLE hdir;
    BY_HANDLE_FILE_INFORMATION info;
    TCHAR prev;

    if(!IS_SEP(path[i]))
      continue;
    prev = path[i];
    path[i] = '\0';
    hdir = CreateFile(path, FILE_READ_ATTRIBUTES,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS |
                      FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    path[i] = prev;
    if(hdir == INVALID_HANDLE_VALUE)
      goto out;
    if((GetFileType(hdir) != FILE_TYPE_DISK) ||
       !GetFileInformationByHandle(hdir, &info) ||
       !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
       (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
      CloseHandle(hdir);
      goto out;
    }
    dirs[count++] = hdir;
    while((i < len) && IS_SEP(path[i]))
      ++i;
    if(i == len)
      break;
    --i;
  }

  *dirsp = dirs;
  *countp = count;
  return TRUE;
out:
  tool_ssls_win32_unlock_dirs(dirs, count);
  return result;
}
#endif

static char *tool_ssls_logname(const char *filename)
{
  const unsigned char *p = (const unsigned char *)filename;
  struct dynbuf escaped;

  curlx_dyn_init(&escaped, CURL_MAX_INPUT_LENGTH);
  while(*p) {
    if(ISPRINT(*p)) {
      if(curlx_dyn_addn(&escaped, (const char *)p, 1))
        return NULL;
    }
    else if(curlx_dyn_addf(&escaped, "\\x%02x", *p))
      return NULL;
    ++p;
  }
  return curlx_dyn_ptr(&escaped);
}

static FILE *tool_ssls_fopen(const char *filename, char **tempname)
{
#ifdef _WIN32
  FILE *fp;
  int fd;
  bool created = FALSE;
  HANDLE hfile = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION info;
  DWORD err;
  PSID sid = tool_ssls_win32_sid();
  HANDLE *dirs = NULL;
  size_t dircount = 0;
  SECURITY_ATTRIBUTES sa;
  SECURITY_DESCRIPTOR sd;
  PACL dacl = NULL;
  EXPLICIT_ACCESS ea;
  TCHAR *tchar_filename;

  *tempname = NULL;
  if(!sid) {
    errno = EACCES;
    return NULL;
  }

  memset(&ea, 0, sizeof(ea));
  ea.grfAccessPermissions = GENERIC_ALL;
  ea.grfAccessMode = SET_ACCESS;
  ea.grfInheritance = NO_INHERITANCE;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
  ea.Trustee.ptstrName = (LPTSTR)sid;
  if((SetEntriesInAcl(1, &ea, NULL, &dacl) != ERROR_SUCCESS) ||
     !InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) ||
     !SetSecurityDescriptorDacl(&sd, TRUE, dacl, FALSE)) {
    if(dacl)
      LocalFree(dacl);
    free(sid);
    errno = EACCES;
    return NULL;
  }

  sa.nLength = sizeof(sa);
  sa.bInheritHandle = FALSE;
  sa.lpSecurityDescriptor = &sd;

  tchar_filename = curlx_convert_UTF8_to_tchar(filename);
  if(!tchar_filename) {
    LocalFree(dacl);
    free(sid);
    errno = ENOMEM;
    return NULL;
  }
  if(!tool_ssls_win32_lock_dirs(tchar_filename, &dirs, &dircount)) {
    curlx_unicodefree(tchar_filename);
    LocalFree(dacl);
    free(sid);
    errno = EACCES;
    return NULL;
  }

  hfile = CreateFile(tchar_filename,
                     GENERIC_READ | GENERIC_WRITE | WRITE_DAC,
                     0, &sa, CREATE_NEW,
                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                     NULL);
  if(hfile == INVALID_HANDLE_VALUE) {
    err = GetLastError();
    if(err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS) {
      hfile = CreateFile(tchar_filename,
                         GENERIC_READ | GENERIC_WRITE | WRITE_DAC,
                         0, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                         NULL);
      err = GetLastError();
    }
    else if(err == ERROR_PATH_NOT_FOUND)
      err = ERROR_FILE_NOT_FOUND;
  }
  else
    created = TRUE;
  curlx_unicodefree(tchar_filename);
  tool_ssls_win32_unlock_dirs(dirs, dircount);
  LocalFree(dacl);
  if(hfile == INVALID_HANDLE_VALUE) {
    free(sid);
    errno = (err == ERROR_FILE_NOT_FOUND) ? ENOENT : EACCES;
    return NULL;
  }

  if(GetFileType(hfile) != FILE_TYPE_DISK ||
     !GetFileInformationByHandle(hfile, &info) ||
     (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
     (info.nNumberOfLinks != 1) ||
     (!created && (!tool_ssls_win32_owner(hfile, sid) ||
                   !tool_ssls_win32_safe_dacl(hfile, sid))) ||
     !tool_ssls_restrict_win32_file(hfile, sid)) {
    CloseHandle(hfile);
    free(sid);
    errno = EACCES;
    return NULL;
  }
  free(sid);

  fd = _open_osfhandle((intptr_t)hfile, O_RDWR | CURL_O_BINARY);
  if(fd == -1) {
    CloseHandle(hfile);
    return NULL;
  }
  if(ftruncate(fd, 0)) {
    close(fd);
    return NULL;
  }

  fp = fdopen(fd, FOPEN_WRITETEXT);
  if(fp)
    return fp;

  close(fd);
  return NULL;
#else
  char *dir;
  unsigned int i;

  *tempname = NULL;
  dir = tool_ssls_dirslash(filename);
  if(!dir) {
    errno = ENOMEM;
    return NULL;
  }

#ifdef HAVE_MKSTEMP
  {
    char *tempstore = aprintf("%scurl-ssls.XXXXXX", dir);
    int fd;
    FILE *fp;

    if(!tempstore) {
      errno = ENOMEM;
      free(dir);
      return NULL;
    }

    do {
      fd = mkstemp(tempstore);
      /* Keep retrying in the hope that it is not interrupted sometime */
      /* !checksrc! disable ERRNOVAR 1 */
    } while(fd == -1 && errno == EINTR);
    if(fd != -1) {
      fp = fdopen(fd, FOPEN_WRITETEXT);
      if(fp) {
        *tempname = tempstore;
        free(dir);
        return fp;
      }

      {
        int err = errno;
        close(fd);
        unlink(tempstore);
        free(tempstore);
        errno = err;
      }
      free(dir);
      return NULL;
    }
    free(tempstore);
  }
#else
  {
    struct timeval now = tvrealnow();
    unsigned long nonce =
      (((unsigned long)now.tv_sec) << 20) ^ (unsigned long)now.tv_usec;

    for(i = 0; i < 100; ++i) {
      char *tempstore = aprintf("%scurl-ssls.%lx.%u.tmp", dir, nonce, i);
      int fd;
      FILE *fp;

      if(!tempstore) {
        errno = ENOMEM;
        break;
      }

      do {
        fd = open(tempstore,
                  O_WRONLY | O_CREAT | O_EXCL | CURL_O_BINARY
#ifdef O_NOFOLLOW
                  | O_NOFOLLOW
#endif
                  , 0600);
        /* Keep retrying in the hope that it is not interrupted sometime */
        /* !checksrc! disable ERRNOVAR 1 */
      } while(fd == -1 && errno == EINTR);
      if(fd == -1) {
        free(tempstore);
        if(errno == EEXIST || errno == EISDIR)
          continue;
        break;
      }

      fp = fdopen(fd, FOPEN_WRITETEXT);
      if(fp) {
        *tempname = tempstore;
        free(dir);
        return fp;
      }

      {
        int err = errno;
        close(fd);
        unlink(tempstore);
        free(tempstore);
        errno = err;
      }
      break;
    }
  }
#endif

  free(dir);
  return NULL;
#endif
}

static int tool_ssls_rename(const char *oldpath, const char *newpath)
{
  return rename(oldpath, newpath);
}

static CURLcode tool_ssls_easy(struct OperationConfig *config,
                               CURLSH *share, CURL **peasy)
{
  CURLcode result = CURLE_OK;

  *peasy = curl_easy_init();
  if(!*peasy)
    return CURLE_OUT_OF_MEMORY;

  result = curl_easy_setopt(*peasy, CURLOPT_SHARE, share);
  if(!result && (global->tracetype != TRACE_NONE)) {
    my_setopt(*peasy, CURLOPT_DEBUGFUNCTION, tool_debug_cb);
    my_setopt(*peasy, CURLOPT_DEBUGDATA, config);
    my_setopt_long(*peasy, CURLOPT_VERBOSE, 1L);
  }
  return result;
}

CURLcode tool_ssls_load(struct OperationConfig *config,
                        CURLSH *share, const char *filename)
{
  FILE *fp;
  CURL *easy = NULL;
  struct dynbuf buf;
  unsigned char *shmac = NULL, *sdata = NULL;
  char *c, *line, *end;
  size_t shmac_len, sdata_len;
  CURLcode r = CURLE_OK;
  int i, imported;
  bool error = FALSE;

  curlx_dyn_init(&buf, MAX_SSLS_LINE);
  fp = fopen(filename, FOPEN_READTEXT);
  if(!fp) { /* ok if it does not exist */
    notef("SSL session file does not exist (yet?): %s", filename);
    goto out;
  }

  r = tool_ssls_easy(config, share, &easy);
  if(r)
    goto out;

  i = imported = 0;
  while(my_get_line(fp, &buf, &error)) {
    ++i;
    curl_free(shmac);
    curl_free(sdata);
    line = curlx_dyn_ptr(&buf);

    c = memchr(line, ':', strlen(line));
    if(!c) {
      warnf("unrecognized line %d in ssl session file %s", i, filename);
      continue;
    }
    *c = '\0';
    r = curlx_base64_decode(line, &shmac, &shmac_len);
    if(r) {
      warnf("invalid shmax base64 encoding in line %d", i);
      continue;
    }
    line = c + 1;
    end = line + strlen(line) - 1;
    while((end > line) && (*end == '\n' || *end == '\r' || ISBLANK(*line))) {
      *end = '\0';
      --end;
    }
    r = curlx_base64_decode(line, &sdata, &sdata_len);
    if(r) {
      warnf("invalid sdata base64 encoding in line %d: %s", i, line);
      continue;
    }

    r = curl_easy_ssls_import(easy, NULL, shmac, shmac_len, sdata, sdata_len);
    if(r) {
      warnf("import of session from line %d rejected(%d)", i, r);
      continue;
    }
    ++imported;
  }
  if(error)
    r = CURLE_FAILED_INIT;
  else
    r = CURLE_OK;

out:
  if(easy)
    curl_easy_cleanup(easy);
  if(fp)
    fclose(fp);
  curlx_dyn_free(&buf);
  curl_free(shmac);
  curl_free(sdata);
  return r;
}

struct tool_ssls_ctx {
  FILE *fp;
  int exported;
};

static CURLcode tool_ssls_exp(CURL *easy, void *userptr,
                              const char *session_key,
                              const unsigned char *shmac, size_t shmac_len,
                              const unsigned char *sdata, size_t sdata_len,
                              curl_off_t valid_until, int ietf_tls_id,
                              const char *alpn, size_t earlydata_max)
{
  struct tool_ssls_ctx *ctx = userptr;
  char *enc = NULL;
  size_t enc_len;
  CURLcode r;

  (void)easy;
  (void)valid_until;
  (void)ietf_tls_id;
  (void)alpn;
  (void)earlydata_max;
  if(!ctx->exported)
    fputs("# Your SSL session cache. https://curl.se/docs/ssl-sessions.html\n"
        "# This file was generated by libcurl! Edit at your own risk.\n",
        ctx->fp);

  r = curlx_base64_encode((const char *)shmac, shmac_len, &enc, &enc_len);
  if(r)
    goto out;
  r = CURLE_WRITE_ERROR;
  if(enc_len != fwrite(enc, 1, enc_len, ctx->fp))
    goto out;
  if(EOF == fputc(':', ctx->fp))
    goto out;
  curl_free(enc);
  r = curlx_base64_encode((const char *)sdata, sdata_len, &enc, &enc_len);
  if(r)
    goto out;
  r = CURLE_WRITE_ERROR;
  if(enc_len != fwrite(enc, 1, enc_len, ctx->fp))
    goto out;
  if(EOF == fputc('\n', ctx->fp))
    goto out;
  r = CURLE_OK;
  ctx->exported++;
out:
  if(r)
    warnf("Warning: error saving SSL session for '%s': %d", session_key, r);
  curl_free(enc);
  return r;
}

CURLcode tool_ssls_save(struct OperationConfig *config,
                        CURLSH *share, const char *filename)
{
  struct tool_ssls_ctx ctx;
  CURL *easy = NULL;
  char *tempname = NULL;
  char *logname = NULL;
  CURLcode r = CURLE_OK;

  ctx.exported = 0;
  ctx.fp = NULL;
  ctx.fp = tool_ssls_fopen(filename, &tempname);
  if(!ctx.fp) {
    logname = tool_ssls_logname(filename);
    warnf("Warning: Failed to create SSL session file %s: %s",
          logname ? logname : "(oom)", strerror(errno));
    free(logname);
    goto out;
  }

  r = tool_ssls_easy(config, share, &easy);
  if(r)
    goto out;

  r = curl_easy_ssls_export(easy, tool_ssls_exp, &ctx);

out:
  if(easy)
    curl_easy_cleanup(easy);
  if(ctx.fp) {
    if(fclose(ctx.fp) && !r)
      r = CURLE_WRITE_ERROR;
  }
  if(!r && tempname && tool_ssls_rename(tempname, filename)) {
    logname = tool_ssls_logname(filename);
    warnf("Warning: Failed to create SSL session file %s: %s",
          logname ? logname : "(oom)", strerror(errno));
    free(logname);
    r = CURLE_WRITE_ERROR;
  }
  if(r && tempname)
    unlink(tempname);
  free(tempname);
  return r;
}
