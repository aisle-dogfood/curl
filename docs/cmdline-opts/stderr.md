---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: stderr
Arg: <file>
Help: Where to redirect stderr
Category: verbose global
Added: 6.2
Multi: single
Scope: global
See-also:
  - verbose
  - silent
Example:
  - --stderr output.txt $URL
---

# `--stderr`

Redirect all writes to stderr to the specified file instead. If the filename
is a plain '-', it is instead written to stdout.

On systems supporting secure file creation (POSIX and Windows), the output
file is created with restrictive permissions (owner read/write only, mode 0600
on POSIX) to prevent potential exposure of sensitive information that may be
logged to stderr. On other platforms, the file is created with default umask
permissions; users should ensure their umask is set appropriately (e.g., 077)
if stderr logs may contain sensitive data.
