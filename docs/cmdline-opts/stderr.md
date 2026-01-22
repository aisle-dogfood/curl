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
  - trace
  - trace-ascii
Example:
  - --stderr output.txt $URL
---

# `--stderr`

Redirect all writes to stderr to the specified file instead. If the filename
is a plain '-', it is instead written to stdout.

This file may contain sensitive data, including usernames, credentials or
secret data content from curl's error messages and any verbose or trace output.
Be aware and be careful when using this option and when sharing the resulting
output files with others. Consider using restrictive file permissions to
protect the file from unauthorized access.
