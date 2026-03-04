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

Note that stderr output from curl might contain sensitive data, including
usernames, credentials or secret data content, especially when used with
options like --verbose or --trace. Be aware and be careful when sharing or
storing redirected stderr logs. Consider setting restrictive file permissions
(owner-only access) on the output file to protect sensitive information.
