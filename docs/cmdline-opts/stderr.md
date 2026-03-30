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

When used together with --verbose, --trace, --trace-ascii or similar options,
the redirected stderr output may contain sensitive data, including usernames,
credentials, headers or secret data content. Ensure the output file is created
with appropriate permissions (e.g., owner-only access) to prevent unauthorized
disclosure. Be aware and be careful when sharing stderr logs with others.
