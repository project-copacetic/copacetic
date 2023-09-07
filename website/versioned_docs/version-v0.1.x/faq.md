---
title: FAQ
---

## What kind of vulnerabilities can Copa patch?
Copa is capable of patching "OS level" vulnerabilities. This includes packages (like `openssl`) in the image that are managed by a package manager such as `apt` or `yum`. Copa is not currently capable of patching vulnerabilities at the "application level" such as Python packages or Go modules.