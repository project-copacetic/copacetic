---
title: FAQ
---

## What kind of vulnerabilities can Copa patch?

Copa is capable of patching "OS level" vulnerabilities. This includes packages (like `openssl`) in the image that are managed by a package manager such as `apt` or `yum`. Copa is not currently capable of patching vulnerabilities at the "application level" such as Python packages or Go modules (see [below](#what-kind-of-vulnerabilities-can-copa-not-patch) for more details).


## What kind of vulnerabilities can Copa not patch?

Copa is not capable of patching vulnerabilities for compiled languages, like Go, at the "application level", for instance, Go modules. If your application uses a vulnerable version of the `golang.org/x/net` module, Copa will be unable to patch it. This is because Copa doesn't have access to the application's source code or the knowledge of how to build it, such as compiler flags, preventing it from patching vulnerabilities at the application level.

To patch vulnerabilities for applications, you can package these applications and consume them from package repositories, like `http://archive.ubuntu.com/ubuntu/` for Ubuntu, and ensure Trivy can scan and report vulnerabilities for these packages. This way, Copa can patch the applications as a whole, though it cannot patch specific modules within the applications.
