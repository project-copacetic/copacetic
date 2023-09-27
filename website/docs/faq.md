---
title: FAQ
---

## What kind of vulnerabilities can Copa patch?
Copa is capable of patching "OS level" vulnerabilities. This includes packages (like `openssl`) in the image that are managed by a package manager such as `apt` or `yum`. Copa is not currently capable of patching vulnerabilities at the "application level" such as Python packages or Go modules.

## Can I replace the package repositories in the image with my own?

:::caution

Experimental: This feature might change without preserving backwards compatibility.

:::

Copa does not support replacing the repositories in the package managers with alternatives. Images must already use the intended package repositories. For example, for debian, updating `/etc/apt/sources.list` from `http://archive.ubuntu.com/ubuntu/` to a mirror, such as `https://mirrors.wikimedia.org/ubuntu/`. If you need the tooling image to use a different package repository, you can create a custom tooling image with the desired package repository and specify it using `--custom-tooling-image` flag.

```shell
copa patch --image docker.io/myorg/image:tag --custom-tooling-image docker.io/myorg/tooling-base:tag ...
```
