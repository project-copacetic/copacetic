---
title: FAQ
---

## What kind of vulnerabilities can Copa patch?

Copa is capable of patching "OS level" vulnerabilities. This includes packages (like `openssl`) in the image that are managed by a package manager such as `apt` or `yum`. Copa is not currently capable of patching vulnerabilities at the "application level" such as Python packages or Go modules (see [below](#what-kind-of-vulnerabilities-can-copa-not-patch) for more details).


## What kind of vulnerabilities can Copa not patch?

Copa is not capable of patching vulnerabilities for compiled languages, like Go, at the "application level", for instance, Go modules. If your application uses a vulnerable version of the `golang.org/x/net` module, Copa will be unable to patch it. This is because Copa doesn't have access to the application's source code or the knowledge of how to build it, such as compiler flags, preventing it from patching vulnerabilities at the application level.

To patch vulnerabilities for applications, you can package these applications and consume them from package repositories, like `http://archive.ubuntu.com/ubuntu/` for Ubuntu, and ensure Trivy can scan and report vulnerabilities for these packages. This way, Copa can patch the applications as a whole, though it cannot patch specific modules within the applications.

## Can I replace the package repositories in the image with my own?

:::caution

Experimental: This feature might change without preserving backwards compatibility.

:::

Copa does not support replacing the repositories in the package managers with alternatives. Images must already use the intended package repositories. For example, for debian, updating `/etc/apt/sources.list` from `http://archive.ubuntu.com/ubuntu/` to a mirror, such as `https://mirrors.wikimedia.org/ubuntu/`.

If you need the tooling image to use a different package repository, you can create a source policy to define a replacement image and/or pin to a digest. For example, the following source policy replaces `docker.io/library/debian:11-slim` image with `foo.io/bar/baz:latest@sha256:42d3e6bc186572245aded5a0be381012adba6d89355fa9486dd81b0c634695b5`:

```shell
cat <<EOF > source-policy.json
{
    "rules": [
        {
            "action": "CONVERT",
            "selector": {
                "identifier": "docker-image://docker.io/library/debian:11-slim"
            },
            "updates": {
                "identifier": "docker-image://foo.io/bar/baz:latest@sha256:42d3e6bc186572245aded5a0be381012adba6d89355fa9486dd81b0c634695b5"
            }
        }
    ]
}
EOF

export EXPERIMENTAL_BUILDKIT_SOURCE_POLICY=source-policy.json
```

> Tooling image for Debian-based images are `docker.io/library/debian:11-slim` and RPM-based repos are `mcr.microsoft.com/cbl-mariner/base/core:2.0`.

For more information on source policies, see [Buildkit Source Policies](https://docs.docker.com/build/building/env-vars/#experimental_buildkit_source_policy).