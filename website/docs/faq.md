---
title: FAQ
---

## What kind of vulnerabilities can Copa patch?

Copa is capable of patching "OS level" vulnerabilities. This includes packages (like `openssl`) in the image that are managed by a package manager such as `apt` or `yum`. Copa is not currently capable of patching vulnerabilities at the "application level" such as Python packages or Go modules (see [below](#what-kind-of-vulnerabilities-can-copa-not-patch) for more details).


## What kind of vulnerabilities can Copa not patch?

Copa is not capable of patching vulnerabilities for compiled languages, like Go, at the "application level", for instance, Go modules. If your application uses a vulnerable version of the `golang.org/x/net` module, Copa will be unable to patch it. This is because Copa doesn't have access to the application's source code or the knowledge of how to build it, such as compiler flags, preventing it from patching vulnerabilities at the application level.

To patch vulnerabilities for applications, you can package these applications and consume them from package repositories, like `http://archive.ubuntu.com/ubuntu/` for Ubuntu, and ensure Trivy can scan and report vulnerabilities for these packages. This way, Copa can patch the applications as a whole, though it cannot patch specific modules within the applications.

## My disk space is being filled up after using Copa. How can I fix this?

If you find that your storage is rapidly being taken up after working with Copa, run `docker system prune`. This will prune all unused images, containers and caches. 

## How does Copa determine what tooling image to use?

All images being passed into Copa have their versioning data carefully extracted and stripped so that an appropriate tooling image can be obtained from a container repository.

Debian: All debian-based images have their `minor.patch` versioning stripped and `-slim` appended. e.g. if `nginx:1.21.6` is being patched, `debian:11-slim` is used as the tooling image.

Ubuntu: All Ubuntu-based images use the same versioning that was passed in. e.g. if `tomcat:10.1.17-jre17-temurin-jammy` is passed in, `ubuntu:22.04` will be used for the tooling image.

There is one caveat for Ubuntu-based images. If an Ubuntu-based image is being patched without a Trivy scan, Copa is unable to parse a scan for versioning information. In these scenarios, Copa will fallback to `debian:stable-slim` as the tooling image.

RPM: All RPM-based images will use `mcr.microsoft.com/cbl-mariner/base/core:2.0` as the tooling image.

APK: APK-based images never use a tooling image, as Copa does not patch distroless alpine images.

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

> The tooling image for Debian-based images can be `docker.io/library/debian:11-slim` or `docker.io/library/debian:12-slim` depending on the target image version. RPM-based repos use `mcr.microsoft.com/cbl-mariner/base/core:2.0`.

For more information on source policies, see [Buildkit Source Policies](https://docs.docker.com/build/building/env-vars/#experimental_buildkit_source_policy).
