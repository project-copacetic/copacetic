---
title: FAQ
---

## What kind of vulnerabilities can Copa patch?

Copa patches "OS level" vulnerabilities (e.g. `openssl`, `glibc`) managed by system package managers (`apt`, `yum/dnf`, `apk`, etc.).

Additionally, Copa now supports (experimental) patching of Python packages installed via `pip` when they are present in the image filesystem. These language-level updates are applied in-place and included in VEX output using PyPI Package URLs (`pkg:pypi/<name>@<version>`). Python support currently focuses on pinned version upgrades surfaced through scanner reports or comprehensive update mode.

> Experimental: Python language package patching behavior and tooling selection may change in future minor releases.

## What kind of vulnerabilities can Copa not patch?

Copa does not patch arbitrary application or source-level dependencies that require a project build context (e.g. Go modules, Node.js/npm packages, Java/Maven dependencies, compiled binaries built from source). If your application embeds a vulnerable Go module like `golang.org/x/net`, Copa cannot currently rebuild the application with a fixed dependency version.

To patch such application vulnerabilities, package the application itself into a system package (e.g. a `.deb` or `.rpm`) or ensure the base image provides updated language runtime packages that scanners recognize. Copa can then patch the packaged artifact at the OS package layer. Python is presently the only language ecosystem with direct (experimental) in-image package replacement support.

## My disk space is being filled up after using Copa. How can I fix this?

If you find that your storage is rapidly being taken up after working with Copa, run `docker system prune`. This will prune all unused images, containers and caches.

## How does Copa determine what tooling image to use?

All images being passed into Copa have their versioning data carefully extracted and stripped so that an appropriate tooling image can be obtained from a container repository.

### DPKG

#### Debian

All debian-based images have their `minor.patch` versioning stripped and `-slim` appended. e.g. if `nginx:1.21.6` is being patched, `debian:11-slim` is used as the tooling image.

#### Ubuntu

All Ubuntu-based images use the same versioning that was passed in. e.g. if `tomcat:10.1.17-jre17-temurin-jammy` is passed in, `ubuntu:22.04` will be used for the tooling image.

There is one caveat for Ubuntu-based images. If an Ubuntu-based image is being patched without a Trivy scan, Copa is unable to parse a scan for versioning information. In these scenarios, Copa will fallback to `debian:stable-slim` as the tooling image.

### RPM

#### Azure Linux 3.0+

Azure Linux based images will use `mcr.microsoft.com/azurelinux/base/core` with the same version as the image being patched.

#### CBL-Mariner (Azure Linux 1 and 2), CentOS, Oracle Linux, Rocky Linux, Alma Linux, and Amazon Linux

These RPM-based distros will use `mcr.microsoft.com/cbl-mariner/base/core:2.0`

### APK (Alpine)

APK-based images never use a tooling image, as Copa does not patch distroless alpine images.

## After Copa patched the image, why does the scanner still show patched OS package vulnerabilities?

After scanning the patched image, if you’re still seeing vulnerabilities that have already been addressed in the patch layer, it could be due to the scanner reporting issues on each individual layer. Please reach out to your scanner vendor for assistance in resolving this.

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

## I am getting `downloaded package ... version ... lower than required ... for update` error when trying to patch an image. What does this mean?

This error means that the package manager is trying to install a version of the package that is lower than the version that was required from the scanner report. This can happen for a few reasons:

- Package repositories are not updated to the latest version of the package. For example, sometimes there is a lag between when a CVE is detected by Trivy using Red Hat vulnerability database and when it is available in the package repositories for CentOS.

- Scanner reports are not up to date. Make sure to run the scanner with the latest vulnerability database. If you are using Trivy, it is recommended to pull the latest version of the Trivy DB, and not rely on cached or stale versions.

To verify the package version discrepancies, you can compare the package version provided by the package repositories and the scanner reports. Follow the Trivy documentation on [how to find the security advisory data sources](https://aquasecurity.github.io/trivy/dev/community/contribute/discussion/#false-detection), and then compare the package version in the scanner report with the applicable security advisory, and applicable package repository.

If you are continuing to see this and the package repositories and vulnerability databases are not updated, you can either:

- use `--ignore-errors` flag or [filter the applicable vulnerability in the scanner](troubleshooting.md#filtering-vulnerabilities).

- update all packages without any scanner reports. This can be done by not providing a scanner report to Copa, and Copa will update all packages to the latest version available in the package repositories.

## Can I use Dependabot with Copa patched images?

Yes, see [best practices](best-practices.md#dependabot) to learn more about using Dependabot with Copa patched images.

## Does Copa cause a buildup of patched layers on each patch?

No. To prevent a buildup of layers, Copa discards the previous patch layer with each new patch. Each subsequent patch removes the earlier patch layer and creates a new one, which includes all patches applied since the original base image Copa started with. Essentially, Copa is creating a new layer with the latest patch, based on the base/original image. This new layer is a combination (or squash) of both the previous updates and the new updates requested. Discarding the patch layer also reduces the size of the resulting patched images in the future.

## Why am I getting 404 errors when trying to patch an image?

If you're seeing errors related to missing **Release files** or `404 Not Found` errors during patching, your base image is likely using an End-of-Life (EOL) release of a distribution. Copa cannot patch images based on EOL operating systems where the package repositories have been removed or archived.

## What does "End-of-Life" mean for patching?

When a release of Linux distribution reaches its End-of-Life date:

- Package repositories are typically removed from primary mirrors
- Security updates are no longer published
- The distribution maintainers no longer provide patches for vulnerabilities

Without access to these repositories, Copa cannot find or apply security updates.

## How do I identify if my image is using an EOL distribution?

Common indicators include:

- Copa Errors mentioning missing Release files
- `404` Not Found errors when accessing repository URLs
- References to old distribution codenames (e.g., Debian "Stretch" or "Buster")
  - Check the output of `cat /etc/os-release` for codenames like:
    ```shell
    PRETTY_NAME="Debian GNU/Linux 9 (stretch)"
    NAME="Debian GNU/Linux"
    VERSION_ID="9"
    VERSION="9 (stretch)"
    VERSION_CODENAME=stretch
    ID=debian
    ```

:::tip Check Distribution End-of-Life Status

Visit [endoflife.date](https://endoflife.date/) to easily check the End-of-Life (EOL) dates for your Linux distribution, programming languages, frameworks, and other software.

:::

## What are my options for handling EOL images?

1. **Preferred: Upgrade to a supported distribution version**

   - Update your Dockerfile to use a newer base image
   - Example: Change `FROM debian:stretch` to `FROM debian:bookworm`

2. **Alternative: Use archive repositories**

   - Modify your image to use archive.debian.org or similar archive repositories

     > **Note**: Archived repositories won't receive new security updates.

3. **Rebuild from source**
   - For critical applications, consider rebuilding packages from source with security patches
