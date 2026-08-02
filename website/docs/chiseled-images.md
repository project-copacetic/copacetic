---
title: Ubuntu Chiseled Images
---

Copa supports Ubuntu Chiseled images in two forms. The metadata present in the
image determines which patching flow is used.

| Image layout | Identifying metadata | Targeted patching with `--report` | Comprehensive patching without a report |
| --- | --- | --- | --- |
| External full dpkg status | Full `/var/lib/dpkg/status` exists, but one or more required tools are unavailable: `apt-get`, `apt-mark`, `dpkg`, `sh`, `grep`, or `tee` | Supported | Supported |
| Native Chisel manifest | `/var/lib/chisel/manifest.wall` | Not supported | Supported |

If both metadata formats are present, Copa treats the image as a native Chisel
image. This prevents a synthetic dpkg database from taking precedence over the
manifest that owns the sliced filesystem.

## Apt-less images with a full dpkg status file

Some Ubuntu Chiseled images, including Microsoft .NET Chiseled images, retain a
complete `/var/lib/dpkg/status` file but remove `apt-get`, `apt-mark`, `dpkg`, a
shell, and common text-processing tools.

Copa reconstructs a temporary dpkg database in its tooling environment, applies
the selected `.deb` packages to the target root, and writes the updated package
metadata back in the same full-status form.

```bash
# Targeted update from a scanner report.
trivy image --pkg-types os --scanners vuln --ignore-unfixed \
  --format json --output report.json "$IMAGE"
copa patch --image "$IMAGE" --report report.json

# Comprehensive update of all installed OS packages.
copa patch --image "$IMAGE"
```

The patched image keeps `/var/lib/dpkg/status`; Copa does not introduce
`/var/lib/dpkg/status.d`, apt, dpkg, BusyBox, or a shell. When validating a
report-driven update, confirm that the findings from the input report are gone.
Do not require the entire post-patch image to have zero findings: installing
complete `.deb` archives can add dependency packages that were not represented
in the original report.

:::warning Full-package filesystem expansion

A full dpkg status file records packages, not the exact subset of files that was
selected when the image was originally chiseled. Updating this layout installs
content from complete `.deb` archives. The patched image can therefore contain
additional files from those packages even though package-manager and tooling
executables are removed before export. Because these images do not retain the
original dpkg lifecycle database, Copa applies archive payloads with maintainer
scripts and dpkg triggers disabled rather than executing them against incomplete
package state. Review the resulting filesystem and test the application before
deployment, especially when a package normally generates files in `postinst`.

:::

## Native images with `manifest.wall`

A native Chisel image records its installed packages, selected slices, and owned
filesystem paths in a zstd-compressed JSONWall manifest at
`/var/lib/chisel/manifest.wall`.

Copa updates this layout by running a comprehensive re-cut:

1. Read and validate the original manifest.
2. Re-cut every selected slice into a fresh staging root with the resolved
   Chisel release.
3. Reject package downgrades or a result that loses an originally selected
   slice.
4. Replace Chisel-owned paths and the generated manifest while preserving paths
   that were not owned by the original manifest.
5. Validate the final file digests, sizes, modes, links, and package records.

Copa does not run Chisel in place against the application root, and the final
image does not gain a dpkg database, apt, BusyBox, or a shell.

Targeted native-manifest patching is intentionally deferred. Supplying a report
for this layout fails before image modification with:

```text
targeted patching of native Chisel manifests is not supported;
omit --report to run a comprehensive Chisel update
```

Run native Chisel patching without a report:

```bash
copa patch --image "$IMAGE"
```

## Tested image layouts

Copa's real-image end-to-end suite exercises both first-party and community
images. The references used by the tests are pinned by digest in the
[Chiseled e2e fixtures](https://github.com/project-copacetic/copacetic/blob/main/test/e2e/chisel/fixtures/test-images.json).

| Image family | Layout | Validation performed |
| --- | --- | --- |
| Canonical `ubuntu/dotnet-runtime:8.0-24.04_stable_145` | Native Chisel manifest | Release inference, complete slice retention, package upgrades without downgrades, manifest package metadata, runtime behavior, and no-update repatching |
| Community `ghcr.io/hadrienpatte/sonarr` | Native Chisel manifest | Explicit release override, preservation of the `/Sonarr` application tree and image configuration, isolated application startup, and no-update repatching |
| Microsoft `mcr.microsoft.com/dotnet/runtime:8.0.0-jammy-chiseled` | Apt-less full dpkg status | Trivy OS-only report patching, comprehensive follow-up, targeted finding removal, status preservation, runtime behavior, and no-update repatching |
| Canonical multi-platform .NET index | Native Chisel manifest | Partial amd64 patching while preserving the complete arm64, ppc64le, and s390x descriptors and referenced OCI blobs |

These images are regression fixtures, not an allowlist. Other images are
supported when they match one of the documented metadata layouts and their
packages are available from the appropriate public Ubuntu archives. Native
images must also have every selected slice available in the resolved Chisel
release.

The suite also verifies that patched images preserve the original user,
entrypoint, command, environment, and working directory, and that apt, dpkg,
BusyBox, and a shell do not leak into the result. See
[Development and Testing Tips](./development-tips.md#run-ubuntu-chiseled-real-image-tests)
for contributor instructions.

## Selecting a Chisel release

Release selection applies only to native images containing
`/var/lib/chisel/manifest.wall`. Apt-less full-status images use the Ubuntu
distribution and repository information detected from the target image.

Copa resolves the native Chisel release in this order:

1. An explicit override.
2. Otherwise, `ubuntu-<VERSION_ID>` inferred from the target's
   `/etc/os-release` file. For example, `VERSION_ID="24.04"` resolves to
   `ubuntu-24.04`.

Native community images that omit a usable `/etc/os-release` must provide an
explicit override.

Use `--chisel-release` to override inference for a single-image CLI operation:

| Form | Example | Notes |
| --- | --- | --- |
| Standard release name | `--chisel-release ubuntu-24.04` | Uses the named Canonical Chisel release. |
| Local release directory | `--chisel-release ./releases/ubuntu-24.04` | The directory must contain a valid Chisel release definition. Relative paths are resolved from the Copa process. |
| Pinned HTTPS Git URL | `--chisel-release https://example.com/releases.git#abc123` | A commit or tag fragment is mandatory. An unpinned URL is rejected. |

CLI and bulk pinned Git release sources must use HTTPS and must not contain
embedded credentials. Copa does not persist mutable release definitions in the
target image. The Chisel tooling image is an internal implementation detail and
has no user-facing override.

### BuildKit frontend

The BuildKit frontend accepts a standard release name or a path supplied through
the dedicated `chisel-release` build context. It rejects Git URL values so a
frontend caller cannot make the BuildKit worker fetch an arbitrary network
location. Use the Copa CLI or bulk configuration when a pinned HTTPS Git release
source is required.

Pass the matching frontend option through `buildctl`:

```bash
buildctl build \
  --frontend=gateway.v0 \
  --opt source=ghcr.io/project-copacetic/copacetic-frontend:latest \
  --opt image="$IMAGE" \
  --opt chisel-release=ubuntu-24.04 \
  --output type=image,name="$IMAGE-patched"
```

Or pass it as a Docker Buildx build argument:

```bash
docker buildx build \
  --build-arg BUILDKIT_SYNTAX=ghcr.io/project-copacetic/copacetic-frontend:latest \
  --build-arg image="$IMAGE" \
  --build-arg chisel-release=ubuntu-24.04 \
  --output type=image,name="$IMAGE-patched" \
  .
```

To use a local release directory with `buildctl`, expose it as the dedicated
`chisel-release` local context and use a path relative to that context:

```bash
buildctl build \
  --frontend=gateway.v0 \
  --opt source=ghcr.io/project-copacetic/copacetic-frontend:latest \
  --opt image="$IMAGE" \
  --local chisel-release=./releases/ubuntu-24.04 \
  --opt context:chisel-release=local:chisel-release \
  --opt chisel-release=. \
  --output type=image,name="$IMAGE-patched"
```

With Docker Buildx, use the Copa frontend in the Dockerfile:

```dockerfile
# syntax=ghcr.io/project-copacetic/copacetic-frontend:latest
```

Then pass the named context and a path relative to it:

```bash
docker buildx build \
  --build-arg image="$IMAGE" \
  --build-arg chisel-release=. \
  --build-context chisel-release=./releases/ubuntu-24.04 \
  --output type=image,name="$IMAGE-patched" \
  .
```

Here, `.` is interpreted relative to the named `chisel-release` context, not
the host working directory. Absolute host paths and paths that escape the
supplied context are rejected.

### Bulk configuration

Only bulk jobs for native images with `/var/lib/chisel/manifest.wall` are
comprehensive-update-only and must run without a report. Bulk jobs for other
supported image layouts may use a report directory. Set a default Chisel
release at the top level and override it for individual images when necessary:

```yaml
apiVersion: copa.sh/v1alpha1
kind: PatchConfig

chiselRelease: ubuntu-24.04

images:
  - name: app
    image: example.com/app
    tags:
      strategy: list
      list: ["1.0"]

  - name: app-with-custom-release
    image: example.com/custom-app
    chiselRelease: https://example.com/releases.git#abc123
    tags:
      strategy: list
      list: ["2.0"]
```

The per-image value overrides the top-level default. If both are omitted, Copa
uses release inference. Do not combine the CLI `--chisel-release` flag with
`--config`; put the release values in the bulk YAML instead.

## Public archive limitation

Initial Chisel support resolves packages from public archives declared by the
selected release. Copa does not forward credentials for Ubuntu Pro, ESM, FIPS,
private mirrors, or other authenticated archives. If an installed slice cannot
be resolved from the selected public release, patching fails rather than
silently skipping it, changing releases, or downgrading a package.

## Trivy limitation

As verified on **July 31, 2026** with the Trivy version pinned by Copa
(`v0.69.3`), Trivy recognizes Debian package metadata from
`/var/lib/dpkg/status` and `/var/lib/dpkg/status.d`, but it does not extract the
OS package inventory from `/var/lib/chisel/manifest.wall`. A Trivy scan of a
native-manifest image can therefore report zero OS packages and zero OS
vulnerabilities even though the Chisel manifest lists installed packages.

This has two consequences:

- Trivy reports remain usable for the apt-less full-status layout.
- Do not treat a zero-package Trivy result as validation of a native Chisel
  image, and do not pass that report to Copa. Run the comprehensive no-report
  flow instead.

Native Trivy `manifest.wall` scanning and report-driven native Chisel patching
are separate future work.

## Platforms and provenance

Native Chisel re-cuts are platform-specific. Copa maps OCI architectures to
Chisel/Debian architectures as follows:

| OCI platform | Chisel architecture |
| --- | --- |
| `linux/amd64` | `amd64` |
| `linux/arm64` | `arm64` |
| `linux/386` | `i386` |
| `linux/arm/v7` | `armhf` |
| `linux/ppc64le` | `ppc64el` |
| `linux/s390x` | `s390x` |
| `linux/riscv64` | `riscv64` |

`linux/arm/v6` is not supported for native Chisel patching. In a partially
selected multi-platform image, unselected platform descriptors and layers are
preserved unchanged.

Each selected native platform is re-cut independently. To patch only amd64 and
write a complete OCI layout that retains the unchanged platform descriptors and
blobs:

```bash
copa patch \
  --image "$IMAGE" \
  --platform linux/amd64 \
  --chisel-release ubuntu-24.04 \
  --oci-dir ./patched-oci
```

When using one scanner-report file, pass at most one `--platform` value. Copa
honors that explicit platform for the patch. Use a report directory for
targeted multi-platform patching, because each platform requires its own
architecture-specific report.

Patched native images record the resolved release provenance as both image
configuration labels and OCI manifest annotations:

- `sh.copa.chisel.release`
- `sh.copa.chisel.version`

Named releases record values such as `ubuntu-24.04`. Pinned Git sources record
the URL with its resolved commit, and local directories record a content-derived
`local:<directory>@sha256:<digest>` value. The tooling version is recorded as
`v1.4.2`.
