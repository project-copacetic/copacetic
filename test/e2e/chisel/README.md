# Ubuntu Chiseled real-image end-to-end tests

This package validates Copa against immutable, digest-pinned examples of all
three supported Debian metadata layouts used by Chiseled and distroless images.
It is intentionally separate from the network-independent fixture tests in
`integration/chisel`.

## Coverage

| Test | Real image | What it validates |
| --- | --- | --- |
| `TestNativeChiselRealImage` | Canonical Ubuntu .NET Chiseled, amd64 | Inferred release, complete native re-cut, slice retention, upgrades without downgrades, independent manifest-to-rootfs validation, runtime/config preservation, and no-update repatching |
| `TestNativeChiselRealImageARM64` | Canonical Ubuntu .NET Chiseled, arm64 | The same complete native flow on a real arm64 manifest and runtime |
| `TestNativeChiselMultiPlatformOCIUpdatesAMD64AndARM64` | Canonical multi-platform Ubuntu .NET Chiseled index | Patches amd64 and arm64 independently in one operation and validates each output manifest, config, package set, and managed rootfs |
| `TestNativeChiselSecondaryArchitecturesOCI` | Canonical multi-platform Ubuntu .NET Chiseled index, ppc64le and s390x | Re-cuts both secondary architectures in one OCI output and validates changed platform descriptors, preserved image configuration, package upgrades without downgrades, and each managed rootfs against its generated manifest |
| `TestNativeChiselCommunityImagePreservesApplication` | Community Sonarr image, amd64 | Explicit release override, preservation of the complete `/Sonarr` tree, isolated application startup, provenance labels, and no-update repatching |
| `TestAptlessFullStatusRealImage` | Microsoft .NET Jammy Chiseled, amd64 | Trivy OS-only report patching keyed by vulnerability ID and package, final dpkg versions at or above every reported fixed version, full-status preservation, runtime/config preservation, and comprehensive follow-up |
| `TestAptlessFullStatusComprehensiveFromBaselineARM64` | Microsoft .NET Jammy Chiseled, arm64 | Comprehensive patching directly from the unpatched baseline, strict package upgrades, cleanup, runtime/config preservation, and no-update repatching |
| `TestAptlessFullStatusComprehensiveFromBaselineARMv7` | Microsoft .NET Jammy Chiseled, arm/v7 | The same baseline comprehensive flow under emulation, including full-status preservation, package upgrades without downgrades, cleanup, runtime/config preservation, and no-update repatching |
| `TestDistrolessStatusDirectoryPreservesEncodedFilenames` | Google distroless Debian 12, amd64 | A digest-pinned real `status.d` root with an injected unmanaged sentinel and encoded status filename; validates exact filename preservation, absence of `/var/lib/dpkg/status`, package upgrades, sentinel preservation, and tooling cleanup |
| `TestNativeChiselPartialPlatformOCI` | Canonical multi-platform Ubuntu .NET Chiseled index | Patches amd64 while preserving complete arm64, ppc64le, and s390x descriptors and every referenced OCI blob |
| `TestNativeChiselRejectsTargetedReportBeforeOutput` | Canonical Ubuntu .NET Chiseled | Exact comprehensive-only report error and strict absence of Docker or OCI output |
| `TestNativeChiselRejectsARMv6BeforeOutput` | Canonical rootfs relabeled as linux/arm/v6 | Exact unsupported-platform error and strict absence of Docker or OCI output |
| `TestNativeChiselUnresolvablePrivatePackageFailsBeforeOutput` | Canonical manifest with an injected unresolved private slice | Public-release resolution fails with the package named and produces no Docker or OCI output |
| `TestIndependentManifestRootFSValidation` | Synthetic tar fixture | Exercises independent digest, size, mode, symlink-target, regular hard-link, and hard-linked-symlink validation without Docker |

The exact registry references are stored in
[`fixtures/test-images.json`](./fixtures/test-images.json). Do not replace a
digest with a mutable tag. Synthetic derivatives are built only from those
pinned references and the pinned Copa Chisel tooling image.

## Prerequisites

- Docker with the containerd image store enabled.
- Docker Buildx.
- Permission to run the pinned `tonistiigi/binfmt` image with `--privileged`;
  the default suite installs arm64 emulation when needed, and the opt-in secondary
  suite installs arm/v7, ppc64le, and s390x emulation.
- Trivy for the apt-less report-driven full-status test.
- Network access to the pinned image registries, the pinned Trivy database, and
  the public Ubuntu and Debian archives.
- A locally built Copa binary.
- The project Chisel tooling image available under the immutable reference
  expected by Copa.

Build the prerequisites from the repository root:

```bash
make build

docker pull --platform linux/amd64 \
  ghcr.io/project-copacetic/copacetic/chisel@sha256:587015954e14bf51aea440e69c8bf30bd010abd57ed8dd42c19e2159577e8c80
```

Run the complete package:

```bash
COPA_BIN="$(pwd)/dist/$(go env GOOS)_$(go env GOARCH)/release/copa"

go test ./test/e2e/chisel \
  --addr=docker:// \
  --copa="$COPA_BIN" \
  -timeout 115m \
  -v
```

Run one case while iterating:

```bash
go test ./test/e2e/chisel \
  -run '^TestNativeChiselRealImageARM64$' \
  --addr=docker:// \
  --copa="$COPA_BIN" \
  -timeout 50m \
  -v
```

Run the slower secondary-architecture cases explicitly:

```bash
COPA_CHISEL_SECONDARY_ARCHES=1 COPA_CHISEL_PATCH_TIMEOUT=75m \
  go test ./test/e2e/chisel \
  -run '^(TestNativeChiselSecondaryArchitecturesOCI|TestAptlessFullStatusComprehensiveFromBaselineARMv7)$' \
  --addr=docker:// \
  --copa="$COPA_BIN" \
  -timeout 100m \
  -v
```

These opt-in cases re-cut the Canonical native image for ppc64le and s390x and
comprehensively patch the Microsoft full-status image for arm/v7. They run under
emulation and are separated from the default package run to keep its duration
predictable.

Allow approximately 75 to 115 minutes for the complete package, depending on
registry, emulation, and Ubuntu/Debian archive performance. The tests are
skipped with `-short`. They must not use `t.Parallel`: the cases share Docker,
BuildKit caches, binfmt registration, public archive bandwidth, and the locally
tagged tooling image.

## CI

The `test-chisel` job in `.github/workflows/build.yml` pulls
`ghcr.io/project-copacetic/copacetic/chisel@sha256:587015954e14bf51aea440e69c8bf30bd010abd57ed8dd42c19e2159577e8c80`
and runs the default package on an amd64 runner, including the real arm64
Canonical, Microsoft, and community-image cases. The
`test-chisel-secondary-architectures` job executes the tooling image for 386,
arm/v7, ppc64le, riscv64, and s390x, then runs the opt-in native and full-status
patch tests for arm/v7, ppc64le, and s390x. The 386 and riscv64 coverage is
currently limited to tooling-image execution plus Copa's architecture-mapping
unit tests because no suitable digest-pinned real-image patch fixtures are in
the suite. The publication workflow separately verifies every supported
tooling-image platform, SBOM and provenance attestations,
Chisel commit labels, the validator source checksum, and amd64/arm64 tooling
runtime behavior.
