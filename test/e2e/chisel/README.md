# Ubuntu Chiseled real-image end-to-end tests

This package validates Copa against immutable, digest-pinned examples of both
supported Ubuntu Chiseled layouts. It is intentionally separate from the
network-independent fixture tests in `integration/chisel`.

## Coverage

| Test | Real image | What it validates |
| --- | --- | --- |
| `TestNativeChiselRealImage` | Canonical Ubuntu .NET Chiseled | Inferred release, complete native re-cut, slice retention, upgrades without downgrades, manifest package metadata, runtime/config preservation, and no-update repatching |
| `TestNativeChiselCommunityImagePreservesApplication` | Community Sonarr image | Explicit release override, preservation of the complete `/Sonarr` tree, isolated application startup, provenance labels, and no-update repatching |
| `TestAptlessFullStatusRealImage` | Microsoft .NET Jammy Chiseled | Trivy OS-only report patching, targeted finding removal, full-status preservation, comprehensive follow-up, runtime/config preservation, and no-update repatching |
| `TestNativeChiselPartialPlatformOCI` | Canonical multi-platform Ubuntu .NET Chiseled index | Patching amd64 while preserving complete arm64, ppc64le, and s390x descriptors and every referenced OCI blob |

The exact image references are stored in
[`fixtures/test-images.json`](./fixtures/test-images.json). Do not replace a
digest with a mutable tag.

## Prerequisites

- Docker with the containerd image store enabled.
- Docker Buildx.
- Trivy for the apt-less full-status test.
- Network access to the pinned image registries, the pinned Trivy database, and
  the public Ubuntu archives.
- A locally built Copa binary.
- The project Chisel tooling image built locally under the reference expected by
  Copa.

Build the prerequisites from the repository root:

```bash
make build

docker buildx build \
  --platform linux/amd64 \
  --file images/chisel/Dockerfile \
  --tag ghcr.io/project-copacetic/copacetic/chisel:v1.4.2 \
  --load \
  .
```

Run the complete package:

```bash
COPA_BIN="$(pwd)/dist/$(go env GOOS)_$(go env GOARCH)/release/copa"

go test ./test/e2e/chisel \
  --addr=docker:// \
  --copa="$COPA_BIN" \
  -timeout 55m \
  -v
```

Run one case while iterating:

```bash
go test ./test/e2e/chisel \
  -run '^TestNativeChiselCommunityImagePreservesApplication$' \
  --addr=docker:// \
  --copa="$COPA_BIN" \
  -timeout 20m \
  -v
```

Allow approximately 30 to 55 minutes for the complete package, depending on
registry and Ubuntu archive performance. The tests are skipped with `-short`.
They must not use `t.Parallel`: the cases share Docker, BuildKit caches, public
archive bandwidth, and the locally tagged tooling image.

## CI

The `test-chisel` job in `.github/workflows/build.yml` builds the tooling image
from the repository source and runs this package on an amd64 runner. This proves
the source-built tooling and patching flow work together. Validation of a
published tooling image by immutable digest remains a separate release check.
