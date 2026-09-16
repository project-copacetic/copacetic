# Debian test images

The Debian fixtures use Debian 12 with older package versions so scanner reports
still contain updates to apply. Image digests pin the contents, including images
whose tag is `latest`.

| Previous fixture | Debian 12 replacement | Coverage |
| --- | --- | --- |
| `nginx:1.21.6` | `nginx:1.27.0-bookworm` | Full dpkg status, apt, and local image references |
| `kube-proxy:v1.23.4` | `registry.k8s.io/build-image/debian-base:bookworm-v1.0.2` | Full dpkg status and apt with an empty `resolv.conf` |
| `kube-proxy:v1.26.1` and `v1.27.2` | `kube-proxy:v1.29.0` | Custom distroless `status.d` files, no apt, and `libssl3` |
| `openpolicyagent/opa:0.46.0` | `gcr.io/distroless/base-debian12` | Distroless `status.d` files without a shell or apt |
| OpenSSL `test-debian` | OpenSSL `test-debian12` | Debian 12 distroless with a custom `openssl.cnf` |

The two old distroless kube-proxy entries pinned the same digest. They now share
one fixture. Debian 12 uses `libssl3`; dotted package names and exact status-file
matching remain covered by [dpkg unit tests](../../../pkg/pkgmgr/dpkg_test.go).
The distroless base digest also appears in the Chisel end-to-end fixtures.

The local nginx fixture pins the amd64 manifest to match the patch tests' explicit
platform. The remote nginx fixture pins the multi-platform index.

Frontend language tests use `python:3.11.9-slim-bookworm`, which retains pip,
setuptools, and wheel updates to exercise library patching. Multi-platform
runtime tests use `mcr.microsoft.com/dotnet/runtime:8.0.11-bookworm-slim` for
ARMv7 and ARM64 coverage.

The OpenSSL fixture is built during **every single-architecture CI job** from
[`openssl-test-img-debian/Dockerfile`](openssl-test-img-debian/Dockerfile).
The recipe pins an older official Distroless Debian 12 base and copies the exact
`foo\n` OpenSSL configuration. Keep that base pinned: the test requires fixable
`libssl3` vulnerabilities before patching.

[The fixture setup script](../../../.github/workflows/scripts/singlearch-fixture.sh)
builds `linux/amd64`, pushes only to a disposable loopback registry, and exports
the resulting manifest digest in `COPA_TEST_OPENSSL_IMAGE`. Standalone and buildx
BuildKit daemons use host networking for these jobs so they can read the same
registry. The custom-unix Docker job imports the built archive into its nested
daemon and verifies an identical digest in its own loopback registry. Podman's
BuildKit already uses host networking. No prepublished OpenSSL image or registry
credentials are needed.

`TestPatchBuiltOpenSSL` runs in both report-driven and update-all matrices. It
requires a freshly provisioned digest, confirms the initial vulnerable package,
rescans the patched image, and verifies exact custom configuration, package
status records, and runtime image configuration through the selected image
loader. For Podman, the loaded output is pushed to the same disposable registry
for rescanning, so Trivy does not require a Podman API socket. Missing setup
fails with a provisioning instruction rather than skipping the fixture. The
job's final cleanup step removes its fixture resources even when tests fail.

For local runs, follow the same workflow order: run the script's `build` phase
with `GITHUB_ENV` pointing to a temporary environment file, export its entries,
source the selected `buildkitenvs` script, and run `load` before the singlearch
tests. Run `cleanup` afterward with the recorded environment. The pinned recipe
is the source of truth; do not add a registry digest for this generated fixture
to `test-images.json`.
