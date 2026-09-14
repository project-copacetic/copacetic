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

The OpenSSL fixture is published as
`docker.io/sozercan/copa-test-openssl:test-debian12` for testing.
To refresh it, build `openssl-test-img-debian/Dockerfile`
for `linux/amd64` and publish it under a new tag. Record its registry digest in
`test-images.json` and update the expected patched tag in
[the build workflow](../../../.github/workflows/build.yml).
