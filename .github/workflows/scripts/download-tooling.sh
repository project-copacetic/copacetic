#!/usr/bin/env bash

set -eu -o pipefail

# SECURITY NOTE (CVE-2026-33634): Trivy suffered a supply chain attack in March 2026.
# Versions 0.69.4, 0.69.5, 0.69.6 on Docker Hub were malicious.
# v0.69.3 is the last known clean release. We verify the binary using GitHub's
# Sigstore-based attestation (independent of the release page itself).
# If upgrading Trivy, verify the new version is safe before updating.
TRIVY_EXPECTED_SHA256="a484057aafde31089cf2558ca0f79a4bc835125a5ee6834183a5bcf0735af358"
curl -sfL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb -o trivy.deb
echo "${TRIVY_EXPECTED_SHA256}  trivy.deb" | sha256sum -c -
sudo dpkg -i trivy.deb
rm trivy.deb

curl -sfL https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz -o buildkit.tar.gz
sudo tar -zxvf buildkit.tar.gz -C /usr/local/
rm buildkit.tar.gz

sudo apt-get update
sudo apt-get install -y podman
systemctl --user enable --now podman.socket || true

go install gotest.tools/gotestsum@v1.13.0
