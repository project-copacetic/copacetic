#!/usr/bin/env bash

set -eu -o pipefail

curl -sfL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb -o trivy.deb
sudo dpkg -i trivy.deb
rm trivy.deb

curl -sfL https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz -o buildkit.tar.gz
sudo tar -zxvf buildkit.tar.gz -C /usr/local/
rm buildkit.tar.gz

# sudo apt-get update
# sudo apt-get install -y podman
# systemctl --user enable --now podman.socket || true