#!/usr/bin/env bash

runner=$1

set -eu -o pipefail

if [ -z "$runner" ]; then
    echo "runner is not set"
    exit 1
fi

if [ "$runner" == "ubuntu-22.04" ]; then
    curl -sfL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb -o trivy.deb
    sudo dpkg -i trivy.deb
    rm trivy.deb

    curl -sfL https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz -o buildkit.tar.gz
    sudo tar -zxvf buildkit.tar.gz -C /usr/local/
    rm buildkit.tar.gz

    elif [ "$runner" == "macos-13" ]; then
    curl -sfL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz -o trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz
    tar -xvf trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz
    sudo mv trivy /usr/local/bin

    curl -sfL https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.darwin-arm64.tar.gz -o buildkit.tar.gz
    sudo tar -zxvf buildkit.tar.gz -C /usr/local/
    rm buildkit.tar.gz

    brew install colima docker
    colima start
else
    echo "runner type is not supported"
    exit 1
fi



