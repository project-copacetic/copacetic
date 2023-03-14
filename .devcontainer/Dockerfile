# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.245.0/containers/go/.devcontainer/base.Dockerfile

# [Choice] Go version (use -bullseye variants on local arm64/Apple Silicon): 1, 1.19, 1.18, 1-bullseye, 1.19-bullseye, 1.18-bullseye, 1-buster, 1.19-buster, 1.18-buster
ARG VARIANT="1.19-bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/go:0-${VARIANT}

# [Choice] Node.js version: none, lts/*, 18, 16, 14
ARG NODE_VERSION="none"

# [Choice] Trivy version: see https://github.com/aquasecurity/trivy/releases. Must be >0.20.0.
ARG TRIVY_VERSION="0.37.3"

# [Choice] Buildkit version: see https://github.com/moby/buildkit/releases. Must be >0.10.3.
ARG BUILDKIT_VERSION="0.11.4"

# Optionally install nodejs if specified
RUN if [ "${NODE_VERSION}" != "none" ]; then su vscode -c "umask 0002 && . /usr/local/share/nvm/nvm.sh && nvm install ${NODE_VERSION} 2>&1"; fi

# Install additional OS packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y --no-install-recommends make \
    && apt-get autoremove -y && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy.
ARG TARGETARCH
RUN if [ "${TARGETARCH}" = "amd64" ]; then DEBARCH="64bit"; \
    elif [ "${TARGETARCH}" = "arm64" ]; then DEBARCH="ARM64"; \
    else echo "Error: unsupported TARGETARCH ${TARGETARCH}"; exit 1; fi \
    && curl -sfL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${DEBARCH}.deb -o trivy.deb \
    && dpkg -i trivy.deb \
    && rm trivy.deb

# Install buildkit.
RUN curl -sfL https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-${TARGETARCH}.tar.gz -o buildkit.tar.gz \
    && tar -zxvf buildkit.tar.gz -C /usr/local/ \
    && rm buildkit.tar.gz

# Add a first run notice to the correct location for Codespaces.
COPY first-run-notice.txt /usr/local/etc/vscode-dev-containers/

# Install devcontainer CLI as global node package.
RUN su vscode -c "source /usr/local/share/nvm/nvm.sh && npm install -g @devcontainers/cli" 2>&1

# Default to vscode user
USER vscode
