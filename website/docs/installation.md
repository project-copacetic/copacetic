---
title: Installation
---

The following instructions are for **Ubuntu 22.04** with the dependency versions supported as part of the [dev container](../../.devcontainer/README.md) environment we use for builds and tests. For other distributions and OS, refer to the appropriate installation instructions for each of the components instead.

1. Install [Go v1.19](https://go.dev/doc/install) or newer.

2. Install the [make](https://www.gnu.org/software/make/) build tool.

3. Install and start [Docker](https://www.docker.com/get-started/).

4. Install [buildkit v0.10.5](https://github.com/moby/buildkit#quick-start) or newer. Alternatively, the `copa` CLI tool can also be used with the [buildkit container](https://hub.docker.com/r/moby/buildkit/tags/).

5. Install [trivy v0.34.0](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) or newer.

6. Clone and make **copa**:

   ```bash
   sudo apt update
   sudo apt install git
   git clone https://github.com/project-copacetic/copacetic
   cd copacetic
   make
   # OPTIONAL: install copa to a pathed folder
   sudo mv dist/linux_amd64/release/copa /usr/local/bin/
   ```