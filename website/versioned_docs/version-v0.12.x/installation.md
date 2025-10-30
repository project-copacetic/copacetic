---
title: Installation
---

## Homebrew
On macOS and Linux, `copa` can be installed via [Homebrew](https://brew.sh/):

```bash
brew install copa
```

## GitHub
You can download the latest and previous versions of `copa` from the [GitHub releases page](https://github.com/project-copacetic/copacetic/releases).

## Development Setup

### Prerequisites
- [Go](https://go.dev/doc/install)
- [Docker](https://docs.docker.com/engine/install/)
- [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) (optional as a scanner)

```bash
git clone https://github.com/project-copacetic/copacetic
cd copacetic
make
# OPTIONAL: install copa to a pathed folder (i.e. /usr/local/bin)
# Note: if you installed copa via Homebrew, you will need to uninstall it first
make install
```
