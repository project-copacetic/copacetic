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
The following instructions are for **Ubuntu 22.04** with the dependency versions supported as part of the [dev container](./contributing.md/#visual-studio-code-development-container) environment we use for builds and tests. For other distributions and OS, refer to the appropriate installation instructions for each of the components instead.

```bash
git clone https://github.com/project-copacetic/copacetic
cd copacetic
make
# OPTIONAL: install copa to a pathed folder
sudo mv dist/linux_amd64/release/copa /usr/local/bin/
```