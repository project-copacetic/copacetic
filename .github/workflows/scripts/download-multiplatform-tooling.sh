#!/usr/bin/env bash

set -eu -o pipefail

sudo apt update
sudo apt install qemu-user-static qemu-system qemu-utils binfmt-support
