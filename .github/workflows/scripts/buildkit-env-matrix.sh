#!/usr/bin/env bash

set -eu -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Collect all the modes into a bash array
modes=()
for i in ${SCRIPT_DIR}/buildkitenvs/*; do
    base="${i##*/}"
    for j in "${i}"/*; do
        modes+=(${base}/${j##*/})
    done
done

# Convert bash array to json
jq -c --null-input '$ARGS.positional' --args -- "${modes[@]}"
