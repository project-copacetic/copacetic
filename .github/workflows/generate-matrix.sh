#!/usr/bin/env bash

set -eu -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Collect all the modes into a bash array
modes=()
for i in scripts/ci/setup/*; do
    base="${i##*/}"
    for j in "${i}"/*; do
        modes+=(${base}/${j##*/})
    done
done


tmp="$(mktemp -d)"
trap "rm -rf ${tmp}" EXIT

input="${SCRIPT_DIR}/test-images.json"

# The input from `test-images.json` is an array of objects.
# For every mode we need a copy of every object in the `test-images.json` with a mode field (and mode value) set on it.
# This effectively turns `[{"foo": "bar"}]` into `[{"foo": "bar", "mode": "mode1"}, {"foo": "bar", "mode": "mode2"}]`
# Ideally jq would be able to do this all in one shot but I haven't found a way to do that (it probably can, just haven't figured out the incantation).
# Instead we need to write a tempfile for every mode with the mode injected into every object in the array, then at the end we'll use jq to slurp all that into one array
#
# Example of what this for-loop would look like:
# input json: [{"foo": "bar"}]
# modes: ["mode1", "mode2"]
# Results:
#   $TMPDIR/$TMPFILE1: [{"foo": "bar", "mode": "mode1"}]
#   $TMPDIR/$TMPFILE2: [{"foo": "bar", "mode": "mode2"}]
for mode in ${modes[@]}; do
    jq --arg mode "${mode}" 'map(.+{mode: $mode})' "${input}"  > "$(mktemp --tmpdir="${tmp}")"
done

jq_args=""

if [ -v CI ] && [ "${CI}" = "true" ]; then
    # We are running in CI where we need this to be a single line so use `-c` to compact the output json
    # Otherwise its nice to be able to see the non-compact version when running locally
    jq_args+=" -c"
fi

# Taking the example from above, this would exand into:
#   jq -s '. | flatten' $TMPDIR/$TMPFILE1 $TMPDIR/$TMPFILE2
# The `-s` option for jq tells jq to read each file and insert the objects in those files into an array.
# So the input for is an array of an array of objects: [ [{...}], [{...}] ]
# We need it to be a flat array, so use `add` to concatenate each array
jq ${jq_args} -s 'add' "${tmp}"/*