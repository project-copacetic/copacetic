#!/usr/bin/env bash

set -euo pipefail

if (( $# != 1 )); then
	echo "usage: $0 <image:tag>" >&2
	exit 2
fi

readonly image_ref="$1"
inspect_output="$(mktemp)"
readonly inspect_output
trap 'rm -f "${inspect_output}"' EXIT

set +e
docker buildx imagetools inspect "${image_ref}" >"${inspect_output}" 2>&1
readonly inspect_status=$?
set -e

if (( inspect_status == 0 )); then
	digest="$(awk '$1 == "Digest:" { print $2; exit }' "${inspect_output}")"
	if [[ -z "${digest}" ]]; then
		digest="unknown"
	fi
	echo "::error title=Immutable image tag already exists::Refusing to overwrite ${image_ref} (${digest}). Publish a new versioned tag instead." >&2
	exit 1
fi

if grep -Eiq '(manifest unknown|name unknown|no such manifest|: not found[[:space:]]*$)' "${inspect_output}"; then
	echo "Confirmed that immutable tag ${image_ref} does not exist."
	exit 0
fi

echo "::error title=Unable to verify immutable tag::Registry inspection of ${image_ref} failed for a reason other than a missing manifest; refusing to publish." >&2
cat "${inspect_output}" >&2
exit "${inspect_status}"
