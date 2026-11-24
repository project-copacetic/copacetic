#!/usr/bin/env bash
# Fail unless every named test passed in a `go test -json` (gotestsum --jsonfile) stream.
# A test that was skipped, filtered out or renamed fails this check, so a CI job
# cannot silently stop running the tests it exists for.
#
# usage: require-tests-passed.sh JSONFILE TEST_NAME...
#   TEST_NAME is the full name as go test reports it, e.g. TestPatch/Multi-arch_Jupyter_base-notebook_2025-01-27,_no_push

set -eu -o pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 JSONFILE TEST_NAME..." >&2
	exit 2
fi

json_file="$1"
shift

if [[ ! -s "${json_file}" ]]; then
	echo "error: ${json_file} is missing or empty" >&2
	exit 1
fi

passed="$(jq -r 'select(.Action == "pass" and .Test != null) | .Test' "${json_file}" | LC_ALL=C sort -u)"

missing=0
for name in "$@"; do
	if ! grep -Fxq -- "${name}" <<<"${passed}"; then
		echo "error: required test ${name} did not pass (it failed, was skipped, or did not run)" >&2
		missing=1
	fi
done

if [[ "${missing}" -ne 0 ]]; then
	exit 1
fi
echo "all $# required tests passed"
