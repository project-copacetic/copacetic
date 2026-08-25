#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest_json="${fixture_dir}/manifest.jsonwall"
manifest_wall="${fixture_dir}/manifest.wall"
expected="${fixture_dir}/expected.json"

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
zstd --quiet --decompress --stdout "${manifest_wall}" >"${tmp}"
cmp "${manifest_json}" "${tmp}"

expected_data_digest="$(jq -r 'select(.kind == "path" and .path == "/opt/copa-fixture/data.txt") | .sha256' "${manifest_json}")"
actual_data_digest="$(sha256sum "${fixture_dir}/data.txt" | awk '{print $1}')"
test "${actual_data_digest}" = "${expected_data_digest}"

jq -e -s --slurpfile expected "${expected}" '
  .[0].jsonwall == $expected[0].jsonwall and
  .[0].schema == $expected[0].schema and
  (length == $expected[0].recordsIncludingHeader) and
  ([.[] | select(.kind == "package")] | length == $expected[0].packages) and
  ([.[] | select(.kind == "slice")] | length == $expected[0].slices) and
  ([.[] | select(.kind == "content")] | length == $expected[0].contents) and
  ([.[] | select(.kind == "path")] | length == $expected[0].paths) and
  ([.[] | select(.kind == "path") | .path] | sort == ($expected[0].ownedPaths | sort))
' "${manifest_json}" >/dev/null
