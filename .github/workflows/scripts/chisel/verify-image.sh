#!/usr/bin/env bash

set -euo pipefail

if (( $# != 4 )); then
	echo "usage: $0 <image@sha256:digest> <expected-version> <expected-commit> <report-path>" >&2
	exit 2
fi

readonly image_ref="$1"
readonly expected_version="$2"
readonly expected_commit="$3"
readonly report_path="$4"
readonly image_name="${image_ref%@*}"
readonly image_digest="${image_ref##*@}"
work_dir="$(mktemp -d)"
readonly work_dir
readonly index_file="${work_dir}/index.json"
readonly expected_platforms_file="${work_dir}/expected-platforms.txt"
readonly actual_platforms_file="${work_dir}/actual-platforms.txt"
readonly expected_platforms=(
	"linux/386"
	"linux/amd64"
	"linux/arm/v7"
	"linux/arm64"
	"linux/ppc64le"
	"linux/riscv64"
	"linux/s390x"
)

trap 'rm -rf "${work_dir}"' EXIT

fail() {
	echo "::error title=Chisel image verification failed::$*" >&2
	exit 1
}

if [[ "${image_name}" == "${image_ref}" || ! "${image_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
	fail "image reference must be pinned by sha256 digest: ${image_ref}"
fi

mkdir -p "$(dirname -- "${report_path}")"

docker buildx imagetools inspect "${image_ref}" --raw >"${index_file}"
if ! jq -e '
	(.mediaType == "application/vnd.oci.image.index.v1+json" or
	 .mediaType == "application/vnd.docker.distribution.manifest.list.v2+json") and
	(.manifests | type == "array")
' "${index_file}" >/dev/null; then
	fail "${image_ref} is not a manifest list"
fi

printf '%s\n' "${expected_platforms[@]}" | LC_ALL=C sort >"${expected_platforms_file}"
jq -r '
	.manifests[]
	| select((.annotations["vnd.docker.reference.type"] // "") != "attestation-manifest")
	| select(.platform.os != "unknown" and .platform.architecture != "unknown")
	| [.platform.os, .platform.architecture, (.platform.variant // empty)]
	| map(select(length > 0))
	| join("/")
' "${index_file}" | LC_ALL=C sort >"${actual_platforms_file}"

if ! platform_diff="$(diff -u "${expected_platforms_file}" "${actual_platforms_file}")"; then
	echo "${platform_diff}" >&2
	fail "manifest list platforms do not match the required Copa Chisel platform set"
fi

{
	echo "# Chisel tooling image verification"
	echo
	echo "- Reference: \`${image_ref}\`"
	echo "- Expected Chisel version: \`${expected_version}\`"
	echo "- Expected Chisel commit: \`${expected_commit}\`"
	echo
	echo "| Platform | Image manifest | Provenance | SBOM | Commit label |"
	echo "| --- | --- | --- | --- | --- |"
} >"${report_path}"

for platform in "${expected_platforms[@]}"; do
	IFS=/ read -r platform_os platform_arch platform_variant <<<"${platform}"

	platform_digests=()
	while IFS= read -r digest; do
		platform_digests+=("${digest}")
	done < <(jq -r \
		--arg os "${platform_os}" \
		--arg arch "${platform_arch}" \
		--arg variant "${platform_variant:-}" '
		[
			.manifests[]
			| select((.annotations["vnd.docker.reference.type"] // "") != "attestation-manifest")
			| select(.platform.os == $os and .platform.architecture == $arch)
			| select((.platform.variant // "") == $variant)
			| .digest
		][]
	' "${index_file}")
	if (( ${#platform_digests[@]} != 1 )); then
		fail "expected exactly one image manifest for ${platform}, found ${#platform_digests[@]}"
	fi
	platform_digest="${platform_digests[0]}"

	actual_commit="$(docker buildx imagetools inspect "${image_name}@${platform_digest}" \
		--format '{{ index .Image.Config.Labels "sh.copa.chisel.commit" }}')"
	if [[ "${actual_commit}" != "${expected_commit}" ]]; then
		fail "${platform} has sh.copa.chisel.commit=${actual_commit:-<missing>}, expected ${expected_commit}"
	fi

	actual_version="$(docker buildx imagetools inspect "${image_name}@${platform_digest}" \
		--format '{{ index .Image.Config.Labels "org.opencontainers.image.version" }}')"
	if [[ "${actual_version}" != "${expected_version}" ]]; then
		fail "${platform} has org.opencontainers.image.version=${actual_version:-<missing>}, expected ${expected_version}"
	fi

	attestation_digests=()
	while IFS= read -r digest; do
		attestation_digests+=("${digest}")
	done < <(jq -r --arg digest "${platform_digest}" '
		[
			.manifests[]
			| select(.annotations["vnd.docker.reference.type"] == "attestation-manifest")
			| select(.annotations["vnd.docker.reference.digest"] == $digest)
			| .digest
		][]
	' "${index_file}")
	if (( ${#attestation_digests[@]} == 0 )); then
		fail "${platform} has no attached provenance/SBOM manifest"
	fi

	provenance_found=false
	sbom_found=false
	for attestation_digest in "${attestation_digests[@]}"; do
		attestation_file="${work_dir}/attestation-${attestation_digest#sha256:}.json"
		docker buildx imagetools inspect "${image_name}@${attestation_digest}" --raw >"${attestation_file}"
		if jq -e '
			any(.layers[]?;
				.mediaType == "application/vnd.in-toto+json" and
				((.annotations["in-toto.io/predicate-type"] // "") | startswith("https://slsa.dev/provenance/")))
		' "${attestation_file}" >/dev/null; then
			provenance_found=true
		fi
		if jq -e '
			any(.layers[]?;
				.mediaType == "application/vnd.in-toto+json" and
				.annotations["in-toto.io/predicate-type"] == "https://spdx.dev/Document")
		' "${attestation_file}" >/dev/null; then
			sbom_found=true
		fi
	done

	if [[ "${provenance_found}" != true ]]; then
		fail "${platform} is missing a SLSA provenance attestation"
	fi
	if [[ "${sbom_found}" != true ]]; then
		fail "${platform} is missing an SPDX SBOM attestation"
	fi

	printf "| \`%s\` | \`%s\` | yes | yes | \`%s\` |\n" \
		"${platform}" "${platform_digest}" "${actual_commit}" >>"${report_path}"
done

{
	echo
	echo "## Runtime smoke tests"
	echo
} >>"${report_path}"

for platform in linux/amd64 linux/arm64; do
	IFS=/ read -r platform_os platform_arch platform_variant <<<"${platform}"
	runtime_digests=()
	while IFS= read -r digest; do
		runtime_digests+=("${digest}")
	done < <(jq -r \
		--arg os "${platform_os}" \
		--arg arch "${platform_arch}" \
		--arg variant "${platform_variant:-}" '
		[
			.manifests[]
			| select((.annotations["vnd.docker.reference.type"] // "") != "attestation-manifest")
			| select(.platform.os == $os and .platform.architecture == $arch)
			| select((.platform.variant // "") == $variant)
			| .digest
		][]
	' "${index_file}")
	if (( ${#runtime_digests[@]} != 1 )); then
		fail "expected exactly one runtime image manifest for ${platform}, found ${#runtime_digests[@]}"
	fi

	runtime_ref="${image_name}@${runtime_digests[0]}"
	version_output="$(docker run --rm --pull=always --platform "${platform}" "${runtime_ref}" version)"
	version_output="${version_output//$'\r'/}"
	if [[ "${version_output}" != "${expected_version}" ]]; then
		printf -v quoted_version_output '%q' "${version_output}"
		fail "chisel version on ${platform} returned ${quoted_version_output}, expected ${expected_version}"
	fi
	echo "- \`${platform}\`: \`chisel version\` returned \`${version_output}\`." >>"${report_path}"
done

cat "${report_path}"
