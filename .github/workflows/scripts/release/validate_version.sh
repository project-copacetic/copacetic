#!/usr/bin/env bash
#
# .github/workflows/scripts/release/validate_version.sh
#
# Checks if a new pushed tag is semantically greater than the
# immediate previous tag using GNU sort -V, with a manual
# override for SemVer pre-release vs. final release comparisons.
#
# This script is intended to be run from a GitHub Actions workflow.
# It relies on the following environment variables being set:
#
#   PUSHED_TAG:   The new tag being validated (e.g., "v1.2.3")
#   PREVIOUS_TAG: The immediate previous tag (e.g., "v1.2.2" or "v0.0.0")
#
# Exits with 0 on success (validation passed).
# Exits with 1 on failure (validation failed).
#

# Exit on error, on unset variable, or pipe failure
set -euo pipefail

# 1. Check that environment variables are set
if [ -z "${PUSHED_TAG:-}" ]; then
	echo "::error::PUSHED_TAG environment variable is not set." >&2
	exit 1
fi

if [ -z "${PREVIOUS_TAG:-}" ]; then
	echo "::error::PREVIOUS_TAG environment variable is not set." >&2
	exit 1
fi

# 2. Log the inputs
echo "Validating pushed tag: ${PUSHED_TAG}"
echo "Comparing against previous tag: ${PREVIOUS_TAG}"

# 3. Check for identical tags (a definite failure)
if [ "$PUSHED_TAG" == "$PREVIOUS_TAG" ]; then
	echo "::error::Validation Failed: Pushed tag '${PUSHED_TAG}' is identical to the previous tag '${PREVIOUS_TAG}'."
	exit 1
fi

# 4. Extract base versions (before any '-' pre-release suffix)
#    Example: "v0.12.0-rc.1" -> "v0.12.0"
#    Example: "v0.12.0"      -> "v0.12.0"
PUSHED_BASE="${PUSHED_TAG%%-*}"
PREVIOUS_BASE="${PREVIOUS_TAG%%-*}"

# 5. Handle the special SemVer case: pre-release vs. final
#    This is the case where 'sort -V' fails.
if [ "$PUSHED_BASE" == "$PREVIOUS_BASE" ]; then

	# CASE A: Pushed tag is a final release, previous was a pre-release.
	# This is GOOD. (e.g., v0.12.0 > v0.12.0-rc.3)
	# PUSHED_TAG == PUSHED_BASE (it has no '-')
	# PREVIOUS_TAG != PREVIOUS_BASE (it has a '-')
	if [ "$PUSHED_TAG" == "$PUSHED_BASE" ] && [ "$PREVIOUS_TAG" != "$PREVIOUS_BASE" ]; then
		echo "✅ Version validation passed (final release after pre-release)."
		exit 0
	fi

	# CASE B: Pushed tag is a pre-release, previous was final.
	# This is BAD. (e.g., v0.12.0-rc.1 < v0.12.0)
	# PUSHED_TAG != PUSHED_BASE (it has a '-')
	# PREVIOUS_TAG == PREVIOUS_BASE (it has no '-')
	if [ "$PUSHED_TAG" != "$PUSHED_BASE" ] && [ "$PREVIOUS_TAG" == "$PREVIOUS_BASE" ]; then
		echo "::error::Validation Failed: Pushed tag '${PUSHED_TAG}' is a pre-release for a version that is already final ('${PREVIOUS_TAG}')."
		exit 1
	fi

	# If both are pre-releases (rc.4 vs rc.3) or both are final (which
	# is caught by the identical check), we fall through to the
	# standard 'sort -V' logic, which handles rc.4 > rc.3 correctly.
fi

# 6. For all other cases (different base versions), use standard version sort.
#    This correctly handles:
#    - v0.12.1 > v0.12.0
#    - v0.13.0 > v0.12.9
#    - v0.12.0-rc.4 > v0.12.0-rc.3
LATEST_SORTED=$(printf "%s\n%s" "$PUSHED_TAG" "$PREVIOUS_TAG" | sort -V | tail -n1)

# 7. Check failure condition
if [ "$LATEST_SORTED" != "$PUSHED_TAG" ]; then
	echo "::error::Validation Failed: Pushed tag '${PUSHED_TAG}' is not strictly greater than the previous tag '${PREVIOUS_TAG}'."
	echo "::error::This could be a typo. Did you mean to release a different version?"
	exit 1
fi

echo "✅ Version validation passed."
exit 0
