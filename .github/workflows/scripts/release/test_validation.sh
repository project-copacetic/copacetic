#!/usr/bin/env bash
#
# test_validation.sh
#
# Unit test harness for validate_version.sh
#
# This script is "stateless" and does not require a git repository.
# It tests the logic of validate_version.sh by passing
# environment variables (PUSHED_TAG, PREVIOUS_TAG) and checking
# the exit code.
#

set -e # Exit on first error

# --- Robust Path Detection ---
# Get the absolute directory where this script is located.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
VALIDATE_SCRIPT="${SCRIPT_DIR}/validate_version.sh"

if [ ! -f "$VALIDATE_SCRIPT" ]; then
	echo "Error: Validation script not found at '$VALIDATE_SCRIPT'" >&2
	echo "Please ensure validate_version.sh is in the same directory as this test script." >&2
	exit 1
fi

# --- Test Harness ---
TEST_COUNT=0
FAIL_COUNT=0

# Helper to run a test
# $1: Expected exit code (0 for pass, 1 for fail)
# $2: The "pushed" tag to test
# $3: The "previous" tag to simulate
# $4: Test description
run_test() {
	local expected_code="$1"
	local pushed_tag="$2"
	local previous_tag="$3"
	local description="$4"
	local actual_code=0
	local output=""

	TEST_COUNT=$((TEST_COUNT + 1))
	echo -n "Test: $description... "

	# Run the validation script, capturing stdout/stderr and exit code
	# We pass the tags as environment variables, just like the workflow
	output=$(
		PUSHED_TAG="$pushed_tag" \
			PREVIOUS_TAG="$previous_tag" \
			"$VALIDATE_SCRIPT" 2>&1
	) || actual_code=$?

	if [ "$actual_code" -eq "$expected_code" ]; then
		echo "PASS ✅"
	else
		FAIL_COUNT=$((FAIL_COUNT + 1))
		echo "FAIL ❌"
		echo "  Expected exit code: $expected_code"
		echo "  Got exit code: $actual_code"
		echo "  PUSHED_TAG=$pushed_tag, PREVIOUS_TAG=$previous_tag"
		echo "  Script output:"
		echo "$output" | sed 's/^/    /' # Indent output for readability
	fi
}

# --- Main Execution ---

echo
echo "--- Running Validation Logic Tests ---"

# --- PASSING Scenarios (Expected Exit 0) ---
echo
echo "Running PASS scenarios (expected exit 0)..."
run_test 0 "v0.1.0" "v0.0.0" "First release"
run_test 0 "v0.12.0" "v0.12.0-rc.3" "Special case: Final release (v0.12.0 > v0.12.0-rc.3)"
run_test 0 "v0.12.0-rc.4" "v0.12.0-rc.3" "Subsequent RC (rc.4 > rc.3)"
run_test 0 "v0.12.1" "v0.12.0" "Patch bump (v0.12.1 > v0.12.0)"
run_test 0 "v0.13.0" "v0.12.9" "Minor bump (v0.13.0 > v0.12.9)"
run_test 0 "v1.0.0" "v0.99.0" "Major bump (v1.0.0 > v0.99.0)"
run_test 0 "v1.10.0" "v1.9.0" "Version sort check (1.10.0 > 1.9.0)"
run_test 0 "v2.0.0" "v1.10.5" "Version sort check (2.0.0 > 1.10.5)"

# --- FAILING Scenarios (Expected Exit 1) ---
echo
echo "Running FAIL scenarios (expected exit 1)..."
run_test 1 "v0.12.0-rc.3" "v0.12.0-rc.3" "Same tag (rc.3 == rc.3)"
run_test 1 "v1.2.3" "v1.2.3" "Same tag (final == final)"
run_test 1 "v0.12.0-rc.2" "v0.12.0-rc.3" "Lower RC (rc.2 < rc.3)"
run_test 1 "v0.12.0-beta" "v0.12.0-rc.1" "Lower pre-release type (beta < rc)"
run_test 1 "v0.11.0" "v0.12.0" "Lower minor version (v0.11.0 < v0.12.0)"
run_test 1 "v1.2.0" "v1.3.0" "Lower minor version (v1.2.0 < v1.3.0)"
run_test 1 "v0.12.0-rc.1" "v0.12.0" "Pre-release after final (rc.1 < final)"
run_test 1 "v1.9.0" "v1.10.0" "Version sort check (1.9.0 < 1.10.0)"

# --- Final Report ---
echo
echo "--- Test Summary ---"
if [ "$FAIL_COUNT" -eq 0 ]; then
	echo "All $TEST_COUNT tests passed! 🎉"
	exit 0
else
	echo "$FAIL_COUNT out of $TEST_COUNT tests failed. ❌"
	exit 1
fi
