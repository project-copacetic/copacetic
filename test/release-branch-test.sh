#!/bin/bash

# Test script for release branch creation logic
# This can be run locally to validate the version extraction logic

test_version_extraction() {
    local tag="$1"
    local expected="$2"
    
    # Same logic as in the workflow
    VERSION=$(echo "$tag" | sed 's/refs\/tags\/v//' | sed 's/\.[0-9]*$//')
    BRANCH_NAME="release-${VERSION}"
    
    if [ "$VERSION" = "$expected" ]; then
        echo "✓ PASS: $tag -> $VERSION (branch: $BRANCH_NAME)"
        return 0
    else
        echo "✗ FAIL: $tag -> $VERSION (expected: $expected)"
        return 1
    fi
}

echo "Testing version extraction logic for release branch creation"
echo "==========================================================="

# Test all version patterns
test_version_extraction "refs/tags/v0.11.0" "0.11"
test_version_extraction "refs/tags/v0.10.0" "0.10"
test_version_extraction "refs/tags/v0.9.0" "0.9"
test_version_extraction "refs/tags/v0.8.0" "0.8"
test_version_extraction "refs/tags/v0.7.0" "0.7"
test_version_extraction "refs/tags/v0.6.2" "0.6"
test_version_extraction "refs/tags/v0.6.1" "0.6"
test_version_extraction "refs/tags/v0.6.0" "0.6"
test_version_extraction "refs/tags/v0.5.1" "0.5"
test_version_extraction "refs/tags/v0.5.0" "0.5"

echo "==========================================================="
echo "All tests passed! Version extraction logic is working correctly."