#!/usr/bin/env bash

set -euo pipefail

# This script verifies the deterministc hashes of artifacts listed in T0.json

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed." >&2
    exit 1
fi

T0_FILE="T0.json"
if [ ! -f "$T0_FILE" ]; then
    echo "Error: $T0_FILE not found in the current directory." >&2
    exit 1
fi

echo "Verifying T0.json artifacts hashes..."
ERROR_COUNT=0

# Extract artifact paths and hashes from T0.json
while read -r row; do
    # Extract path and expected sha256 using jq
    ARTIFACT_PATH=$(echo "$row" | jq -r '.path')
    EXPECTED_HASH=$(echo "$row" | jq -r '.sha256')

    if [ ! -f "$ARTIFACT_PATH" ]; then
        echo "FAIL: Artifact not found - $ARTIFACT_PATH"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        continue
    fi

    # Calculate actual sha256
    ACTUAL_HASH=$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')

    if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
        echo "FAIL: Hash mismatch for $ARTIFACT_PATH"
        echo "  Expected: $EXPECTED_HASH"
        echo "  Actual:   $ACTUAL_HASH"
        ERROR_COUNT=$((ERROR_COUNT + 1))
    else
        echo "OK: $ARTIFACT_PATH"
    fi
done < <(jq -c '.artifacts[]' "$T0_FILE")

if [ "$ERROR_COUNT" -gt 0 ]; then
    echo "Verification FAILED: $ERROR_COUNT errors found."
    exit 1
else
    echo "Verification PASSED: All artifact hashes match."
fi
