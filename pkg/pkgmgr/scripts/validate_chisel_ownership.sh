#!/bin/sh

set -eu

: "${OWNED_PATHS_ZSTD:?}"
: "${OWNED_PATHS:?}"
: "${TARGET_ROOT:?}"
: "${STAGED_ROOT:?}"
: "${VALIDATION_MARK:?}"

zstd -q -d -c "$OWNED_PATHS_ZSTD" > "$OWNED_PATHS"

xargs -0 sh -c '
    for path do
        target_ownership=$(stat -c "%u:%g" "$TARGET_ROOT$path") || {
            printf "unable to read current ownership for %s\n" "$path" >&2
            exit 1
        }
        staged_ownership=$(stat -c "%u:%g" "$STAGED_ROOT$path") || {
            printf "unable to read staged ownership for %s\n" "$path" >&2
            exit 1
        }
        if [ "$target_ownership" != "$staged_ownership" ]; then
            printf "path %s ownership is %s, expected %s\n" "$path" "$target_ownership" "$staged_ownership" >&2
            exit 1
        fi
    done
' sh < "$OWNED_PATHS"

touch "$VALIDATION_MARK"
