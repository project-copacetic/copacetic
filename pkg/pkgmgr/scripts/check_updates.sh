#!/bin/sh

set -eu

manager=$1
tool=$2
marker=$3

# Query stdout can contain diagnostics even when the command fails.
fail_with_output() {
    status=$1
    output=$2
    if [ -n "$output" ]; then
        printf '%s\n' "$output"
    fi
    exit "$status"
}

# A previous check or input image must not supply this check's result.
rm -f "$marker"

case "$manager" in
    yum|dnf|tdnf|microdnf)
        if [ "$manager" = microdnf ]; then
            "$tool" install dnf -y
            tool=dnf
        fi

        "$tool" clean all
        if [ "$manager" = yum ]; then
            "$tool" makecache fast
        else
            "$tool" makecache --refresh -y
        fi

        # Yum/DNF use 100 for available updates; tdnf versions may return 0
        # with package output. Neither may hide a real failure in a pipeline.
        status=0
        updates=$("$tool" -q check-update) || status=$?
        case "$status" in
            0|100) ;;
            *) fail_with_output "$status" "$updates" ;;
        esac
        if [ "$status" -eq 100 ] || [ -n "$updates" ]; then
            : > "$marker"
        fi
        ;;
    apk)
        updates=$("$tool" list -u) || fail_with_output "$?" "$updates"
        if [ -n "$updates" ]; then
            : > "$marker"
        fi
        ;;
    apt)
        # APT's exit 100 is an error, unlike Yum/DNF's check-update status.
        updates=$("$tool" -s upgrade) || fail_with_output "$?" "$updates"
        status=0
        printf '%s\n' "$updates" | grep '^Inst' > /dev/null || status=$?
        case "$status" in
            0) : > "$marker" ;;
            1) ;;
            *) exit "$status" ;;
        esac
        ;;
    pacman)
        # pacman -Qu uses 1 for both no matches and failures. Only an empty
        # result without diagnostics is a normal no-match result.
        diagnostics=$(mktemp)
        trap 'rm -f "$diagnostics"' EXIT
        status=0
        updates=$("$tool" -Qu 2> "$diagnostics") || status=$?
        cat "$diagnostics" >&2
        case "$status" in
            0)
                if [ -n "$updates" ]; then
                    : > "$marker"
                fi
                ;;
            1)
                if [ -n "$updates" ] || [ -s "$diagnostics" ]; then
                    fail_with_output "$status" "$updates"
                fi
                ;;
            *) fail_with_output "$status" "$updates" ;;
        esac
        ;;
    *)
        printf 'unsupported package manager for update check: %s\n' "$manager" >&2
        exit 1
        ;;
esac
