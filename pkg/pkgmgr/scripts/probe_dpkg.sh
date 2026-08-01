#!/bin/sh

# This script is executed by the temporary BusyBox copied into the target state.
# Do not invoke any binary from the target image: target tools are only checked
# for existence and executability.

TARGET_ROOT=${TARGET_ROOT:-}
BUSYBOX=${BUSYBOX:-}
TARGET_TOOL_PATHS=${TARGET_TOOL_PATHS:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}

bb() {
    if [ -n "$BUSYBOX" ]; then
        "$BUSYBOX" "$@"
    else
        "$@"
    fi
}

has_target_tool() {
    tool=$1
    old_ifs=$IFS
    IFS=:
    for directory in $TARGET_TOOL_PATHS; do
        if [ -x "${TARGET_ROOT}${directory}/${tool}" ]; then
            IFS=$old_ifs
            return 0
        fi
    done
    IFS=$old_ifs
    return 1
}

manifest_path="${TARGET_ROOT}${CHISEL_MANIFEST_PATH}"
status_path="${TARGET_ROOT}${DPKG_STATUS_PATH}"
status_directory_path="${TARGET_ROOT}${DPKG_STATUS_FOLDER}"

has_manifest=0
has_status=0
has_status_directory=0
missing_tools=""

bb mkdir -p "$RESULTS_PATH"

if [ -f "$manifest_path" ]; then
    has_manifest=1
fi

if [ -f "$status_path" ]; then
    has_status=1
    bb cp "$status_path" "$RESULT_STATUS_PATH"

    for tool in $REQUIRED_DPKG_TOOLS; do
        if ! has_target_tool "$tool"; then
            if [ -n "$missing_tools" ]; then
                missing_tools="$missing_tools $tool"
            else
                missing_tools=$tool
            fi
        fi
    done
fi

if [ -d "$status_directory_path" ]; then
    has_status_directory=1
    bb mkdir -p "$RESULT_STATUSD_FILES_PATH"
    bb ls -1A "$status_directory_path" > "$RESULT_STATUSD_LIST_PATH"
    bb cp -a "$status_directory_path/." "$RESULT_STATUSD_FILES_PATH/"
fi

{
    printf 'manifest=%s\n' "$has_manifest"
    printf 'status=%s\n' "$has_status"
    printf 'status_directory=%s\n' "$has_status_directory"
    printf 'missing_tools=%s\n' "$missing_tools"
} > "$PROBE_OUTPUT_PATH"
