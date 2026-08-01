#!/bin/sh

set -eu

DPKG_ROOT=${DPKG_ROOT:-/tmp/debian-rootfs}
DPKG_LIB="$DPKG_ROOT/var/lib/dpkg"
STATUS_FILE="$DPKG_LIB/status"
OUTPUT_DIR="$DPKG_LIB/status.d"

cleanup_dpkg_database_except() {
    keep_name=$1

    for entry in "$DPKG_LIB"/* "$DPKG_LIB"/.[!.]* "$DPKG_LIB"/..?*; do
        if [ ! -e "$entry" ] && [ ! -L "$entry" ]; then
            continue
        fi
        if [ "${entry##*/}" = "$keep_name" ]; then
            continue
        fi
        rm -rf "$entry"
    done
}

case "$DPKG_INSTALLATION_MODE" in
    external-full-status)
        if [ ! -f "$STATUS_FILE" ]; then
            echo "updated dpkg status file was not generated at $STATUS_FILE" >&2
            exit 1
        fi
        cleanup_dpkg_database_except "status"
        ;;
    external-status-directory)
        rm -rf "$OUTPUT_DIR"
        mkdir -p "$OUTPUT_DIR"

        package_name=""
        package_content=""

        get_original_filename() {
            pkg=$1
            printf '%s\n' "$STATUSD_FILE_MAP" | grep "\"$pkg\":" | sed 's/.*"'"$pkg"'":"\([^"]*\)".*/\1/'
        }

        write_package_block() {
            if [ -z "$package_name" ]; then
                return
            fi

            original_filename=$(get_original_filename "$package_name" || true)
            if [ -n "$original_filename" ]; then
                output_name=$original_filename
            else
                output_name=$package_name
            fi

            printf '%s\n' "$package_content" > "$OUTPUT_DIR/$output_name"
        }

        while IFS= read -r line || [ -n "$line" ]; do
            if [ -z "$line" ]; then
                write_package_block
                package_name=""
                package_content=""
                continue
            fi

            if [ -z "$package_content" ]; then
                package_content=$line
            else
                package_content="$package_content
$line"
            fi

            case "$line" in
                "Package:"*)
                    package_name=${line#Package:}
                    package_name=${package_name#" "}
                    ;;
            esac
        done < "$STATUS_FILE"

        write_package_block
        cleanup_dpkg_database_except "status.d"
        ;;
    *)
        echo "unsupported external dpkg installation mode: $DPKG_INSTALLATION_MODE" >&2
        exit 1
        ;;
esac
