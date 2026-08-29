#!/bin/sh

set -eu

INSTALLED_PACKAGES_FILE=${INSTALLED_PACKAGES_FILE:-/copa-dpkg-installed-packages}
UPDATE_PACKAGES_FILE=${UPDATE_PACKAGES_FILE:-/copa-dpkg-downloads/packages.txt}
UPDATES_MARKER_FILE=${UPDATES_MARKER_FILE:-/updates.txt}

tmp_file="${UPDATE_PACKAGES_FILE}.tmp"
rm -f "$UPDATE_PACKAGES_FILE" "$UPDATES_MARKER_FILE" "$tmp_file"
mkdir -p "$(dirname "$UPDATE_PACKAGES_FILE")"
: > "$tmp_file"

while IFS='|' read -r package installed_version selection extra || [ -n "${package}${installed_version}${selection}${extra}" ]; do
    if [ -z "$package" ] || [ -z "$installed_version" ] || [ -z "$selection" ] || [ -n "$extra" ]; then
        echo "invalid installed package record in $INSTALLED_PACKAGES_FILE" >&2
        exit 1
    fi

    case "$selection" in
        hold)
            continue
            ;;
        install)
            ;;
        *)
            echo "invalid package selection '$selection' for $package in $INSTALLED_PACKAGES_FILE" >&2
            exit 1
            ;;
    esac

    if policy=$(apt-cache policy "$package"); then
        :
    else
        echo "failed to query repository candidate for package $package" >&2
        exit 1
    fi

    candidate=$(printf '%s\n' "$policy" | sed -n 's/^[[:space:]]*Candidate:[[:space:]]*//p' | sed -n '1p')
    case "$candidate" in
        ""|"(none)")
            continue
            ;;
    esac

    # dpkg implements Debian's epoch, tilde, and revision ordering. A package
    # is selected only when the repository candidate is strictly newer.
    if dpkg --compare-versions "$candidate" gt "$installed_version"; then
        printf '%s\n' "$package" >> "$tmp_file"
    else
        compare_status=$?
        if [ "$compare_status" -gt 1 ]; then
            echo "invalid Debian version comparison for package $package: candidate=$candidate installed=$installed_version" >&2
            exit 1
        fi
    fi
done < "$INSTALLED_PACKAGES_FILE"

if [ -s "$tmp_file" ]; then
    mv "$tmp_file" "$UPDATE_PACKAGES_FILE"
    : > "$UPDATES_MARKER_FILE"
else
    rm -f "$tmp_file"
fi
