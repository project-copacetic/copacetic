#!/bin/sh

if [ "$IGNORE_ERRORS" = "true" ]; then
    set -x
else
    set -ex
fi

DPKG_ROOT=${DPKG_ROOT:-/tmp/debian-rootfs}
DOWNLOAD_DIR=${DOWNLOAD_DIR:-/copa-dpkg-downloads}
PACKAGES_FILE=${PACKAGES_FILE:-$DOWNLOAD_DIR/packages.txt}
VERSION_FLOORS_FILE=${VERSION_FLOORS_FILE:-/copa-dpkg-version-floors}
FINALIZE_DPKG_STATUS_SCRIPT=${FINALIZE_DPKG_STATUS_SCRIPT:-/finalize_dpkg_status.sh}
RESULT_MANIFEST=${RESULT_MANIFEST:-$DPKG_ROOT/manifest}

case "$UPDATE_ALL" in
    true|false)
        ;;
    *)
        echo "invalid UPDATE_ALL value: $UPDATE_ALL" >&2
        exit 1
        ;;
esac

mkdir -p "$DOWNLOAD_DIR"
cd "$DOWNLOAD_DIR"
: > "$RESULT_MANIFEST"

# Build positional parameters from a generated one-package-per-line file. Go
# validates every package name before creating this file; no package value is
# interpolated into shell source.
set --
while IFS= read -r package || [ -n "$package" ]; do
    [ -n "$package" ] || continue
    set -- "$@" "$package"
done < "$PACKAGES_FILE"

if [ "$#" -eq 0 ]; then
    echo "no packages were selected for download" >&2
    exit 1
fi

apt-get -o Acquire::Retries=3 update
mkdir -p "$DOWNLOAD_DIR/partial"
if [ "$DPKG_INSTALLATION_MODE" = "external-full-status" ]; then
    # Resolve the explicitly selected upgrades and their complete dependency
    # closure against the reconstructed target status. A plain `apt-get
    # download` fetches only the named archives and can leave a newly introduced
    # or tightened dependency absent from the patched root.
    if ! apt-get \
        -o Acquire::Retries=3 \
        -o "Dir::State::status=$DPKG_ROOT/var/lib/dpkg/status" \
        -o "Dir::Cache::archives=$DOWNLOAD_DIR" \
        -o Debug::NoLocking=1 \
        --download-only \
        --fix-broken \
        --no-install-recommends \
        -y install -- "$@"; then
        echo "failed to resolve and download the selected package dependency closure" >&2
        exit 1
    fi
else
    # Preserve the established status.d flow: its temporary database is built
    # by reinstalling the complete package inventory before this script runs.
    apt-get -o Acquire::Retries=3 download --no-install-recommends -- "$@"
fi

lookup_version_floor() {
    wanted_package=$1
    FLOOR_INSTALLED=""
    FLOOR_FIXED=""

    while IFS='|' read -r floor_package installed_version fixed_version extra || [ -n "${floor_package}${installed_version}${fixed_version}${extra}" ]; do
        if [ -z "$floor_package" ] || [ -n "$extra" ]; then
            echo "invalid package version floor record in $VERSION_FLOORS_FILE" >&2
            exit 1
        fi
        if [ "$floor_package" = "$wanted_package" ]; then
            FLOOR_INSTALLED=$installed_version
            FLOOR_FIXED=$fixed_version
            return 0
        fi
    done < "$VERSION_FLOORS_FILE"

    return 1
}

version_satisfies() {
    actual=$1
    relation=$2
    required=$3

    if dpkg --compare-versions "$actual" "$relation" "$required"; then
        return 0
    else
        compare_status=$?
    fi
    if [ "$compare_status" -gt 1 ]; then
        echo "invalid Debian version comparison: actual=$actual relation=$relation required=$required" >&2
        exit 1
    fi
    return 1
}

is_selected_package() {
    wanted_package=$1

    while IFS= read -r selected_package || [ -n "$selected_package" ]; do
        [ -n "$selected_package" ] || continue
        if [ "$selected_package" = "$wanted_package" ]; then
            return 0
        fi
    done < "$PACKAGES_FILE"

    return 1
}

record_package_version() {
    package=$1
    version=$2
    printf 'Package: %s\nVersion: %s\n' "$package" "$version" >> "$RESULT_MANIFEST"
}

unsafe_downloads=false
for deb in ./*.deb; do
    [ -f "$deb" ] || continue

    package=$(dpkg-deb -f "$deb" Package)
    version=$(dpkg-deb -f "$deb" Version)
    unsafe_reason=""

    if ! lookup_version_floor "$package"; then
        # APT may download a new dependency that was not present in the
        # original minimal image. It has no installed-version floor.
        FLOOR_INSTALLED=""
        FLOOR_FIXED=""
    elif [ "$UPDATE_ALL" = "true" ]; then
        if [ -z "$FLOOR_INSTALLED" ]; then
            unsafe_reason="downloaded package $package has no installed-version baseline"
        elif ! version_satisfies "$version" gt "$FLOOR_INSTALLED"; then
            unsafe_reason="downloaded package $package version $version is not newer than installed version $FLOOR_INSTALLED"
        fi
    else
        if [ -n "$FLOOR_INSTALLED" ] && ! version_satisfies "$version" ge "$FLOOR_INSTALLED"; then
            unsafe_reason="downloaded package $package version $version is lower than installed version $FLOOR_INSTALLED"
        elif [ -n "$FLOOR_FIXED" ] && ! version_satisfies "$version" ge "$FLOOR_FIXED"; then
            unsafe_reason="downloaded package $package version $version is lower than requested fixed version $FLOOR_FIXED"
        fi
    fi

    if [ -n "$unsafe_reason" ]; then
        echo "$unsafe_reason; refusing to install it" >&2
        # Preserve the attempted version in the result manifest so Go-side
        # validation reports explicitly selected packages when --ignore-errors
        # is active.
        record_package_version "$package" "$version"
        rm -f "$deb"
        unsafe_downloads=true

        # A dependency archive cannot be skipped independently: installing the
        # selected package set without it would break the closure APT resolved.
        # Fail closed even under --ignore-errors rather than produce an
        # inconsistent target filesystem.
        if ! is_selected_package "$package"; then
            echo "unsafe package $package is part of the resolved dependency closure; refusing to install an incomplete closure" >&2
            exit 1
        fi
        if [ "$IGNORE_ERRORS" != "true" ]; then
            exit 1
        fi
    fi
done

# Full-status images omit the shell and helper programs package maintainer
# scripts assume. Rebuild only that layout's archives without scripts; preserve
# the established status.d installation behavior.
if [ "$DPKG_INSTALLATION_MODE" = "external-full-status" ]; then
    sanitize_root=$(mktemp -d)
    sanitized_dir="$DOWNLOAD_DIR/sanitized"
    mkdir -p "$sanitized_dir"
    for deb in ./*.deb; do
        [ -f "$deb" ] || continue
        package=$(dpkg-deb -f "$deb" Package)
        unpacked="$sanitize_root/$package"
        rm -rf "$unpacked"
        dpkg-deb -R "$deb" "$unpacked"
        rm -f \
            "$unpacked/DEBIAN/config" "$unpacked/DEBIAN/preinst" \
            "$unpacked/DEBIAN/postinst" "$unpacked/DEBIAN/prerm" \
            "$unpacked/DEBIAN/postrm" "$unpacked/DEBIAN/triggers"
        dpkg-deb -b "$unpacked" "$sanitized_dir/$(basename "$deb")" >/dev/null
    done
    rm -rf "$sanitize_root"
    set -- "$sanitized_dir"/*.deb
else
    set -- ./*.deb
fi
if [ ! -f "$1" ]; then
    set --
fi

if [ "$#" -gt 0 ]; then
    dpkg --root="$DPKG_ROOT" --admindir="$DPKG_ROOT/var/lib/dpkg" --force-all --force-confold --install "$@"
    dpkg --root="$DPKG_ROOT" --configure -a
fi

if [ "$DPKG_INSTALLATION_MODE" = "external-full-status" ]; then
    # Dependency closure packages may contain package-manager or shell tooling
    # used only while maintainer scripts run. Never leave those executables in
    # the patched apt-less image.
    rm -f \
        "$DPKG_ROOT"/bin/bash "$DPKG_ROOT"/bin/busybox \
        "$DPKG_ROOT"/bin/dash "$DPKG_ROOT"/bin/sh \
        "$DPKG_ROOT"/usr/bin/apt "$DPKG_ROOT"/usr/bin/apt-* \
        "$DPKG_ROOT"/usr/bin/bash "$DPKG_ROOT"/usr/bin/busybox \
        "$DPKG_ROOT"/usr/bin/dash "$DPKG_ROOT"/usr/bin/dpkg* \
        "$DPKG_ROOT"/usr/bin/sh "$DPKG_ROOT"/sbin/apk
fi

# Preserve the target image's original dpkg metadata layout and remove the
# temporary administrative database reconstructed for the update.
DPKG_ROOT="$DPKG_ROOT" /bin/sh "$FINALIZE_DPKG_STATUS_SCRIPT"

# Write results manifest for validation. Rejected packages were recorded above;
# safe downloaded packages are recorded after installation.
for deb in "$@"; do
    package=$(dpkg-deb -f "$deb" Package)
    version=$(dpkg-deb -f "$deb" Version)
    record_package_version "$package" "$version"
done

if [ "$unsafe_downloads" = "true" ]; then
    echo "one or more unsafe package versions were skipped" >&2
fi
