#!/bin/sh

set -ex

DPKG_ROOT=${DPKG_ROOT:-/tmp/debian-rootfs}
DOWNLOAD_DIR=${DOWNLOAD_DIR:-/copa-dpkg-downloads}
PACKAGES_FILE=${PACKAGES_FILE:-$DOWNLOAD_DIR/packages.txt}
VERSION_FLOORS_FILE=${VERSION_FLOORS_FILE:-/copa-dpkg-version-floors}
FINALIZE_DPKG_STATUS_SCRIPT=${FINALIZE_DPKG_STATUS_SCRIPT:-/finalize_dpkg_status.sh}
RESULT_MANIFEST=${RESULT_MANIFEST:-$DPKG_ROOT/manifest}
RESOLVER_STATUS_FILE=${RESOLVER_STATUS_FILE:-$DOWNLOAD_DIR/resolver-status}
TARGET_DPKG_ARCH=${TARGET_DPKG_ARCH:-}
BUSYBOX=${BUSYBOX:-/bin/busybox}
LIFECYCLE_PACKAGES=${LIFECYCLE_PACKAGES-dpkg dash init-system-helpers debconf perl-base tar apt apt-utils bash busybox busybox-static}
DPKG_TOOL=${DPKG_TOOL:-$(command -v dpkg)}
DPKG_DEB_TOOL=${DPKG_DEB_TOOL:-$(command -v dpkg-deb)}

case "$UPDATE_ALL" in
    true|false) ;;
    *)
        echo "invalid UPDATE_ALL value: $UPDATE_ALL" >&2
        exit 1
        ;;
esac

mkdir -p "$DOWNLOAD_DIR"
cd "$DOWNLOAD_DIR"
: > "$RESULT_MANIFEST"

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
    if [ ! -s "$RESOLVER_STATUS_FILE" ]; then
        echo "resolver status is missing or empty: $RESOLVER_STATUS_FILE" >&2
        exit 1
    fi
    if ! apt-get \
        -o Acquire::Retries=3 \
        -o "Dir::State::status=$RESOLVER_STATUS_FILE" \
        -o "Dir::Cache::archives=$DOWNLOAD_DIR" \
        -o Debug::NoLocking=1 \
        --download-only \
        --no-remove \
        --no-install-recommends \
        -y install -- "$@"; then
        echo "failed to resolve and download the selected package dependency closure" >&2
        exit 1
    fi
else
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
    if "$DPKG_TOOL" --compare-versions "$actual" "$relation" "$required"; then
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

is_lifecycle_package() {
    wanted_package=$1
    for lifecycle_package in $LIFECYCLE_PACKAGES; do
        if [ "$lifecycle_package" = "$wanted_package" ]; then
            return 0
        fi
    done
    return 1
}

normalize_dependency_text() {
    printf '%s\n' "$1" | awk '{$1=$1; print}'
}

original_dependency_clause_present() {
    odcp_source=$1
    odcp_clause=$(normalize_dependency_text "$2")
    awk -v source="$odcp_source" '
        BEGIN { RS = "" }
        {
            package_name = ""
            active = 0
            count = split($0, lines, "\n")
            for (i = 1; i <= count; i++) {
                if (lines[i] ~ /^Package:[[:space:]]*/) {
                    package_name = lines[i]
                    sub(/^Package:[[:space:]]*/, "", package_name)
                    active = 0
                } else if (lines[i] ~ /^(Depends|Pre-Depends):[[:space:]]*/) {
                    relation = lines[i]
                    sub(/^(Depends|Pre-Depends):[[:space:]]*/, "", relation)
                    if (package_name == source) print relation
                    active = package_name == source
                } else if (lines[i] ~ /^[[:space:]]/ && active) {
                    print lines[i]
                } else if (lines[i] !~ /^[[:space:]]/) {
                    active = 0
                }
            }
        }
    ' "$original_status" |
        tr ',' '\n' |
        awk '{$1=$1; print}' |
        grep -Fxq "$odcp_clause"
}

final_alternative_satisfied() {
    fas_alternative=$1
    fas_package=$(printf '%s\n' "$fas_alternative" | sed -n 's/^[[:space:]]*\([a-z0-9][a-z0-9+.-]*\).*/\1/p')
    [ -n "$fas_package" ] || return 1
    fas_constraint=$(printf '%s\n' "$fas_alternative" | sed -n 's/.*([[:space:]]*\(<<\|<=\|=\|>=\|>>\)[[:space:]]*\([^)]*\)).*/\1|\2/p')
    fas_operator=""
    fas_required=""
    if [ -n "$fas_constraint" ]; then
        fas_operator=${fas_constraint%%|*}
        fas_required=${fas_constraint#*|}
        case "$fas_operator" in
            '<<') fas_operator=lt ;;
            '<=') fas_operator=le ;;
            '=') fas_operator=eq ;;
            '>=') fas_operator=ge ;;
            '>>') fas_operator=gt ;;
            *) return 1 ;;
        esac
    fi
    while IFS='|' read -r fas_identity fas_version fas_extra || [ -n "${fas_identity}${fas_version}${fas_extra}" ]; do
        [ "${fas_identity%%:*}" = "$fas_package" ] || continue
        if [ -z "$fas_operator" ]; then
            return 0
        fi
        if [ -n "$fas_version" ] && "$DPKG_TOOL" --compare-versions "$fas_version" "$fas_operator" "$fas_required"; then
            return 0
        fi
    done < "$final_versions"
    return 1
}

validate_final_dependencies() {
    vfd_archive=$1
    vfd_source=$("$DPKG_DEB_TOOL" -f "$vfd_archive" Package)
    vfd_clauses=$(mktemp)
    {
        "$DPKG_DEB_TOOL" -f "$vfd_archive" Depends 2>/dev/null || true
        "$DPKG_DEB_TOOL" -f "$vfd_archive" Pre-Depends 2>/dev/null || true
    } | tr ',' '\n' > "$vfd_clauses"
    while IFS= read -r vfd_clause || [ -n "$vfd_clause" ]; do
        [ -n "$vfd_clause" ] || continue
        vfd_safe=false
        vfd_alternatives=$(mktemp)
        printf '%s\n' "$vfd_clause" | tr '|' '\n' > "$vfd_alternatives"
        while IFS= read -r vfd_alternative || [ -n "$vfd_alternative" ]; do
            vfd_dependency=$(printf '%s\n' "$vfd_alternative" | sed -n 's/^[[:space:]]*\([a-z0-9][a-z0-9+.-]*\).*/\1/p')
            [ -n "$vfd_dependency" ] || continue
            if final_alternative_satisfied "$vfd_alternative"; then
                vfd_safe=true
                break
            fi
        done < "$vfd_alternatives"
        rm -f "$vfd_alternatives"
        if [ "$vfd_safe" != true ] && original_dependency_clause_present "$vfd_source" "$vfd_clause"; then
            vfd_safe=true
        fi
        if [ "$vfd_safe" != true ]; then
            echo "package $vfd_source has unresolved final dependency clause '$vfd_clause'" >&2
            return 1
        fi
    done < "$vfd_clauses"
    rm -f "$vfd_clauses"
}

record_package_version() {
    package=$1
    architecture=$2
    version=$3
    printf 'Package: %s\n' "$package" >> "$RESULT_MANIFEST"
    if [ -n "$architecture" ]; then
        printf 'Architecture: %s\n' "$architecture" >> "$RESULT_MANIFEST"
    fi
    printf 'Version: %s\n' "$version" >> "$RESULT_MANIFEST"
}

assert_target_path_safe() {
    target_path_to_check=$1
    candidate_parent=$(dirname "$target_path_to_check")
    while [ ! -e "$candidate_parent" ] && [ ! -L "$candidate_parent" ]; do
        next_parent=$(dirname "$candidate_parent")
        if [ "$next_parent" = "$candidate_parent" ]; then
            echo "cannot resolve target path ancestor: $target_path_to_check" >&2
            exit 1
        fi
        candidate_parent=$next_parent
    done
    resolved_parent=$(readlink -f "$candidate_parent") || {
        echo "cannot resolve target path ancestor: $candidate_parent" >&2
        exit 1
    }
    case "$resolved_parent" in
        "$dpkg_root_real"|"$dpkg_root_real"/*) ;;
        *)
            echo "target path escapes the mounted root: $target_path_to_check" >&2
            exit 1
            ;;
    esac
}

filter_status_to_final_inventory() {
    current_status=$DPKG_ROOT/var/lib/dpkg/status
    filtered_status=$DOWNLOAD_DIR/filtered-status
    keep_identities=$DOWNLOAD_DIR/keep-identities
    lifecycle_names=$DOWNLOAD_DIR/lifecycle-package-names

    awk -F'|' 'NF >= 1 && $1 != "" { print $1 }' "$VERSION_FLOORS_FILE" > "$keep_identities"
    cat "$retained_identities" >> "$keep_identities"
    sort -u "$keep_identities" -o "$keep_identities"
    : > "$lifecycle_names"
    for lifecycle_package in $LIFECYCLE_PACKAGES; do
        printf '%s\n' "$lifecycle_package" >> "$lifecycle_names"
    done
    sort -u "$lifecycle_names" -o "$lifecycle_names"

    awk -v identities_file="$keep_identities" -v lifecycle_file="$lifecycle_names" '
        BEGIN {
            while ((getline identity < identities_file) > 0) keep[identity] = 1
            close(identities_file)
            while ((getline name < lifecycle_file) > 0) lifecycle[name] = 1
            close(lifecycle_file)
            RS = ""; ORS = "\n\n"
        }
        {
            package_name = ""; architecture = ""
            count = split($0, lines, "\n")
            for (i = 1; i <= count; i++) {
                if (lines[i] ~ /^Package:[[:space:]]*/) {
                    package_name = lines[i]; sub(/^Package:[[:space:]]*/, "", package_name)
                } else if (lines[i] ~ /^Architecture:[[:space:]]*/) {
                    architecture = lines[i]; sub(/^Architecture:[[:space:]]*/, "", architecture)
                }
            }
            if (lifecycle[package_name]) next
            identity = package_name ":" (architecture == "" ? ENVIRON["TARGET_DPKG_ARCH"] : architecture)
            if (keep[identity]) { print $0; kept++ }
        }
        END { if (kept == 0) exit 42 }
    ' "$current_status" > "$filtered_status"

    # Restore original lifecycle and non-installed bookkeeping paragraphs unless
    # a retained archive now owns the same identity.
    awk -v lifecycle_file="$lifecycle_names" -v retained_file="$retained_identities" '
        BEGIN {
            while ((getline name < lifecycle_file) > 0) lifecycle[name] = 1
            close(lifecycle_file)
            while ((getline identity < retained_file) > 0) retained[identity] = 1
            close(retained_file)
            RS = ""; ORS = "\n\n"
        }
        {
            package_name = ""; architecture = ""; status_value = ""
            count = split($0, lines, "\n")
            for (i = 1; i <= count; i++) {
                if (lines[i] ~ /^Package:[[:space:]]*/) {
                    package_name = lines[i]; sub(/^Package:[[:space:]]*/, "", package_name)
                } else if (lines[i] ~ /^Architecture:[[:space:]]*/) {
                    architecture = lines[i]; sub(/^Architecture:[[:space:]]*/, "", architecture)
                } else if (lines[i] ~ /^Status:[[:space:]]*/) {
                    status_value = lines[i]; sub(/^Status:[[:space:]]*/, "", status_value)
                }
            }
            identity = package_name ":" (architecture == "" ? ENVIRON["TARGET_DPKG_ARCH"] : architecture)
            if (retained[identity]) next
            preserve = lifecycle[package_name]
            if (!preserve && status_value != "") {
                split(status_value, fields, /[[:space:]]+/)
                preserve = fields[3] != "installed"
            }
            if (preserve) print $0
        }
    ' "$original_status" >> "$filtered_status"
    mv "$filtered_status" "$current_status"
}

unsafe_downloads=false
for deb in ./*.deb; do
    [ -f "$deb" ] || continue
    package=$("$DPKG_DEB_TOOL" -f "$deb" Package)
    architecture=$("$DPKG_DEB_TOOL" -f "$deb" Architecture 2>/dev/null || true)
    if [ "$DPKG_INSTALLATION_MODE" = "external-full-status" ] && [ -z "$architecture" ]; then
        echo "downloaded package $package has no Architecture field" >&2
        exit 1
    fi
    identity=$package
    if [ -n "$architecture" ]; then identity=$package:$architecture; fi
    version=$("$DPKG_DEB_TOOL" -f "$deb" Version)
    unsafe_reason=""

    if ! lookup_version_floor "$identity" && ! lookup_version_floor "$package"; then
        FLOOR_INSTALLED=""; FLOOR_FIXED=""
    elif [ "$UPDATE_ALL" = "true" ]; then
        if [ -z "$FLOOR_INSTALLED" ]; then
            unsafe_reason="downloaded package $identity has no installed-version baseline"
        elif ! version_satisfies "$version" gt "$FLOOR_INSTALLED"; then
            unsafe_reason="downloaded package $identity version $version is not newer than installed version $FLOOR_INSTALLED"
        fi
    else
        if [ -n "$FLOOR_INSTALLED" ] && ! version_satisfies "$version" ge "$FLOOR_INSTALLED"; then
            unsafe_reason="downloaded package $identity version $version is lower than installed version $FLOOR_INSTALLED"
        elif [ -n "$FLOOR_FIXED" ] && ! version_satisfies "$version" ge "$FLOOR_FIXED"; then
            unsafe_reason="downloaded package $identity version $version is lower than requested fixed version $FLOOR_FIXED"
        fi
    fi

    if [ -n "$unsafe_reason" ]; then
        echo "$unsafe_reason; refusing to install it" >&2
        record_package_version "$package" "$architecture" "$version"
        rm -f "$deb"
        unsafe_downloads=true
        if ! is_selected_package "$identity" && ! is_selected_package "$package"; then
            echo "unsafe package $identity is part of the resolved dependency closure; refusing to install an incomplete closure" >&2
            exit 1
        fi
        if [ "$IGNORE_ERRORS" != "true" ]; then exit 1; fi
    fi
done

if [ "$DPKG_INSTALLATION_MODE" = "external-full-status" ]; then
    echo "Package maintainer scripts and triggers are intentionally disabled for external full-status images because the original lifecycle database is unavailable." >&2
    original_status=$DOWNLOAD_DIR/original-status
    sanitize_root=$(mktemp -d)
    sanitized_dir=$DOWNLOAD_DIR/sanitized
    retained_dir=$DOWNLOAD_DIR/retained
    retained_archives_file=$DOWNLOAD_DIR/retained-archives
    retained_identities=$DOWNLOAD_DIR/retained-identities
    retained_roots=$DOWNLOAD_DIR/retained-roots
    retained_paths=$DOWNLOAD_DIR/retained-paths
    final_versions=$DOWNLOAD_DIR/final-versions
    transient_roots=$DOWNLOAD_DIR/transient-roots
    transient_backup=$DOWNLOAD_DIR/transient-backup
    transient_remove=$DOWNLOAD_DIR/transient-remove
    transient_restore=$DOWNLOAD_DIR/transient-restore
    transient_directories=$DOWNLOAD_DIR/transient-directories
    mkdir -p "$sanitized_dir" "$retained_dir" "$transient_backup"
    : > "$retained_archives_file"; : > "$retained_identities"; : > "$retained_roots"; : > "$retained_paths"; : > "$transient_roots"
    : > "$transient_remove"; : > "$transient_restore"; : > "$transient_directories"
    cp "$DPKG_ROOT/var/lib/dpkg/status" "$original_status"
    dpkg_root_real=$(readlink -f "$DPKG_ROOT")

    for deb in ./*.deb; do
        [ -f "$deb" ] || continue
        package=$("$DPKG_DEB_TOOL" -f "$deb" Package)
        architecture=$("$DPKG_DEB_TOOL" -f "$deb" Architecture)
        if { is_selected_package "$package:$architecture" || is_selected_package "$package"; } && is_lifecycle_package "$package"; then
            echo "targeted updates of lifecycle tooling package $package are not supported for external full-status images" >&2
            exit 1
        fi
        unpacked=$sanitize_root/$(basename "$deb" .deb)
        "$DPKG_DEB_TOOL" -R "$deb" "$unpacked"
        if is_lifecycle_package "$package"; then
            printf '%s\n' "$unpacked" >> "$transient_roots"
        else
            cp "$deb" "$retained_dir/$(basename "$deb")"
            printf '%s\n' "$unpacked" >> "$retained_roots"
            printf '%s\n' "$retained_dir/$(basename "$deb")" >> "$retained_archives_file"
            printf '%s:%s\n' "$package" "$architecture" >> "$retained_identities"
        fi
        rm -f "$unpacked/DEBIAN/config" "$unpacked/DEBIAN/preinst" "$unpacked/DEBIAN/postinst" \
            "$unpacked/DEBIAN/prerm" "$unpacked/DEBIAN/postrm" "$unpacked/DEBIAN/triggers"
        "$DPKG_DEB_TOOL" -b "$unpacked" "$sanitized_dir/$(basename "$deb")" >/dev/null
    done
    sort -u "$retained_identities" -o "$retained_identities"
    while IFS= read -r retained_root || [ -n "$retained_root" ]; do
        [ -n "$retained_root" ] || continue
        find "$retained_root" -mindepth 1 -path "$retained_root/DEBIAN" -prune -o -print | while IFS= read -r retained_path; do
            printf '%s\n' "${retained_path#"$retained_root"}" >> "$retained_paths"
        done
    done < "$retained_roots"
    sort -u "$retained_paths" -o "$retained_paths"

    awk -F'|' 'NF >= 2 { versions[$1] = $2 } END { for (identity in versions) print identity "|" versions[identity] }' \
        "$VERSION_FLOORS_FILE" > "$final_versions"
    while IFS= read -r retained_archive || [ -n "$retained_archive" ]; do
        [ -f "$retained_archive" ] || continue
        retained_package=$("$DPKG_DEB_TOOL" -f "$retained_archive" Package)
        retained_architecture=$("$DPKG_DEB_TOOL" -f "$retained_archive" Architecture)
        retained_version=$("$DPKG_DEB_TOOL" -f "$retained_archive" Version)
        printf '%s:%s|%s\n' "$retained_package" "$retained_architecture" "$retained_version" >> "$final_versions"
        retained_provides=$("$DPKG_DEB_TOOL" -f "$retained_archive" Provides 2>/dev/null || true)
        retained_provides_file=$(mktemp)
        printf '%s\n' "$retained_provides" | tr ',' '\n' > "$retained_provides_file"
        while IFS= read -r retained_provide || [ -n "$retained_provide" ]; do
            retained_capability=$(printf '%s\n' "$retained_provide" | sed -n 's/^[[:space:]]*\([a-z0-9][a-z0-9+.-]*\).*/\1/p')
            [ -n "$retained_capability" ] || continue
            retained_capability_version=$(printf '%s\n' "$retained_provide" | sed -n 's/.*([[:space:]]*=[[:space:]]*\([^)]*\)).*/\1/p')
            printf '%s:%s|%s\n' "$retained_capability" "$retained_architecture" "$retained_capability_version" >> "$final_versions"
        done < "$retained_provides_file"
        rm -f "$retained_provides_file"
    done < "$retained_archives_file"
    awk -F'|' '{ versions[$1] = $2 } END { for (identity in versions) print identity "|" versions[identity] }' \
        "$final_versions" | sort > "$final_versions.tmp"
    mv "$final_versions.tmp" "$final_versions"

    # Add virtual capabilities from unchanged installed providers. Providers
    # replaced by retained archives are excluded because their new Provides
    # fields were already recorded above.
    original_provides=$DOWNLOAD_DIR/original-provides
    awk '
        BEGIN { RS = ""; OFS = "|" }
        {
            package_name = ""; architecture = ""; provides = ""; active = 0
            count = split($0, lines, "\n")
            for (i = 1; i <= count; i++) {
                if (lines[i] ~ /^Package:[[:space:]]*/) {
                    package_name = lines[i]; sub(/^Package:[[:space:]]*/, "", package_name); active = 0
                } else if (lines[i] ~ /^Architecture:[[:space:]]*/) {
                    architecture = lines[i]; sub(/^Architecture:[[:space:]]*/, "", architecture); active = 0
                } else if (lines[i] ~ /^Provides:[[:space:]]*/) {
                    line = lines[i]; sub(/^Provides:[[:space:]]*/, "", line); provides = line; active = 1
                } else if (lines[i] ~ /^[[:space:]]/ && active) {
                    provides = provides " " lines[i]
                } else if (lines[i] !~ /^[[:space:]]/) {
                    active = 0
                }
            }
            if (package_name != "" && provides != "") print package_name ":" architecture, architecture, provides
        }
    ' "$original_status" > "$original_provides"
    while IFS='|' read -r provider_identity provider_architecture provider_values provider_extra || [ -n "${provider_identity}${provider_architecture}${provider_values}${provider_extra}" ]; do
        [ -n "$provider_identity" ] || continue
        if grep -Fxq "$provider_identity" "$retained_identities"; then
            continue
        fi
        provider_items=$(mktemp)
        printf '%s\n' "$provider_values" | tr ',' '\n' > "$provider_items"
        while IFS= read -r provider_item || [ -n "$provider_item" ]; do
            capability=$(printf '%s\n' "$provider_item" | sed -n 's/^[[:space:]]*\([a-z0-9][a-z0-9+.-]*\).*/\1/p')
            [ -n "$capability" ] || continue
            capability_version=$(printf '%s\n' "$provider_item" | sed -n 's/.*([[:space:]]*=[[:space:]]*\([^)]*\)).*/\1/p')
            printf '%s:%s|%s\n' "$capability" "$provider_architecture" "$capability_version" >> "$final_versions"
        done < "$provider_items"
        rm -f "$provider_items"
    done < "$original_provides"
    sort -u "$final_versions" -o "$final_versions"

    while IFS= read -r retained_archive || [ -n "$retained_archive" ]; do
        [ -f "$retained_archive" ] || continue
        validate_final_dependencies "$retained_archive"
    done < "$retained_archives_file"

    while IFS= read -r transient_root || [ -n "$transient_root" ]; do
        [ -n "$transient_root" ] || continue
        find "$transient_root" -mindepth 1 -path "$transient_root/DEBIAN" -prune -o -print | while IFS= read -r source_path; do
            relative_path=${source_path#"$transient_root"}
            if grep -Fxq "$relative_path" "$retained_paths"; then
                continue
            fi
            target_path=$DPKG_ROOT$relative_path
            assert_target_path_safe "$target_path"
            if [ -d "$source_path" ] && [ ! -L "$source_path" ]; then
                if [ ! -e "$target_path" ] && [ ! -L "$target_path" ]; then
                    printf 'd|%s\n' "$relative_path" >> "$transient_remove"
                elif [ -L "$target_path" ]; then
                    resolved=$(readlink -f "$target_path")
                    case "$resolved" in "$dpkg_root_real"/*) ;; *) exit 1 ;; esac
                    backup=$transient_backup$relative_path
                    mkdir -p "$(dirname "$backup")"; cp -a "$target_path" "$backup"
                    printf '%s\n' "$relative_path" >> "$transient_restore"
                elif [ -d "$target_path" ]; then
                    metadata=$("$BUSYBOX" stat -c '%a|%u|%g' "$target_path")
                    printf '%s|%s\n' "$relative_path" "$metadata" >> "$transient_directories"
                else
                    echo "temporary lifecycle path conflicts with target: $relative_path" >&2; exit 1
                fi
            elif [ -e "$target_path" ] || [ -L "$target_path" ]; then
                backup=$transient_backup$relative_path
                mkdir -p "$(dirname "$backup")"; cp -a "$target_path" "$backup"
                printf '%s\n' "$relative_path" >> "$transient_restore"
            else
                printf 'f|%s\n' "$relative_path" >> "$transient_remove"
            fi
        done
    done < "$transient_roots"
    sort -u "$transient_remove" -o "$transient_remove"
    sort -u "$transient_restore" -o "$transient_restore"
    sort -u "$transient_directories" -o "$transient_directories"

    # The Go preflight rejects targets with an existing dpkg info directory,
    # and the temporary database is reconstructed with empty lifecycle state.
    # Fail closed if any input hook or trigger nevertheless reached this stage.
    if find "$DPKG_ROOT/var/lib/dpkg/info" "$DPKG_ROOT/var/lib/dpkg/triggers" -mindepth 1 -print -quit | grep -q .; then
        echo "external full-status lifecycle metadata must be empty before script-free installation" >&2
        exit 1
    fi

    set -- "$sanitized_dir"/*.deb
    if [ ! -f "$1" ]; then set --; fi
    if [ "$#" -gt 0 ]; then
        "$DPKG_TOOL" --root="$DPKG_ROOT" --admindir="$DPKG_ROOT/var/lib/dpkg" --force-all --force-confold --install "$@"
    fi

    sorted_remove=$DOWNLOAD_DIR/transient-remove-sorted
    awk -F'|' '{ print length($2) "|" $0 }' "$transient_remove" | sort -t'|' -k1,1nr | cut -d'|' -f2- > "$sorted_remove"
    while IFS='|' read -r kind relative || [ -n "${kind}${relative}" ]; do
        [ -n "$relative" ] || continue
        target=$DPKG_ROOT$relative; assert_target_path_safe "$target"
        case "$kind" in f) rm -f "$target" ;; d) rmdir "$target" 2>/dev/null || true ;; *) exit 1 ;; esac
    done < "$sorted_remove"
    while IFS= read -r relative || [ -n "$relative" ]; do
        [ -n "$relative" ] || continue
        target=$DPKG_ROOT$relative; backup=$transient_backup$relative; assert_target_path_safe "$target"
        rm -f "$target"; mkdir -p "$(dirname "$target")"; cp -a "$backup" "$target"
    done < "$transient_restore"
    while IFS='|' read -r relative mode uid gid extra || [ -n "${relative}${mode}${uid}${gid}${extra}" ]; do
        [ -n "$relative" ] || continue
        target=$DPKG_ROOT$relative; assert_target_path_safe "$target"
        if [ -d "$target" ] && [ ! -L "$target" ]; then chmod "$mode" "$target"; chown "$uid:$gid" "$target"; fi
    done < "$transient_directories"

    filter_status_to_final_inventory
    rm -rf "$sanitize_root"
else
    set -- ./*.deb
    if [ ! -f "$1" ]; then set --; fi
    if [ "$#" -gt 0 ]; then
        "$DPKG_TOOL" --root="$DPKG_ROOT" --admindir="$DPKG_ROOT/var/lib/dpkg" --force-all --force-confold --install "$@"
        "$DPKG_TOOL" --root="$DPKG_ROOT" --configure -a
    fi
fi

DPKG_ROOT="$DPKG_ROOT" /bin/sh "$FINALIZE_DPKG_STATUS_SCRIPT"

if [ "$DPKG_INSTALLATION_MODE" = "external-full-status" ]; then
    while IFS= read -r deb || [ -n "$deb" ]; do
        [ -f "$deb" ] || continue
        package=$("$DPKG_DEB_TOOL" -f "$deb" Package)
        architecture=$("$DPKG_DEB_TOOL" -f "$deb" Architecture)
        version=$("$DPKG_DEB_TOOL" -f "$deb" Version)
        record_package_version "$package" "$architecture" "$version"
    done < "$retained_archives_file"
else
    for deb in "$@"; do
        [ -f "$deb" ] || continue
        package=$("$DPKG_DEB_TOOL" -f "$deb" Package)
        architecture=$("$DPKG_DEB_TOOL" -f "$deb" Architecture 2>/dev/null || true)
        version=$("$DPKG_DEB_TOOL" -f "$deb" Version)
        record_package_version "$package" "$architecture" "$version"
    done
fi

if [ "$unsafe_downloads" = "true" ]; then
    echo "one or more unsafe package versions were skipped" >&2
fi
