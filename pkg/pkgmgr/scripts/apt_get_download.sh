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

is_lifecycle_package() {
    wanted_package=$1
    for lifecycle_package in $LIFECYCLE_PACKAGES; do
        if [ "$lifecycle_package" = "$wanted_package" ]; then
            return 0
        fi
    done
    return 1
}

case "$UPDATE_ALL" in
    true|false) ;;
    *)
        echo "invalid UPDATE_ALL value: $UPDATE_ALL" >&2
        exit 1
        ;;
esac

mkdir -p "$DOWNLOAD_DIR"
cd "$DOWNLOAD_DIR"

set --
while IFS= read -r package || [ -n "$package" ]; do
    [ -n "$package" ] || continue
    set -- "$@" "$package"
done < "$PACKAGES_FILE"

if [ "$#" -eq 0 ]; then
    echo "no packages were selected for download" >&2
    exit 1
fi

# Reject direct lifecycle-package selections before writing to the mounted
# target root. The downloaded-archive check below remains as defense in depth.
if [ "$DPKG_INSTALLATION_MODE" = "external-full-status" ]; then
    for selected_identity in "$@"; do
        selected_package=${selected_identity%%:*}
        if is_lifecycle_package "$selected_package"; then
            echo "external full-status images cannot safely update lifecycle package $selected_package because the required dpkg lifecycle metadata is unavailable" >&2
            exit 1
        fi
    done
fi

: > "$RESULT_MANIFEST"

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

package_identity_matches() {
    pim_left=$1
    pim_right=$2
    [ "$pim_left" = "$pim_right" ] && return 0

    pim_left_name=${pim_left%%:*}
    pim_right_name=${pim_right%%:*}
    [ "$pim_left_name" = "$pim_right_name" ] || return 1
    case "$pim_left" in *:*) pim_left_architecture=${pim_left#*:} ;; *) return 0 ;; esac
    case "$pim_right" in *:*) pim_right_architecture=${pim_right#*:} ;; *) return 0 ;; esac
    if { [ "$pim_left_architecture" = all ] && [ "$pim_right_architecture" = "$TARGET_DPKG_ARCH" ]; } ||
        { [ "$pim_right_architecture" = all ] && [ "$pim_left_architecture" = "$TARGET_DPKG_ARCH" ]; }; then
        return 0
    fi
    return 1
}

lookup_version_floor() {
    wanted_package=$1
    FLOOR_INSTALLED=""
    FLOOR_FIXED=""
    while IFS='|' read -r floor_package installed_version fixed_version extra || [ -n "${floor_package}${installed_version}${fixed_version}${extra}" ]; do
        if [ -z "$floor_package" ] || [ -n "$extra" ]; then
            echo "invalid package version floor record in $VERSION_FLOORS_FILE" >&2
            exit 1
        fi
        if package_identity_matches "$floor_package" "$wanted_package"; then
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
        if package_identity_matches "$selected_package" "$wanted_package"; then
            return 0
        fi
    done < "$PACKAGES_FILE"
    return 1
}

normalize_dependency_text() {
    printf '%s\n' "$1" | awk '{$1=$1; print}'
}

provided_capability_record() {
    pci_provide=$1
    pci_provider_architecture=$2
    pci_package=$(printf '%s\n' "$pci_provide" | sed -n 's/^[[:space:]]*\([a-z0-9][a-z0-9+.-]*\).*/\1/p')
    [ -n "$pci_package" ] || return 1
    pci_qualifier=$(printf '%s\n' "$pci_provide" | sed -n 's/^[[:space:]]*[a-z0-9][a-z0-9+.-]*:\([a-z0-9][a-z0-9-]*\).*/\1/p')
    case "$pci_qualifier" in
        '')
            pci_architecture=$pci_provider_architecture
            if [ -z "$pci_architecture" ] || [ "$pci_architecture" = all ]; then
                pci_architecture=$TARGET_DPKG_ARCH
            fi
            ;;
        native)
            pci_architecture=$TARGET_DPKG_ARCH
            ;;
        any)
            pci_architecture=$pci_provider_architecture
            if [ -z "$pci_architecture" ] || [ "$pci_architecture" = all ]; then
                pci_architecture=$TARGET_DPKG_ARCH
            fi
            ;;
        *)
            pci_architecture=$pci_qualifier
            ;;
    esac
    if [ -z "$pci_qualifier" ]; then
        pci_qualifier=unqualified
    fi
    printf '%s:%s|%s\n' "$pci_package" "$pci_architecture" "$pci_qualifier"
}

original_dependency_clause_present() {
    odcp_source=$1
    odcp_source_architecture=$2
    odcp_clause=$(normalize_dependency_text "$3")
    awk -v source="$odcp_source" -v source_architecture="$odcp_source_architecture" -v target_architecture="$TARGET_DPKG_ARCH" '
        BEGIN { RS = "" }
        {
            package_name = ""; architecture = ""
            count = split($0, lines, "\n")
            for (i = 1; i <= count; i++) {
                if (lines[i] ~ /^Package:[[:space:]]*/) {
                    package_name = lines[i]
                    sub(/^Package:[[:space:]]*/, "", package_name)
                } else if (lines[i] ~ /^Architecture:[[:space:]]*/) {
                    architecture = lines[i]
                    sub(/^Architecture:[[:space:]]*/, "", architecture)
                }
            }
            if (architecture == "") architecture = target_architecture
            if (package_name != source || architecture != source_architecture) next

            active = 0
            for (i = 1; i <= count; i++) {
                if (lines[i] ~ /^(Depends|Pre-Depends):[[:space:]]*/) {
                    relation = lines[i]
                    sub(/^(Depends|Pre-Depends):[[:space:]]*/, "", relation)
                    print relation
                    active = 1
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
    fas_source_architecture=$2
    fas_excluded_provider=${3:-}
    fas_versions_file=${4:-$final_versions}
    fas_relationship_mode=${5:-positive}
    case "$fas_relationship_mode" in
        positive|negative) ;;
        *) return 1 ;;
    esac

    fas_package=$(printf '%s\n' "$fas_alternative" | sed -n 's/^[[:space:]]*\([a-z0-9][a-z0-9+.-]*\).*/\1/p')
    [ -n "$fas_package" ] || return 1
    fas_qualifier=$(printf '%s\n' "$fas_alternative" | sed -n 's/^[[:space:]]*[a-z0-9][a-z0-9+.-]*:\([a-z0-9][a-z0-9-]*\).*/\1/p')
    if [ "$fas_relationship_mode" = negative ]; then
        case "$fas_qualifier" in
            ''|any) fas_required_architecture=any ;;
            native) fas_required_architecture=$TARGET_DPKG_ARCH ;;
            *) fas_required_architecture=$fas_qualifier ;;
        esac
    else
        case "$fas_qualifier" in
            any)
                fas_required_architecture=any
                ;;
            native)
                fas_required_architecture=$TARGET_DPKG_ARCH
                ;;
            '')
                fas_required_architecture=$fas_source_architecture
                if [ -z "$fas_required_architecture" ] || [ "$fas_required_architecture" = all ]; then
                    fas_required_architecture=$TARGET_DPKG_ARCH
                fi
                ;;
            *)
                fas_required_architecture=$fas_qualifier
                ;;
        esac
    fi

    fas_operator=""
    fas_required=""
    case "$fas_alternative" in
        *"("*")"*)
            fas_constraint=${fas_alternative#*(}
            fas_constraint=${fas_constraint%%)*}
            fas_constraint=$(normalize_dependency_text "$fas_constraint")
            case "$fas_constraint" in
                '<<'*) fas_operator=lt; fas_required=${fas_constraint#<<} ;;
                '<='*) fas_operator=le; fas_required=${fas_constraint#<=} ;;
                '>='*) fas_operator=ge; fas_required=${fas_constraint#>=} ;;
                '>>'*) fas_operator=gt; fas_required=${fas_constraint#>>} ;;
                '='*) fas_operator=eq; fas_required=${fas_constraint#=} ;;
                *) return 1 ;;
            esac
            fas_required=$(normalize_dependency_text "$fas_required")
            [ -n "$fas_required" ] || return 1
            case "$fas_required" in *" "*) return 1 ;; esac
            ;;
    esac

    while IFS='|' read -r fas_identity fas_version fas_multiarch fas_provider_identity fas_candidate_kind fas_extra || [ -n "${fas_identity}${fas_version}${fas_multiarch}${fas_provider_identity}${fas_candidate_kind}${fas_extra}" ]; do
        [ -z "$fas_extra" ] || continue
        if [ -n "$fas_excluded_provider" ] && [ "$fas_provider_identity" = "$fas_excluded_provider" ]; then
            continue
        fi
        fas_identity_package=${fas_identity%%:*}
        [ "$fas_identity_package" = "$fas_package" ] || continue
        fas_identity_architecture=${fas_identity#*:}
        if [ "$fas_identity_architecture" = "$fas_identity" ] || [ "$fas_identity_architecture" = all ]; then
            fas_identity_architecture=$TARGET_DPKG_ARCH
        fi

        if [ "$fas_relationship_mode" = negative ]; then
            if [ "$fas_required_architecture" != any ] && [ "$fas_identity_architecture" != "$fas_required_architecture" ]; then
                continue
            fi
        else
            case "$fas_qualifier" in
                any)
                    case "$fas_candidate_kind" in
                        any|package|unqualified) [ "$fas_multiarch" = allowed ] || continue ;;
                        *) continue ;;
                    esac
                    ;;
                native)
                    if [ "$fas_identity_architecture" != "$TARGET_DPKG_ARCH" ]; then
                        continue
                    fi
                    ;;
                '')
                    if [ "$fas_identity_architecture" != "$fas_required_architecture" ] && \
                        [ "$fas_multiarch" != foreign ]; then
                        continue
                    fi
                    ;;
                *)
                    if [ "$fas_identity_architecture" != "$fas_required_architecture" ]; then
                        continue
                    fi
                    ;;
            esac
        fi

        if [ -z "$fas_operator" ]; then
            return 0
        fi
        if [ -n "$fas_version" ] && "$DPKG_TOOL" --compare-versions "$fas_version" "$fas_operator" "$fas_required"; then
            return 0
        fi
    done < "$fas_versions_file"
    return 1
}

original_dependency_clause_was_unresolved() {
    odcu_source=$1
    odcu_source_architecture=$2
    odcu_clause=$3
    original_dependency_clause_present "$odcu_source" "$odcu_source_architecture" "$odcu_clause" || return 1

    odcu_satisfied=false
    odcu_alternatives=$(mktemp)
    printf '%s\n' "$odcu_clause" | tr '|' '\n' > "$odcu_alternatives"
    while IFS= read -r odcu_alternative || [ -n "$odcu_alternative" ]; do
        if final_alternative_satisfied "$odcu_alternative" "$odcu_source_architecture" "" "$original_versions" positive; then
            odcu_satisfied=true
            break
        fi
    done < "$odcu_alternatives"
    rm -f "$odcu_alternatives"
    [ "$odcu_satisfied" != true ]
}

validate_final_dependency_value() {
    vfd_source=$1
    vfd_source_architecture=$2
    vfd_value=$3
    [ -n "$vfd_value" ] || return 0

    vfd_error=""
    vfd_clauses=$(mktemp)
    printf '%s\n' "$vfd_value" | tr ',' '\n' > "$vfd_clauses"
    while IFS= read -r vfd_clause || [ -n "$vfd_clause" ]; do
        [ -n "$vfd_clause" ] || continue
        vfd_safe=false
        vfd_alternatives=$(mktemp)
        printf '%s\n' "$vfd_clause" | tr '|' '\n' > "$vfd_alternatives"
        while IFS= read -r vfd_alternative || [ -n "$vfd_alternative" ]; do
            vfd_dependency=$(printf '%s\n' "$vfd_alternative" | sed -n 's/^[[:space:]]*\([a-z0-9][a-z0-9+.-]*\).*/\1/p')
            [ -n "$vfd_dependency" ] || continue
            if final_alternative_satisfied "$vfd_alternative" "$vfd_source_architecture" "" "$final_versions" positive; then
                vfd_safe=true
                break
            fi
        done < "$vfd_alternatives"
        rm -f "$vfd_alternatives"
        # Full-status Chiseled inventories can intentionally retain incomplete
        # pre-existing dependency relationships. Grandfather a clause only when
        # the same source architecture already had that unresolved clause.
        if [ "$vfd_safe" != true ] && original_dependency_clause_was_unresolved "$vfd_source" "$vfd_source_architecture" "$vfd_clause"; then
            vfd_safe=true
        fi
        if [ "$vfd_safe" != true ]; then
            vfd_error="package $vfd_source has unresolved final dependency clause '$vfd_clause'"
            break
        fi
    done < "$vfd_clauses"
    rm -f "$vfd_clauses"
    if [ -n "$vfd_error" ]; then
        echo "$vfd_error" >&2
        return 1
    fi
}

validate_final_dependencies() {
    vfd_archive=$1
    vfd_archive_source=$("$DPKG_DEB_TOOL" -f "$vfd_archive" Package)
    vfd_archive_architecture=$("$DPKG_DEB_TOOL" -f "$vfd_archive" Architecture)
    for vfd_archive_field in Depends Pre-Depends; do
        vfd_archive_value=$("$DPKG_DEB_TOOL" -f "$vfd_archive" "$vfd_archive_field" 2>/dev/null || true)
        validate_final_dependency_value "$vfd_archive_source" "$vfd_archive_architecture" "$vfd_archive_value"
    done
}

validate_final_negative_relationship_value() {
    vfn_source=$1
    vfn_source_architecture=$2
    vfn_field=$3
    vfn_value=$4
    [ -n "$vfn_value" ] || return 0

    vfn_source_identity=$vfn_source:$vfn_source_architecture
    vfn_error=""
    vfn_clauses=$(mktemp)
    printf '%s\n' "$vfn_value" | tr ',' '\n' > "$vfn_clauses"
    while IFS= read -r vfn_clause || [ -n "$vfn_clause" ]; do
        [ -n "$vfn_clause" ] || continue
        vfn_alternatives=$(mktemp)
        printf '%s\n' "$vfn_clause" | tr '|' '\n' > "$vfn_alternatives"
        while IFS= read -r vfn_alternative || [ -n "$vfn_alternative" ]; do
            if final_alternative_satisfied "$vfn_alternative" "$vfn_source_architecture" "$vfn_source_identity" "$final_versions" negative; then
                vfn_error="package $vfn_source has final $vfn_field relationship '$vfn_clause' that matches the installed package inventory"
                break
            fi
        done < "$vfn_alternatives"
        rm -f "$vfn_alternatives"
        [ -z "$vfn_error" ] || break
    done < "$vfn_clauses"
    rm -f "$vfn_clauses"
    if [ -n "$vfn_error" ]; then
        echo "$vfn_error" >&2
        return 1
    fi
}

validate_final_negative_relationships() {
    vfn_archive=$1
    vfn_archive_source=$("$DPKG_DEB_TOOL" -f "$vfn_archive" Package)
    vfn_archive_architecture=$("$DPKG_DEB_TOOL" -f "$vfn_archive" Architecture)
    for vfn_archive_field in Breaks Conflicts; do
        vfn_archive_value=$("$DPKG_DEB_TOOL" -f "$vfn_archive" "$vfn_archive_field" 2>/dev/null || true)
        validate_final_negative_relationship_value "$vfn_archive_source" "$vfn_archive_architecture" "$vfn_archive_field" "$vfn_archive_value"
    done
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

    awk -v identities_file="$keep_identities" -v lifecycle_file="$lifecycle_names" -v retained_file="$retained_identities" '
        BEGIN {
            while ((getline identity < identities_file) > 0) keep[identity] = 1
            close(identities_file)
            while ((getline name < lifecycle_file) > 0) lifecycle[name] = 1
            close(lifecycle_file)
            while ((getline identity < retained_file) > 0) retained[identity] = 1
            close(retained_file)
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
            identity = package_name ":" (architecture == "" ? ENVIRON["TARGET_DPKG_ARCH"] : architecture)
            if (lifecycle[package_name] && !retained[identity]) next
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
    retained_replacement_identities=$DOWNLOAD_DIR/retained-replacement-identities
    retained_roots=$DOWNLOAD_DIR/retained-roots
    retained_paths=$DOWNLOAD_DIR/retained-paths
    final_versions=$DOWNLOAD_DIR/final-versions
    original_versions=$DOWNLOAD_DIR/original-versions
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
            echo "external full-status images cannot safely update lifecycle package $package because the required dpkg lifecycle metadata is unavailable" >&2
            exit 1
        fi
        unpacked=$sanitize_root/$(basename "$deb" .deb)
        "$DPKG_DEB_TOOL" -R "$deb" "$unpacked"
        if is_lifecycle_package "$package"; then
            # Dependency-closure lifecycle packages are temporary resolver
            # helpers only. Their scripts are stripped, every payload path is
            # restored or removed after dpkg runs, and the original status
            # paragraph is reinstated instead of retaining this archive.
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
    awk -F':' -v target_architecture="$TARGET_DPKG_ARCH" '
        NF == 2 {
            print $0
            if ($2 == "all") print $1 ":" target_architecture
            else if ($2 == target_architecture) print $1 ":all"
        }
    ' "$retained_identities" | sort -u > "$retained_replacement_identities"
    while IFS= read -r retained_root || [ -n "$retained_root" ]; do
        [ -n "$retained_root" ] || continue
        find "$retained_root" -mindepth 1 -path "$retained_root/DEBIAN" -prune -o -print | while IFS= read -r retained_path; do
            printf '%s\n' "${retained_path#"$retained_root"}" >> "$retained_paths"
        done
    done < "$retained_roots"
    sort -u "$retained_paths" -o "$retained_paths"

    original_multiarch=$DOWNLOAD_DIR/original-multiarch
    awk '
        BEGIN { RS = ""; OFS = "|" }
        {
            package_name = ""; architecture = ""; multiarch = ""
            count = split($0, lines, "\n")
            for (i = 1; i <= count; i++) {
                if (lines[i] ~ /^Package:[[:space:]]*/) {
                    package_name = lines[i]; sub(/^Package:[[:space:]]*/, "", package_name)
                } else if (lines[i] ~ /^Architecture:[[:space:]]*/) {
                    architecture = lines[i]; sub(/^Architecture:[[:space:]]*/, "", architecture)
                } else if (lines[i] ~ /^Multi-Arch:[[:space:]]*/) {
                    multiarch = lines[i]; sub(/^Multi-Arch:[[:space:]]*/, "", multiarch)
                }
            }
            if (package_name != "") {
                if (architecture == "") architecture = ENVIRON["TARGET_DPKG_ARCH"]
                print package_name ":" architecture, multiarch
            }
        }
    ' "$original_status" > "$original_multiarch"

    awk -F'|' -v metadata_file="$original_multiarch" '
        BEGIN {
            while ((getline line < metadata_file) > 0) {
                split(line, fields, "|")
                multiarch[fields[1]] = fields[2]
            }
            close(metadata_file)
            OFS = "|"
        }
        NF >= 2 && $1 != "" {
            identity = $1
            if (index(identity, ":") == 0) identity = identity ":" ENVIRON["TARGET_DPKG_ARCH"]
            versions[identity] = $2
        }
        END {
            for (identity in versions) print identity, versions[identity], multiarch[identity], identity, "package"
        }
    ' "$VERSION_FLOORS_FILE" > "$final_versions"
    cp "$final_versions" "$original_versions"
    awk -F'|' -v replacements_file="$retained_replacement_identities" '
        BEGIN {
            while ((getline identity < replacements_file) > 0) replacements[identity] = 1
            close(replacements_file)
        }
        !($1 in replacements) { print }
    ' "$final_versions" > "$final_versions.tmp"
    mv "$final_versions.tmp" "$final_versions"
    while IFS= read -r retained_archive || [ -n "$retained_archive" ]; do
        [ -f "$retained_archive" ] || continue
        retained_package=$("$DPKG_DEB_TOOL" -f "$retained_archive" Package)
        retained_architecture=$("$DPKG_DEB_TOOL" -f "$retained_archive" Architecture)
        retained_version=$("$DPKG_DEB_TOOL" -f "$retained_archive" Version)
        retained_multiarch=$("$DPKG_DEB_TOOL" -f "$retained_archive" Multi-Arch 2>/dev/null || true)
        retained_identity=$retained_package:$retained_architecture
        printf '%s|%s|%s|%s|package\n' "$retained_identity" "$retained_version" "$retained_multiarch" "$retained_identity" >> "$final_versions"
        retained_provides=$("$DPKG_DEB_TOOL" -f "$retained_archive" Provides 2>/dev/null || true)
        retained_provides_file=$(mktemp)
        printf '%s\n' "$retained_provides" | tr ',' '\n' > "$retained_provides_file"
        while IFS= read -r retained_provide || [ -n "$retained_provide" ]; do
            retained_capability_record=$(provided_capability_record "$retained_provide" "$retained_architecture") || continue
            retained_capability_identity=${retained_capability_record%%|*}
            retained_capability_kind=${retained_capability_record#*|}
            retained_capability_version=$(printf '%s\n' "$retained_provide" | sed -n 's/.*([[:space:]]*=[[:space:]]*\([^)]*\)).*/\1/p')
            printf '%s|%s|%s|%s|%s\n' "$retained_capability_identity" "$retained_capability_version" "$retained_multiarch" "$retained_identity" "$retained_capability_kind" >> "$final_versions"
        done < "$retained_provides_file"
        rm -f "$retained_provides_file"
    done < "$retained_archives_file"
    awk -F'|' '
        NF >= 3 {
            provider = $4 == "" ? $1 : $4
            kind = $5 == "" ? "package" : $5
            key = $1 SUBSEP provider SUBSEP kind
            identities[key] = $1
            versions[key] = $2
            multiarch[key] = $3
            providers[key] = provider
            kinds[key] = kind
        }
        END {
            for (key in versions) print identities[key] "|" versions[key] "|" multiarch[key] "|" providers[key] "|" kinds[key]
        }
    ' "$final_versions" | sort > "$final_versions.tmp"
    mv "$final_versions.tmp" "$final_versions"

    # Add virtual capabilities from unchanged installed providers. Providers
    # replaced by retained archives are excluded because their new Provides
    # fields were already recorded above.
    original_provides=$DOWNLOAD_DIR/original-provides
    awk '
        BEGIN { RS = ""; OFS = "|" }
        {
            package_name = ""; architecture = ""; multiarch = ""; status_value = ""; provides = ""; active = 0
            count = split($0, lines, "\n")
            for (i = 1; i <= count; i++) {
                if (lines[i] ~ /^Package:[[:space:]]*/) {
                    package_name = lines[i]; sub(/^Package:[[:space:]]*/, "", package_name); active = 0
                } else if (lines[i] ~ /^Architecture:[[:space:]]*/) {
                    architecture = lines[i]; sub(/^Architecture:[[:space:]]*/, "", architecture); active = 0
                } else if (lines[i] ~ /^Multi-Arch:[[:space:]]*/) {
                    multiarch = lines[i]; sub(/^Multi-Arch:[[:space:]]*/, "", multiarch); active = 0
                } else if (lines[i] ~ /^Status:[[:space:]]*/) {
                    status_value = lines[i]; sub(/^Status:[[:space:]]*/, "", status_value); active = 0
                } else if (lines[i] ~ /^Provides:[[:space:]]*/) {
                    line = lines[i]; sub(/^Provides:[[:space:]]*/, "", line); provides = line; active = 1
                } else if (lines[i] ~ /^[[:space:]]/ && active) {
                    provides = provides " " lines[i]
                } else if (lines[i] !~ /^[[:space:]]/) {
                    active = 0
                }
            }
            installed = status_value == ""
            if (status_value != "") {
                split(status_value, status_fields, /[[:space:]]+/)
                installed = status_fields[3] == "installed"
            }
            if (architecture == "") architecture = ENVIRON["TARGET_DPKG_ARCH"]
            if (installed && package_name != "" && provides != "") print package_name ":" architecture, architecture, multiarch, provides
        }
    ' "$original_status" > "$original_provides"
    while IFS='|' read -r provider_identity provider_architecture provider_multiarch provider_values provider_extra || [ -n "${provider_identity}${provider_architecture}${provider_multiarch}${provider_values}${provider_extra}" ]; do
        [ -n "$provider_identity" ] || continue
        provider_replaced=false
        if grep -Fxq "$provider_identity" "$retained_replacement_identities"; then
            provider_replaced=true
        fi
        provider_items=$(mktemp)
        printf '%s\n' "$provider_values" | tr ',' '\n' > "$provider_items"
        while IFS= read -r provider_item || [ -n "$provider_item" ]; do
            capability_record=$(provided_capability_record "$provider_item" "$provider_architecture") || continue
            capability_identity=${capability_record%%|*}
            capability_kind=${capability_record#*|}
            capability_version=$(printf '%s\n' "$provider_item" | sed -n 's/.*([[:space:]]*=[[:space:]]*\([^)]*\)).*/\1/p')
            capability_line=$(printf '%s|%s|%s|%s|%s' "$capability_identity" "$capability_version" "$provider_multiarch" "$provider_identity" "$capability_kind")
            printf '%s\n' "$capability_line" >> "$original_versions"
            if [ "$provider_replaced" != true ]; then
                printf '%s\n' "$capability_line" >> "$final_versions"
            fi
        done < "$provider_items"
        rm -f "$provider_items"
    done < "$original_provides"
    sort -u "$original_versions" -o "$original_versions"
    sort -u "$final_versions" -o "$final_versions"

    original_relationships=$DOWNLOAD_DIR/original-relationships
    awk -v retained_file="$retained_replacement_identities" '
        BEGIN {
            while ((getline identity < retained_file) > 0) retained[identity] = 1
            close(retained_file)
            RS = ""; OFS = "\t"
        }
        {
            package_name = ""; architecture = ""; status_value = ""
            depends_value = ""; predepends_value = ""; breaks_value = ""; conflicts_value = ""; active = ""
            count = split($0, lines, "\n")
            for (i = 1; i <= count; i++) {
                if (lines[i] ~ /^Package:[[:space:]]*/) {
                    package_name = lines[i]; sub(/^Package:[[:space:]]*/, "", package_name); active = ""
                } else if (lines[i] ~ /^Architecture:[[:space:]]*/) {
                    architecture = lines[i]; sub(/^Architecture:[[:space:]]*/, "", architecture); active = ""
                } else if (lines[i] ~ /^Status:[[:space:]]*/) {
                    status_value = lines[i]; sub(/^Status:[[:space:]]*/, "", status_value); active = ""
                } else if (lines[i] ~ /^Depends:[[:space:]]*/) {
                    depends_value = lines[i]; sub(/^Depends:[[:space:]]*/, "", depends_value); active = "depends"
                } else if (lines[i] ~ /^Pre-Depends:[[:space:]]*/) {
                    predepends_value = lines[i]; sub(/^Pre-Depends:[[:space:]]*/, "", predepends_value); active = "predepends"
                } else if (lines[i] ~ /^Breaks:[[:space:]]*/) {
                    breaks_value = lines[i]; sub(/^Breaks:[[:space:]]*/, "", breaks_value); active = "breaks"
                } else if (lines[i] ~ /^Conflicts:[[:space:]]*/) {
                    conflicts_value = lines[i]; sub(/^Conflicts:[[:space:]]*/, "", conflicts_value); active = "conflicts"
                } else if (lines[i] ~ /^[[:space:]]/ && active == "depends") {
                    depends_value = depends_value " " lines[i]
                } else if (lines[i] ~ /^[[:space:]]/ && active == "predepends") {
                    predepends_value = predepends_value " " lines[i]
                } else if (lines[i] ~ /^[[:space:]]/ && active == "breaks") {
                    breaks_value = breaks_value " " lines[i]
                } else if (lines[i] ~ /^[[:space:]]/ && active == "conflicts") {
                    conflicts_value = conflicts_value " " lines[i]
                } else if (lines[i] !~ /^[[:space:]]/) {
                    active = ""
                }
            }
            installed = status_value == ""
            if (status_value != "") {
                split(status_value, status_fields, /[[:space:]]+/)
                installed = status_fields[3] == "installed"
            }
            if (architecture == "") architecture = ENVIRON["TARGET_DPKG_ARCH"]
            identity = package_name ":" architecture
            if (!installed || package_name == "" || retained[identity]) next
            gsub(/[[:space:]]+/, " ", depends_value)
            gsub(/[[:space:]]+/, " ", predepends_value)
            gsub(/[[:space:]]+/, " ", breaks_value)
            gsub(/[[:space:]]+/, " ", conflicts_value)
            if (depends_value != "") print identity, "Depends", depends_value
            if (predepends_value != "") print identity, "Pre-Depends", predepends_value
            if (breaks_value != "") print identity, "Breaks", breaks_value
            if (conflicts_value != "") print identity, "Conflicts", conflicts_value
        }
    ' "$original_status" > "$original_relationships"

    relationship_tab=$(printf '\t')
    while IFS="$relationship_tab" read -r relationship_identity relationship_field relationship_value || [ -n "${relationship_identity}${relationship_field}${relationship_value}" ]; do
        [ -n "$relationship_identity" ] || continue
        relationship_source=${relationship_identity%%:*}
        relationship_architecture=${relationship_identity#*:}
        case "$relationship_field" in
            Depends|Pre-Depends)
                validate_final_dependency_value "$relationship_source" "$relationship_architecture" "$relationship_value"
                ;;
            Breaks|Conflicts)
                validate_final_negative_relationship_value "$relationship_source" "$relationship_architecture" "$relationship_field" "$relationship_value"
                ;;
            *)
                echo "unsupported relationship field $relationship_field" >&2
                exit 1
                ;;
        esac
    done < "$original_relationships"

    while IFS= read -r retained_archive || [ -n "$retained_archive" ]; do
        [ -f "$retained_archive" ] || continue
        validate_final_dependencies "$retained_archive"
        validate_final_negative_relationships "$retained_archive"
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
