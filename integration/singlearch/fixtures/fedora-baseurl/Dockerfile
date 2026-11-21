# check=skip=InvalidDefaultArgInFrom
# Copies the pinned Fedora 45 image with its repositories pointed at one fixed
# server instead of the Fedora metalink, so dnf doesn't depend on which
# community mirror, possibly stale or mid-sync, the metalink hands out. Only the
# fedora and updates repositories stay enabled. Fedora 45 keeps its repository
# definitions in /usr/share/dnf5/repos.d, and Copa's chroot path reads them from
# there too, so they're edited in place. BASE_IMAGE is required; the fixture
# script passes integration/common.Fedora45Image.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG FEDORA_MIRROR=https://dl.fedoraproject.org/pub/fedora/linux
RUN set -eu; \
    repos=/usr/share/dnf5/repos.d; \
    sed -i -e "/^\[fedora\]/,/^\[/ s|^metalink=.*|baseurl=${FEDORA_MIRROR}/releases/\$releasever/Everything/\$basearch/os/|" \
        "${repos}/fedora.repo"; \
    sed -i -e "/^\[updates\]/,/^\[/ s|^metalink=.*|baseurl=${FEDORA_MIRROR}/updates/\$releasever/Everything/\$basearch/|" \
        "${repos}/fedora-updates.repo"; \
    sed -i -e '/^\[updates-testing\]/,/^\[/ s|^enabled=.*|enabled=0|' "${repos}/fedora-updates-testing.repo"; \
    sed -i -e '/^\[fedora-cisco-openh264\]/,/^\[/ s|^enabled=.*|enabled=0|' "${repos}/fedora-cisco-openh264.repo"; \
    enabled="$(cat "${repos}"/*.repo /etc/yum.repos.d/*.repo 2>/dev/null \
        | awk '/^\[/ { repo = $0 } /^enabled=1/ { print repo }' | sort | tr '\n' ' ')"; \
    if [ "$enabled" != "[fedora] [updates] " ]; then \
        echo "unexpected enabled repositories: ${enabled}" >&2; \
        exit 1; \
    fi; \
    grep -qx "baseurl=${FEDORA_MIRROR}/releases/\$releasever/Everything/\$basearch/os/" "${repos}/fedora.repo"; \
    grep -qx "baseurl=${FEDORA_MIRROR}/updates/\$releasever/Everything/\$basearch/" "${repos}/fedora-updates.repo"
