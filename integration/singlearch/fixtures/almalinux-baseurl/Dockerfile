# Copies an AlmaLinux image with its repositories pointed at repo.almalinux.org
# instead of the geo mirrorlist. The fixture script builds this in CI so that
# package downloads don't depend on which mirror the runner is given.
ARG BASE_IMAGE=docker.io/library/almalinux:9
FROM ${BASE_IMAGE}
RUN set -eu; \
    sed -i -e 's|^mirrorlist=|#mirrorlist=|' -e 's|^# *baseurl=|baseurl=|' /etc/yum.repos.d/almalinux*.repo; \
    if grep -q '^mirrorlist=' /etc/yum.repos.d/*.repo; then \
        echo "a repository still uses a mirrorlist" >&2; \
        exit 1; \
    fi; \
    grep -q '^baseurl=https://repo\.almalinux\.org/almalinux/\$releasever/BaseOS/' /etc/yum.repos.d/almalinux-baseos.repo; \
    grep -q '^baseurl=https://repo\.almalinux\.org/almalinux/\$releasever/AppStream/' /etc/yum.repos.d/almalinux-appstream.repo; \
    grep -q '^baseurl=https://repo\.almalinux\.org/almalinux/\$releasever/extras/' /etc/yum.repos.d/almalinux-extras.repo
