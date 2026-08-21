# syntax=docker/dockerfile:1.7

# This fixture models Microsoft .NET's apt-less Ubuntu Chiseled layout: package
# control paragraphs without lifecycle-package records or Status fields, and
# none of the target-side tools Copa normally invokes.
# Keep the default base immutable and on GA package versions that remain in the
# Ubuntu release pocket while newer security versions exercise patching.
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:24.04@sha256:562456a05a0dbd62a671c1854868862a4687bf979a96d48ae8e766642cd911e8
FROM ${UBUNTU_IMAGE}

RUN test -s /var/lib/dpkg/status \
    && test ! -e /var/lib/dpkg/status.d \
    && sed -i '/^Status:/d' /var/lib/dpkg/status \
    && awk 'BEGIN { RS = ""; ORS = "\n\n" } \
        { \
            package = ""; \
            for (i = 1; i <= NF; i++) { \
                if ($i == "Package:") { \
                    package = $(i + 1); \
                    break; \
                } \
            } \
            if (package !~ /^(dpkg|dash|init-system-helpers|debconf|perl-base|tar|apt|apt-utils|bash|busybox|busybox-static)$/) { \
                print; \
            } \
        }' /var/lib/dpkg/status > /tmp/copa-dpkg-status \
    && mv /tmp/copa-dpkg-status /var/lib/dpkg/status \
    && test "$(grep -c '^Package:' /var/lib/dpkg/status)" -gt 1 \
    && ! grep -q '^Status:' /var/lib/dpkg/status \
    && ! grep -Eq '^Package: (dpkg|dash|init-system-helpers|debconf|perl-base|tar|apt|apt-utils|bash|busybox|busybox-static)$' /var/lib/dpkg/status \
    && mv /var/lib/dpkg/status /tmp/copa-dpkg-status \
    && rm -rf /var/lib/dpkg \
    && mkdir -p /var/lib/dpkg \
    && mv /tmp/copa-dpkg-status /var/lib/dpkg/status \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
    && rm -rf /usr/lib/apt /usr/lib/dpkg \
    && rm -f \
        /bin/bash /bin/busybox /bin/dash /bin/sh \
        /sbin/apk \
        /usr/bin/apt /usr/bin/apt-* \
        /usr/bin/bash /usr/bin/busybox /usr/bin/dash /usr/bin/dpkg \
        /usr/bin/dpkg-deb /usr/bin/dpkg-divert /usr/bin/dpkg-maintscript-helper \
        /usr/bin/dpkg-query /usr/bin/dpkg-realpath /usr/bin/dpkg-split \
        /usr/bin/dpkg-statoverride /usr/bin/dpkg-trigger /usr/bin/grep \
        /usr/bin/sh /usr/bin/tee /usr/bin/update-alternatives \
        /usr/libexec/dpkg/dpkg-db-backup /usr/sbin/start-stop-daemon

COPY sentinel.txt /opt/copa-fixture/sentinel.txt

LABEL org.opencontainers.image.title="Copa apt-less full-status integration fixture" \
      sh.copa.fixture.layout="external-full-status"

USER 1654:1654
WORKDIR /opt/copa-fixture
ENTRYPOINT ["/usr/bin/true"]
