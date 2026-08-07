# syntax=docker/dockerfile:1.7

# This fixture models Microsoft .NET's apt-less Ubuntu Chiseled layout: a
# complete /var/lib/dpkg/status made from package control paragraphs, but no
# Status fields and none of the target-side tools Copa normally invokes.
# Keep the default base immutable; callers may override it deliberately.
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90
FROM ${UBUNTU_IMAGE}

RUN test -s /var/lib/dpkg/status \
    && test ! -e /var/lib/dpkg/status.d \
    && sed -i '/^Status:/d' /var/lib/dpkg/status \
    && test "$(grep -c '^Package:' /var/lib/dpkg/status)" -gt 1 \
    && ! grep -q '^Status:' /var/lib/dpkg/status \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
    && rm -rf /usr/lib/apt /usr/lib/dpkg \
    && rm -f \
        /bin/bash /bin/busybox /bin/dash /bin/sh \
        /sbin/apk \
        /usr/bin/apt /usr/bin/apt-cache /usr/bin/apt-cdrom \
        /usr/bin/apt-config /usr/bin/apt-get /usr/bin/apt-mark \
        /usr/bin/bash /usr/bin/busybox /usr/bin/dash /usr/bin/dpkg \
        /usr/bin/dpkg-deb /usr/bin/dpkg-divert /usr/bin/dpkg-maintscript-helper \
        /usr/bin/dpkg-query /usr/bin/dpkg-realpath /usr/bin/dpkg-split \
        /usr/bin/dpkg-statoverride /usr/bin/dpkg-trigger /usr/bin/grep \
        /usr/bin/sh /usr/bin/tee

COPY sentinel.txt /opt/copa-fixture/sentinel.txt

LABEL org.opencontainers.image.title="Copa apt-less full-status integration fixture" \
      sh.copa.fixture.layout="external-full-status"

USER 1654:1654
WORKDIR /opt/copa-fixture
ENTRYPOINT ["/usr/bin/true"]
