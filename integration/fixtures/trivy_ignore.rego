package trivy

import data.lib.trivy

default ignore = false

# Ignore the following Vulnerability IDs
ignore_vulnerability_ids := {
    # docker.io/library/centos:7.6.1810
    # bind-license package version "9.11.4-26.P2.el7_9.15" does not exist
    "CVE-2023-3341",
    # libssh2 package version "1.8.0-4.el7_9.1" does not exist yet
    "CVE-2020-22218",

    # docker.io/library/nginx:1.21.6
    # debian db bug since there's no libgnutls30 3.7.1-5+deb11u5
    "CVE-2024-0567", "CVE-2023-5981"
}

# For ignoring vulnID
ignore {
    input.VulnerabilityID == ignore_vulnerability_ids[_]
}
