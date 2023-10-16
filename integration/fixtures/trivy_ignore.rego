package trivy

import data.lib.trivy

default ignore = false

# Ignore the following Vulnerability IDs
ignore_vulnerability_ids := {
    # centos 7.6.1810
    # bind-license package version "9.11.4-26.P2.el7_9.15" does not exist
    "CVE-2023-3341",
    # libssh2 package version "1.8.0-4.el7_9.1" does not exist yet
    "CVE-2020-22218"
}

# For ignoring vulnID
ignore {
    input.VulnerabilityID == ignore_vulnerability_ids[_]
}
