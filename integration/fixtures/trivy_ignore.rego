package trivy

import data.lib.trivy

default ignore = false

ignore_vulnerability_ids := {
    # centos 7.6.1810
    # libssh2 package version "1.8.0-4.el7_9.1" does not exist yet
    "CVE-2020-22218"
}