package trivy

import data.lib.trivy

default ignore = false

ignore_vulnerability_ids := {
    # centos 7.6.1810
    # bind-license package version "9.11.4-26.P2.el7_9.14" does not exist
    "CVE-2023-2828"
}