package trivy

import data.lib.trivy

default ignore = false

# Ignore the following Vulnerability IDs
ignore_vulnerability_ids := {}

# For ignoring vulnID
ignore {
    input.VulnerabilityID == ignore_vulnerability_ids[_]
}

# shadow CVEs ignored for registry.k8s.io/kube-proxy:v1.23.4-patched
shadow_cves := {
    "CVE-2023-4641",
    "CVE-2023-29383",
}

ignore {
    input.VulnerabilityID == shadow_cves[_]
}

# CBL Mariner CVEs to ignore
cbl_mariner_cves := {
    "CVE-2025-3576", # due to krb5 1.19.4-4 not found in PMC
}

ignore {
    input.VulnerabilityID == cbl_mariner_cves[_]
}
