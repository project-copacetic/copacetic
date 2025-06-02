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
