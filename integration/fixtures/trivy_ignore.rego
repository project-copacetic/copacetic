package trivy

import data.lib.trivy

default ignore = false

# Ignore the following Vulnerability IDs
ignore_vulnerability_ids := {
    # debian db bug since there's no libgnutls30 3.7.1-5+deb11u5
    "CVE-2024-0567"
}

# For ignoring vulnID
ignore {
    input.VulnerabilityID == ignore_vulnerability_ids[_]
}
