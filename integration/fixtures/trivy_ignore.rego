package trivy

import data.lib.trivy

default ignore = false

# Ignore the following Vulnerability IDs
ignore_vulnerability_ids := {}

# For ignoring vulnID
ignore {
    input.VulnerabilityID == ignore_vulnerability_ids[_]
}
