---
title: Troubleshooting
---

## Copa and Trivy throw errors when Oracle Linux is passed in

Copa supports patching Oracle Linux in two ways:

With a vulnerability scan, `--ignore-errors` must be passed in. This will patch all CVEs aside from false positives reported by Trivy:

```bash
copa patch -r /oracle-7.9-vulns.json -i docker.io/library/oraclelinux:7.9 --ignore-errors
```

Without a vulnerability scan, Copa will update all packages in the image:

```bash
copa patch -i docker.io/library/oraclelinux:7.9
```

Oracle reports CVEs in a way that causes Trivy to report false positives that Copa will be unable to patch. To patch the entire image, use the Copa `--ignore-errors` flag or omit the vulnerability scan report to upgrade all outdated packages. See [this GitHub issue](https://github.com/aquasecurity/trivy/issues/1967#issuecomment-1092987400) for more information.
## Filtering Vulnerabilities

You might want to filter/ignore some of the vulnerabilities while patching. To do so, you need to first filter those undesired vulnerabilities from your scanner output.

For Trivy, vulnerabilities can be filtered by the following 2 ways:

### Rego Policy

An example rego file which demonstrates how to ignore certain Vulnerability IDs or Package Names:

```bash
$ cat trivy_ignore.rego

package trivy

import data.lib.trivy

default ignore = false


# Ignore the following Vulnerability IDs
ignore_vulnerability_ids := {
   "CVE-2018-14618"
}
# Ignore the following Package Names
ignore_pkgs := {"bash", "vim"}


# For ignoring vulnID
ignore {
   input.VulnerabilityID == ignore_vulnerability_ids[_]
}
# For ignoring pkgName
ignore {
	input.PkgName == ignore_pkgs[_]
}

```

After adding the above rego file, run the image scan with the `--ignore-policy` flag followed by the file name to ignore them while scanning:

```bash
trivy image --ignore-policy trivy_ignore.rego ruby:2.4.0
```
In the above example, the vulnerability "CVE-2018-14618"  and the packages "bash" & "vim" are ignored while scanning, and hence patching the image.

### Ignore File

Use a `.trivyignore` file to list all the vulnerabilities you want to ignore.

Example:
```bash
$ cat .trivyignore

# Accept the risk
CVE-2018-14618
```
In the above example, the vulnerability CVE-2018-14618 is ignored while scanning, and hence while patching the image.

For a more detailed explanation on how to ignore certain vulnerabilities with Trivy, please refer to the official documentation [here](https://aquasecurity.github.io/trivy/v0.44/docs/configuration/filtering/).
