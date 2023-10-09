---
title: Scanner Plugins
---

# Motivation

By default, `copa` uses [Trivy](https://github.com/aquasecurity/trivy) to scan container images for vulnerabilities. However, we understand that different organizations have different requirements and may want to use different vulnerability scanners.

`copa` is designed to be extensible to support different vulnerability scanners. Plugin architecture allows users to use the vulnerability scanner of their choice to patch container images without having to modify `copa`'s core codebase.

# Usage

Scanner plugin binaries must be in `$PATH` and should be prefixed with `copa-`. Copa will automatically detect and use the scanner plugin if it is in `$PATH`.

For example, if you have a scanner plugin binary called `copa-foo` in `$PATH`, you can run `copa` with the following command:

```bash
copa patch --scanner foo --image $IMAGE ...
```

# Community Scanner Plugins

If you have built a scanner plugin and would like to add it to this list, please submit a PR to update this page.

If you have any issues with a specific plugin, please open an issue in the applicable plugin's repository.


# Writing a Scanner Plugin

Please see [Scanner Plugin Template](https://github.com/project-copacetic/scanner-plugin-template) for a template to write your own scanner plugin.

Here are the steps to write your own scanner plugin:

1. Clone [Scanner Plugin Template](https://github.com/project-copacetic/scanner-plugin-template) repo
2. Rename the `scanner-plugin-template` repo to the name of your plugin
3. Update applicable types for [`FakeReport`](types.go) to match your scanner's structure
4. Update [`parse`](main.go) to parse your scanner's report format accordingly
5. Update `CLI_BINARY` in the [`Makefile`](Makefile) to match your scanner's CLI binary name (resulting binary must be prefixed with `copa-`)
5. Update this [`README.md`](README.md) to match your plugin's usage

# Scanner Plugin Interface

Scanner plugins must implement the following interface:

## v1alpha1

```go
type UpdateManifest struct {
    // API version of the interface (e.g. v1alpha1)
	APIVersion	     string         `json:"apiVersion"`
    // OS Type (e.g. debian, alpine, etc.)
	OSType           string         `json:"osType"`
    // OS Version (e.g. 11.3)
	OSVersion        string         `json:"osVersion"`
    // OS Architecture (e.g. amd64)
	Arch             string         `json:"arch"`
    // Package information
	Updates          UpdatePackages `json:"updates"`
}

type UpdatePackages []UpdatePackage

type UpdatePackage struct {
    // Package name
	Name             string `json:"name"`
    // Installed version
	InstalledVersion string `json:"installedVersion"`
    // Fixed version
	FixedVersion     string `json:"fixedVersion"`
    // Vulnerability ID
	VulnerabilityID  string `json:"vulnerabilityID"`
}
```

From the above, we can see that the plugin must return a JSON object via standard out with the following fields. For example:

```json
{
    "apiVersion": "v1alpha1",
    "ostype": "debian",
    "osversion": "11.3",
    "arch": "amd64",
    "updates": [
        {
            "name": "libcurl4",
            "installedVersion": "7.74.0-1.3+deb11u1",
            "fixedVersion": "7.74.0-1.3+deb11u2",
            "vulnerabilityID": "CVE-2021-22945"
        },
        ...
    ]
}
```
