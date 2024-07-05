---
title: Scanner Plugins
---

# Motivation

By default, `copa` uses [Trivy](https://github.com/aquasecurity/trivy) to scan container images for vulnerabilities. However, we understand that different organizations have different requirements and may want to use different vulnerability scanners.

Starting with v0.5.0 and later, `copa` offers extensibility to support different vulnerability scanners. Plugin architecture allows users to use the vulnerability scanner of their choice to patch container images without having to modify `copa`'s core codebase.

# Usage

Scanner plugin binaries must be in `$PATH`, and should be prefixed with `copa-` and have executable permissions. Copa will automatically detect and use the scanner plugin if it is in `$PATH`.

For example, if you have a scanner plugin binary called `copa-foo` in `$PATH`, you can run `copa` with the following command:

```bash
copa patch --scanner foo --image $IMAGE ...
```

# Scanner Plugins from the Community

If you have built a scanner plugin and would like to add it to this list, please submit a PR to update this section with your plugin.

:::note

If you have any issues with a specific plugin, please open an issue in the applicable plugin's repository.

:::

- Grype: https://github.com/anubhav06/copa-grype

# Writing a Scanner Plugin

Please see instructions at [Scanner Plugin Template](https://github.com/project-copacetic/scanner-plugin-template) for a template to get started with writing a scanner plugin.

# Scanner Plugin Interface

:::note

`alpha` versions of the API are not guarenteed to be backwards compatible. Once the API graduates to `beta` and `stable`, it will be backwards compatible.

:::

Scanner plugins must implement the following interface:

## v1alpha1

```go
type UpdateManifest struct {
    // API version of the interface (e.g. v1alpha1)
    APIVersion string         `json:"apiVersion"`
    // Metadata contains information about the OS and config
    Metadata   Metadata       `json:"metadata"`
    // Updates is a list of UpdatePackage that contains information about the package updates
    Updates    UpdatePackages `json:"updates"`
}

// UpdatePackages is a list of UpdatePackage
type UpdatePackages []UpdatePackage

// Metadata contains information about the OS and config
type Metadata struct {
    OS     OS     `json:"os"`
    Config Config `json:"config"`
}

type OS struct {
    // OS Type (e.g. debian, alpine, etc.)
    Type    string `json:"type"`
    // OS Version (e.g. 11.3)
    Version string `json:"version"`
}

// Config contains information about the config
type Config struct {
    // OS Architecture (e.g. amd64, arm64)
    Arch string `json:"arch"`
}

// UpdatePackage contains information about the package update
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
  "metadata": {
    "os": {
        "type": "debian",
        "version": "11.3",
    },
    "config": {
      "arch": "amd64"
    }
  },
  "updates": [
      {
          "name": "libcurl4",
          "installedVersion": "7.74.0-1.3+deb11u1",
          "fixedVersion": "7.74.0-1.3+deb11u2",
          "vulnerabilityID": "CVE-2021-22945"
      }
  ]
}
```
