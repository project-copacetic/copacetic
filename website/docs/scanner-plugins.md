---
title: Scanner Plugins
---

## Motivation

By default, `copa` uses [Trivy](https://github.com/aquasecurity/trivy) to scan container images for vulnerabilities. However, we understand that different organizations have different requirements and may want to use different vulnerability scanners.

Starting with v0.5.0 and later, `copa` offers extensibility to support different vulnerability scanners. Plugin architecture allows users to use the vulnerability scanner of their choice to patch container images without having to modify `copa`'s core codebase.

## Usage

Scanner plugin binaries must be in `$PATH`, and should be prefixed with `copa-` and have executable permissions. Copa will automatically detect and use the scanner plugin if it is in `$PATH`.

For example, if you have a scanner plugin binary called `copa-foo` in `$PATH`, you can run `copa` with the following command:

```bash
copa patch --scanner foo --image $IMAGE ...
```

:::note

You can also a submit scan report in native `v1alpha1` format (interface mentioned below) by using `--scanner native` flag along with `-r <report>` flag.

:::

## Scanner Plugins from the Community

If you have built a scanner plugin and would like to add it to this list, please submit a PR to update this section with your plugin.

:::note

If you have any issues with a specific plugin, please open an issue in the applicable plugin's repository.

:::

- Grype: https://github.com/anubhav06/copa-grype

## Writing a Scanner Plugin

Please see instructions at [Scanner Plugin Template](https://github.com/project-copacetic/scanner-plugin-template) for a template to get started with writing a scanner plugin.

## Scanner Plugin Interface

:::note

`alpha` versions of the API are not guarenteed to be backwards compatible. Once the API graduates to `beta` and `stable`, it will be backwards compatible.

**API Versions:**

- **v1alpha1**: Original format with single `updates` field - existing plugins continue to work
- **v1alpha2**: New format with separate `osupdates` and `langupdates` fields that supports app-level patching

:::

Scanner plugins support two API versions for backwards compatibility:

## v1alpha1

```go
type UpdateManifest struct {
    // API version (v1alpha1)
    APIVersion string         `json:"apiVersion"`
    // Metadata contains information about the OS and config
    Metadata   Metadata       `json:"metadata"`
    // Updates contains all package updates (OS packages only)
    Updates    UpdatePackages `json:"updates"`
}

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

type Metadata struct {
    OS     OS     `json:"os"`
    Config Config `json:"config"`
}

type Config struct {
    // OS Architecture (e.g. amd64, arm64)
    Arch string `json:"arch"`
}
```

## v1alpha2

```go
type UpdateManifest struct {
    // API version (v1alpha2)
    APIVersion  string             `json:"apiVersion"`
    // Metadata contains information about the OS and config
    Metadata    Metadata           `json:"metadata"`
    // OSUpdates is a list of OS package updates
    OSUpdates   UpdatePackages     `json:"osupdates"`
    // LangUpdates is a list of language/library package updates
    LangUpdates LangUpdatePackages `json:"langupdates"`
}

type UpdatePackage struct {
    // Package name
    Name             string `json:"name"`
    // Installed version
    InstalledVersion string `json:"installedVersion"`
    // Fixed version
    FixedVersion     string `json:"fixedVersion"`
    // Vulnerability ID
    VulnerabilityID  string `json:"vulnerabilityID"`
    // Package type (python-pkg)
    Type             string `json:"type"`
    // Package class (os-pkgs, lang-pkgs)
    Class            string `json:"class"`
}

type Config struct {
    // OS Architecture (e.g. amd64, arm64)
    Arch    string `json:"arch"`
    // Architecture variant (e.g. v8)
    Variant string `json:"variant,omitempty"`
}
```

## Format Examples

From the above, we can see that the plugin must return a JSON object via standard out with the following fields.

### v1alpha1

```json
{
  "apiVersion": "v1alpha1",
  "metadata": {
    "os": {
        "type": "debian",
        "version": "11.3"
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

### v1alpha2

```json
{
  "apiVersion": "v1alpha2",
  "metadata": {
    "os": {
        "type": "debian",
        "version": "11.3"
    },
    "config": {
      "arch": "amd64",
      "variant": "v8"
    }
  },
  "osupdates": [
      {
          "name": "libcurl4",
          "installedVersion": "7.74.0-1.3+deb11u1",
          "fixedVersion": "7.74.0-1.3+deb11u2",
          "vulnerabilityID": "CVE-2021-22945",
          "type": "debian",
          "class": "os-pkgs"
      }
  ],
  "langupdates": [
      {
          "name": "requests",
          "installedVersion": "2.25.1",
          "fixedVersion": "2.31.0",
          "vulnerabilityID": "CVE-2023-32681",
          "type": "python-pkg",
          "class": "lang-pkgs"
      }
  ]
}
```
