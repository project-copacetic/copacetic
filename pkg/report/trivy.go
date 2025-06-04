package report

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

type TrivyParser struct{}

// parseVersion parses a semantic version string and returns major, minor, patch as integers.
func parseVersion(version string) (major, minor, patch int, err error) {
	// Remove any prefix like 'v'
	version = strings.TrimPrefix(version, "v")

	// Split by dots
	parts := strings.Split(version, ".")
	if len(parts) < 1 {
		return 0, 0, 0, errors.New("invalid version format")
	}

	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, err
	}

	if len(parts) >= 2 {
		minor, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, 0, err
		}
	}

	if len(parts) >= 3 {
		// Handle patch versions that might have additional suffixes (e.g., "16-1ubuntu2.1")
		patchStr := strings.Split(parts[2], "-")[0]
		patch, err = strconv.Atoi(patchStr)
		if err != nil {
			return 0, 0, 0, err
		}
	}

	return major, minor, patch, nil
}

// compareVersions compares two version strings, returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
func compareVersions(v1, v2 string) int {
	maj1, min1, patch1, err1 := parseVersion(v1)
	maj2, min2, patch2, err2 := parseVersion(v2)

	// If parsing fails, fall back to string comparison
	if err1 != nil || err2 != nil {
		return strings.Compare(v1, v2)
	}

	if maj1 != maj2 {
		if maj1 < maj2 {
			return -1
		}
		return 1
	}

	if min1 != min2 {
		if min1 < min2 {
			return -1
		}
		return 1
	}

	if patch1 != patch2 {
		if patch1 < patch2 {
			return -1
		}
		return 1
	}

	return 0
}

// findOptimalFixedVersion finds the minimum version that fixes all CVEs for a package.
// It prefers patch versions over minor versions, and minor versions over major versions.
func findOptimalFixedVersion(installedVersion string, fixedVersions []string) string {
	if len(fixedVersions) == 0 {
		return ""
	}

	// Flatten comma-separated versions
	var allVersions []string
	for _, versionStr := range fixedVersions {
		if strings.Contains(versionStr, ",") {
			// Split comma-separated versions
			parts := strings.Split(versionStr, ",")
			for _, part := range parts {
				trimmed := strings.TrimSpace(part)
				if trimmed != "" {
					allVersions = append(allVersions, trimmed)
				}
			}
		} else {
			trimmed := strings.TrimSpace(versionStr)
			if trimmed != "" {
				allVersions = append(allVersions, trimmed)
			}
		}
	}

	if len(allVersions) == 0 {
		return ""
	}

	if len(allVersions) == 1 {
		return allVersions[0]
	}

	// Parse installed version to understand current major.minor.patch
	installedMajor, installedMinor, _, err := parseVersion(installedVersion)
	if err != nil {
		// If we can't parse the installed version, just return the first fixed version
		return allVersions[0]
	}

	// Sort fixed versions
	sortedVersions := make([]string, len(allVersions))
	copy(sortedVersions, allVersions)

	// Sort using our custom comparison
	for i := 0; i < len(sortedVersions)-1; i++ {
		for j := i + 1; j < len(sortedVersions); j++ {
			if compareVersions(sortedVersions[i], sortedVersions[j]) > 0 {
				sortedVersions[i], sortedVersions[j] = sortedVersions[j], sortedVersions[i]
			}
		}
	}

	// Find versions that fix the vulnerability, prioritizing by type
	// Collect all valid patch, minor, and major versions
	var patchVersions, minorVersions, majorVersions []string

	for _, version := range sortedVersions {
		if compareVersions(version, installedVersion) <= 0 {
			continue // This version doesn't fix the vulnerability
		}

		fixedMajor, fixedMinor, _, err := parseVersion(version)
		if err != nil {
			continue
		}

		// Collect patch versions in same major.minor
		if fixedMajor == installedMajor && fixedMinor == installedMinor {
			patchVersions = append(patchVersions, version)
		}

		// Collect minor versions in same major
		if fixedMajor == installedMajor {
			minorVersions = append(minorVersions, version)
		}

		// Collect all versions that fix it
		majorVersions = append(majorVersions, version)
	}

	// Return the highest version in order of preference
	// For patch versions, pick the highest one (assumes it fixes the most CVEs)
	if len(patchVersions) > 0 {
		highestPatch := patchVersions[0]
		for _, v := range patchVersions[1:] {
			if compareVersions(v, highestPatch) > 0 {
				highestPatch = v
			}
		}
		return highestPatch
	}

	// For minor versions, pick the lowest one (smallest upgrade)
	if len(minorVersions) > 0 {
		return minorVersions[0]
	}

	// For major versions, pick the lowest one (smallest upgrade)
	if len(majorVersions) > 0 {
		return majorVersions[0]
	}

	// Fallback to the first (smallest) fixed version
	return sortedVersions[0]
}

func parseTrivyReport(file string) (*trivyTypes.Report, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var msr trivyTypes.Report
	if err = json.Unmarshal(data, &msr); err != nil {
		return nil, &ErrorUnsupported{err}
	}
	return &msr, nil
}

func NewTrivyParser() *TrivyParser {
	return &TrivyParser{}
}

func (t *TrivyParser) Parse(file string) (*unversioned.UpdateManifest, error) {
	report, err := parseTrivyReport(file)
	if err != nil {
		return nil, err
	}

	updates := unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    string(report.Metadata.OS.Family),
				Version: report.Metadata.OS.Name,
			},
			Config: unversioned.Config{
				Arch: report.Metadata.ImageConfig.Architecture,
			},
		},
	}

	// Process Language packages - group by package name to find optimal fixed version
	langPackageVulns := make(map[string][]trivyTypes.DetectedVulnerability)
	langPackageInfo := make(map[string]unversioned.UpdatePackage)

	for i := range report.Results {
		r := &report.Results[i]

		// Process OS packages using the original simple logic
		if r.Class == "os-pkgs" {
			for v := range r.Vulnerabilities {
				vuln := &r.Vulnerabilities[v]
				if vuln.FixedVersion != "" {
					updates.OSUpdates = append(updates.OSUpdates, unversioned.UpdatePackage{
						Name:             vuln.PkgName,
						Type:             string(r.Type),
						Class:            string(r.Class),
						FixedVersion:     vuln.FixedVersion,
						InstalledVersion: vuln.InstalledVersion,
						VulnerabilityID:  vuln.VulnerabilityID,
					})
				}
			}
		}

		// Process Language packages with optimal version selection
		if r.Class == "lang-pkgs" {
			if r.Target == "Python" {
				for v := range r.Vulnerabilities {
					vuln := &r.Vulnerabilities[v]
					if vuln.FixedVersion != "" {
						if _, exists := langPackageVulns[vuln.PkgName]; !exists {
							langPackageVulns[vuln.PkgName] = []trivyTypes.DetectedVulnerability{}
							langPackageInfo[vuln.PkgName] = unversioned.UpdatePackage{
								Name:             vuln.PkgName,
								Type:             string(r.Type),
								Class:            string(r.Class),
								InstalledVersion: vuln.InstalledVersion,
							}
						}
						langPackageVulns[vuln.PkgName] = append(langPackageVulns[vuln.PkgName], *vuln)
					}
				}
			}
		}
	}

	// Process Language packages to find optimal fixed versions
	for pkgName, vulns := range langPackageVulns {
		var fixedVersions []string

		for _, vuln := range vulns {
			if vuln.FixedVersion != "" {
				// Handle comma-separated fixed versions
				if strings.Contains(vuln.FixedVersion, ",") {
					versions := strings.Split(vuln.FixedVersion, ",")
					for _, v := range versions {
						v = strings.TrimSpace(v)
						if v != "" {
							fixedVersions = append(fixedVersions, v)
						}
					}
				} else {
					fixedVersions = append(fixedVersions, vuln.FixedVersion)
				}
			}
		}

		if len(fixedVersions) > 0 {
			info := langPackageInfo[pkgName]
			optimalVersion := findOptimalFixedVersion(info.InstalledVersion, fixedVersions)
			info.FixedVersion = optimalVersion
			updates.LangUpdates = append(updates.LangUpdates, info)
		}
	}

	return &updates, nil
}
