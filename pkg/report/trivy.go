// Package report contains parsers and helpers for vulnerability scan reports (e.g., Trivy).
package report

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

type TrivyParser struct{}

// getSpecialPackagePatchLevels returns a map of package names to their special patch level handling rules.
func getSpecialPackagePatchLevels() map[string]string {
	return map[string]string{
		"certifi": "major", // Always use latest version for certificate handling
	}
}

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

// findOptimalFixedVersion finds the best version that fixes all CVEs while being most compatible.
// The algorithm prefers patch versions over minor versions over major versions.
// When multiple CVEs require different versions, it picks the highest version to ensure all are fixed.
func findOptimalFixedVersion(installedVersion string, fixedVersions []string) string {
	return FindOptimalFixedVersionWithPatchLevel(installedVersion, fixedVersions, "patch")
}

// FindOptimalFixedVersionWithPatchLevel finds the best version that fixes all CVEs based on library patch level preference.
// libraryPatchLevel can be "patch", "minor", or "major":
// - "patch": only updates to patch versions (same major.minor), no fallback to minor/major
// - "minor": only updates to patch or minor versions, never major versions
// - "major": behavior depends on version format:
//   - If comma-separated versions exist: prefers patch > minor > major for compatibility
//   - If no comma-separated versions: chooses highest available version to fix all CVEs
func FindOptimalFixedVersionWithPatchLevel(installedVersion string, fixedVersions []string, libraryPatchLevel string) string {
	if len(fixedVersions) == 0 {
		return ""
	}

	// Detect if any version entries contain comma-separated values
	hasCommaSeparatedVersions := false
	for _, versionStr := range fixedVersions {
		if strings.Contains(versionStr, ",") {
			hasCommaSeparatedVersions = true
			break
		}
	}

	// Collect all possible fixed versions
	var allCandidates []string

	for _, versionStr := range fixedVersions {
		if strings.Contains(versionStr, ",") {
			// Split comma-separated versions
			parts := strings.Split(versionStr, ",")
			for _, part := range parts {
				trimmed := strings.TrimSpace(part)
				if trimmed != "" {
					allCandidates = append(allCandidates, trimmed)
				}
			}
		} else {
			trimmed := strings.TrimSpace(versionStr)
			if trimmed != "" {
				allCandidates = append(allCandidates, trimmed)
			}
		}
	}

	if len(allCandidates) == 0 {
		return ""
	}

	// Filter out versions that are not higher than installed version
	var validCandidates []string
	for _, version := range allCandidates {
		if compareVersions(version, installedVersion) > 0 {
			validCandidates = append(validCandidates, version)
		}
	}

	if len(validCandidates) == 0 {
		// If no valid candidates (no versions higher than installed), do not update
		return ""
	}

	// Group versions by upgrade type (even for single candidates to respect patch level)
	installedParts := parseVersionParts(installedVersion)
	var patchVersions, minorVersions, majorVersions []string

	for _, v := range validCandidates {
		vParts := parseVersionParts(v)

		// Categorize version by upgrade type
		switch {
		case len(vParts) >= 2 && len(installedParts) >= 2 &&
			vParts[0] == installedParts[0] && vParts[1] == installedParts[1]:
			// Patch-level upgrade (same major.minor)
			patchVersions = append(patchVersions, v)
		case len(vParts) >= 1 && len(installedParts) >= 1 && vParts[0] == installedParts[0]:
			// Minor-level upgrade (same major)
			minorVersions = append(minorVersions, v)
		default:
			// Major-level upgrade
			majorVersions = append(majorVersions, v)
		}
	}

	// Apply library patch level preference
	switch libraryPatchLevel {
	case "patch":
		// Only update to patch versions, no fallback to minor/major
		if len(patchVersions) > 0 {
			return getHighestVersion(patchVersions)
		}
		// If no patch versions available, do not update
		return ""

	case "minor":
		// Only update to patch or minor versions, never major
		if len(patchVersions) > 0 {
			return getHighestVersion(patchVersions)
		}
		if len(minorVersions) > 0 {
			return getHighestVersion(minorVersions)
		}
		// Do not fall back to major versions
		return ""

	case "major":
		// For major patch level, the behavior depends on whether we have comma-separated versions
		if hasCommaSeparatedVersions {
			// When comma-separated versions exist, prefer patch > minor > major for compatibility
			if len(patchVersions) > 0 {
				return getHighestVersion(patchVersions)
			}
			if len(minorVersions) > 0 {
				return getHighestVersion(minorVersions)
			}
			if len(majorVersions) > 0 {
				return getHighestVersion(majorVersions)
			}
		} else {
			// When no comma-separated versions, pick the highest version to fix all CVEs.
			// While this approach fixes the most vulnerabilities, it may introduce breaking changes
			// or compatibility issues. Users should weigh the security benefits against the
			// potential risks of upgrading to a higher version.
			return getHighestVersion(validCandidates)
		}
		return ""

	default:
		// Default to patch behavior for invalid values
		if len(patchVersions) > 0 {
			return getHighestVersion(patchVersions)
		}
		// If no patch versions available, do not update
		return ""
	}
}

// getHighestVersion returns the highest version from a slice of version strings.
func getHighestVersion(versions []string) string {
	if len(versions) == 0 {
		return ""
	}

	highest := versions[0]
	for _, v := range versions[1:] {
		if compareVersions(v, highest) > 0 {
			highest = v
		}
	}
	return highest
}

// parseVersionParts parses a version string into integer parts.
func parseVersionParts(version string) []int {
	// Remove common prefixes like 'v'
	version = strings.TrimPrefix(version, "v")

	// Split by dots and parse each part as integer
	parts := strings.Split(version, ".")
	var intParts []int

	for _, part := range parts {
		// Handle parts that might have additional suffixes like "-r1", "-alpha", etc.
		// Take only the numeric prefix
		var numStr string
		for _, char := range part {
			if char >= '0' && char <= '9' {
				numStr += string(char)
			} else {
				break
			}
		}

		if numStr != "" {
			if num, err := strconv.Atoi(numStr); err == nil {
				intParts = append(intParts, num)
			} else {
				intParts = append(intParts, 0)
			}
		} else {
			intParts = append(intParts, 0)
		}
	}

	return intParts
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

// extractVersionsFromImageHistory extracts Node.js and Yarn versions from Docker image history.
// It looks for ENV commands like "ENV NODE_VERSION=18.20.3" and "ENV YARN_VERSION=1.22.19".
func extractVersionsFromImageHistory(history []v1.History) (nodeVersion, yarnVersion string) {
	// Regular expressions to match version environment variables
	nodeVersionRe := regexp.MustCompile(`ENV NODE_VERSION=([0-9]+\.[0-9]+\.[0-9]+)`)
	yarnVersionRe := regexp.MustCompile(`ENV YARN_VERSION=([0-9]+\.[0-9]+\.[0-9]+)`)

	for _, h := range history {
		if h.CreatedBy == "" {
			continue
		}

		// Extract Node.js version
		if nodeVersion == "" {
			if matches := nodeVersionRe.FindStringSubmatch(h.CreatedBy); len(matches) > 1 {
				nodeVersion = matches[1]
			}
		}

		// Extract Yarn version
		if yarnVersion == "" {
			if matches := yarnVersionRe.FindStringSubmatch(h.CreatedBy); len(matches) > 1 {
				yarnVersion = matches[1]
			}
		}

		// Stop early if both found
		if nodeVersion != "" && yarnVersion != "" {
			break
		}
	}

	return nodeVersion, yarnVersion
}

func NewTrivyParser() *TrivyParser {
	return &TrivyParser{}
}

func (t *TrivyParser) Parse(file string) (*unversioned.UpdateManifest, error) {
	// Default to "patch" level for backward compatibility
	return t.ParseWithLibraryPatchLevel(file, "patch")
}

func (t *TrivyParser) ParseWithLibraryPatchLevel(file, libraryPatchLevel string) (*unversioned.UpdateManifest, error) {
	report, err := parseTrivyReport(file)
	if err != nil {
		return nil, err
	}

	// Extract Node.js and Yarn versions from image history
	var nodeVersion, yarnVersion string
	if report.Metadata.ImageConfig.History != nil {
		nodeVersion, yarnVersion = extractVersionsFromImageHistory(report.Metadata.ImageConfig.History)
	}

	// Initialize OS metadata with safe defaults
	osType := ""
	osVersion := ""
	if report.Metadata.OS != nil {
		osType = string(report.Metadata.OS.Family)
		osVersion = report.Metadata.OS.Name
	}

	updates := unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    osType,
				Version: osVersion,
			},
			Config: unversioned.Config{
				Arch:    report.Metadata.ImageConfig.Architecture,
				Variant: report.Metadata.ImageConfig.Variant,
			},
			NodeVersion: nodeVersion,
			YarnVersion: yarnVersion,
		},
	}

	// Process Language packages - group by package name to find optimal fixed version
	langPackageVulns := make(map[string][]trivyTypes.DetectedVulnerability)
	langPackageInfo := make(map[string]unversioned.UpdatePackage)
	// track all vulnerability IDs per lang package for VEX emission
	langPackageVulnIDs := make(map[string]map[string]struct{})

	for i := range report.Results {
		r := &report.Results[i]

		// Process OS packages
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

		// Process Language packages
		if r.Class == utils.LangPackages {
			// Check if this is a Python or Node.js related target
			if r.Type == utils.PythonPackages || r.Type == utils.NodePackages {
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
								PkgPath:          vuln.PkgPath, // Preserve package path from Trivy
							}
							langPackageVulnIDs[vuln.PkgName] = make(map[string]struct{})
						}
						langPackageVulns[vuln.PkgName] = append(langPackageVulns[vuln.PkgName], *vuln)
						if vuln.VulnerabilityID != "" {
							langPackageVulnIDs[vuln.PkgName][vuln.VulnerabilityID] = struct{}{}
						}
					}
				}
			}

			// Check if this is a .NET-related target
			if r.Type == utils.DotNetPackages {
				for v := range r.Vulnerabilities {
					vuln := &r.Vulnerabilities[v]
					// Skip Microsoft.Build.* packages as they are SDK/build-time dependencies, not runtime
					if strings.HasPrefix(vuln.PkgName, "Microsoft.Build.") {
						continue
					}
					if vuln.FixedVersion != "" {
						if _, exists := langPackageVulns[vuln.PkgName]; !exists {
							langPackageVulns[vuln.PkgName] = []trivyTypes.DetectedVulnerability{}
							langPackageInfo[vuln.PkgName] = unversioned.UpdatePackage{
								Name:             vuln.PkgName,
								Type:             string(r.Type),
								Class:            string(r.Class),
								InstalledVersion: vuln.InstalledVersion,
							}
							langPackageVulnIDs[vuln.PkgName] = make(map[string]struct{})
						}
						langPackageVulns[vuln.PkgName] = append(langPackageVulns[vuln.PkgName], *vuln)
						if vuln.VulnerabilityID != "" {
							langPackageVulnIDs[vuln.PkgName][vuln.VulnerabilityID] = struct{}{}
						}
					}
				}
			}
		}
	}

	// Process Language packages to find optimal fixed versions
	for pkgName, vulns := range langPackageVulns {
		var fixedVersions []string

		for i := range vulns {
			if vulns[i].FixedVersion != "" {
				// Handle comma-separated fixed versions
				if strings.Contains(vulns[i].FixedVersion, ",") {
					versions := strings.Split(vulns[i].FixedVersion, ",")
					for _, v := range versions {
						v = strings.TrimSpace(v)
						if v != "" {
							fixedVersions = append(fixedVersions, v)
						}
					}
				} else {
					fixedVersions = append(fixedVersions, vulns[i].FixedVersion)
				}
			}
		}

		if len(fixedVersions) > 0 {
			info, ok := langPackageInfo[pkgName]
			if !ok {
				// Defensive: skip if info not recorded (shouldn't happen)
				continue
			}

			// Determine patch level to use, with special handling for certain packages
			patchLevelToUse := libraryPatchLevel
			if specialPatchLevel, exists := getSpecialPackagePatchLevels()[pkgName]; exists {
				patchLevelToUse = specialPatchLevel
			}

			optimalVersion := FindOptimalFixedVersionWithPatchLevel(info.InstalledVersion, fixedVersions, patchLevelToUse)
			if idsMap, ok2 := langPackageVulnIDs[pkgName]; ok2 {
				var ids []string
				for id := range idsMap {
					ids = append(ids, id)
				}
				sort.Strings(ids)
				for _, vid := range ids {
					clone := info
					clone.FixedVersion = optimalVersion
					clone.VulnerabilityID = vid
					updates.LangUpdates = append(updates.LangUpdates, clone)
				}
			} else {
				info.FixedVersion = optimalVersion
				updates.LangUpdates = append(updates.LangUpdates, info)
			}
		}
	}

	sort.SliceStable(updates.LangUpdates, func(i, j int) bool {
		if updates.LangUpdates[i].Name != updates.LangUpdates[j].Name {
			return updates.LangUpdates[i].Name < updates.LangUpdates[j].Name
		}
		return updates.LangUpdates[i].VulnerabilityID < updates.LangUpdates[j].VulnerabilityID
	})

	return &updates, nil
}
