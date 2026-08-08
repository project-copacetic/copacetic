// Package report contains parsers and helpers for vulnerability scan reports (e.g., Trivy).
package report

import (
	"encoding/json"
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

var (
	nodeVersionRe = regexp.MustCompile(`ENV NODE_VERSION=([0-9]+\.[0-9]+\.[0-9]+)`)
	yarnVersionRe = regexp.MustCompile(`ENV YARN_VERSION=([0-9]+\.[0-9]+\.[0-9]+)`)

	specialPackagePatchLevels = map[string]string{
		"certifi": "major", // Always use latest version for certificate handling
	}
)

// isUnpatchableDotnetRuntimePackage returns true for .NET runtime/platform packages
// that have the DotnetPlatform NuGet package type and cannot be installed via
// PackageReference in a .csproj file (dotnet restore fails with NU1213).
// These packages are part of the .NET shared framework and are updated by
// upgrading the runtime itself, not through NuGet.
func isUnpatchableDotnetRuntimePackage(pkgName string) bool {
	unpatchablePrefixes := []string{
		"Microsoft.AspNetCore.App.Runtime.",
		"Microsoft.NETCore.App.Runtime.",
		"Microsoft.WindowsDesktop.App.Runtime.",
		"Microsoft.AspNetCore.App.Ref",
		"Microsoft.NETCore.App.Ref",
		"Microsoft.NETCore.App.Host.",
	}
	for _, prefix := range unpatchablePrefixes {
		if strings.HasPrefix(pkgName, prefix) {
			return true
		}
	}
	return false
}

// parseVersion parses a semantic version string and returns major, minor, patch as integers.
func parseVersion(version string) (major, minor, patch int, err error) {
	// Remove any prefix like 'v'
	version = strings.TrimPrefix(version, "v")

	majorPart, rest, hasRest := strings.Cut(version, ".")
	major, err = strconv.Atoi(majorPart)
	if err != nil {
		return 0, 0, 0, err
	}
	if !hasRest {
		return major, 0, 0, nil
	}

	minorPart, rest, hasRest := strings.Cut(rest, ".")
	minor, err = strconv.Atoi(minorPart)
	if err != nil {
		return 0, 0, 0, err
	}
	if !hasRest {
		return major, minor, 0, nil
	}

	// Match the previous strings.Split behavior: the patch is the third dot-separated
	// segment, with any dash suffix ignored (e.g., "16-1ubuntu2.1" -> "16").
	patchPart, _, _ := strings.Cut(rest, ".")
	patchPart, _, _ = strings.Cut(patchPart, "-")
	patch, err = strconv.Atoi(patchPart)
	if err != nil {
		return 0, 0, 0, err
	}

	return major, minor, patch, nil
}

type versionCandidate struct {
	value      string
	major      int
	minor      int
	patch      int
	comparable bool
	prefix     versionPartPrefix
}

type versionPartPrefix struct {
	first  int
	second int
	length int
}

func newVersionCandidate(value string) versionCandidate {
	major, minor, patch, err := parseVersion(value)
	return versionCandidate{
		value:      value,
		major:      major,
		minor:      minor,
		patch:      patch,
		comparable: err == nil,
	}
}

func compareVersionCandidates(v1, v2 versionCandidate) int {
	// If parsing fails, fall back to string comparison.
	if !v1.comparable || !v2.comparable {
		return strings.Compare(v1.value, v2.value)
	}

	if v1.major != v2.major {
		if v1.major < v2.major {
			return -1
		}
		return 1
	}

	if v1.minor != v2.minor {
		if v1.minor < v2.minor {
			return -1
		}
		return 1
	}

	if v1.patch != v2.patch {
		if v1.patch < v2.patch {
			return -1
		}
		return 1
	}

	return 0
}

func setHighestVersionCandidate(highest *versionCandidate, candidate versionCandidate) {
	if highest.value == "" || compareVersionCandidates(candidate, *highest) > 0 {
		*highest = candidate
	}
}

func parseVersionPartPrefix(version string) versionPartPrefix {
	version = strings.TrimPrefix(version, "v")
	part, rest, found := strings.Cut(version, ".")
	prefix := versionPartPrefix{
		first:  parseLeadingInt(part),
		length: 1,
	}
	if !found {
		return prefix
	}

	part, _, _ = strings.Cut(rest, ".")
	prefix.second = parseLeadingInt(part)
	prefix.length = 2
	return prefix
}

func parseLeadingInt(part string) int {
	digitEnd := 0
	for digitEnd < len(part) && part[digitEnd] >= '0' && part[digitEnd] <= '9' {
		digitEnd++
	}
	if digitEnd == 0 {
		return 0
	}
	num, err := strconv.Atoi(part[:digitEnd])
	if err != nil {
		return 0
	}
	return num
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

	installed := newVersionCandidate(installedVersion)
	installed.prefix = parseVersionPartPrefix(installedVersion)
	hasCommaSeparatedVersions := false
	var highestPatch, highestMinor, highestMajor, highestAny versionCandidate

	processCandidate := func(candidate string) {
		version := strings.TrimSpace(candidate)
		if version == "" {
			return
		}

		candidateVersion := newVersionCandidate(version)

		// Filter out versions that are not higher than installed version.
		if compareVersionCandidates(candidateVersion, installed) <= 0 {
			return
		}

		setHighestVersionCandidate(&highestAny, candidateVersion)

		// Group versions by upgrade type (even for single candidates to respect patch level).
		candidateVersion.prefix = parseVersionPartPrefix(version)
		switch {
		case candidateVersion.prefix.length >= 2 && installed.prefix.length >= 2 &&
			candidateVersion.prefix.first == installed.prefix.first && candidateVersion.prefix.second == installed.prefix.second:
			setHighestVersionCandidate(&highestPatch, candidateVersion)
		case candidateVersion.prefix.length >= 1 && installed.prefix.length >= 1 && candidateVersion.prefix.first == installed.prefix.first:
			setHighestVersionCandidate(&highestMinor, candidateVersion)
		default:
			setHighestVersionCandidate(&highestMajor, candidateVersion)
		}
	}

	for _, versionStr := range fixedVersions {
		if strings.Contains(versionStr, ",") {
			hasCommaSeparatedVersions = true
			for {
				part, rest, found := strings.Cut(versionStr, ",")
				processCandidate(part)
				if !found {
					break
				}
				versionStr = rest
			}
		} else {
			processCandidate(versionStr)
		}
	}

	if highestAny.value == "" {
		// If no valid candidates (no versions higher than installed), do not update.
		return ""
	}

	// Apply library patch level preference.
	switch libraryPatchLevel {
	case "patch":
		// Only update to patch versions, no fallback to minor/major.
		return highestPatch.value

	case "minor":
		// Only update to patch or minor versions, never major.
		if highestPatch.value != "" {
			return highestPatch.value
		}
		return highestMinor.value

	case "major":
		// For major patch level, the behavior depends on whether we have comma-separated versions.
		if hasCommaSeparatedVersions {
			// When comma-separated versions exist, prefer patch > minor > major for compatibility.
			if highestPatch.value != "" {
				return highestPatch.value
			}
			if highestMinor.value != "" {
				return highestMinor.value
			}
			return highestMajor.value
		}

		// When no comma-separated versions, pick the highest version to fix all CVEs.
		// While this approach fixes the most vulnerabilities, it may introduce breaking changes
		// or compatibility issues. Users should weigh the security benefits against the
		// potential risks of upgrading to a higher version.
		return highestAny.value

	default:
		// Default to patch behavior for invalid values.
		return highestPatch.value
	}
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
	return t.ParseWithPackageTypes(file, utils.PkgTypeOS+","+utils.PkgTypeLibrary, libraryPatchLevel)
}

func (t *TrivyParser) ParseWithPackageTypes(file, pkgTypes, libraryPatchLevel string) (*unversioned.UpdateManifest, error) {
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

	includeOS := strings.Contains(pkgTypes, utils.PkgTypeOS)
	includeLibrary := strings.Contains(pkgTypes, utils.PkgTypeLibrary)

	// Summary counts, tracked separately for OS and library so that
	// pkgTypes filtering in defaultParseScanReport can drop the irrelevant half.
	osSummary := &unversioned.PatchSummary{}
	libSummary := &unversioned.PatchSummary{}

	// Process Language packages - group by (name, pkgPath) to find optimal fixed version.
	// Using a composite key ensures the same package at different locations (e.g. system
	// Python vs a venv) is treated as a separate upgrade target.
	var langPackageFixedVersions map[string][]string
	var langPackageInfo map[string]unversioned.UpdatePackage
	// track all vulnerability IDs per lang package for VEX emission
	var langPackageVulnIDs map[string]map[string]struct{}
	if includeLibrary {
		langPackageFixedVersions = make(map[string][]string)
		langPackageInfo = make(map[string]unversioned.UpdatePackage)
		langPackageVulnIDs = make(map[string]map[string]struct{})
	}

	for i := range report.Results {
		r := &report.Results[i]

		// Process OS packages
		if includeOS && r.Class == "os-pkgs" {
			for v := range r.Vulnerabilities {
				vuln := &r.Vulnerabilities[v]
				osSummary.Total++
				if vuln.FixedVersion != "" {
					osSummary.Patched++
					updates.OSUpdates = append(updates.OSUpdates, unversioned.UpdatePackage{
						Name:             vuln.PkgName,
						Type:             string(r.Type),
						Class:            string(r.Class),
						FixedVersion:     vuln.FixedVersion,
						InstalledVersion: vuln.InstalledVersion,
						VulnerabilityID:  vuln.VulnerabilityID,
					})
				} else {
					osSummary.Skipped++
				}
			}
		}

		// Process Language packages
		if includeLibrary && r.Class == utils.LangPackages {
			// Check if this is a Python, Node.js, or Go related target
			if r.Type == utils.PythonPackages || r.Type == utils.NodePackages || r.Type == utils.GoModules || r.Type == utils.GoBinary {
				for v := range r.Vulnerabilities {
					vuln := &r.Vulnerabilities[v]
					libSummary.Total++
					// For gobinary results, Trivy puts the binary path in the Result's Target
					// field but may leave PkgPath empty (especially for stdlib vulns).
					// Fall back to Target so Copa can locate the binary for rebuilding.
					pkgPath := vuln.PkgPath
					if pkgPath == "" && r.Type == utils.GoBinary {
						pkgPath = string(r.Target)
					}
					if vuln.FixedVersion != "" {
						// Composite key: same package at different paths is a separate upgrade target.
						key := vuln.PkgName + "\x00" + pkgPath
						if _, exists := langPackageFixedVersions[key]; !exists {
							langPackageFixedVersions[key] = nil
							langPackageInfo[key] = unversioned.UpdatePackage{
								Name:             vuln.PkgName,
								Type:             string(r.Type),
								Class:            string(r.Class),
								InstalledVersion: vuln.InstalledVersion,
								PkgPath:          pkgPath,
							}
							langPackageVulnIDs[key] = make(map[string]struct{})
						}
						langPackageFixedVersions[key] = append(langPackageFixedVersions[key], vuln.FixedVersion)
						if vuln.VulnerabilityID != "" {
							langPackageVulnIDs[key][vuln.VulnerabilityID] = struct{}{}
						}
					} else {
						libSummary.Skipped++
					}
				}
			}

			// Check if this is a .NET-related target
			if r.Type == utils.DotNetPackages {
				for v := range r.Vulnerabilities {
					vuln := &r.Vulnerabilities[v]
					// Skip packages that cannot be patched via NuGet PackageReference:
					// - Microsoft.Build.* are SDK/build-time dependencies
					// - *.App.Runtime.* are DotnetPlatform packages (e.g. Microsoft.AspNetCore.App.Runtime.linux-x64,
					//   Microsoft.NETCore.App.Runtime.linux-x64) that fail dotnet restore with NU1213
					if strings.HasPrefix(vuln.PkgName, "Microsoft.Build.") || isUnpatchableDotnetRuntimePackage(vuln.PkgName) {
						libSummary.Total++
						libSummary.Skipped++
						continue
					}
					libSummary.Total++
					if vuln.FixedVersion != "" {
						key := vuln.PkgName + "\x00" + vuln.PkgPath
						if _, exists := langPackageFixedVersions[key]; !exists {
							langPackageFixedVersions[key] = nil
							langPackageInfo[key] = unversioned.UpdatePackage{
								Name:             vuln.PkgName,
								Type:             string(r.Type),
								Class:            string(r.Class),
								InstalledVersion: vuln.InstalledVersion,
								PkgPath:          vuln.PkgPath,
							}
							langPackageVulnIDs[key] = make(map[string]struct{})
						}
						langPackageFixedVersions[key] = append(langPackageFixedVersions[key], vuln.FixedVersion)
						if vuln.VulnerabilityID != "" {
							langPackageVulnIDs[key][vuln.VulnerabilityID] = struct{}{}
						}
					} else {
						libSummary.Skipped++
					}
				}
			}
		}
	}

	// Process Language packages to find optimal fixed versions.
	// The key is a composite of PkgName + NUL + PkgPath.
	for key, fixedVersionValues := range langPackageFixedVersions {
		fixedVersions := make([]string, 0, len(fixedVersionValues))

		for _, fixedVersion := range fixedVersionValues {
			if fixedVersion == "" {
				continue
			}
			// Handle comma-separated fixed versions. Keep this split here to preserve
			// existing ParseWithLibraryPatchLevel behavior.
			if strings.Contains(fixedVersion, ",") {
				for {
					version, rest, found := strings.Cut(fixedVersion, ",")
					version = strings.TrimSpace(version)
					if version != "" {
						fixedVersions = append(fixedVersions, version)
					}
					if !found {
						break
					}
					fixedVersion = rest
				}
			} else {
				fixedVersions = append(fixedVersions, fixedVersion)
			}
		}

		if len(fixedVersions) > 0 {
			info, ok := langPackageInfo[key]
			if !ok {
				// Defensive: skip if info not recorded (shouldn't happen)
				continue
			}

			// Determine patch level to use, with special handling for certain packages.
			// Use info.Name (the actual package name) not the composite key.
			patchLevelToUse := libraryPatchLevel
			if specialPatchLevel, exists := specialPackagePatchLevels[info.Name]; exists {
				patchLevelToUse = specialPatchLevel
			}

			optimalVersion := FindOptimalFixedVersionWithPatchLevel(info.InstalledVersion, fixedVersions, patchLevelToUse)

			// Count CVEs in this package group for the library summary.
			// If patch-level constraints prevent patching (optimalVersion == ""),
			// these vulns had a fix but it couldn't be applied — count as skipped.
			vulnCount := len(langPackageVulnIDs[key])
			if vulnCount == 0 {
				// Defensive: langPackageVulnIDs is populated alongside langPackageVulns,
				// so this key should always have at least one entry. Guard against
				// unexpected desync to ensure we never silently drop a count.
				vulnCount = 1
			}
			if optimalVersion != "" {
				libSummary.Patched += vulnCount
			} else {
				libSummary.Skipped += vulnCount
			}

			if idsMap, ok2 := langPackageVulnIDs[key]; ok2 {
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

	if includeOS {
		updates.OSSummary = osSummary
	}
	if includeLibrary {
		updates.LibrarySummary = libSummary
	}

	return &updates, nil
}
