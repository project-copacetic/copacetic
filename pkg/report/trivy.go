// Package report contains parsers and helpers for vulnerability scan reports (e.g., Trivy).
package report

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
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

// findOptimalFixedVersion finds the best version that fixes the most CVEs while being most compatible.
// See FindOptimalFixedVersionWithPatchLevel for how fixedVersions is interpreted.
func findOptimalFixedVersion(installedVersion string, fixedVersions []string) string {
	return FindOptimalFixedVersionWithPatchLevel(installedVersion, fixedVersions, "patch")
}

// splitFixedVersions splits the fixed versions Trivy reports for a single CVE
// (for example "6.29.1, 7.30.1, 8.12.2") into trimmed, non-empty versions.
func splitFixedVersions(fixed string) []versionCandidate {
	var versions []versionCandidate
	for part := range strings.SplitSeq(fixed, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		candidate := newVersionCandidate(part)
		candidate.prefix = parseVersionPartPrefix(part)
		versions = append(versions, candidate)
	}
	return versions
}

// allowedByPatchLevel reports whether upgrading from installed to candidate stays
// within the given library patch level. Unknown levels behave like "patch".
func allowedByPatchLevel(installed, candidate versionCandidate, libraryPatchLevel string) bool {
	switch libraryPatchLevel {
	case "major":
		return true
	case "minor":
		return candidate.prefix.length >= 1 && installed.prefix.length >= 1 &&
			candidate.prefix.first == installed.prefix.first
	default:
		return candidate.prefix.length >= 2 && installed.prefix.length >= 2 &&
			candidate.prefix.first == installed.prefix.first && candidate.prefix.second == installed.prefix.second
	}
}

// versionFixesVulnerability reports whether installing version resolves a CVE with
// the given Trivy FixedVersion, a comma-separated list with one fix per supported
// release line. A version resolves the CVE when it is at or above the fix on its
// closest release line (same major.minor, else same major), or above every listed
// fix when none shares its major.
func versionFixesVulnerability(version, fixed string) bool {
	candidate := newVersionCandidate(version)
	candidate.prefix = parseVersionPartPrefix(version)
	return candidateFixesVulnerability(candidate, splitFixedVersions(fixed))
}

// candidateFixesVulnerability compares the candidate against the fix on its closest
// release line: the listed fixes sharing its major.minor, else those sharing its
// major. The highest of those decides. When no fix shares the candidate's major,
// the candidate only fixes the CVE if it is above every listed fix.
func candidateFixesVulnerability(candidate versionCandidate, fixed []versionCandidate) bool {
	if len(fixed) == 0 {
		return false
	}
	var sameMajor, sameMinor *versionCandidate
	aboveAll := true
	for i := range fixed {
		f := &fixed[i]
		if compareVersionCandidates(*f, candidate) >= 0 {
			aboveAll = false
		}
		if f.prefix.first != candidate.prefix.first {
			continue
		}
		if sameMajor == nil || compareVersionCandidates(*f, *sameMajor) > 0 {
			sameMajor = f
		}
		if f.prefix.second == candidate.prefix.second &&
			(sameMinor == nil || compareVersionCandidates(*f, *sameMinor) > 0) {
			sameMinor = f
		}
	}
	closest := sameMinor
	if closest == nil {
		closest = sameMajor
	}
	if closest == nil {
		return aboveAll
	}
	return compareVersionCandidates(*closest, candidate) <= 0
}

// FindOptimalFixedVersionWithPatchLevel picks the version to upgrade a package to.
//
// Each element of fixedVersions holds the FixedVersion reported for one CVE, which
// may be a comma-separated list of alternative fixes on different release lines
// (for example "6.29.1, 7.30.1, 8.12.2"). The result is the lowest version that is
// newer than installedVersion, is allowed by libraryPatchLevel, and fixes the
// largest number of CVEs. It returns "" when no allowed version fixes any CVE.
//
// libraryPatchLevel can be "patch", "minor", or "major":
//   - "patch": only updates within the installed major.minor
//   - "minor": only updates within the installed major
//   - "major": any newer version
func FindOptimalFixedVersionWithPatchLevel(installedVersion string, fixedVersions []string, libraryPatchLevel string) string {
	installed := newVersionCandidate(installedVersion)
	installed.prefix = parseVersionPartPrefix(installedVersion)

	cves := make([][]versionCandidate, 0, len(fixedVersions))
	var candidates []versionCandidate
	for _, fixed := range fixedVersions {
		versions := splitFixedVersions(fixed)
		if len(versions) == 0 {
			continue
		}
		cves = append(cves, versions)
		for _, v := range versions {
			// Only versions newer than the installed one that the patch level allows can be installed.
			if compareVersionCandidates(v, installed) > 0 && allowedByPatchLevel(installed, v, libraryPatchLevel) {
				candidates = append(candidates, v)
			}
		}
	}

	// Walk the candidates from lowest to highest so that ties keep the smallest upgrade.
	slices.SortStableFunc(candidates, compareVersionCandidates)
	best, bestFixed := "", 0
	for _, candidate := range candidates {
		fixedCount := 0
		for _, versions := range cves {
			if candidateFixesVulnerability(candidate, versions) {
				fixedCount++
			}
		}
		if fixedCount > bestFixed {
			best, bestFixed = candidate.value, fixedCount
		}
	}
	return best
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
	// track all vulnerability IDs per lang package (with the fixed versions reported
	// for each) for VEX emission and the patch summary
	var langPackageVulnIDs map[string]map[string][]string
	if includeLibrary {
		langPackageFixedVersions = make(map[string][]string)
		langPackageInfo = make(map[string]unversioned.UpdatePackage)
		langPackageVulnIDs = make(map[string]map[string][]string)
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
							langPackageVulnIDs[key] = make(map[string][]string)
						}
						langPackageFixedVersions[key] = append(langPackageFixedVersions[key], vuln.FixedVersion)
						if vuln.VulnerabilityID != "" {
							langPackageVulnIDs[key][vuln.VulnerabilityID] = append(langPackageVulnIDs[key][vuln.VulnerabilityID], vuln.FixedVersion)
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
							langPackageVulnIDs[key] = make(map[string][]string)
						}
						langPackageFixedVersions[key] = append(langPackageFixedVersions[key], vuln.FixedVersion)
						if vuln.VulnerabilityID != "" {
							langPackageVulnIDs[key][vuln.VulnerabilityID] = append(langPackageVulnIDs[key][vuln.VulnerabilityID], vuln.FixedVersion)
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
		// Each entry holds the FixedVersion of one vulnerability and may be a
		// comma-separated list. Keep them grouped per vulnerability so the selection
		// can tell which CVEs a candidate version actually fixes.
		fixedVersions := make([]string, 0, len(fixedVersionValues))
		for _, fixedVersion := range fixedVersionValues {
			if strings.TrimSpace(fixedVersion) != "" {
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

			idsMap := langPackageVulnIDs[key]
			if len(idsMap) == 0 {
				// Defensive: langPackageVulnIDs is populated alongside langPackageFixedVersions,
				// so this key should always have at least one entry. Guard against
				// unexpected desync to ensure we never silently drop a count.
				if optimalVersion != "" {
					libSummary.Patched++
				} else {
					libSummary.Skipped++
				}
				continue
			}

			ids := make([]string, 0, len(idsMap))
			for id := range idsMap {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, vid := range ids {
				// A vulnerability counts as patched only if the selected version fixes it.
				// If patch-level constraints prevent patching (optimalVersion == ""), or the
				// selected version is still affected, the vulnerability had a fix that
				// couldn't be applied, so count it as skipped and don't report it as fixed.
				fixed := optimalVersion != ""
				for _, fixedVersion := range idsMap[vid] {
					if !versionFixesVulnerability(optimalVersion, fixedVersion) {
						fixed = false
						break
					}
				}

				clone := info
				clone.VulnerabilityID = vid
				if fixed {
					clone.FixedVersion = optimalVersion
					libSummary.Patched++
				} else {
					libSummary.Skipped++
				}
				updates.LangUpdates = append(updates.LangUpdates, clone)
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
