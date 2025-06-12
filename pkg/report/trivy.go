package report

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	log "github.com/sirupsen/logrus"
)

type TrivyParser struct{}

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

// extractAppropriateFixedVersion selects the most appropriate fixed version from a comma-separated list.
// For Node.js packages, we prefer to stay within the same major version if possible.
func extractAppropriateFixedVersion(installedVersion, fixedVersions string) string {
	// If there's only one version, return it
	if !strings.Contains(fixedVersions, ",") {
		return strings.TrimSpace(fixedVersions)
	}

	// Split the versions
	versions := strings.Split(fixedVersions, ",")

	// Extract major version from installed version
	installedParts := strings.Split(installedVersion, ".")
	if len(installedParts) == 0 {
		// If we can't parse, just return the first fixed version
		return strings.TrimSpace(versions[0])
	}
	installedMajor := installedParts[0]

	// Look for a fixed version with the same major version
	for _, v := range versions {
		v = strings.TrimSpace(v)
		fixedParts := strings.Split(v, ".")
		if len(fixedParts) > 0 && fixedParts[0] == installedMajor {
			return v
		}
	}

	// If no same-major version found, return the first one
	// This might require manual intervention but it's better than nothing
	return strings.TrimSpace(versions[0])
}

func (t *TrivyParser) Parse(file string) (*unversioned.UpdateManifest, error) {
	report, err := parseTrivyReport(file)
	if err != nil {
		return nil, err
	}

	// Find OS packages result
	var osResult *trivyTypes.Result
	var nodeResult *trivyTypes.Result

	for i := range report.Results {
		r := &report.Results[i]
		switch r.Class {
		case trivyTypes.ClassOSPkg:
			if osResult != nil {
				return nil, errors.New("unexpected multiple results for os-pkgs")
			}
			osResult = r
		case trivyTypes.ClassLangPkg:
			// Check if this is a Node.js/npm result
			if r.Type == "npm" || r.Type == "nodejs" || r.Type == "yarn" || r.Type == "pnpm" || r.Type == "node-pkg" {
				log.Infof("Found Node.js vulnerabilities in %s", r.Target)
				nodeResult = r
			}
		}
	}

	// Initialize the update manifest
	updates := unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    string(report.Metadata.OS.Family),
				Version: report.Metadata.OS.Name,
			},
			Config: unversioned.Config{
				Arch:    report.Metadata.ImageConfig.Architecture,
				Variant: report.Metadata.ImageConfig.Variant,
			},
		},
	}

	// Count updates for logging
	osUpdateCount := 0
	nodeUpdateCount := 0

	// Process OS package vulnerabilities
	if osResult != nil {
		for i := range osResult.Vulnerabilities {
			vuln := &osResult.Vulnerabilities[i]
			if vuln.FixedVersion != "" {
				updates.Updates = append(updates.Updates, unversioned.UpdatePackage{
					Name:             vuln.PkgName,
					InstalledVersion: vuln.InstalledVersion,
					FixedVersion:     vuln.FixedVersion,
					VulnerabilityID:  vuln.VulnerabilityID,
				})
				osUpdateCount++
			}
		}
	}

	// Process Node.js package vulnerabilities
	if nodeResult != nil {
		for i := range nodeResult.Vulnerabilities {
			vuln := &nodeResult.Vulnerabilities[i]
			if vuln.FixedVersion != "" {
				// Extract the most appropriate fixed version for Node.js packages
				fixedVersion := extractAppropriateFixedVersion(vuln.InstalledVersion, vuln.FixedVersion)
				if fixedVersion != "" {
					updates.NodeUpdates = append(updates.NodeUpdates, unversioned.UpdatePackage{
						Name:             vuln.PkgName,
						InstalledVersion: vuln.InstalledVersion,
						FixedVersion:     fixedVersion,
						VulnerabilityID:  vuln.VulnerabilityID,
					})
					nodeUpdateCount++
				}
			}
		}
	}

	// Log summary of found updates
	log.Infof("Found %d OS package updates and %d Node.js package updates", osUpdateCount, nodeUpdateCount)

	// Check if we have any patchable vulnerabilities
	if osResult == nil && nodeResult == nil {
		return nil, errors.New("no scanning results for os-pkgs or node-pkg found")
	}

	return &updates, nil
}
