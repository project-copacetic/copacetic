package report

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
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
				Arch:    report.Metadata.ImageConfig.Architecture,
			},
		},
	}


	// Precondition check
	result := trivyTypes.Result{}
	for i := range report.Results {
		r := &report.Results[i]
		if r.Class == "os-pkgs" {
			if result.Class != "" {
				return nil, errors.New("unexpected multiple results for os-pkgs")
			}
			for v := range r.Vulnerabilities {
				vuln := &r.Vulnerabilities[v]
				if vuln.FixedVersion != "" {
					updates.Updates = append(updates.Updates, unversioned.UpdatePackage{
						Name: vuln.PkgName,
						Type: string(r.Type),
						Class: string(r.Class),
						FixedVersion: vuln.FixedVersion,
					})
				}
			}
		}
		if r.Class == "lang-pkgs" {
			if r.Target == "Python" {
				for v := range r.Vulnerabilities {
					vuln := &r.Vulnerabilities[v]
					if vuln.FixedVersion != "" {
						// TODO(sertac): handle multiple fixed versions
						// For now, just take the first one if there are multiple
						if strings.Contains(vuln.FixedVersion, ",") {
							splitVersions := strings.Split(vuln.FixedVersion, ",")
							vuln.FixedVersion = strings.TrimSpace(splitVersions[0])
						}

						updates.LangUpdates = append(updates.LangUpdates, unversioned.UpdatePackage{
							Name: vuln.PkgName,
							Type: string(r.Type),
							Class: string(r.Class),
							FixedVersion: vuln.FixedVersion,
						})
					}
				}
			}
		}
	}



	for i := range result.Vulnerabilities {
		vuln := &result.Vulnerabilities[i]
		if vuln.FixedVersion != "" {
			updates.Updates = append(updates.Updates, unversioned.UpdatePackage{
				Name:             vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				VulnerabilityID:  vuln.VulnerabilityID,
			})
		}
	}

	return &updates, nil
}
