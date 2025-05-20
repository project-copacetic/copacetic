package wiz

import (
	"encoding/json"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"os"
)

type WizParser struct{}

func parseWizReport(file string) (*WizFakeReport, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var msr WizFakeReport
	if err = json.Unmarshal(data, &msr); err != nil {
		return nil, &WizErrorUnsupported{err}
	}
	return &msr, nil
}

func NewWizParser() *WizParser {
	return &WizParser{}
}

func (w *WizParser) Parse(file string) (*unversioned.UpdateManifest, error) {
	wizFakeReport, err := parseWizReport(file)
	if err != nil {
		return nil, err
	}

	// TODO: Implement the parsing logic according to the Wiz report structure
	// pseudo code:
	updates := unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    wizFakeReport.OSType,
				Version: wizFakeReport.OSVersion,
			},
			Config: unversioned.Config{
				Arch: wizFakeReport.Arch,
			},
		},
	}

	for _, pkg := range wizFakeReport.Packages {
		updates.Updates = append(updates.Updates, unversioned.UpdatePackage{
			Name:             pkg.Name,
			InstalledVersion: pkg.InstalledVersion,
			FixedVersion:     pkg.FixedVersion,
			VulnerabilityID:  pkg.VulnerabilityID,
		})
	}

	return &updates, nil
}
