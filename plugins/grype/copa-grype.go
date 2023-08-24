package main

import (
	"encoding/json"
	"errors"
	"os"

	grypeTypes "github.com/anchore/grype/grype/presenter/models"
	"github.com/project-copacetic/copacetic/pkg/types"
)

type grypeParser struct{}

func parseGrypeReport(file string) (*grypeTypes.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var gr grypeTypes.Document
	if err = json.Unmarshal(data, &gr); err != nil {
		return nil, err
	}

	return &gr, nil
}

func (gp *grypeParser) Parse(file string) (*types.UpdateManifest, error) {
	// Parse the grype scan results
	report, err := parseGrypeReport(file)
	if err != nil {
		return nil, err
	}

	// Unmarshal function is not able to detect if the report is in the correct format. It returns no error even if the report is in the wrong format.
	// Therefore, we check if the report is in the correct format by parsing the Descriptor Name
	// If the name does not contain grype, then it is not in the correct format, report is marked as unsupported
	if report.Descriptor.Name != "grype" {
		return nil, errors.New("report format not supported by grype")
	}

	if err != nil {
		return nil, err
	}

	updates := types.UpdateManifest{
		OSType:    report.Distro.Name,
		OSVersion: report.Distro.Version,
		Arch:      report.Source.Target.(map[string]interface{})["architecture"].(string),
	}

	// Check if vulnerability is OS-lvl package & check if vulnerability is fixable
	for i := range report.Matches {
		vuln := &report.Matches[i]
		if vuln.Artifact.Language == "" && vuln.Vulnerability.Fix.State == "fixed" {
			updates.Updates = append(updates.Updates, types.UpdatePackage{Name: vuln.Artifact.Name, Version: vuln.Vulnerability.Fix.Versions[0]})
		}
	}
	return &updates, nil
}

var Parser grypeParser