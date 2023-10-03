// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package report

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/project-copacetic/copacetic/pkg/types"
)

type ErrorUnsupported struct {
	err error
}

func (e *ErrorUnsupported) Error() string { return e.err.Error() }

type ScanReportParser interface {
	Parse(string) (*types.UpdateManifest, error)
}

func TryParseScanReport(file, scanner string) (*types.UpdateManifest, error) {

	if scanner == "" {
		return defaultParseScanReport(file)
	} else {
		return customParseScanReport(file, scanner)
	}
}

func customParseScanReport(file, scanner string) (*types.UpdateManifest, error) {

	// Execute the plugin binary
	scannerCommand := exec.Command(scanner, file)
	// Capture the output
	scannerOutput, err := scannerCommand.CombinedOutput()

	if err != nil {
		return nil, fmt.Errorf("error running scanner %s: %w", scanner, err)
	}
	// Convert the output to a UpdateManifest struct
	var um types.UpdateManifest
	if err := json.Unmarshal(scannerOutput, &um); err != nil {
		return nil, fmt.Errorf("error parsing scanner output: %w", err)
	}

	return &um, nil
}

func defaultParseScanReport(file string) (*types.UpdateManifest, error) {

	allParsers := []ScanReportParser{
		&TrivyParser{},
		&QualysParser{},
	}
	for _, parser := range allParsers {
		manifest, err := parser.Parse(file)
		if err == nil {
			return manifest, nil
		} else if _, ok := err.(*ErrorUnsupported); ok {
			continue
		} else {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%s is not a supported scan report format", file)
}
