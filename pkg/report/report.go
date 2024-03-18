package report

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

type ErrorUnsupported struct {
	err error
}

func (e *ErrorUnsupported) Error() string { return e.err.Error() }

type ScanReportParser interface {
	Parse(string) (*unversioned.UpdateManifest, error)
}

func TryParseScanReport(file, scanner string) (*unversioned.UpdateManifest, error) {
	if scanner == "trivy" {
		return defaultParseScanReport(file)
	}
	return customParseScanReport(file, scanner)
}

func customParseScanReport(file, scanner string) (*unversioned.UpdateManifest, error) {
	// Execute the plugin binary
	cmd := "copa-" + scanner
	scannerCommand := exec.Command(cmd, file)
	// Capture the output
	scannerOutput, err := scannerCommand.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error running scanner %s: %w", scanner, err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(scannerOutput, &m); err != nil {
		return nil, fmt.Errorf("error parsing scanner output: %w", err)
	}

	// Convert the output to an unversioned UpdateManifest struct
	updateManifest, err := convertToUnversionedAPI(scannerOutput, m)
	if err != nil {
		return nil, err
	}

	return updateManifest, nil
}

func defaultParseScanReport(file string) (*unversioned.UpdateManifest, error) {
	allParsers := []ScanReportParser{
		&TrivyParser{},
	}
	for _, parser := range allParsers {
		manifest, err := parser.Parse(file)
		if err == nil {
			return manifest, nil
		} else if _, ok := err.(*ErrorUnsupported); ok {
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("%s is not a supported scan report format", file)
}

func convertToUnversionedAPI(scannerOutput []byte, m map[string]interface{}) (*unversioned.UpdateManifest, error) {
	switch v := m["apiVersion"].(type) {
	case string:
		if v == "v1alpha1" {
			um, err := v1alpha1.ConvertV1alpha1UpdateManifestToUnversionedUpdateManifest(scannerOutput)
			return um, err
		}
		return nil, &ErrorUnsupported{fmt.Errorf("unsupported apiVersion: %s", v)}
	default:
		return nil, &ErrorUnsupported{fmt.Errorf("unsupported apiVersion type: %v", v)}
	}
}
