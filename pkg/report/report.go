package report

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
	"github.com/project-copacetic/copacetic/pkg/types/v1alpha2"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

const (
	v1alpha1APIVersion = "v1alpha1"
	v1alpha2APIVersion = "v1alpha2"
)

type ErrorUnsupported struct {
	err error
}

func (e *ErrorUnsupported) Error() string { return e.err.Error() }

type ScanReportParser interface {
	Parse(string) (*unversioned.UpdateManifest, error)
	ParseWithLibraryPatchLevel(string, string) (*unversioned.UpdateManifest, error)
}

// PatchSummary captures vulnerability patching visibility for a scan report.
type PatchSummary struct {
	TotalVulnerabilities int
	Patched              int
	PatchedOS            int
	PatchedLibrary       int
	SkippedNoFix         int
}

func TryParseScanReport(file, scanner, pkgTypes, libraryPatchLevel string) (*unversioned.UpdateManifest, error) {
	if scanner == "trivy" {
		return defaultParseScanReport(file, pkgTypes, libraryPatchLevel)
	}
	return customParseScanReport(file, scanner)
}

// TrySummarizeScanReport returns patchability summary details for supported scanners.
// For unsupported scanners, it returns (nil, nil).
func TrySummarizeScanReport(file, scanner, pkgTypes string) (*PatchSummary, error) {
	if scanner == "trivy" {
		return summarizeTrivyReport(file, pkgTypes)
	}
	return nil, nil
}

func customParseScanReport(file, scanner string) (*unversioned.UpdateManifest, error) {
	var scannerOutput []byte
	var err error

	if scanner != "native" {
		// Execute the plugin binary
		cmd := "copa-" + scanner
		scannerCommand := exec.Command(cmd, file)
		// Capture the output
		scannerOutput, err = scannerCommand.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("error running scanner %s: %w", scanner, err)
		}
	} else {
		// Read the file directly if they are in v1alpha1 format
		scannerOutput, err = os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("error reading file %s: %w", file, err)
		}
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

func defaultParseScanReport(file, pkgTypes, libraryPatchLevel string) (*unversioned.UpdateManifest, error) {
	allParsers := []ScanReportParser{
		&TrivyParser{},
	}
	for _, parser := range allParsers {
		manifest, err := parser.ParseWithLibraryPatchLevel(file, libraryPatchLevel)
		if err == nil {
			// Filter updates based on pkg-types early
			if manifest != nil {
				// Only process library updates if "library" is in pkg-types
				if !strings.Contains(pkgTypes, utils.PkgTypeLibrary) {
					manifest.LangUpdates = []unversioned.UpdatePackage{}
				}
				// Only process OS updates if "os" is in pkg-types
				if !strings.Contains(pkgTypes, utils.PkgTypeOS) {
					manifest.OSUpdates = []unversioned.UpdatePackage{}
				}
			}
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
		if v == v1alpha1APIVersion {
			um, err := v1alpha1.ConvertV1alpha1UpdateManifestToUnversionedUpdateManifest(scannerOutput)
			return um, err
		}
		if v == v1alpha2APIVersion {
			um, err := v1alpha2.ConvertV1alpha2UpdateManifestToUnversionedUpdateManifest(scannerOutput)
			return um, err
		}
		return nil, &ErrorUnsupported{fmt.Errorf("unsupported apiVersion: %s", v)}
	default:
		return nil, &ErrorUnsupported{fmt.Errorf("unsupported apiVersion type: %v", v)}
	}
}
