// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package report

import (
	"fmt"

	"github.com/project-copacetic/copacetic/pkg/types"
)

type ErrorUnsupported struct {
	err error
}

func (e *ErrorUnsupported) Error() string { return e.err.Error() }

type ScanReportParser interface {
	Parse(string) (*types.UpdateManifest, error)
}

func TryParseScanReport(file string) (*types.UpdateManifest, error) {
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
