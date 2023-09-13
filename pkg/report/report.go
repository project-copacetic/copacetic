// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package report

import (
	"fmt"
	"os"
	"plugin"

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
		return defaultParse(file)
	} else {
		return pluginParse(file, scanner)
	}
}

func pluginParse(file, scanner string) (*types.UpdateManifest, error) {
	// Define the path where all copa plugins are located
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("%s/.copa/plugins/%s.so", home, scanner)

	// load module
	plug, err := plugin.Open(path)
	if err != nil {
		return nil, err
	}

	// look up symbol (an exported function or variable)
	// in this case, variable Parser
	symPluginParser, err := plug.Lookup("Parser")
	if err != nil {
		return nil, err
	}

	// Assert that the variable is of the expected type and get its value
	var reportParser ScanReportParser
	reportParser, ok := symPluginParser.(ScanReportParser)
	if !ok {
		return nil, fmt.Errorf("unexpected type from module symbol")
	}

	// Call the plugin's Parse function
	return reportParser.Parse(file)
}

func defaultParse(file string) (*types.UpdateManifest, error) {
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
