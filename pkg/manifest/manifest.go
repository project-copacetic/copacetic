package manifest

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/project-copacetic/copacetic/pkg/types"
)

// Really hacky way for now
func DiscoverPlatforms(imageRef, reportDir string) ([]types.Platform, error) {
	// read in from the report directory
	// and match with the image reference
	reports, err := os.ReadDir(reportDir)
	if err != nil {
		return nil, err
	}

	// only take json files with prefix of report-
	filteredReports := []os.DirEntry{}
	for _, report := range reports {
		if report.IsDir() {
			continue
		}
		if !strings.HasPrefix(report.Name(), "report-") {
			continue
		}
		filteredReports = append(filteredReports, report)
	}

	platforms := []types.Platform{}
	for _, report := range filteredReports {
		// parse json
		reportPath := reportDir + "/" + report.Name()
		reportFile, err := os.Open(reportPath)
		if err != nil {
			return nil, err
		}
		defer reportFile.Close()

		var reportData map[string]interface{}
		err = json.NewDecoder(reportFile).Decode(&reportData)
		if err != nil {
			return nil, err
		}
		// get the os from the field "Metadata.ImageConfig.os"
		// hacky way:
		metadata := reportData["Metadata"].(map[string]interface{})
		imageConfig := metadata["ImageConfig"].(map[string]interface{})
		os := imageConfig["os"].(string)
		arch := imageConfig["architecture"].(string)
		digest := metadata["ImageID"].(string)

		platform := types.Platform{
			OS:         os,
			Arch:       arch,
			Variant:    "",
			Digest:     digest,
			ReportPath: reportDir + "/" + report.Name(),
		}
		platforms = append(platforms, platform)
	}

	return platforms, nil
}
