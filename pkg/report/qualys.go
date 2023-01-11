// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package report

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/antchfx/xmlquery"
	"github.com/project-copacetic/copacetic/pkg/types"
	log "github.com/sirupsen/logrus"
)

const (
	osXPathQuery = "//HOST/OS"
	// FLAGS semantics are undocumented, but 'v' seems to indicate upgrade package info exists
	// TODO: Replace with more universal approach. This only applies to DPKG-based images (Debian, Ubunutu, Google Distroless).
	//       It does not currently work for APK/RPM-based images. May require Enrichment phase data to be useful.
	vulnXPathQuery = "//HOST/VULN[FLAGS='u,v']/RESULT"
	vulnDataHeader = "#table cols=\"3\"\nPackage Installed_Version Required_Version\n"
)

type QualysParser struct{}

type osInfo struct {
	family  string
	version string
}

func parseQualysOSInfo(osNode *xmlquery.Node) (*osInfo, error) {
	// Based on sample string: "Debian Linux 11.2"
	tokens := strings.Split(osNode.InnerText(), " ")
	if len(tokens) == 3 && strings.EqualFold(tokens[1], "Linux") {
		if _, err := semver.NewVersion(tokens[2]); err != nil {
			log.Errorf("failed to parse OS version: %s", osNode.InnerText())
			return nil, err
		}
		// note that we case fold to lower the OS family names
		out := osInfo{family: strings.ToLower(tokens[0]), version: tokens[2]}
		return &out, nil
	}
	return nil, errors.New("report is for unsupported non-Linux OS")
}

func parseQualysUpdatePackages(resultNode *xmlquery.Node) (types.UpdatePackages, error) {
	// Based on sample string in CDATA (note inclusion of newlines):
	// #table cols="3"
	// Package Installed_Version Required_Version
	// libexpat1 2.2.10-2 2.2.10-2+deb11u2
	// ... <1:n> entries
	text := resultNode.InnerText()
	if !strings.HasPrefix(text, vulnDataHeader) {
		err := fmt.Errorf("unexpected RESULT node text: %s", text)
		log.Error(err)
		return nil, err
	}
	updates := types.UpdatePackages{}
	lines := strings.Split(text[len(vulnDataHeader):], "\n")
	for _, line := range lines {
		tokens := strings.Split(line, " ")
		if len(tokens) != 3 {
			err := fmt.Errorf("unexpected RESULT node text: %s", text)
			log.Error(err)
			return nil, err
		}
		updates = append(updates, types.UpdatePackage{Name: tokens[0], Version: tokens[2]})
	}
	return updates, nil
}

func (t *QualysParser) Parse(file string) (*types.UpdateManifest, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	doc, err := xmlquery.Parse(f)
	if err != nil {
		return nil, &ErrorUnsupported{err}
	}

	// No published Qualys XML schema for the report, so we can't distinguish between trying to
	// parse a non-Qualys report and Qualys report without patchable vulnerabilities.
	// Use the other necessary metadata fields to catch the former case where possible so that the report can
	// can be marked as unsupported and passed on to the next parser.
	osNodes := xmlquery.Find(doc, osXPathQuery)
	if len(osNodes) != 1 {
		err := fmt.Errorf("%d XML nodes for %s found, does not match expected Qualys report schema", len(osNodes), osXPathQuery)
		log.Debug(err)
		return nil, &ErrorUnsupported{err}
	}
	vulnerabilities := xmlquery.Find(doc, vulnXPathQuery)
	if len(vulnerabilities) == 0 {
		log.Warnf("No elements matching xpath: %s", vulnXPathQuery)
	}

	// Parse OS and version from `os`
	osInfo, err := parseQualysOSInfo(osNodes[0])
	if err != nil {
		return nil, err
	}

	updates := types.UpdateManifest{
		OSType:    osInfo.family,
		OSVersion: osInfo.version,
		// TODO: Qualys report does not specify arch, may need to infer this
		// from elsewhere in the report (e.g. package file name qualifiers)
		Arch: "amd64",
	}

	for _, node := range vulnerabilities {
		update, err := parseQualysUpdatePackages(node)
		if err != nil {
			return nil, err
		}
		updates.Updates = append(updates.Updates, update...)
	}
	return &updates, nil
}
