// Package vex contains logic for generating VEX (Vulnerability Exploitability eXchange) documents.
package vex

import (
	"bytes"
	"net/url"
	"os"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// test seams for time and id generation.
var (
	now        = time.Now
	generateID = func(doc *vex.VEX) (string, error) { return doc.GenerateCanonicalID() }
)

type OpenVex struct{}

func (o *OpenVex) CreateVEXDocument(
	updates *unversioned.UpdateManifest,
	patchedImageName string,
	pkgType string,
) (string, error) {
	doc, err := o.createVEXDocument(updates, patchedImageName, pkgType)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := doc.ToJSON(&buf); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (o *OpenVex) createVEXDocument(
	updates *unversioned.UpdateManifest,
	patchedImageName string,
	pkgType string,
) (*vex.VEX, error) {
	t := now()
	// construct a fresh VEX document per invocation (thread-safe, no shared state)
	doc := &vex.VEX{Metadata: vex.Metadata{
		Context: vex.Context,
		Author:  "Project Copacetic",
		Tooling: "Project Copacetic",
		Version: 1,
	}}
	doc.Timestamp = &t

	// set author from environment variable if it exists
	author := os.Getenv("COPA_VEX_AUTHOR")
	if author != "" {
		doc.Author = author
	}

	id, err := generateID(doc)
	if err != nil {
		return nil, err
	}
	doc.ID = id

	imageProduct := vex.Product{
		Component: vex.Component{
			ID: "pkg:oci/" + patchedImageName,
		},
	}
	pt := utils.CanonicalPkgManagerType(pkgType) // base OS package manager type (apk, deb, rpm)
	osPackagePrefix := "pkg:" + pt + "/" + updates.Metadata.OS.Type + "/"
	osPackageQualifierSuffix := osPackageQualifiers(updates)
	totalUpdates := len(updates.OSUpdates) + len(updates.LangUpdates)
	initialStatementCapacity := min(totalUpdates, 512)
	doc.Statements = make([]vex.Statement, 0, initialStatementCapacity)
	statementByVulnerability := make(map[string]int, initialStatementCapacity)
	seenSubcomponents := make(map[vexSubcomponentKey]struct{}, totalUpdates)

	// helper closure to add a single update (OS or language) to the VEX doc
	addUpdate := func(u unversioned.UpdatePackage) {
		// skip entries without vulnerability IDs; VEX statements represent fixed vulns
		if u.VulnerabilityID == "" {
			log.Debugf("skipping update %s: empty vulnerability id for VEX", u.Name)
			return
		}
		// skip if no fixed version resolved (not actually patched)
		if u.FixedVersion == "" {
			log.Debugf("skipping update %s: empty fixed version (no patch applied)", u.Name)
			return
		}
		// skip if installed version equals fixed version (no change performed)
		if u.InstalledVersion != "" && u.FixedVersion == u.InstalledVersion {
			log.Debugf("skipping update %s: fixed version equals installed version (%s)", u.Name, u.FixedVersion)
			return
		}
		langType := u.Type

		// Use InstalledVersion (vulnerable) for BOM-VEX correlation: the subcomponent
		// PURL should match the input scan/BOM so consumers can map VEX statements back
		// to the original vulnerability report. Fall back to FixedVersion if unavailable.
		purlVersion := u.InstalledVersion
		if purlVersion == "" {
			purlVersion = u.FixedVersion
		}

		var componentID string
		if langType == utils.PythonPackages { // treat python-pkg as coming from PyPI for purl standardization
			// Standard PyPI purl form: pkg:pypi/<name>@<version>
			componentID = "pkg:pypi/" + u.Name + "@" + purlVersion
		} else {
			componentID = osPackagePrefix + u.Name + "@" + purlVersion + osPackageQualifierSuffix
		}
		subComponent := vex.Subcomponent{Component: vex.Component{ID: componentID}}
		// if vulnerability id already exists, append subcomponent
		if statementIndex, ok := statementByVulnerability[u.VulnerabilityID]; ok {
			// deduplicate identical subcomponent IDs
			key := vexSubcomponentKey{vulnerabilityID: u.VulnerabilityID, componentID: subComponent.ID}
			if _, ok := seenSubcomponents[key]; ok {
				log.Debugf("duplicate subcomponent %s ignored", subComponent.ID)
				return
			}
			seenSubcomponents[key] = struct{}{}
			doc.Statements[statementIndex].Products[0].Subcomponents = append(doc.Statements[statementIndex].Products[0].Subcomponents, subComponent)
			return
		}
		// otherwise create new statement
		product := imageProduct
		product.Subcomponents = []vex.Subcomponent{subComponent}
		doc.Statements = append(doc.Statements, vex.Statement{
			Vulnerability: vex.Vulnerability{ID: u.VulnerabilityID, Name: u.VulnerabilityID},
			Products:      []vex.Product{product},
			Status:        "fixed",
		})
		statementByVulnerability[u.VulnerabilityID] = len(doc.Statements) - 1
		seenSubcomponents[vexSubcomponentKey{vulnerabilityID: u.VulnerabilityID, componentID: subComponent.ID}] = struct{}{}
	}

	for _, u := range updates.OSUpdates {
		addUpdate(u)
	}
	for _, u := range updates.LangUpdates {
		addUpdate(u)
	}

	return doc, nil
}

type vexSubcomponentKey struct {
	vulnerabilityID string
	componentID     string
}

func osPackageQualifiers(updates *unversioned.UpdateManifest) string {
	// Build PURL qualifiers: arch is always present, distro added when OS version is known.
	qualifiers := "?arch=" + url.QueryEscape(updates.Metadata.Config.Arch)
	if updates.Metadata.OS.Version != "" {
		qualifiers += "&distro=" + url.QueryEscape(updates.Metadata.OS.Type+"-"+updates.Metadata.OS.Version)
	}
	return qualifiers
}
