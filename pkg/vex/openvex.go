// Package vex contains logic for generating VEX (Vulnerability Exploitability eXchange) documents.
package vex

import (
	"bytes"
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
		return "", err
	}
	doc.ID = id

	imageProduct := vex.Product{
		Component: vex.Component{
			ID: "pkg:oci/" + patchedImageName,
		},
	}

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
		// choose package type: prefer provided pkgType (OS) if u.Type is empty, else use u.Type (e.g. python-pkg)
		pt := utils.CanonicalPkgManagerType(pkgType) // base OS package manager type (apk, deb, rpm)
		langType := u.Type

		var componentID string
		if langType == utils.PythonPackages { // treat python-pkg as coming from PyPI for purl standardization
			// Standard PyPI purl form: pkg:pypi/<name>@<version>
			componentID = "pkg:pypi/" + u.Name + "@" + u.FixedVersion
		} else {
			componentID = "pkg:" + pt + "/" + updates.Metadata.OS.Type + "/" + u.Name + "@" + u.FixedVersion + "?arch=" + updates.Metadata.Config.Arch
		}
		subComponent := vex.Subcomponent{Component: vex.Component{ID: componentID}}
		// if vulnerability id already exists, append subcomponent
		for i := range doc.Statements {
			if doc.Statements[i].Vulnerability.ID == u.VulnerabilityID {
				// deduplicate identical subcomponent IDs
				for _, existing := range doc.Statements[i].Products[0].Subcomponents {
					if existing.ID == subComponent.ID {
						log.Debugf("duplicate subcomponent %s ignored", subComponent.ID)
						return
					}
				}
				doc.Statements[i].Products[0].Subcomponents = append(doc.Statements[i].Products[0].Subcomponents, subComponent)
				return
			}
		}
		// otherwise create new statement
		imageProduct.Subcomponents = []vex.Subcomponent{subComponent}
		doc.Statements = append(doc.Statements, vex.Statement{
			Vulnerability: vex.Vulnerability{ID: u.VulnerabilityID},
			Products:      []vex.Product{imageProduct},
			Status:        "fixed",
		})
	}

	for _, u := range updates.OSUpdates {
		addUpdate(u)
	}
	for _, u := range updates.LangUpdates {
		addUpdate(u)
	}

	var buf bytes.Buffer
	err = doc.ToJSON(&buf)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
