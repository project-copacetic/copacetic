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
	return o.createMultiVEXDocument([]ImageUpdates{{
		Updates:          updates,
		PkgType:          pkgType,
		PatchedImageName: patchedImageName,
	}})
}

func (o *OpenVex) createMultiVEXDocument(images []ImageUpdates) (*vex.VEX, error) {
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

	totalUpdates := 0
	for _, image := range images {
		if image.Updates == nil {
			continue
		}
		totalUpdates += len(image.Updates.OSUpdates) + len(image.Updates.LangUpdates)
	}
	initialStatementCapacity := min(totalUpdates, 512)
	doc.Statements = make([]vex.Statement, 0, initialStatementCapacity)
	statementByVulnerability := make(map[string]int, initialStatementCapacity)
	seenSubcomponents := make(map[vexSubcomponentKey]struct{}, totalUpdates)

	// helper closure to add a single update (OS or language) to the VEX doc.
	// Subcomponent de-duplication is per product so the same package can be
	// listed once under each platform image that fixed the vulnerability.
	addUpdate := func(imageProduct vex.Product, osPackagePrefix, osPackageQualifierSuffix string, u unversioned.UpdatePackage) {
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
		key := vexSubcomponentKey{
			vulnerabilityID: u.VulnerabilityID,
			productID:       imageProduct.ID,
			componentID:     subComponent.ID,
		}
		// if vulnerability id already exists, append this image's product or subcomponent
		if statementIndex, ok := statementByVulnerability[u.VulnerabilityID]; ok {
			if _, seen := seenSubcomponents[key]; seen {
				log.Debugf("duplicate subcomponent %s ignored", subComponent.ID)
				return
			}
			seenSubcomponents[key] = struct{}{}
			products := doc.Statements[statementIndex].Products
			productIndex := -1
			for i := range products {
				if products[i].ID == imageProduct.ID {
					productIndex = i
					break
				}
			}
			if productIndex < 0 {
				product := imageProduct
				product.Subcomponents = []vex.Subcomponent{subComponent}
				products = append(products, product)
				doc.Statements[statementIndex].Products = products
				return
			}
			doc.Statements[statementIndex].Products[productIndex].Subcomponents = append(
				doc.Statements[statementIndex].Products[productIndex].Subcomponents,
				subComponent,
			)
			return
		}
		// otherwise create new statement. Statements follow first-seen order
		// across images, and products follow image input order.
		product := imageProduct
		product.Subcomponents = []vex.Subcomponent{subComponent}
		doc.Statements = append(doc.Statements, vex.Statement{
			Vulnerability: vex.Vulnerability{Name: vex.VulnerabilityID(u.VulnerabilityID), ID: u.VulnerabilityID},
			Products:      []vex.Product{product},
			Status:        "fixed",
		})
		statementByVulnerability[u.VulnerabilityID] = len(doc.Statements) - 1
		seenSubcomponents[key] = struct{}{}
	}

	for _, image := range images {
		if image.Updates == nil {
			continue
		}
		imageProduct := vex.Product{
			Component: vex.Component{
				ID: "pkg:oci/" + image.PatchedImageName,
			},
		}
		pt := utils.CanonicalPkgManagerType(image.PkgType) // base OS package manager type (apk, deb, rpm)
		osPackagePrefix := "pkg:" + pt + "/" + image.Updates.Metadata.OS.Type + "/"
		osPackageQualifierSuffix := osPackageQualifiers(image.Updates)
		for _, u := range image.Updates.OSUpdates {
			addUpdate(imageProduct, osPackagePrefix, osPackageQualifierSuffix, u)
		}
		for _, u := range image.Updates.LangUpdates {
			addUpdate(imageProduct, osPackagePrefix, osPackageQualifierSuffix, u)
		}
	}

	return doc, nil
}

type vexSubcomponentKey struct {
	vulnerabilityID string
	productID       string
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
