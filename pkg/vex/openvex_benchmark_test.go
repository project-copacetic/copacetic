package vex

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

func BenchmarkOpenVexCreateVEXDocumentLargeManifest(b *testing.B) {
	updates := benchmarkVEXManifest(2400, 400)
	o := &OpenVex{}

	backupNow := now
	now = func() time.Time { return time.Unix(1700000000, 0).UTC() }
	defer func() { now = backupNow }()

	backupID := generateID
	generateID = func(_ *openvex.VEX) (string, error) { return "https://openvex.dev/benchmark", nil }
	defer func() { generateID = backupID }()

	b.ReportAllocs()
	b.SetBytes(int64(len(updates.OSUpdates) + len(updates.LangUpdates)))
	for i := 0; i < b.N; i++ {
		doc, err := o.CreateVEXDocument(updates, "registry.example.com/team/app:patched", "deb")
		if err != nil {
			b.Fatal(err)
		}
		if len(doc) == 0 {
			b.Fatal("empty VEX document")
		}
	}
}

func BenchmarkTryOutputVexDocumentLargeManifest(b *testing.B) {
	updates := benchmarkVEXManifest(2400, 400)
	outDir := b.TempDir()

	backupNow := now
	now = func() time.Time { return time.Unix(1700000000, 0).UTC() }
	defer func() { now = backupNow }()

	backupID := generateID
	generateID = func(_ *openvex.VEX) (string, error) { return "https://openvex.dev/benchmark", nil }
	defer func() { generateID = backupID }()

	b.ReportAllocs()
	b.SetBytes(int64(len(updates.OSUpdates) + len(updates.LangUpdates)))
	for i := 0; i < b.N; i++ {
		outputPath := filepath.Join(outDir, fmt.Sprintf("vex-%06d.json", i))
		if err := TryOutputVexDocument(updates, "deb", "registry.example.com/team/app:patched", "openvex", outputPath); err != nil {
			b.Fatal(err)
		}
		if err := os.Remove(outputPath); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkVEXManifest(totalUpdates, uniqueVulns int) *unversioned.UpdateManifest {
	updates := &unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS:     unversioned.OS{Type: "debian", Version: "12"},
			Config: unversioned.Config{Arch: "amd64"},
		},
		OSUpdates:   make([]unversioned.UpdatePackage, 0, totalUpdates),
		LangUpdates: make([]unversioned.UpdatePackage, 0, totalUpdates/8),
	}

	for i := 0; i < totalUpdates; i++ {
		vulnID := fmt.Sprintf("CVE-2024-%04d", i%uniqueVulns)
		pkgName := fmt.Sprintf("libexample-%04d", i)
		// Every tenth item intentionally duplicates an earlier package/vuln pair so
		// the benchmark covers subcomponent de-duplication as well as grouping.
		if i >= uniqueVulns && i%10 == 0 {
			pkgName = fmt.Sprintf("libexample-%04d", i%uniqueVulns)
		}
		updates.OSUpdates = append(updates.OSUpdates, unversioned.UpdatePackage{
			Name:             pkgName,
			InstalledVersion: fmt.Sprintf("1.%d.%d", i%17, i%29),
			FixedVersion:     fmt.Sprintf("1.%d.%d", i%17, (i%29)+1),
			VulnerabilityID:  vulnID,
		})
	}

	for i := 0; i < totalUpdates/8; i++ {
		updates.LangUpdates = append(updates.LangUpdates, unversioned.UpdatePackage{
			Name:             fmt.Sprintf("python-package-%04d", i),
			InstalledVersion: fmt.Sprintf("0.%d.%d", i%11, i%13),
			FixedVersion:     fmt.Sprintf("0.%d.%d", i%11, (i%13)+1),
			VulnerabilityID:  fmt.Sprintf("PYSEC-2024-%04d", i%(uniqueVulns/4)),
			Type:             utils.PythonPackages,
		})
	}
	return updates
}
