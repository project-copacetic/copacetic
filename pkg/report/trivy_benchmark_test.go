package report

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

func BenchmarkFindOptimalFixedVersionWithPatchLevel(b *testing.B) {
	fixedVersions := make([]string, 0, 512)
	for i := 0; i < 256; i++ {
		fixedVersions = append(fixedVersions,
			fmt.Sprintf("1.26.%d, 2.%d.0", i+17, i%16),
			fmt.Sprintf("1.%d.0", 27+i%8),
		)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if got := FindOptimalFixedVersionWithPatchLevel("1.26.16", fixedVersions, majorPatchLevel); got == "" {
			b.Fatal("expected a fixed version")
		}
	}
}

func BenchmarkTrivyParserParseLargeReport(b *testing.B) {
	path := writeBenchmarkTrivyReport(b, 500, 500)
	parser := &TrivyParser{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manifest, err := parser.ParseWithLibraryPatchLevel(path, majorPatchLevel)
		if err != nil {
			b.Fatal(err)
		}
		if len(manifest.OSUpdates) == 0 || len(manifest.LangUpdates) == 0 {
			b.Fatalf("expected OS and language updates, got %d/%d", len(manifest.OSUpdates), len(manifest.LangUpdates))
		}
	}
}

func BenchmarkDefaultParseScanReportOSOnlyLargeReport(b *testing.B) {
	path := writeBenchmarkTrivyReport(b, 500, 500)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manifest, err := defaultParseScanReport(path, utils.PkgTypeOS, majorPatchLevel)
		if err != nil {
			b.Fatal(err)
		}
		if len(manifest.OSUpdates) == 0 {
			b.Fatal("expected OS updates")
		}
		if len(manifest.LangUpdates) != 0 {
			b.Fatalf("expected language updates to be filtered out, got %d", len(manifest.LangUpdates))
		}
		if manifest.LibrarySummary != nil {
			b.Fatal("expected library summary to be filtered out")
		}
	}
}

func writeBenchmarkTrivyReport(b *testing.B, osVulns, langVulns int) string {
	b.Helper()

	osVulnerabilities := make([]trivyTypes.DetectedVulnerability, osVulns)
	for i := range osVulnerabilities {
		osVulnerabilities[i] = trivyTypes.DetectedVulnerability{
			VulnerabilityID:  fmt.Sprintf("CVE-2099-%04d", i),
			PkgName:          fmt.Sprintf("lib-%04d", i%200),
			InstalledVersion: "1.0.0-r0",
			FixedVersion:     fmt.Sprintf("1.0.%d-r0", i%20+1),
		}
	}

	langVulnerabilities := make([]trivyTypes.DetectedVulnerability, langVulns)
	for i := range langVulnerabilities {
		langVulnerabilities[i] = trivyTypes.DetectedVulnerability{
			VulnerabilityID:  fmt.Sprintf("CVE-3099-%04d", i),
			PkgName:          fmt.Sprintf("libpkg%d", i%100),
			PkgPath:          fmt.Sprintf("/app/service%d/requirements.txt", i%10),
			InstalledVersion: "1.26.16",
			FixedVersion:     fmt.Sprintf("1.26.%d, 2.%d.0", i%40+17, i%5),
		}
	}

	report := trivyTypes.Report{
		SchemaVersion: 2,
		ArtifactName:  "benchmark:latest",
		ArtifactType:  "container_image",
		Metadata: trivyTypes.Metadata{
			OS: &ftypes.OS{Family: "alpine", Name: "3.20.0"},
			ImageConfig: v1.ConfigFile{
				Architecture: "amd64",
				History: []v1.History{
					{CreatedBy: "ENV NODE_VERSION=20.11.1"},
					{CreatedBy: "ENV YARN_VERSION=1.22.22"},
				},
			},
		},
		Results: []trivyTypes.Result{
			{
				Target:          "benchmark:latest (alpine 3.20.0)",
				Class:           trivyTypes.ClassOSPkg,
				Type:            "alpine",
				Vulnerabilities: osVulnerabilities,
			},
			{
				Target:          "requirements.txt",
				Class:           utils.LangPackages,
				Type:            utils.PythonPackages,
				Vulnerabilities: langVulnerabilities,
			},
		},
	}

	data, err := json.Marshal(&report)
	if err != nil {
		b.Fatal(err)
	}
	file, err := os.CreateTemp(b.TempDir(), "trivy-bench-*.json")
	if err != nil {
		b.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		b.Fatal(err)
	}
	if err := file.Close(); err != nil {
		b.Fatal(err)
	}
	return file.Name()
}
