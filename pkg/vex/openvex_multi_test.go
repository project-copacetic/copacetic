package vex

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

func TestCreateMultiVEXDocument(t *testing.T) {
	t.Setenv("COPA_VEX_AUTHOR", "test author")
	restore := stubVEXIdentity(t, time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC), "https://openvex.dev/test")
	defer restore()

	amd64Image := "nginx@sha256:amd64"
	arm64Image := "nginx@sha256:arm64"
	sharedCVE := "CVE-2024-0001"
	amdOnlyCVE := "CVE-2024-0002"
	armOnlyCVE := "CVE-2024-0003"

	amd64Shared := osUpdate("openssl", "1.1.1", "1.1.2", sharedCVE)
	arm64Shared := osUpdate("openssl", "1.1.1", "1.1.2", sharedCVE)
	amd64Only := osUpdate("zlib", "1.2.0", "1.2.1", amdOnlyCVE)
	arm64Only := osUpdate("curl", "8.0.0", "8.0.1", armOnlyCVE)

	tests := []struct {
		name    string
		images  []ImageUpdates
		want    []expectedStatement
		wantErr bool
	}{
		{
			name: "shared CVE is one statement with one product per image",
			images: []ImageUpdates{
				imageUpdates(amd64Image, "apk", "alpine", "amd64", "", amd64Shared),
				imageUpdates(arm64Image, "apk", "alpine", "arm64", "", arm64Shared),
			},
			want: []expectedStatement{
				{
					vulnerability: sharedCVE,
					products: []expectedProduct{
						{
							id: "pkg:oci/" + amd64Image,
							subcomponents: []string{
								"pkg:apk/alpine/openssl@1.1.1?arch=amd64",
							},
						},
						{
							id: "pkg:oci/" + arm64Image,
							subcomponents: []string{
								"pkg:apk/alpine/openssl@1.1.1?arch=arm64",
							},
						},
					},
				},
			},
		},
		{
			name: "CVE fixed on only one image has one product",
			images: []ImageUpdates{
				imageUpdates(amd64Image, "apk", "alpine", "amd64", "", amd64Shared, amd64Only),
				imageUpdates(arm64Image, "apk", "alpine", "arm64", "", arm64Shared, arm64Only),
			},
			want: []expectedStatement{
				{
					vulnerability: sharedCVE,
					products: []expectedProduct{
						{id: "pkg:oci/" + amd64Image, subcomponents: []string{"pkg:apk/alpine/openssl@1.1.1?arch=amd64"}},
						{id: "pkg:oci/" + arm64Image, subcomponents: []string{"pkg:apk/alpine/openssl@1.1.1?arch=arm64"}},
					},
				},
				{
					vulnerability: amdOnlyCVE,
					products: []expectedProduct{
						{id: "pkg:oci/" + amd64Image, subcomponents: []string{"pkg:apk/alpine/zlib@1.2.0?arch=amd64"}},
					},
				},
				{
					vulnerability: armOnlyCVE,
					products: []expectedProduct{
						{id: "pkg:oci/" + arm64Image, subcomponents: []string{"pkg:apk/alpine/curl@8.0.0?arch=arm64"}},
					},
				},
			},
		},
		{
			name: "skip rules and per-product subcomponent dedup",
			images: []ImageUpdates{
				{
					Updates: &unversioned.UpdateManifest{
						Metadata: alpineMetadata("amd64", ""),
						OSUpdates: []unversioned.UpdatePackage{
							osUpdate("openssl", "1.1.1", "1.1.2", sharedCVE),
							osUpdate("openssl", "1.1.1", "1.1.2", sharedCVE),
							{Name: "empty-id", InstalledVersion: "1.0", FixedVersion: "1.1", VulnerabilityID: ""},
							{Name: "empty-fix", InstalledVersion: "1.0", FixedVersion: "", VulnerabilityID: sharedCVE},
							{Name: "already", InstalledVersion: "1.0", FixedVersion: "1.0", VulnerabilityID: amdOnlyCVE},
						},
						LangUpdates: []unversioned.UpdatePackage{
							{
								Name:             "requests",
								InstalledVersion: "2.31.0",
								FixedVersion:     "2.32.0",
								VulnerabilityID:  sharedCVE,
								Type:             utils.PythonPackages,
							},
						},
					},
					PkgType:          "apk",
					PatchedImageName: amd64Image,
				},
				{
					Updates: &unversioned.UpdateManifest{
						Metadata: alpineMetadata("amd64", ""),
						OSUpdates: []unversioned.UpdatePackage{
							osUpdate("openssl", "1.1.1", "1.1.2", sharedCVE),
							osUpdate("openssl", "1.1.1", "1.1.2", sharedCVE),
						},
					},
					PkgType:          "apk",
					PatchedImageName: arm64Image,
				},
			},
			want: []expectedStatement{
				{
					vulnerability: sharedCVE,
					products: []expectedProduct{
						{
							id: "pkg:oci/" + amd64Image,
							subcomponents: []string{
								"pkg:apk/alpine/openssl@1.1.1?arch=amd64",
								"pkg:pypi/requests@2.31.0",
							},
						},
						{
							id: "pkg:oci/" + arm64Image,
							subcomponents: []string{
								"pkg:apk/alpine/openssl@1.1.1?arch=amd64",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := (&OpenVex{}).createMultiVEXDocument(tt.images)
			if (err != nil) != tt.wantErr {
				t.Fatalf("createMultiVEXDocument() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			assertStatements(t, doc, tt.want)
		})
	}
}

func TestCreateVEXDocumentMatchesSingleImageMultiDocument(t *testing.T) {
	t.Setenv("COPA_VEX_AUTHOR", "test author")
	restore := stubVEXIdentity(t, time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC), "https://openvex.dev/test")
	defer restore()

	updates := &unversioned.UpdateManifest{
		OSUpdates: []unversioned.UpdatePackage{
			{
				Name:             "test1",
				InstalledVersion: "1.0",
				FixedVersion:     "1.1",
				VulnerabilityID:  "CVE-2020-1234",
			},
			{
				Name:             "skipped",
				InstalledVersion: "1.0",
				FixedVersion:     "1.0",
				VulnerabilityID:  "CVE-2020-9999",
			},
		},
		LangUpdates: []unversioned.UpdatePackage{
			{
				Name:             "requests",
				InstalledVersion: "2.31.0",
				FixedVersion:     "2.32.3",
				VulnerabilityID:  "GHSA-xxxx-yyyy-zzzz",
				Type:             utils.PythonPackages,
			},
		},
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    utils.OSTypeAlpine,
				Version: "3.20",
			},
			Config: unversioned.Config{Arch: "x86_64"},
		},
	}
	patchedImageName := "registry.example/app:patched"
	pkgType := "apk"

	gotSingle, err := (&OpenVex{}).CreateVEXDocument(updates, patchedImageName, pkgType)
	if err != nil {
		t.Fatalf("CreateVEXDocument() error = %v", err)
	}
	doc, err := (&OpenVex{}).createMultiVEXDocument([]ImageUpdates{{
		Updates:          updates,
		PkgType:          pkgType,
		PatchedImageName: patchedImageName,
	}})
	if err != nil {
		t.Fatalf("createMultiVEXDocument() error = %v", err)
	}
	var buf bytes.Buffer
	if err := doc.ToJSON(&buf); err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}
	if !jsonEqual(gotSingle, buf.String()) {
		t.Fatalf("single-image multi document differs from CreateVEXDocument()\ncreate=%s\nmulti=%s", gotSingle, buf.String())
	}

	const want = `{
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/test",
  "author": "test author",
  "version": 1,
  "tooling": "Project Copacetic",
  "statements": [
    {
      "vulnerability": {"@id": "CVE-2020-1234", "name": "CVE-2020-1234"},
      "products": [
        {
          "@id": "pkg:oci/registry.example/app:patched",
          "subcomponents": [
            {"@id": "pkg:apk/alpine/test1@1.0?arch=x86_64&distro=alpine-3.20"}
          ]
        }
      ],
      "status": "fixed"
    },
    {
      "vulnerability": {"@id": "GHSA-xxxx-yyyy-zzzz", "name": "GHSA-xxxx-yyyy-zzzz"},
      "products": [
        {
          "@id": "pkg:oci/registry.example/app:patched",
          "subcomponents": [
            {"@id": "pkg:pypi/requests@2.31.0"}
          ]
        }
      ],
      "status": "fixed"
    }
  ],
  "timestamp": "2009-11-17T20:34:58Z"
}`
	if !jsonEqual(gotSingle, want) {
		t.Fatalf("CreateVEXDocument() JSON mismatch\ngot=%s\nwant=%s", gotSingle, want)
	}
}

func TestTryOutputMultiVexDocument(t *testing.T) {
	t.Setenv("COPA_VEX_AUTHOR", "test author")
	restore := stubVEXIdentity(t, time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), "https://openvex.dev/multi")
	defer restore()

	images := []ImageUpdates{
		imageUpdates("app@sha256:amd64", "deb", "debian", "amd64", "12", osUpdate("openssl", "3.0.0", "3.0.1", "CVE-2024-1111")),
		imageUpdates("app@sha256:arm64", "deb", "debian", "arm64", "12", osUpdate("openssl", "3.0.0", "3.0.1", "CVE-2024-1111")),
	}

	t.Run("writes one file containing both image ids", func(t *testing.T) {
		outputPath := filepath.Join(t.TempDir(), "vex.json")
		if err := TryOutputMultiVexDocument(images, "openvex", outputPath); err != nil {
			t.Fatalf("TryOutputMultiVexDocument() error = %v", err)
		}
		got, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("failed to read VEX file: %v", err)
		}
		body := string(got)
		if !containsAll(body, []string{"pkg:oci/app@sha256:amd64", "pkg:oci/app@sha256:arm64"}) {
			t.Fatalf("VEX file missing image ids: %s", body)
		}
		amdIdx := strings.Index(body, "pkg:oci/app@sha256:amd64")
		armIdx := strings.Index(body, "pkg:oci/app@sha256:arm64")
		if amdIdx < 0 || armIdx < 0 || amdIdx > armIdx {
			t.Fatalf("products not in input order: %s", body)
		}
	})

	t.Run("rejects unsupported format", func(t *testing.T) {
		err := TryOutputMultiVexDocument(images, "fakevex", filepath.Join(t.TempDir(), "vex.json"))
		if err == nil {
			t.Fatal("TryOutputMultiVexDocument() error = nil, want unsupported format error")
		}
		if err.Error() != "unsupported output format fakevex specified" {
			t.Fatalf("TryOutputMultiVexDocument() error = %q", err.Error())
		}
	})
}

type expectedStatement struct {
	vulnerability string
	products      []expectedProduct
}

type expectedProduct struct {
	id            string
	subcomponents []string
}

func assertStatements(t *testing.T, doc *openvex.VEX, want []expectedStatement) {
	t.Helper()
	if doc == nil {
		t.Fatal("document is nil")
	}
	if len(doc.Statements) != len(want) {
		t.Fatalf("statement count = %d, want %d", len(doc.Statements), len(want))
	}
	for i, wantStatement := range want {
		got := doc.Statements[i]
		if string(got.Vulnerability.Name) != wantStatement.vulnerability || got.Vulnerability.ID != wantStatement.vulnerability {
			t.Fatalf("statement[%d] vulnerability = %s/%s, want %s", i, got.Vulnerability.ID, got.Vulnerability.Name, wantStatement.vulnerability)
		}
		if got.Status != "fixed" {
			t.Fatalf("statement[%d] status = %s, want fixed", i, got.Status)
		}
		if len(got.Products) != len(wantStatement.products) {
			t.Fatalf("statement[%d] product count = %d, want %d", i, len(got.Products), len(wantStatement.products))
		}
		for j, wantProduct := range wantStatement.products {
			gotProduct := got.Products[j]
			if gotProduct.ID != wantProduct.id {
				t.Fatalf("statement[%d] product[%d] = %s, want %s", i, j, gotProduct.ID, wantProduct.id)
			}
			if len(gotProduct.Subcomponents) != len(wantProduct.subcomponents) {
				t.Fatalf("statement[%d] product[%d] subcomponent count = %d, want %d (%v)", i, j, len(gotProduct.Subcomponents), len(wantProduct.subcomponents), subcomponentIDs(gotProduct))
			}
			for k, wantSub := range wantProduct.subcomponents {
				if gotProduct.Subcomponents[k].ID != wantSub {
					t.Fatalf("statement[%d] product[%d] subcomponent[%d] = %s, want %s", i, j, k, gotProduct.Subcomponents[k].ID, wantSub)
				}
			}
		}
	}
}

func subcomponentIDs(product openvex.Product) []string {
	ids := make([]string, len(product.Subcomponents))
	for i, sub := range product.Subcomponents {
		ids[i] = sub.ID
	}
	return ids
}

func imageUpdates(image, pkgType, osType, arch, osVersion string, updates ...unversioned.UpdatePackage) ImageUpdates {
	return ImageUpdates{
		Updates: &unversioned.UpdateManifest{
			Metadata: unversioned.Metadata{
				OS:     unversioned.OS{Type: osType, Version: osVersion},
				Config: unversioned.Config{Arch: arch},
			},
			OSUpdates: updates,
		},
		PkgType:          pkgType,
		PatchedImageName: image,
	}
}

func alpineMetadata(arch, version string) unversioned.Metadata {
	return unversioned.Metadata{
		OS:     unversioned.OS{Type: utils.OSTypeAlpine, Version: version},
		Config: unversioned.Config{Arch: arch},
	}
}

func osUpdate(name, installed, fixed, vuln string) unversioned.UpdatePackage {
	return unversioned.UpdatePackage{
		Name:             name,
		InstalledVersion: installed,
		FixedVersion:     fixed,
		VulnerabilityID:  vuln,
	}
}

func stubVEXIdentity(t *testing.T, ts time.Time, id string) func() {
	t.Helper()
	prevNow := now
	prevID := generateID
	now = func() time.Time { return ts }
	generateID = func(_ *openvex.VEX) (string, error) { return id, nil }
	return func() {
		now = prevNow
		generateID = prevID
	}
}
