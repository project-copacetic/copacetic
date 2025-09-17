package vex

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

func TestOpenVex_CreateVEXDocument(t *testing.T) {
	config := &buildkit.Config{}
	alpineManager, _ := pkgmgr.GetPackageManager(utils.OSTypeAlpine, "", config, utils.DefaultTempWorkingFolder)
	debianManager, _ := pkgmgr.GetPackageManager(utils.OSTypeDebian, "", config, utils.DefaultTempWorkingFolder)
	patchedImageName := "foo.io/bar:latest"
	t.Setenv("COPA_VEX_AUTHOR", "test author")

	// mock time
	expectedTime := time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	now = func() time.Time { return expectedTime }

	// mock id
	generateID = func(_ *vex.VEX) (string, error) { return "https://openvex.dev/test", nil }

	type args struct {
		updates          *unversioned.UpdateManifest
		pkgmgr           pkgmgr.PackageManager
		patchedImageName string
	}
	tests := []struct {
		name    string
		o       *OpenVex
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "valid openvex document",
			o:    &OpenVex{},
			args: args{
				patchedImageName: patchedImageName,
				updates: &unversioned.UpdateManifest{
					OSUpdates: []unversioned.UpdatePackage{
						{
							Name:             "test1",
							InstalledVersion: "1.0",
							FixedVersion:     "1.1",
							VulnerabilityID:  "CVE-2020-1234",
						},
					},
					Metadata: unversioned.Metadata{
						OS: unversioned.OS{
							Type: utils.OSTypeAlpine,
						},
						Config: unversioned.Config{
							Arch: "x86_64",
						},
					},
				},
				pkgmgr: alpineManager,
			},
			want: `{
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/test",
  "author": "test author",
  "timestamp": "2009-11-17T20:34:58.651387237Z",
  "version": 1,
  "tooling": "Project Copacetic",
  "statements": [
    {
      "vulnerability": {
        "@id": "CVE-2020-1234"
      },
      "products": [
        {
          "@id": "pkg:oci/foo.io/bar:latest",
          "subcomponents": [
            {
              "@id": "pkg:apk/alpine/test1@1.1?arch=x86_64"
            }
          ]
        }
      ],
      "status": "fixed"
    }
  ]
}
`,
			wantErr: false,
		},
		{
			name: "valid openvex document with multiple statements and multiple vulnerabilities",
			o:    &OpenVex{},
			args: args{
				patchedImageName: patchedImageName,
				updates: &unversioned.UpdateManifest{
					OSUpdates: []unversioned.UpdatePackage{
						{
							Name:             "test1",
							InstalledVersion: "1.0",
							FixedVersion:     "1.1",
							VulnerabilityID:  "CVE-2020-1234",
						},
						{
							Name:             "test2",
							InstalledVersion: "1.0",
							FixedVersion:     "1.2",
							VulnerabilityID:  "CVE-2020-1234",
						},
						{
							Name:             "test3",
							InstalledVersion: "1.0",
							FixedVersion:     "1.3",
							VulnerabilityID:  "CVE-2020-1235",
						},
					},
					Metadata: unversioned.Metadata{
						OS: unversioned.OS{
							Type: utils.OSTypeDebian,
						},
						Config: unversioned.Config{
							Arch: "x86_64",
						},
					},
				},
				pkgmgr: debianManager,
			},
			want: `{
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/test",
  "author": "test author",
  "timestamp": "2009-11-17T20:34:58.651387237Z",
  "version": 1,
  "tooling": "Project Copacetic",
  "statements": [
    {
      "vulnerability": {
        "@id": "CVE-2020-1234"
      },
      "products": [
        {
          "@id": "pkg:oci/foo.io/bar:latest",
          "subcomponents": [
            {
	              "@id": "pkg:deb/debian/test1@1.1?arch=x86_64"
            },
            {
              "@id": "pkg:deb/debian/test2@1.2?arch=x86_64"
            }
          ]
        }
      ],
      "status": "fixed"
    },
    {
      "vulnerability": {
        "@id": "CVE-2020-1235"
      },
      "products": [
        {
          "@id": "pkg:oci/foo.io/bar:latest",
          "subcomponents": [
            {
              "@id": "pkg:deb/debian/test3@1.3?arch=x86_64"
            }
          ]
        }
      ],
      "status": "fixed"
    }
  ]
}
`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OpenVex{}
			pkgType := tt.args.pkgmgr.GetPackageType()
			got, err := o.CreateVEXDocument(tt.args.updates, tt.args.patchedImageName, pkgType)
			if (err != nil) != tt.wantErr {
				t.Errorf("OpenVex.CreateVEXDocument() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !jsonEqual(got, tt.want) {
				t.Errorf("OpenVex.CreateVEXDocument() JSON mismatch. got=%s want=%s", got, tt.want)
			}
		})
	}
}

// TestOpenVex_CreateVEXDocument_LangUpdates ensures language updates are included
// independently of previously added OS updates and do not collide with other tests.
func TestOpenVex_CreateVEXDocument_LangUpdates(t *testing.T) {
	config := &buildkit.Config{}
	workingFolder := utils.DefaultTempWorkingFolder
	alpineManager, _ := pkgmgr.GetPackageManager(utils.OSTypeAlpine, "", config, workingFolder)
	patchedImageName := "foo.io/bar:latest"
	// isolate environment author
	t.Setenv("COPA_VEX_AUTHOR", "lang test author")

	// mock time/id specific to this test (not reusing mutated package-level doc state across tests)
	expectedTime := time.Date(2011, 1, 11, 11, 11, 11, 111111111, time.UTC)
	backupNow := now
	now = func() time.Time { return expectedTime }
	defer func() { now = backupNow }()

	backupID := generateID
	generateID = func(_ *vex.VEX) (string, error) { return "https://openvex.dev/langtest", nil }
	defer func() { generateID = backupID }()

	updates := &unversioned.UpdateManifest{
		LangUpdates: []unversioned.UpdatePackage{
			// valid vuln id - should appear
			{
				Name:             "requests",
				InstalledVersion: "2.31.0",
				FixedVersion:     "2.32.3",
				VulnerabilityID:  "GHSA-xxxx-yyyy-zzzz",
				Type:             "python-pkg",
			},
			// empty vuln id - should be skipped by VEX generator
			{
				Name:             "idna",
				InstalledVersion: "3.6.0",
				FixedVersion:     "3.7",
				VulnerabilityID:  "",
				Type:             "python-pkg",
			},
		},
		Metadata: unversioned.Metadata{
			OS:     unversioned.OS{Type: utils.OSTypeAlpine},
			Config: unversioned.Config{Arch: "x86_64"},
		},
	}

	pkgType := alpineManager.GetPackageType()
	got, err := (&OpenVex{}).CreateVEXDocument(updates, patchedImageName, pkgType)
	if err != nil {
		// Using t.Fatalf to abort; failure indicates missing inclusion logic.
		// Should not happen if CreateVEXDocument handles LangUpdates correctly.
		t.Fatalf("unexpected error: %v", err)
	}

	// Minimal assertions: ensure vulnerability id present and python package id included, and skipped entry absent.
	if !containsAll(got, []string{"GHSA-xxxx-yyyy-zzzz", "pkg:pypi/requests@2.32.3"}) {
		t.Errorf("expected lang update identifiers not found in output: %s", got)
	}
	if strings.Contains(got, "pkg:pypi/idna@3.7") {
		t.Errorf("idna package with empty vulnerability id should have been skipped: %s", got)
	}
}

// TestOpenVex_PurlPerOSType validates that the canonical package manager type is
// used in generated subcomponent purls for different OS families/distros.
func TestOpenVex_PurlPerOSType(t *testing.T) {
	t.Setenv("COPA_VEX_AUTHOR", "purl os test")
	// mock deterministic time/id
	expectedTime := time.Date(2022, 2, 2, 2, 2, 2, 222222222, time.UTC)
	backupNow := now
	now = func() time.Time { return expectedTime }
	defer func() { now = backupNow }()
	backupID := generateID
	generateID = func(_ *vex.VEX) (string, error) { return "https://openvex.dev/purlos", nil }
	defer func() { generateID = backupID }()

	type tc struct {
		name         string
		osType       string
		pkgMgrType   string // expected manager.GetPackageType()
		expectedPurl string
	}

	config := &buildkit.Config{}

	cases := []tc{
		// apk based
		{name: "alpine->apk", osType: utils.OSTypeAlpine, pkgMgrType: "apk", expectedPurl: "pkg:apk/alpine/pkgA@1.2.3?arch=x86_64"},
		// deb based
		{name: "debian->deb", osType: utils.OSTypeDebian, pkgMgrType: "deb", expectedPurl: "pkg:deb/debian/pkgA@1.2.3?arch=x86_64"},
		{name: "ubuntu->deb", osType: utils.OSTypeUbuntu, pkgMgrType: "deb", expectedPurl: "pkg:deb/ubuntu/pkgA@1.2.3?arch=x86_64"},
		// rpm based
		{name: "cbl-mariner->rpm", osType: utils.OSTypeCBLMariner, pkgMgrType: "rpm", expectedPurl: "pkg:rpm/cbl-mariner/pkgA@1.2.3?arch=x86_64"},
		{name: "azurelinux->rpm", osType: utils.OSTypeAzureLinux, pkgMgrType: "rpm", expectedPurl: "pkg:rpm/azurelinux/pkgA@1.2.3?arch=x86_64"},
		{name: "centos->rpm", osType: utils.OSTypeCentOS, pkgMgrType: "rpm", expectedPurl: "pkg:rpm/centos/pkgA@1.2.3?arch=x86_64"},
		{name: "oracle->rpm", osType: utils.OSTypeOracle, pkgMgrType: "rpm", expectedPurl: "pkg:rpm/oracle/pkgA@1.2.3?arch=x86_64"},
		{name: "redhat->rpm", osType: utils.OSTypeRedHat, pkgMgrType: "rpm", expectedPurl: "pkg:rpm/redhat/pkgA@1.2.3?arch=x86_64"},
		{name: "rocky->rpm", osType: utils.OSTypeRocky, pkgMgrType: "rpm", expectedPurl: "pkg:rpm/rocky/pkgA@1.2.3?arch=x86_64"},
		{name: "amazon->rpm", osType: utils.OSTypeAmazon, pkgMgrType: "rpm", expectedPurl: "pkg:rpm/amazon/pkgA@1.2.3?arch=x86_64"},
		{name: "alma->rpm", osType: utils.OSTypeAlma, pkgMgrType: "rpm", expectedPurl: "pkg:rpm/alma/pkgA@1.2.3?arch=x86_64"},
	}

	for _, cse := range cases {
		t.Run(cse.name, func(t *testing.T) {
			// Acquire a manager to supply pkgType if supported; fall back to expected pkgMgrType if not.
			mgr, _ := pkgmgr.GetPackageManager(cse.osType, "", config, utils.DefaultTempWorkingFolder)
			pkgType := cse.pkgMgrType
			if mgr != nil {
				pkgType = mgr.GetPackageType()
			}
			updates := &unversioned.UpdateManifest{
				OSUpdates: []unversioned.UpdatePackage{{
					Name:             "pkgA",
					InstalledVersion: "1.0.0",
					FixedVersion:     "1.2.3",
					VulnerabilityID:  "CVE-1111-2222",
				}},
				Metadata: unversioned.Metadata{OS: unversioned.OS{Type: cse.osType}, Config: unversioned.Config{Arch: "x86_64"}},
			}
			got, err := (&OpenVex{}).CreateVEXDocument(updates, "example.io/image:tag", pkgType)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(got, cse.expectedPurl) {
				t.Fatalf("expected purl %s not found in output: %s", cse.expectedPurl, got)
			}
		})
	}
}

// containsAll returns true if all substrings are present in s.
func containsAll(s string, subs []string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// jsonEqual unmarshals both strings and compares their structures.
func jsonEqual(a, b string) bool {
	var ja any
	var jb any
	if err := json.Unmarshal([]byte(a), &ja); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &jb); err != nil {
		return false
	}
	return deepEqualJSON(ja, jb)
}

// deepEqualJSON performs a semantic comparison accounting for map key ordering.
func deepEqualJSON(a, b any) bool {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, v := range av {
			if !deepEqualJSON(v, bv[k]) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !deepEqualJSON(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}
