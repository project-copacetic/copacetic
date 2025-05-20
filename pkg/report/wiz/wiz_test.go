package wiz

import "testing"

func TestParseWizReport(t *testing.T) {
	// TODO: Implement the parsing logic according to the Wiz report structure
	// pseudo code:
	tests := []struct {
		name    string
		file    string
		msr     *WizFakeReport
		wantErr bool
	}{
		{
			name: "valid file",
			file: "testdata/wiz_valid.json",
			msr: &WizFakeReport{
				OSType:    "linux",
				OSVersion: "5.4.0",
				Arch:      "amd64",
				Packages: []WizFakePackage{
					{
						Name:             "libc6",
						InstalledVersion: "2.31-0ubuntu",
						FixedVersion:     "2.31-0ubuntu9.9",
						VulnerabilityID:  "CVE-2021-33574",
					},
				},
			},
		},
		{
			name:    "invalid file",
			file:    "testdata/invalid.json",
			msr:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewWizParser()
			fakeUpdateManifest, err := parser.Parse(tt.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if fakeUpdateManifest == nil {
				t.Errorf("Parse() got = %v, want %v", fakeUpdateManifest, tt.msr)
				return
			}
			targetOS := tt.msr.OSType
			if fakeUpdateManifest.Metadata.OS.Type != targetOS {
				t.Errorf("Parse() got OS.Type = %v, want %v", fakeUpdateManifest.Metadata.OS.Type, targetOS)
			}
			targetVersion := tt.msr.OSVersion
			if fakeUpdateManifest.Metadata.OS.Version != targetVersion {
				t.Errorf("Parse() got OS.Version = %v, want %v", fakeUpdateManifest.Metadata.OS.Version, targetVersion)
			}
			targetArch := tt.msr.Arch
			if fakeUpdateManifest.Metadata.Config.Arch != targetArch {
				t.Errorf("Parse() got OS.Arch = %v, want %v", fakeUpdateManifest.Metadata.Config.Arch, targetArch)
			}

			if len(fakeUpdateManifest.Updates) != len(tt.msr.Packages) {
				t.Errorf("Parse() got Updates = %v, want %v", len(fakeUpdateManifest.Updates), len(tt.msr.Packages))
			}

			// Iterate over the updates and check if they match the expected values
			for i, pkg := range tt.msr.Packages {
				if fakeUpdateManifest.Updates[i].Name != pkg.Name {
					t.Errorf("Parse() got Updates[%d].Name = %v, want %v", i, fakeUpdateManifest.Updates[i].Name, pkg.Name)
				}
				if fakeUpdateManifest.Updates[i].InstalledVersion != pkg.InstalledVersion {
					t.Errorf("Parse() got Updates[%d].InstalledVersion = %v, want %v", i, fakeUpdateManifest.Updates[i].InstalledVersion, pkg.InstalledVersion)
				}
				if fakeUpdateManifest.Updates[i].FixedVersion != pkg.FixedVersion {
					t.Errorf("Parse() got Updates[%d].FixedVersion = %v, want %v", i, fakeUpdateManifest.Updates[i].FixedVersion, pkg.FixedVersion)
				}
				if fakeUpdateManifest.Updates[i].VulnerabilityID != pkg.VulnerabilityID {
					t.Errorf("Parse() got Updates[%d].VulnerabilityID = %v, want %v", i, fakeUpdateManifest.Updates[i].VulnerabilityID, pkg.VulnerabilityID)
				}
			}
		})
	}
}
