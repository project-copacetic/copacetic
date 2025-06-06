package report

import (
	"reflect"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
)

// TestParseTrivyReport tests the parseTrivyReport function.
func TestParseTrivyReport(t *testing.T) {
	// Define a table of test cases with inputs and expected outputs
	tests := []struct {
		name    string
		file    string
		msr     *trivyTypes.Report
		wantErr bool
	}{
		{
			name: "valid file",
			file: "testdata/trivy_valid.json",
			msr: &trivyTypes.Report{
				SchemaVersion: 2,
				ArtifactName:  "alpine:3.14.0",
				ArtifactType:  "container_image",
				Metadata: trivyTypes.Metadata{
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.14.0",
					},
					ImageConfig: v1.ConfigFile{
						Architecture: "amd64",
					},
				},
				Results: []trivyTypes.Result{
					{
						Target: "alpine:3.14.0 (alpine 3.14.0)",
						Class:  trivyTypes.ClassOSPkg,
						Type:   "alpine",
						Vulnerabilities: []trivyTypes.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2021-36159",
								PkgID:            "apk-tools@2.12.5-r1",
								PkgName:          "apk-tools",
								InstalledVersion: "2.12.5-r1",
								FixedVersion:     "2.12.6-r0",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid file",
			file:    "testdata/invalid.json",
			msr:     nil,
			wantErr: true,
		},
	}

	// Iterate over the test cases and run each subtest with t.Run
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function under test with the input from the test case
			msr, err := parseTrivyReport(tc.file)

			// Check if the output matches the expected output from the test case
			if !reflect.DeepEqual(msr, tc.msr) {
				t.Errorf("got %v, want %v", msr, tc.msr)
			}

			if err != nil && !tc.wantErr {
				t.Errorf("got error %v, want no error", err)
			}
		})
	}
}

// TestTrivyParserParse tests the TrivyParser.Parse method with Node.js packages.
func TestTrivyParserParse(t *testing.T) {
	tests := []struct {
		name            string
		file            string
		wantOSUpdates   int
		wantNodeUpdates int
		wantErr         bool
	}{
		{
			name:            "OS packages only",
			file:            "testdata/trivy_valid.json",
			wantOSUpdates:   1,
			wantNodeUpdates: 0,
			wantErr:         false,
		},
		{
			name:            "OS and Node.js packages",
			file:            "testdata/trivy_node_valid.json",
			wantOSUpdates:   1,
			wantNodeUpdates: 2,
			wantErr:         false,
		},
		{
			name:            "invalid file",
			file:            "testdata/invalid.json",
			wantOSUpdates:   0,
			wantNodeUpdates: 0,
			wantErr:         true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parser := &TrivyParser{}
			manifest, err := parser.Parse(tc.file)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, manifest)
			assert.Equal(t, tc.wantOSUpdates, len(manifest.Updates))
			assert.Equal(t, tc.wantNodeUpdates, len(manifest.NodeUpdates))

			// Validate specific content for Node.js test
			if tc.name == "OS and Node.js packages" {
				// Check OS package
				assert.Equal(t, "protobuf-c", manifest.Updates[0].Name)

				// Check Node.js packages
				assert.Equal(t, "ansi-regex", manifest.NodeUpdates[0].Name)
				assert.Equal(t, "3.0.0", manifest.NodeUpdates[0].InstalledVersion)
				assert.Equal(t, "3.0.1", manifest.NodeUpdates[0].FixedVersion)

				assert.Equal(t, "follow-redirects", manifest.NodeUpdates[1].Name)
				assert.Equal(t, "1.14.7", manifest.NodeUpdates[1].InstalledVersion)
				assert.Equal(t, "1.14.8", manifest.NodeUpdates[1].FixedVersion)
			}
		})
	}
}
