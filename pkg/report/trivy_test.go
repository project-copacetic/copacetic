/*
Copyright (c) Project Copacetic authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package report

import (
	"reflect"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
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
						Class:  "os-pkgs",
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
