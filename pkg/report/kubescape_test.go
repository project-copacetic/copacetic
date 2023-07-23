package report

import (
	"reflect"
	"testing"

	kubescapeTypes "github.com/kubescape/storage/pkg/apis/softwarecomposition"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestParseKubescapeReport(t *testing.T) {
	// Define a table of test cases with inputs and expected outputs
	tests := []struct {
		name    string
		file    string
		ksr     *kubescapeTypes.VulnerabilityManifest
		wantErr bool
	}{
		{
			name: "valid file",
			file: "testdata/kubescape_valid.json",
			ksr: &kubescapeTypes.VulnerabilityManifest{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "spdx.softwarecomposition.kubescape.io/v1beta1",
					Kind:       "VulnerabilityManifest",
				},
				Spec: kubescapeTypes.VulnerabilityManifestSpec{
					Payload: kubescapeTypes.GrypeDocument{
						Distro: kubescapeTypes.Distribution{
							Name:    "debian",
							Version: "10",
						},
						Matches: []kubescapeTypes.Match{
							{
								Artifact: kubescapeTypes.GrypePackage{
									Language: "",
									Name:     "libsystemd0",
									PURL:     "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026upstream=systemd\u0026distro=debian-10",
									Type:     "deb",
									Version:  "241-7~deb10u9",
								},
								Vulnerability: kubescapeTypes.Vulnerability{
									Fix: kubescapeTypes.Fix{
										State: "fixed",
										Versions: []string{
											"241-7~deb10u10",
										},
									},
								},
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
			ksr:     nil,
			wantErr: true,
		},
	}

	// Iterate over the test cases and run each subtest with t.Run
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function under test with the input from the test case
			ksr, err := parseKubescapeReport(tc.file)

			// Check if the output matches the expected output from the test case
			if !reflect.DeepEqual(ksr, tc.ksr) {
				t.Errorf("got %v, want %v", ksr, tc.ksr)
			}
			if err != nil && !tc.wantErr {
				t.Errorf("got error %v, want no error", err)
			}
		})
	}
}
