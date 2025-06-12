package v1alpha1

import (
	"reflect"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

func TestConvertV1alpha1UpdateManifestToUnversionedUpdateManifest(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *unversioned.UpdateManifest
		wantErr bool
	}{
		{
			name: "Valid input",
			input: []byte(`{
				"metadata": {
					"os": {
						"type": "linux",
						"version": "4.19"
					},
					"config": {
						"arch": "amd64"
					}
				},
				"updates": [
					{
						"name": "openssl",
						"installedVersion": "1.1.1f-1ubuntu2.16",
						"fixedVersion": "1.1.1f-1ubuntu2.17",
						"vulnerabilityID": "CVE-2023-0286"
					}
				]
			}`),
			want: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "linux",
						Version: "4.19",
					},
					Config: unversioned.Config{
						Arch: "amd64",
					},
				},
				Updates: unversioned.UpdatePackages{
					{
						Name:             "openssl",
						InstalledVersion: "1.1.1f-1ubuntu2.16",
						FixedVersion:     "1.1.1f-1ubuntu2.17",
						VulnerabilityID:  "CVE-2023-0286",
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "Empty input",
			input:   []byte{},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Invalid JSON",
			input:   []byte(`{"metadata": {"os": {"type": "linux"}`),
			want:    nil,
			wantErr: true,
		},
		{
			name: "With NodeUpdates",
			input: []byte(`{
				"metadata": {
					"os": {
						"type": "linux",
						"version": "4.19"
					},
					"config": {
						"arch": "amd64"
					}
				},
				"updates": [
					{
						"name": "openssl",
						"installedVersion": "1.1.1f-1ubuntu2.16",
						"fixedVersion": "1.1.1f-1ubuntu2.17",
						"vulnerabilityID": "CVE-2023-0286"
					}
				],
				"nodeUpdates": [
					{
						"name": "lodash",
						"installedVersion": "4.17.20",
						"fixedVersion": "4.17.21",
						"vulnerabilityID": "CVE-2021-23337"
					}
				]
			}`),
			want: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "linux",
						Version: "4.19",
					},
					Config: unversioned.Config{
						Arch: "amd64",
					},
				},
				Updates: unversioned.UpdatePackages{
					{
						Name:             "openssl",
						InstalledVersion: "1.1.1f-1ubuntu2.16",
						FixedVersion:     "1.1.1f-1ubuntu2.17",
						VulnerabilityID:  "CVE-2023-0286",
					},
				},
				NodeUpdates: unversioned.UpdatePackages{
					{
						Name:             "lodash",
						InstalledVersion: "4.17.20",
						FixedVersion:     "4.17.21",
						VulnerabilityID:  "CVE-2021-23337",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertV1alpha1UpdateManifestToUnversionedUpdateManifest(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertV1alpha1UpdateManifestToUnversionedUpdateManifest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConvertV1alpha1UpdateManifestToUnversionedUpdateManifest() = %v, want %v", got, tt.want)
			}
		})
	}
}
