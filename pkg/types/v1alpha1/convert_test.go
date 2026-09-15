package v1alpha1

import (
	"testing"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestConvertV1alpha1UpdateManifestToUnversionedUpdateManifest(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *unversioned.UpdateManifest
		wantErr bool
	}{
		{
			name: "Valid input with updates",
			input: []byte(`{
				"apiVersion": "v1alpha1",
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
						Arch:    "amd64",
						Variant: "",
					},
				},
				OSUpdates: unversioned.UpdatePackages{
					{
						Name:             "openssl",
						InstalledVersion: "1.1.1f-1ubuntu2.16",
						FixedVersion:     "1.1.1f-1ubuntu2.17",
						VulnerabilityID:  "CVE-2023-0286",
						Type:             "",
						Class:            "",
					},
				},
				LangUpdates: []unversioned.UpdatePackage{},
			},
			wantErr: false,
		},
		{
			name: "Valid input with only OS updates",
			input: []byte(`{
				"apiVersion": "v1alpha1",
				"metadata": {
					"os": {
						"type": "debian",
						"version": "11.3"
					},
					"config": {
						"arch": "amd64"
					}
				},
				"updates": [
					{
						"name": "libcurl4",
						"installedVersion": "7.74.0-1.3+deb11u1",
						"fixedVersion": "7.74.0-1.3+deb11u2",
						"vulnerabilityID": "CVE-2021-22945"
					}
				]
			}`),
			want: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    utils.OSTypeDebian,
						Version: "11.3",
					},
					Config: unversioned.Config{
						Arch:    "amd64",
						Variant: "",
					},
				},
				OSUpdates: unversioned.UpdatePackages{
					{
						Name:             "libcurl4",
						InstalledVersion: "7.74.0-1.3+deb11u1",
						FixedVersion:     "7.74.0-1.3+deb11u2",
						VulnerabilityID:  "CVE-2021-22945",
						Type:             "",
						Class:            "",
					},
				},
				LangUpdates: []unversioned.UpdatePackage{},
			},
			wantErr: false,
		},
		{
			name:    "Empty input",
			input:   []byte{},
			want:    nil,
			wantErr: false,
		},
		{
			name:    "Invalid JSON",
			input:   []byte(`{invalid json`),
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertV1alpha1UpdateManifestToUnversionedUpdateManifest(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
