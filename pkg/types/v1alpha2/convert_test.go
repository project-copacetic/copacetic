package v1alpha2

import (
	"testing"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestConvertV1alpha2UpdateManifestToUnversionedUpdateManifest(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *unversioned.UpdateManifest
		wantErr bool
	}{
		{
			name: "Valid input with both OS and language updates",
			input: []byte(`{
				"apiVersion": "v1alpha2",
				"metadata": {
					"os": {
						"type": "linux",
						"version": "4.19"
					},
					"config": {
						"arch": "amd64",
						"variant": "v1"
					}
				},
				"osupdates": [
					{
						"name": "openssl",
						"installedVersion": "1.1.1f-1ubuntu2.16",
						"fixedVersion": "1.1.1f-1ubuntu2.17",
						"vulnerabilityID": "CVE-2023-0286",
						"type": "deb",
						"class": "os-pkgs"
					}
				],
				"langupdates": [
					{
						"name": "requests",
						"installedVersion": "2.25.1",
						"fixedVersion": "2.31.0",
						"vulnerabilityID": "CVE-2023-32681",
						"type": "python",
						"class": "lang-pkgs"
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
						Variant: "v1",
					},
				},
				OSUpdates: unversioned.UpdatePackages{
					{
						Name:             "openssl",
						InstalledVersion: "1.1.1f-1ubuntu2.16",
						FixedVersion:     "1.1.1f-1ubuntu2.17",
						VulnerabilityID:  "CVE-2023-0286",
						Type:             "deb",
						Class:            "os-pkgs",
					},
				},
				LangUpdates: []unversioned.UpdatePackage{
					{
						Name:             "requests",
						InstalledVersion: "2.25.1",
						FixedVersion:     "2.31.0",
						VulnerabilityID:  "CVE-2023-32681",
						Type:             "python",
						Class:            "lang-pkgs",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid input with only OS updates",
			input: []byte(`{
				"apiVersion": "v1alpha2",
				"metadata": {
					"os": {
						"type": "debian",
						"version": "11.3"
					},
					"config": {
						"arch": "amd64"
					}
				},
				"osupdates": [
					{
						"name": "libcurl4",
						"installedVersion": "7.74.0-1.3+deb11u1",
						"fixedVersion": "7.74.0-1.3+deb11u2",
						"vulnerabilityID": "CVE-2021-22945",
						"type": "deb",
						"class": "os-pkgs"
					}
				],
				"langupdates": []
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
						Type:             "deb",
						Class:            "os-pkgs",
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
			got, err := ConvertV1alpha2UpdateManifestToUnversionedUpdateManifest(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertPkgPath(t *testing.T) {
	input := []byte(`{
		"apiVersion": "v1alpha2",
		"metadata": {"os": {"type": "alpine", "version": "3.18"}, "config": {"arch": "amd64"}},
		"osupdates": [],
		"langupdates": [
			{
				"name": "lodash",
				"installedVersion": "4.17.15",
				"fixedVersion": "4.17.21",
				"vulnerabilityID": "CVE-2021-23337",
				"type": "node-pkg",
				"class": "lang-pkgs",
				"pkgPath": "app/node_modules/lodash/package.json"
			},
			{
				"name": "minimist",
				"installedVersion": "1.2.0",
				"fixedVersion": "1.2.6",
				"vulnerabilityID": "CVE-2021-44906",
				"type": "node-pkg",
				"class": "lang-pkgs"
			}
		]
	}`)

	got, err := ConvertV1alpha2UpdateManifestToUnversionedUpdateManifest(input)
	assert.NoError(t, err)
	if assert.Len(t, got.LangUpdates, 2) {
		assert.Equal(t, "app/node_modules/lodash/package.json", got.LangUpdates[0].PkgPath)
		assert.Empty(t, got.LangUpdates[1].PkgPath, "pkgPath is optional and must default to empty")
	}
}
