package langmgr

import (
	"context"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestValidateNodePackageName(t *testing.T) {
	tests := []struct {
		name        string
		packageName string
		wantErr     bool
	}{
		{
			name:        "valid simple name",
			packageName: "express",
			wantErr:     false,
		},
		{
			name:        "valid scoped package",
			packageName: "@babel/core",
			wantErr:     false,
		},
		{
			name:        "valid with dashes",
			packageName: "node-fetch",
			wantErr:     false,
		},
		{
			name:        "invalid empty",
			packageName: "",
			wantErr:     true,
		},
		{
			name:        "invalid shell injection",
			packageName: "package; rm -rf /",
			wantErr:     true,
		},
		{
			name:        "invalid too long",
			packageName: string(make([]byte, 215)),
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNodePackageName(tt.packageName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateNodeVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantErr bool
	}{
		{
			name:    "valid semver",
			version: "1.2.3",
			wantErr: false,
		},
		{
			name:    "valid with v prefix",
			version: "v1.2.3",
			wantErr: false,
		},
		{
			name:    "valid pre-release",
			version: "1.2.3-beta.1",
			wantErr: false,
		},
		{
			name:    "invalid empty",
			version: "",
			wantErr: true,
		},
		{
			name:    "invalid shell injection",
			version: "1.2.3; rm -rf /",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNodeVersion(tt.version)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsValidNodeVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{
			name:    "valid semver",
			version: "1.2.3",
			want:    true,
		},
		{
			name:    "valid with v prefix",
			version: "v1.2.3",
			want:    true,
		},
		{
			name:    "valid pre-release",
			version: "1.2.3-beta.1",
			want:    true,
		},
		{
			name:    "invalid format",
			version: "not-a-version",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidNodeVersion(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsLessThanNodeVersion(t *testing.T) {
	tests := []struct {
		name string
		v1   string
		v2   string
		want bool
	}{
		{
			name: "v1 less than v2",
			v1:   "1.0.0",
			v2:   "2.0.0",
			want: true,
		},
		{
			name: "v1 equal to v2",
			v1:   "1.0.0",
			v2:   "1.0.0",
			want: false,
		},
		{
			name: "v1 greater than v2",
			v1:   "2.0.0",
			v2:   "1.0.0",
			want: false,
		},
		{
			name: "with v prefix",
			v1:   "v1.0.0",
			v2:   "v2.0.0",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLessThanNodeVersion(tt.v1, tt.v2)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFilterNodePackages(t *testing.T) {
	langUpdates := unversioned.LangUpdatePackages{
		{Name: "express", Type: utils.NodePackages},
		{Name: "requests", Type: utils.PythonPackages},
		{Name: "lodash", Type: utils.NodePackages},
	}

	result := filterNodePackages(langUpdates)

	assert.Len(t, result, 2)
	assert.Equal(t, "express", result[0].Name)
	assert.Equal(t, "lodash", result[1].Name)
}

func TestNodejsManagerInstallUpdates(t *testing.T) {
	tests := []struct {
		name         string
		manifest     *unversioned.UpdateManifest
		ignoreErrors bool
		wantErr      bool
	}{
		{
			name: "no node packages",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{},
			},
			ignoreErrors: false,
			wantErr:      false,
		},
		{
			name: "python packages only",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{
					{
						Name:             "requests",
						InstalledVersion: "2.27.0",
						FixedVersion:     "2.28.0",
						Type:             utils.PythonPackages,
					},
				},
			},
			ignoreErrors: false,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &buildkit.Config{
				ImageState: llb.Image("node:18-alpine"),
			}
			ctx := context.Background()
			manager := &nodejsManager{config: config, workingFolder: "/tmp/test"}
			state, errPkgs, err := manager.InstallUpdates(ctx, &config.ImageState, tt.manifest, tt.ignoreErrors)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, state)
				assert.Equal(t, 0, len(errPkgs))
			}
		})
	}
}

func TestGetUniqueLatestUpdatesNode(t *testing.T) {
	nodeComparer := VersionComparer{isValidNodeVersion, isLessThanNodeVersion}

	tests := []struct {
		name         string
		updates      unversioned.LangUpdatePackages
		ignoreErrors bool
		wantCount    int
		wantErr      bool
	}{
		{
			name:         "empty updates",
			updates:      unversioned.LangUpdatePackages{},
			ignoreErrors: false,
			wantCount:    0,
			wantErr:      false,
		},
		{
			name: "single update",
			updates: unversioned.LangUpdatePackages{
				{Name: "express", FixedVersion: "4.18.2"},
			},
			ignoreErrors: false,
			wantCount:    1,
			wantErr:      false,
		},
		{
			name: "duplicate package, different versions",
			updates: unversioned.LangUpdatePackages{
				{Name: "express", FixedVersion: "4.18.1"},
				{Name: "express", FixedVersion: "4.18.2"},
			},
			ignoreErrors: false,
			wantCount:    1,
			wantErr:      false,
		},
		{
			name: "invalid version",
			updates: unversioned.LangUpdatePackages{
				{Name: "express", FixedVersion: "not-a-version"},
			},
			ignoreErrors: false,
			wantCount:    0,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetUniqueLatestUpdates(tt.updates, nodeComparer, tt.ignoreErrors)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, result, tt.wantCount)
			}
		})
	}
}
