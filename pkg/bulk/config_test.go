package bulk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestPatchConfigChiselRelease(t *testing.T) {
	var config PatchConfig
	err := yaml.Unmarshal([]byte(`
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
chiselRelease: ubuntu-24.04
images:
  - name: default-release
    image: example.com/default
    tags:
      strategy: latest
  - name: overridden-release
    image: example.com/override
    chiselRelease: https://example.com/releases.git#abc123
    tags:
      strategy: latest
`), &config)
	require.NoError(t, err)
	require.Len(t, config.Images, 2)
	assert.Equal(t, "ubuntu-24.04", config.ChiselRelease)
	assert.Empty(t, config.Images[0].ChiselRelease)
	assert.Equal(t, "https://example.com/releases.git#abc123", config.Images[1].ChiselRelease)
}

func TestTagStrategy_UnmarshalYAML(t *testing.T) {
	testCases := []struct {
		name      string
		yamlInput string
		expectErr bool
		checkFunc func(*TagStrategy) bool // Optional check for successful unmarshals
	}{
		{
			name: "Valid Strategy - List",
			yamlInput: `
strategy: "list"
list: ["tag1", "tag2"]`,
			expectErr: false,
			checkFunc: func(ts *TagStrategy) bool {
				return ts.Strategy == "list" && len(ts.List) == 2
			},
		},
		{
			name: "Invalid Strategy - List without items",
			yamlInput: `strategy: "list"
									list: []`,
			expectErr: true,
		},
		{
			name: "Valid Strategy - Pattern",
			yamlInput: `
strategy: "pattern"
pattern: "^1\\.2[0-9]+$"`,
			expectErr: false,
			checkFunc: func(ts *TagStrategy) bool {
				return ts.Strategy == "pattern" && ts.compiledPattern != nil
			},
		},
		{
			name:      "Invalid Strategy - Pattern without pattern string",
			yamlInput: `strategy: "pattern"`,
			expectErr: true,
		},
		{
			name: "Invalid Strategy - Pattern with bad regex",
			yamlInput: `strategy: "pattern"
									pattern: "*not-a-valid-regex"`,
			expectErr: true,
		},
		{
			name:      "Valid Strategy - Latest",
			yamlInput: `strategy: "latest"`,
			expectErr: false,
			checkFunc: func(ts *TagStrategy) bool {
				return ts.Strategy == "latest"
			},
		},
		{
			name:      "Invalid Strategy - Unknown",
			yamlInput: `strategy: "unknown"`,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var ts TagStrategy
			err := yaml.Unmarshal([]byte(tc.yamlInput), &ts)

			if (err != nil) != tc.expectErr {
				t.Errorf("Expected error: %v, but got: %v", tc.expectErr, err)
			}

			if !tc.expectErr && tc.checkFunc != nil {
				if !tc.checkFunc(&ts) {
					t.Errorf("Post-unmarshal check failed for valid case")
				}
			}
		})
	}
}

func TestValidateOverrides(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]OverrideSpec
		wantErr   bool
	}{
		{name: "rewrite", overrides: map[string]OverrideSpec{"app": {From: "slim", To: "bookworm"}}},
		{name: "path only", overrides: map[string]OverrideSpec{"app": {ValuePath: "deployment.image"}}},
		{name: "rewrite and path", overrides: map[string]OverrideSpec{"app": {From: "slim", To: "bookworm", ValuePath: "deployment.image"}}},
		{name: "missing to", overrides: map[string]OverrideSpec{"app": {From: "slim"}}, wantErr: true},
		{name: "empty", overrides: map[string]OverrideSpec{"app": {}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOverrides(tt.overrides)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected validation error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}
