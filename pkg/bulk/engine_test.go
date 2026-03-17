package bulk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildTargetRepository(t *testing.T) {
	tests := []struct {
		name           string
		sourceImage    string
		targetRegistry string
		expected       string
		expectError    bool
	}{
		{
			name:           "empty target registry uses source",
			sourceImage:    "quay.io/opstree/redis",
			targetRegistry: "",
			expected:       "quay.io/opstree/redis",
			expectError:    false,
		},
		{
			name:           "target registry with namespace",
			sourceImage:    "quay.io/opstree/redis",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/redis",
			expectError:    false,
		},
		{
			name:           "docker.io library image",
			sourceImage:    "docker.io/library/nginx",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/nginx",
			expectError:    false,
		},
		{
			name:           "short form image",
			sourceImage:    "nginx",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/nginx",
			expectError:    false,
		},
		{
			name:           "multi-level namespace",
			sourceImage:    "registry.io/team/project/redis",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/redis",
			expectError:    false,
		},
		{
			name:           "target registry with trailing slash",
			sourceImage:    "quay.io/opstree/redis",
			targetRegistry: "ghcr.io/myorg/",
			expected:       "ghcr.io/myorg/redis",
			expectError:    false,
		},
		{
			name:           "registry with port",
			sourceImage:    "registry.io:5000/team/redis",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/redis",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildTargetRepository(tt.sourceImage, tt.targetRegistry)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestMergeTarget(t *testing.T) {
	tests := []struct {
		name         string
		globalTarget TargetSpec
		imageTarget  TargetSpec
		expected     TargetSpec
	}{
		{
			name:         "both empty",
			globalTarget: TargetSpec{},
			imageTarget:  TargetSpec{},
			expected:     TargetSpec{},
		},
		{
			name: "only global target",
			globalTarget: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
			imageTarget: TargetSpec{},
			expected: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
		},
		{
			name:         "only image target",
			globalTarget: TargetSpec{},
			imageTarget: TargetSpec{
				Registry: "ghcr.io/image",
				Tag:      "{{ .SourceTag }}-fixed",
			},
			expected: TargetSpec{
				Registry: "ghcr.io/image",
				Tag:      "{{ .SourceTag }}-fixed",
			},
		},
		{
			name: "image target overrides global registry",
			globalTarget: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
			imageTarget: TargetSpec{
				Registry: "quay.io/override",
			},
			expected: TargetSpec{
				Registry: "quay.io/override",
				Tag:      "{{ .SourceTag }}-patched",
			},
		},
		{
			name: "image target overrides global tag",
			globalTarget: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
			imageTarget: TargetSpec{
				Tag: "{{ .SourceTag }}-fixed",
			},
			expected: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-fixed",
			},
		},
		{
			name: "image target overrides both",
			globalTarget: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
			imageTarget: TargetSpec{
				Registry: "quay.io/override",
				Tag:      "{{ .SourceTag }}-fixed",
			},
			expected: TargetSpec{
				Registry: "quay.io/override",
				Tag:      "{{ .SourceTag }}-fixed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeTarget(tt.globalTarget, tt.imageTarget)
			assert.Equal(t, tt.expected, result)
		})
	}
}
