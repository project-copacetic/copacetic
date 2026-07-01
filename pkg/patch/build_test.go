package patch

import (
	"io"
	"testing"

	"github.com/moby/buildkit/client"
	sourcepolicy "github.com/moby/buildkit/sourcepolicy/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateSourcePolicy tests the validateSourcePolicy function.
func TestValidateSourcePolicy(t *testing.T) {
	testCases := []struct {
		name        string
		policy      *sourcepolicy.Policy
		wantErr     bool
		errContains string
	}{
		{
			name:    "nil policy",
			policy:  nil,
			wantErr: false,
		},
		{
			name: "empty rules",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{},
			},
			wantErr: false,
		},
		{
			name: "supported identifier - ubuntu",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "docker.io/library/ubuntu:20.04",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "supported identifier - alpine",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "docker.io/library/alpine:3.14",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "supported identifier - centos",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "docker.io/library/centos:7",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "unsupported identifier - redhat",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "registry.redhat.io/rhel8/rhel:latest",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "RedHat is not supported via source policies",
		},
		{
			name: "unsupported identifier - rockylinux",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "docker.io/library/rockylinux:8",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "RockyLinux is not supported via source policies",
		},
		{
			name: "unsupported identifier - alma",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "docker.io/library/almalinux:8",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "AlmaLinux is not supported via source policies",
		},
		{
			name: "case sensitive - REDHAT (should not match)",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "docker.io/REDHAT/rhel:8",
						},
					},
				},
			},
			wantErr: false, // strings.Contains is case-sensitive, so "REDHAT" != "redhat"
		},
		{
			name: "partial match - contains redhat in path",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "quay.io/redhat/some-image:latest",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "RedHat is not supported via source policies",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSourcePolicy(tc.policy)

			if tc.wantErr {
				assert.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestRewriteVersionAnnotation pins down the version-rewrite contract used by
// both the single-platform exporter (createBuildConfig) and the multi-platform
// index assembly (createMultiPlatformManifest). The two paths must agree so
// that copa patch produces consistent metadata regardless of input topology.
func TestRewriteVersionAnnotation(t *testing.T) {
	tests := []struct {
		name            string
		originalVersion string
		patchedTag      string
		want            string
	}{
		{
			name:            "patched tag contains original version",
			originalVersion: "1.0.0",
			patchedTag:      "1.0.0-patched",
			want:            "1.0.0-patched",
		},
		{
			name:            "patched tag does not contain original version",
			originalVersion: "1.0.0",
			patchedTag:      "patched",
			want:            "1.0.0-patched",
		},
		{
			name:            "patched tag identical to original version",
			originalVersion: "1.0.0",
			patchedTag:      "1.0.0",
			want:            "1.0.0",
		},
		{
			name:            "empty patched tag returns original",
			originalVersion: "1.0.0",
			patchedTag:      "",
			want:            "1.0.0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rewriteVersionAnnotation(tc.originalVersion, tc.patchedTag)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCreateBuildConfigLocalExportCompression(t *testing.T) {
	tests := []struct {
		name                 string
		compression          string
		forceCompression     bool
		wantCompression      string
		wantForceCompression bool
	}{
		{
			name:            "default compression without force compression",
			wantCompression: defaultLocalExportCompression,
		},
		{
			name:                 "custom compression with force compression",
			compression:          "gzip",
			forceCompression:     true,
			wantCompression:      "gzip",
			wantForceCompression: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pipeR, pipeW := io.Pipe()
			defer pipeR.Close()
			defer pipeW.Close()

			buildConfig, err := createBuildConfig(
				"example.com/app:patched",
				false,
				false,
				pipeW,
				nil,
				"patched",
				tc.compression,
				tc.forceCompression,
			)
			require.NoError(t, err)
			require.Len(t, buildConfig.SolveOpt.Exports, 1)

			export := buildConfig.SolveOpt.Exports[0]
			assert.Equal(t, client.ExporterDocker, export.Type)
			assert.Equal(t, tc.wantCompression, export.Attrs["compression"])
			_, hasForceCompression := export.Attrs["force-compression"]
			assert.Equal(t, tc.wantForceCompression, hasForceCompression)
		})
	}
}

func TestCreateBuildConfigPushDoesNotSetLocalCompressionAttrs(t *testing.T) {
	pipeR, pipeW := io.Pipe()
	defer pipeR.Close()
	defer pipeW.Close()

	buildConfig, err := createBuildConfig(
		"example.com/app:patched",
		false,
		true,
		pipeW,
		nil,
		"patched",
		"gzip",
		true,
	)
	require.NoError(t, err)
	require.Len(t, buildConfig.SolveOpt.Exports, 1)

	export := buildConfig.SolveOpt.Exports[0]
	assert.Equal(t, client.ExporterImage, export.Type)
	assert.NotContains(t, export.Attrs, "compression")
	assert.NotContains(t, export.Attrs, "force-compression")
}
