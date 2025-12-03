package provenance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractSourceRepo(t *testing.T) {
	tests := []struct {
		name        string
		attestation *Attestation
		wantRepoURL string
		wantCommit  string
		wantErr     bool
		errContains string
	}{
		{
			name: "v0.2 provenance with git source in materials",
			attestation: &Attestation{
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Predicate: map[string]any{
					"materials": []any{
						map[string]any{
							"uri": "git+https://github.com/fluxcd/source-controller@refs/heads/main",
							"digest": map[string]any{
								"sha1": "abc123def456",
							},
						},
					},
				},
			},
			wantRepoURL: "https://github.com/fluxcd/source-controller",
			wantCommit:  "abc123def456",
			wantErr:     false,
		},
		{
			name: "v0.2 provenance with configSource",
			attestation: &Attestation{
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Predicate: map[string]any{
					"materials": []any{},
					"invocation": map[string]any{
						"configSource": map[string]any{
							"uri": "git+https://github.com/argoproj/argo-cd@refs/tags/v2.8.0",
							"digest": map[string]any{
								"sha1": "789abc123",
							},
						},
					},
				},
			},
			wantRepoURL: "https://github.com/argoproj/argo-cd",
			wantCommit:  "789abc123",
			wantErr:     false,
		},
		{
			name: "v1.0 provenance with resolvedDependencies",
			attestation: &Attestation{
				PredicateType: "https://slsa.dev/provenance/v1",
				Predicate: map[string]any{
					"buildDefinition": map[string]any{
						"resolvedDependencies": []any{
							map[string]any{
								"uri": "git+https://github.com/goharbor/harbor",
								"digest": map[string]any{
									"sha1": "def789ghi",
								},
							},
						},
					},
				},
			},
			wantRepoURL: "https://github.com/goharbor/harbor",
			wantCommit:  "def789ghi",
			wantErr:     false,
		},
		{
			name:        "nil attestation",
			attestation: nil,
			wantErr:     true,
			errContains: "nil attestation",
		},
		{
			name: "unsupported version",
			attestation: &Attestation{
				PredicateType: "https://slsa.dev/provenance/v0.3",
				Predicate:     map[string]any{},
			},
			wantErr:     true,
			errContains: "unsupported SLSA provenance version",
		},
		{
			name: "v0.2 with no git source",
			attestation: &Attestation{
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Predicate: map[string]any{
					"materials": []any{
						map[string]any{
							"uri": "docker://alpine:latest",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "no git source found",
		},
	}

	parser := NewParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoURL, commit, err := parser.ExtractSourceRepo(tt.attestation)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantRepoURL, repoURL)
			assert.Equal(t, tt.wantCommit, commit)
		})
	}
}

func TestParseBuildInfo(t *testing.T) {
	tests := []struct {
		name        string
		attestation *Attestation
		wantErr     bool
		checkFunc   func(t *testing.T, info *BuildInfo)
	}{
		{
			name: "v0.2 provenance with builder",
			attestation: &Attestation{
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Predicate: map[string]any{
					"builder": map[string]any{
						"id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v1.4.0",
					},
					"invocation": map[string]any{
						"parameters": map[string]any{
							"GO_VERSION": "1.21.0",
						},
					},
					"materials": []any{
						map[string]any{
							"uri": "docker://golang:1.21-alpine",
							"digest": map[string]any{
								"sha256": "abc123",
							},
						},
					},
				},
			},
			wantErr: false,
			checkFunc: func(t *testing.T, info *BuildInfo) {
				assert.NotEmpty(t, info.BuilderID)
				assert.Equal(t, "1.21.0", info.BuildArgs["GO_VERSION"])
			},
		},
		{
			name: "v1.0 provenance with buildDefinition",
			attestation: &Attestation{
				PredicateType: "https://slsa.dev/provenance/v1",
				Predicate: map[string]any{
					"buildDefinition": map[string]any{
						"buildType": "https://github.com/slsa-framework/slsa-github-generator/container@v1",
						"externalParameters": map[string]any{
							"source": map[string]any{
								"repository": "github.com/example/repo",
							},
						},
						"resolvedDependencies": []any{
							map[string]any{
								"uri": "docker://golang:1.22-alpine",
							},
						},
					},
					"runDetails": map[string]any{
						"builder": map[string]any{
							"id": "builder-id",
						},
					},
				},
			},
			wantErr: false,
			checkFunc: func(t *testing.T, info *BuildInfo) {
				assert.Equal(t, "builder-id", info.BuilderID)
			},
		},
		{
			name:        "nil attestation",
			attestation: nil,
			wantErr:     true,
		},
	}

	parser := NewParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parser.ParseBuildInfo(tt.attestation)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, info)

			if tt.checkFunc != nil {
				tt.checkFunc(t, info)
			}
		})
	}
}

func TestAssessCompleteness(t *testing.T) {
	tests := []struct {
		name           string
		buildInfo      *BuildInfo
		wantCanRebuild bool
		wantMissing    []string
	}{
		{
			name: "complete build info",
			buildInfo: &BuildInfo{
				Dockerfile:   "FROM golang:1.21",
				GoVersion:    "1.21",
				BaseImage:    "golang:1.21-alpine",
				BuildCommand: "go build -o app .",
			},
			wantCanRebuild: true,
			wantMissing:    []string{},
		},
		{
			name: "missing Dockerfile but can rebuild",
			buildInfo: &BuildInfo{
				GoVersion: "1.21",
				BaseImage: "golang:1.21-alpine",
			},
			wantCanRebuild: true,
			wantMissing:    []string{"Dockerfile", "build command"},
		},
		{
			name: "missing Go version",
			buildInfo: &BuildInfo{
				Dockerfile: "FROM golang:1.21",
				BaseImage:  "golang:1.21-alpine",
			},
			wantCanRebuild: false,
			wantMissing:    []string{"build command", "Go version"},
		},
		{
			name: "missing base image",
			buildInfo: &BuildInfo{
				GoVersion: "1.21",
			},
			wantCanRebuild: false,
			wantMissing:    []string{"Dockerfile", "build command", "base image"},
		},
		{
			name:           "empty build info",
			buildInfo:      &BuildInfo{},
			wantCanRebuild: false,
			wantMissing:    []string{"Dockerfile", "build command", "base image", "Go version"},
		},
	}

	parser := NewParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			completeness := parser.AssessCompleteness(tt.buildInfo)

			assert.Equal(t, tt.wantCanRebuild, completeness.CanRebuild)

			for _, missing := range tt.wantMissing {
				assert.Contains(t, completeness.MissingInfo, missing)
			}
		})
	}
}

func TestExtractGoVersionFromGoMod(t *testing.T) {
	tests := []struct {
		name  string
		goMod string
		want  string
	}{
		{
			name:  "standard go.mod",
			goMod: "module github.com/example/repo\n\ngo 1.21\n",
			want:  "1.21",
		},
		{
			name:  "go.mod with patch version",
			goMod: "module github.com/example/repo\n\ngo 1.21.5\n\nrequire (\n)\n",
			want:  "1.21.5",
		},
		{
			name:  "go.mod with toolchain directive",
			goMod: "module github.com/example/repo\n\ngo 1.22\ntoolchain go1.22.0\n",
			want:  "1.22",
		},
		{
			name:  "no go directive",
			goMod: "module github.com/example/repo\n\nrequire (\n)\n",
			want:  "",
		},
		{
			name:  "empty string",
			goMod: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGoVersionFromGoMod(tt.goMod)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractModulePathFromGoMod(t *testing.T) {
	tests := []struct {
		name  string
		goMod string
		want  string
	}{
		{
			name:  "standard module path",
			goMod: "module github.com/example/repo\n\ngo 1.21\n",
			want:  "github.com/example/repo",
		},
		{
			name:  "module path with subdirectory",
			goMod: "module github.com/example/repo/v2\n\ngo 1.21\n",
			want:  "github.com/example/repo/v2",
		},
		{
			name:  "go.dev module path",
			goMod: "module golang.org/x/tools\n\ngo 1.20\n",
			want:  "golang.org/x/tools",
		},
		{
			name:  "no module directive",
			goMod: "go 1.21\n\nrequire (\n)\n",
			want:  "",
		},
		{
			name:  "empty string",
			goMod: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractModulePathFromGoMod(tt.goMod)
			assert.Equal(t, tt.want, got)
		})
	}
}
