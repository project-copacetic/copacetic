package provenance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGitHubRepoURL(t *testing.T) {
	tests := []struct {
		name      string
		repoURL   string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			name:      "standard HTTPS URL",
			repoURL:   "https://github.com/fluxcd/source-controller",
			wantOwner: "fluxcd",
			wantRepo:  "source-controller",
			wantErr:   false,
		},
		{
			name:      "git+ prefixed URL",
			repoURL:   "git+https://github.com/argoproj/argo-cd",
			wantOwner: "argoproj",
			wantRepo:  "argo-cd",
			wantErr:   false,
		},
		{
			name:      "URL with .git suffix",
			repoURL:   "https://github.com/goharbor/harbor.git",
			wantOwner: "goharbor",
			wantRepo:  "harbor",
			wantErr:   false,
		},
		{
			name:      "URL with refs",
			repoURL:   "git+https://github.com/example/repo@refs/heads/main",
			wantOwner: "example",
			wantRepo:  "repo",
			wantErr:   false,
		},
		{
			name:      "URL with refs/tags",
			repoURL:   "git+https://github.com/kubernetes/kubernetes@refs/tags/v1.28.0",
			wantOwner: "kubernetes",
			wantRepo:  "kubernetes",
			wantErr:   false,
		},
		{
			name:      "simple github.com prefix",
			repoURL:   "github.com/owner/repo",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantErr:   false,
		},
		{
			name:      "URL with trailing slash",
			repoURL:   "https://github.com/owner/repo/",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantErr:   false,
		},
		{
			name:    "invalid URL - no repo",
			repoURL: "https://github.com/owner",
			wantErr: true,
		},
		{
			name:    "invalid URL - empty",
			repoURL: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := parseGitHubRepoURL(tt.repoURL)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantOwner, owner)
			assert.Equal(t, tt.wantRepo, repo)
		})
	}
}

func TestIsSLSAProvenance(t *testing.T) {
	tests := []struct {
		name          string
		predicateType string
		want          bool
	}{
		{
			name:          "SLSA v0.1",
			predicateType: "https://slsa.dev/provenance/v0.1",
			want:          true,
		},
		{
			name:          "SLSA v0.2",
			predicateType: "https://slsa.dev/provenance/v0.2",
			want:          true,
		},
		{
			name:          "SLSA v1",
			predicateType: "https://slsa.dev/provenance/v1",
			want:          true,
		},
		{
			name:          "SLSA v1.0",
			predicateType: "https://slsa.dev/provenance/v1.0",
			want:          true,
		},
		{
			name:          "non-SLSA predicate",
			predicateType: "https://in-toto.io/Statement/v0.1",
			want:          false,
		},
		{
			name:          "empty predicate type",
			predicateType: "",
			want:          false,
		},
		{
			name:          "SPDX SBOM",
			predicateType: "https://spdx.dev/Document",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSLSAProvenance(tt.predicateType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInferSLSALevel(t *testing.T) {
	tests := []struct {
		name      string
		predicate map[string]any
		want      int
	}{
		{
			name: "v0.2 with builder ID - level 2",
			predicate: map[string]any{
				"builder": map[string]any{
					"id": "https://github.com/slsa-framework/slsa-github-generator",
				},
			},
			want: 2,
		},
		{
			name: "v1.0 with builder in runDetails - level 2",
			predicate: map[string]any{
				"runDetails": map[string]any{
					"builder": map[string]any{
						"id": "builder-id",
					},
				},
			},
			want: 2,
		},
		{
			name: "with materials only - level 1",
			predicate: map[string]any{
				"materials": []any{
					map[string]any{"uri": "docker://alpine"},
				},
			},
			want: 1,
		},
		{
			name:      "nil predicate - level 0",
			predicate: nil,
			want:      0,
		},
		{
			name:      "empty predicate - level 0",
			predicate: map[string]any{},
			want:      0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferSLSALevel(nil, tt.predicate)
			assert.Equal(t, tt.want, got)
		})
	}
}
