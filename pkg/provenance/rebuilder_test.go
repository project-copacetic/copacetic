package provenance

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetermineBaseImage(t *testing.T) {
	tests := []struct {
		name      string
		buildInfo *BuildInfo
		want      string
	}{
		{
			name: "explicit base image",
			buildInfo: &BuildInfo{
				BaseImage: "docker.io/library/golang:1.21-alpine",
				GoVersion: "1.21",
			},
			want: "docker.io/library/golang:1.21-alpine",
		},
		{
			name: "construct from Go version",
			buildInfo: &BuildInfo{
				GoVersion: "1.22",
			},
			want: "golang:1.22-alpine",
		},
		{
			name: "construct from Go version with patch",
			buildInfo: &BuildInfo{
				GoVersion: "1.21.5",
			},
			want: "golang:1.21.5-alpine",
		},
		{
			name:      "empty build info",
			buildInfo: &BuildInfo{},
			want:      "",
		},
	}

	rebuilder := NewRebuilder()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rebuilder.determineBaseImage(tt.buildInfo)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGenerateGoMod(t *testing.T) {
	tests := []struct {
		name      string
		buildInfo *BuildInfo
		updates   map[string]string
		contains  []string
	}{
		{
			name: "basic go.mod",
			buildInfo: &BuildInfo{
				ModulePath: "github.com/example/app",
				GoVersion:  "1.21",
				Dependencies: map[string]string{
					"github.com/pkg/errors": "v0.9.1",
				},
			},
			updates: map[string]string{},
			contains: []string{
				"module github.com/example/app",
				"go 1.21",
				"github.com/pkg/errors v0.9.1",
			},
		},
		{
			name: "go.mod with updates",
			buildInfo: &BuildInfo{
				ModulePath: "github.com/example/app",
				GoVersion:  "1.21",
				Dependencies: map[string]string{
					"github.com/pkg/errors": "v0.9.1",
					"golang.org/x/net":      "v0.18.0",
				},
			},
			updates: map[string]string{
				"golang.org/x/net": "v0.19.0",
			},
			contains: []string{
				"module github.com/example/app",
				"go 1.21",
				"github.com/pkg/errors v0.9.1",
				"golang.org/x/net v0.19.0",
			},
		},
		{
			name: "go.mod replacing existing dependency",
			buildInfo: &BuildInfo{
				ModulePath: "github.com/example/app",
				GoVersion:  "1.22",
				Dependencies: map[string]string{
					"github.com/vulnerable/pkg": "v1.0.0",
				},
			},
			updates: map[string]string{
				"github.com/vulnerable/pkg": "v1.0.1",
			},
			contains: []string{
				"module github.com/example/app",
				"go 1.22",
				"github.com/vulnerable/pkg v1.0.1",
			},
		},
	}

	rebuilder := NewRebuilder()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goMod := rebuilder.generateGoMod(tt.buildInfo, tt.updates)

			for _, s := range tt.contains {
				assert.Contains(t, goMod, s)
			}
		})
	}
}

func TestConstructBuildCommand(t *testing.T) {
	tests := []struct {
		name      string
		buildInfo *BuildInfo
		contains  []string
	}{
		{
			name: "basic build command",
			buildInfo: &BuildInfo{
				CGOEnabled:  false,
				MainPackage: "./cmd/app",
			},
			contains: []string{
				"CGO_ENABLED=0",
				"go build",
				"./cmd/app",
			},
		},
		{
			name: "build with CGO enabled",
			buildInfo: &BuildInfo{
				CGOEnabled:  true,
				MainPackage: ".",
			},
			contains: []string{
				"CGO_ENABLED=1",
				"go build",
			},
		},
		{
			name: "build with GOOS/GOARCH",
			buildInfo: &BuildInfo{
				CGOEnabled: false,
				BuildArgs: map[string]string{
					"GOOS":   "linux",
					"GOARCH": "arm64",
				},
				MainPackage: ".",
			},
			contains: []string{
				"CGO_ENABLED=0",
				"GOOS=linux",
				"GOARCH=arm64",
				"go build",
			},
		},
		{
			name: "build with flags",
			buildInfo: &BuildInfo{
				CGOEnabled:  false,
				BuildFlags:  []string{"-trimpath", "-ldflags=-s -w"},
				MainPackage: "./cmd/server",
			},
			contains: []string{
				"CGO_ENABLED=0",
				"-trimpath",
				"-ldflags=-s -w",
				"./cmd/server",
			},
		},
		{
			name: "default main package",
			buildInfo: &BuildInfo{
				CGOEnabled: false,
			},
			contains: []string{
				"go build",
				".", // Default to current directory
			},
		},
	}

	rebuilder := NewRebuilder()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure BuildArgs is initialized
			if tt.buildInfo.BuildArgs == nil {
				tt.buildInfo.BuildArgs = make(map[string]string)
			}

			cmd := rebuilder.constructBuildCommand(tt.buildInfo)

			for _, s := range tt.contains {
				assert.Contains(t, cmd, s)
			}
		})
	}
}

func TestRebuildStrategy_String(t *testing.T) {
	tests := []struct {
		strategy RebuildStrategy
		want     string
	}{
		{RebuildStrategyAuto, "auto"},
		{RebuildStrategyProvenance, "provenance"},
		{RebuildStrategyHeuristic, "heuristic"},
		{RebuildStrategyNone, "none"},
		{RebuildStrategy(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.strategy.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDiagnoseRebuildIssue(t *testing.T) {
	tests := []struct {
		name       string
		rebuildCtx *RebuildContext
		wantIssues []string
	}{
		{
			name:       "nil context",
			rebuildCtx: nil,
			wantIssues: []string{"No rebuild context available"},
		},
		{
			name: "no provenance",
			rebuildCtx: &RebuildContext{
				Provenance: nil,
			},
			wantIssues: []string{"No SLSA provenance found"},
		},
		{
			name: "missing build info fields",
			rebuildCtx: &RebuildContext{
				Provenance: &Attestation{},
				BuildInfo:  &BuildInfo{
					// Missing GoVersion, ModulePath, Dockerfile
				},
			},
			wantIssues: []string{
				"Go version not detected",
				"Module path not detected",
				"Dockerfile not in provenance",
			},
		},
		{
			name: "no binaries detected",
			rebuildCtx: &RebuildContext{
				Provenance: &Attestation{},
				BuildInfo: &BuildInfo{
					GoVersion:  "1.21",
					ModulePath: "github.com/example/app",
					Dockerfile: "FROM golang:1.21",
				},
				BinaryInfo: nil,
			},
			wantIssues: []string{"No Go binaries detected"},
		},
		{
			name: "complete context",
			rebuildCtx: &RebuildContext{
				Provenance: &Attestation{},
				BuildInfo: &BuildInfo{
					GoVersion:  "1.21",
					ModulePath: "github.com/example/app",
					Dockerfile: "FROM golang:1.21",
				},
				BinaryInfo: []*BinaryInfo{
					{Path: "/app/bin"},
				},
			},
			wantIssues: []string{"Build information appears complete"},
		},
	}

	rebuilder := NewRebuilder()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := rebuilder.DiagnoseRebuildIssue(tt.rebuildCtx)

			for _, want := range tt.wantIssues {
				found := false
				for _, issue := range issues {
					if strings.Contains(issue, want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected issue containing %q not found in %v", want, issues)
				}
			}
		})
	}
}

func TestRebuildError(t *testing.T) {
	tests := []struct {
		name         string
		rebuildError *RebuildError
		wantContains string
	}{
		{
			name: "error with underlying",
			rebuildError: &RebuildError{
				Phase:      "clone",
				Message:    "failed to clone repository",
				Underlying: assert.AnError,
			},
			wantContains: "[clone]",
		},
		{
			name: "error without underlying",
			rebuildError: &RebuildError{
				Phase:   "build",
				Message: "go build failed",
			},
			wantContains: "[build]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.rebuildError.Error()
			assert.Contains(t, errStr, tt.wantContains)
		})
	}
}

func TestFormatRebuildSummary(t *testing.T) {
	rebuilder := NewRebuilder()

	rebuildCtx := &RebuildContext{
		BuildInfo: &BuildInfo{
			GoVersion:  "1.21",
			ModulePath: "github.com/example/app",
			CGOEnabled: false,
			Dockerfile: "FROM golang:1.21",
		},
		BinaryInfo: []*BinaryInfo{
			{Path: "/app/bin", GoVersion: "1.21"},
		},
	}

	result := &RebuildResult{
		Strategy:        "provenance",
		Success:         true,
		BinariesRebuilt: 1,
	}

	summary := rebuilder.FormatRebuildSummary(rebuildCtx, result)

	require.NotEmpty(t, summary)
	assert.Contains(t, summary, "Go Binary Rebuild Summary")
	assert.Contains(t, summary, "Strategy: provenance")
	assert.Contains(t, summary, "Success: true")
	assert.Contains(t, summary, "Go Version: 1.21")
	assert.Contains(t, summary, "Module: github.com/example/app")
	assert.Contains(t, summary, "Dockerfile: Available")
	assert.Contains(t, summary, "Detected Binaries: 1")
}
