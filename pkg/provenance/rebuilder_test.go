package provenance

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
			want: rebuildToolingImage,
		},
		{
			name: "construct from Go version with patch",
			buildInfo: &BuildInfo{
				GoVersion: "1.21.5",
			},
			want: rebuildToolingImage,
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
		{
			name: "go.mod with version normalization (no v prefix)",
			buildInfo: &BuildInfo{
				ModulePath: "github.com/example/app",
				GoVersion:  "1.22",
				Dependencies: map[string]string{
					"github.com/some/pkg": "v1.0.0",
				},
			},
			updates: map[string]string{
				"github.com/some/pkg": "1.0.1",
			},
			contains: []string{
				"module github.com/example/app",
				"go 1.22",
				"github.com/some/pkg v1.0.1",
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
		name       string
		buildInfo  *BuildInfo
		outputPath string
		contains   []string
	}{
		{
			name: "basic build command",
			buildInfo: &BuildInfo{
				CGOEnabled:  false,
				MainPackage: "./cmd/app",
			},
			outputPath: "/output/app",
			contains: []string{
				"CGO_ENABLED=0",
				"/usr/local/go/bin/go build",
				"-o /output/app",
				"./cmd/app",
			},
		},
		{
			name: "build with CGO enabled",
			buildInfo: &BuildInfo{
				CGOEnabled:  true,
				MainPackage: ".",
			},
			outputPath: "/output/binary",
			contains: []string{
				"CGO_ENABLED=1",
				"/usr/local/go/bin/go build",
				"-o /output/binary",
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
			outputPath: "/output/binary",
			contains: []string{
				"CGO_ENABLED=0",
				"GOOS=linux",
				"GOARCH=arm64",
				"/usr/local/go/bin/go build",
				"-o /output/binary",
			},
		},
		{
			name: "build with flags",
			buildInfo: &BuildInfo{
				CGOEnabled:  false,
				BuildFlags:  []string{"-trimpath", "-ldflags=-s -w"},
				MainPackage: "./cmd/server",
			},
			outputPath: "/output/server",
			contains: []string{
				"CGO_ENABLED=0",
				"-o /output/server",
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
			outputPath: "/output/app",
			contains: []string{
				"/usr/local/go/bin/go build",
				"-o /output/app",
				".",
			},
		},
		{
			name: "empty output path",
			buildInfo: &BuildInfo{
				CGOEnabled:  false,
				MainPackage: ".",
			},
			outputPath: "",
			contains: []string{
				"CGO_ENABLED=0",
				"/usr/local/go/bin/go build .",
			},
		},
	}

	rebuilder := NewRebuilder()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.buildInfo.BuildArgs == nil {
				tt.buildInfo.BuildArgs = make(map[string]string)
			}

			cmd, err := rebuilder.constructBuildCommand(tt.buildInfo, "/usr/local/go/bin/go", tt.outputPath)
			assert.NoError(t, err)

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

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.0.0", "v1.0.0"},
		{"v1.0.0", "v1.0.0"},
		{"", ""},
		{"2.3.4", "v2.3.4"},
		{"v0.0.0", "v0.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeVersion(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateBinaryPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid absolute path",
			path:    "/coredns",
			wantErr: false,
		},
		{
			name:    "valid nested path",
			path:    "/usr/bin/myapp",
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
			errMsg:  "empty",
		},
		{
			name:    "relative path",
			path:    "bin/myapp",
			wantErr: true,
			errMsg:  "absolute",
		},
		{
			name:    "path traversal",
			path:    "/usr/../etc/passwd",
			wantErr: true,
			errMsg:  "traversal",
		},
		{
			name:    "path with null byte",
			path:    "/app\x00malicious",
			wantErr: true,
			errMsg:  "null byte",
		},
		{
			name:    "path with shell metacharacters",
			path:    "/app;rm -rf /",
			wantErr: true,
			errMsg:  "unsafe characters",
		},
		{
			name:    "path with pipe",
			path:    "/app|cat",
			wantErr: true,
			errMsg:  "unsafe characters",
		},
		{
			name:    "path with backticks",
			path:    "/app`id`",
			wantErr: true,
			errMsg:  "unsafe characters",
		},
		{
			name:    "path with dollar sign",
			path:    "/app$HOME",
			wantErr: true,
			errMsg:  "unsafe characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBinaryPath(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestStripGoMajorVersionSuffix(t *testing.T) {
	tests := []struct {
		subpath string
		want    string
	}{
		{"", ""},
		{"v2", ""},
		{"v3", ""},
		{"v10", ""},
		{"v1", "v1"},
		{"v0", "v0"},
		{"cmd/app", "cmd/app"},
		{"cluster-autoscaler", "cluster-autoscaler"},
		{"pkg/v2", "pkg"},
		{"internal/cmd/v3", "internal/cmd"},
		{"vfoo", "vfoo"},
	}

	for _, tt := range tests {
		t.Run(tt.subpath, func(t *testing.T) {
			got := stripGoMajorVersionSuffix(tt.subpath)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDeriveRepoFromModulePath(t *testing.T) {
	tests := []struct {
		modulePath  string
		wantRepoURL string
		wantSubpath string
	}{
		{
			modulePath:  "github.com/user/repo",
			wantRepoURL: "https://github.com/user/repo",
			wantSubpath: "",
		},
		{
			modulePath:  "github.com/user/repo/subdir",
			wantRepoURL: "https://github.com/user/repo",
			wantSubpath: "subdir",
		},
		{
			modulePath:  "k8s.io/autoscaler",
			wantRepoURL: "https://github.com/kubernetes/autoscaler",
			wantSubpath: "",
		},
		{
			modulePath:  "k8s.io/autoscaler/cluster-autoscaler",
			wantRepoURL: "https://github.com/kubernetes/autoscaler",
			wantSubpath: "cluster-autoscaler",
		},
		{
			modulePath:  "golang.org/x/net",
			wantRepoURL: "https://github.com/golang/net",
			wantSubpath: "",
		},
		{
			modulePath:  "sigs.k8s.io/controller-runtime",
			wantRepoURL: "https://github.com/kubernetes-sigs/controller-runtime",
			wantSubpath: "",
		},
		{
			modulePath:  "",
			wantRepoURL: "",
			wantSubpath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.modulePath, func(t *testing.T) {
			repoURL, subpath := deriveRepoFromModulePath(tt.modulePath)
			assert.Equal(t, tt.wantRepoURL, repoURL)
			assert.Equal(t, tt.wantSubpath, subpath)
		})
	}
}
