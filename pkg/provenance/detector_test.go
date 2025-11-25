package provenance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBuildInfoOutput(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		binaryPath string
		wantErr    bool
		checkFunc  func(t *testing.T, info *BinaryInfo)
	}{
		{
			name: "standard go version -m output",
			output: `/usr/local/bin/source-controller: go1.21.5
	path	github.com/fluxcd/source-controller
	mod	github.com/fluxcd/source-controller	v1.2.0	h1:abc123
	dep	github.com/go-logr/logr	v1.3.0	h1:2ghi456
	dep	golang.org/x/net	v0.19.0	h1:jkl789
	build	GOOS=linux
	build	GOARCH=amd64
	build	CGO_ENABLED=0
	build	vcs=git
	build	vcs.revision=abc123def456
	build	vcs.time=2023-12-01T10:00:00Z
`,
			binaryPath: "/usr/local/bin/source-controller",
			wantErr:    false,
			checkFunc: func(t *testing.T, info *BinaryInfo) {
				assert.Equal(t, "1.21.5", info.GoVersion)
				assert.Equal(t, "github.com/fluxcd/source-controller", info.ModulePath)
				assert.Equal(t, "github.com/fluxcd/source-controller", info.MainModule)
				assert.Equal(t, "v1.2.0", info.MainModuleVersion)
				assert.Equal(t, "linux", info.GOOS)
				assert.Equal(t, "amd64", info.GOARCH)
				assert.False(t, info.CGOEnabled)
				assert.Equal(t, "abc123def456", info.VCSRevision)
				assert.Equal(t, "git", info.VCS)
				assert.Contains(t, info.Dependencies, "github.com/go-logr/logr")
				assert.Equal(t, "v1.3.0", info.Dependencies["github.com/go-logr/logr"])
			},
		},
		{
			name: "output with CGO enabled",
			output: `/app/main: go1.22.0
	path	github.com/example/app
	mod	github.com/example/app	v0.1.0	h1:xyz
	build	CGO_ENABLED=1
	build	GOOS=linux
	build	GOARCH=arm64
`,
			binaryPath: "/app/main",
			wantErr:    false,
			checkFunc: func(t *testing.T, info *BinaryInfo) {
				assert.Equal(t, "1.22.0", info.GoVersion)
				assert.True(t, info.CGOEnabled)
				assert.Equal(t, "arm64", info.GOARCH)
			},
		},
		{
			name: "minimal output",
			output: `/bin/app: go1.20
	path	example.com/app
`,
			binaryPath: "/bin/app",
			wantErr:    false,
			checkFunc: func(t *testing.T, info *BinaryInfo) {
				assert.Equal(t, "1.20", info.GoVersion)
				assert.Equal(t, "example.com/app", info.ModulePath)
			},
		},
		{
			name:       "empty output",
			output:     "",
			binaryPath: "/bin/app",
			wantErr:    true,
		},
		{
			name: "output without go version",
			output: `	path	example.com/app
`,
			binaryPath: "/bin/app",
			wantErr:    true,
		},
	}

	detector := NewDetector()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := detector.parseBuildInfo(tt.output, tt.binaryPath)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, info)
			assert.Equal(t, tt.binaryPath, info.Path)

			if tt.checkFunc != nil {
				tt.checkFunc(t, info)
			}
		})
	}
}

func TestConvertBinaryInfoToBuildInfo(t *testing.T) {
	detector := NewDetector()

	binaryInfo := &BinaryInfo{
		Path:        "/app/bin",
		ModulePath:  "github.com/example/app",
		GoVersion:   "1.21.0",
		CGOEnabled:  false,
		GOOS:        "linux",
		GOARCH:      "amd64",
		VCSRevision: "abc123",
		Dependencies: map[string]string{
			"github.com/pkg/errors": "v0.9.1",
			"golang.org/x/net":      "v0.19.0",
		},
		BuildSettings: map[string]string{
			"CGO_ENABLED": "0",
			"-trimpath":   "true",
		},
	}

	buildInfo := detector.ConvertBinaryInfoToBuildInfo(binaryInfo)

	assert.Equal(t, "1.21.0", buildInfo.GoVersion)
	assert.Equal(t, "github.com/example/app", buildInfo.ModulePath)
	assert.False(t, buildInfo.CGOEnabled)
	assert.Equal(t, "linux", buildInfo.BuildArgs["GOOS"])
	assert.Equal(t, "amd64", buildInfo.BuildArgs["GOARCH"])
	assert.Equal(t, "abc123", buildInfo.BuildArgs["vcs.revision"])
	assert.Contains(t, buildInfo.Dependencies, "github.com/pkg/errors")
	assert.Equal(t, "v0.9.1", buildInfo.Dependencies["github.com/pkg/errors"])
}

func TestFilterGoBinaries(t *testing.T) {
	// This test would require mocking exec.Command
	// For now, we just test that the function handles empty input
	detector := NewDetector()

	result := detector.FilterGoBinaries(nil)
	assert.Empty(t, result)

	result = detector.FilterGoBinaries([]string{})
	assert.Empty(t, result)
}
