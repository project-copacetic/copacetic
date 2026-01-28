package provenance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGoVersionOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []*BinaryInfo
	}{
		{
			name: "single binary with full info",
			input: `=== BINARY: /coredns ===
/target/coredns: go1.20.7
	path	github.com/coredns/coredns
	mod	github.com/coredns/coredns	v1.11.1	h1:abc123
	dep	github.com/miekg/dns	v1.1.55	h1:def456
	dep	golang.org/x/net	v0.18.0	h1:ghi789
	build	-buildmode=exe
	build	CGO_ENABLED=0
	build	GOOS=linux
	build	GOARCH=amd64
	build	vcs=git
	build	vcs.revision=abc123def456
	build	vcs.time=2023-10-01T12:00:00Z
	build	vcs.modified=false

`,
			expected: []*BinaryInfo{
				{
					Path:       "/coredns",
					GoVersion:  "go1.20.7",
					ModulePath: "github.com/coredns/coredns",
					Main:       "github.com/coredns/coredns@v1.11.1",
					Dependencies: map[string]string{
						"github.com/miekg/dns": "v1.1.55",
						"golang.org/x/net":     "v0.18.0",
					},
					BuildSettings: map[string]string{
						"-buildmode":  "exe",
						"CGO_ENABLED": "0",
						"GOOS":        "linux",
						"GOARCH":      "amd64",
					},
					VCS: map[string]string{
						"vcs":          "git",
						"vcs.revision": "abc123def456",
						"vcs.time":     "2023-10-01T12:00:00Z",
						"vcs.modified": "false",
					},
				},
			},
		},
		{
			name: "multiple binaries",
			input: `=== DEBUG: /target contents ===
total 123456

=== DEBUG: bins found ===
/target/app1 /target/app2

=== BINARY: /app1 ===
/target/app1: go1.21.5
	path	github.com/example/app1
	mod	github.com/example/app1	v1.0.0	h1:abc
	build	CGO_ENABLED=0

=== BINARY: /app2 ===
/target/app2: go1.22.0
	path	github.com/example/app2
	mod	github.com/example/app2	v2.0.0	h1:def
	dep	github.com/pkg/errors	v0.9.1	h1:xyz
	build	CGO_ENABLED=1

`,
			expected: []*BinaryInfo{
				{
					Path:          "/app1",
					GoVersion:     "go1.21.5",
					ModulePath:    "github.com/example/app1",
					Main:          "github.com/example/app1@v1.0.0",
					Dependencies:  map[string]string{},
					BuildSettings: map[string]string{"CGO_ENABLED": "0"},
					VCS:           map[string]string{},
				},
				{
					Path:       "/app2",
					GoVersion:  "go1.22.0",
					ModulePath: "github.com/example/app2",
					Main:       "github.com/example/app2@v2.0.0",
					Dependencies: map[string]string{
						"github.com/pkg/errors": "v0.9.1",
					},
					BuildSettings: map[string]string{"CGO_ENABLED": "1"},
					VCS:           map[string]string{},
				},
			},
		},
		{
			name: "binary with NOT_GO_BINARY marker",
			input: `=== BINARY: /bin/sh ===
NOT_GO_BINARY

=== BINARY: /app ===
/target/app: go1.21.0
	path	github.com/example/app
	mod	github.com/example/app	v1.0.0	h1:abc

`,
			expected: []*BinaryInfo{
				{
					Path:          "/app",
					GoVersion:     "go1.21.0",
					ModulePath:    "github.com/example/app",
					Main:          "github.com/example/app@v1.0.0",
					Dependencies:  map[string]string{},
					BuildSettings: map[string]string{},
					VCS:           map[string]string{},
				},
			},
		},
		{
			name: "binary with ldflags",
			input: `=== BINARY: /myapp ===
/target/myapp: go1.21.0
	path	github.com/example/myapp
	mod	github.com/example/myapp	v1.0.0	h1:abc
	build	-ldflags=-s -w -X main.version=1.0.0

`,
			expected: []*BinaryInfo{
				{
					Path:          "/myapp",
					GoVersion:     "go1.21.0",
					ModulePath:    "github.com/example/myapp",
					Main:          "github.com/example/myapp@v1.0.0",
					Dependencies:  map[string]string{},
					BuildSettings: map[string]string{"-ldflags": "-s -w -X main.version=1.0.0"},
					VCS:           map[string]string{},
				},
			},
		},
		{
			name:     "empty output",
			input:    "",
			expected: nil,
		},
		{
			name: "only debug output no binaries",
			input: `=== DEBUG: /target contents ===
total 0

=== DEBUG: bins found ===

`,
			expected: nil,
		},
		{
			name: "binary without Go version line",
			input: `=== BINARY: /corrupt ===
some garbage output

=== BINARY: /valid ===
/target/valid: go1.21.0
	path	github.com/example/valid

`,
			expected: []*BinaryInfo{
				{
					Path:          "/valid",
					GoVersion:     "go1.21.0",
					ModulePath:    "github.com/example/valid",
					Dependencies:  map[string]string{},
					BuildSettings: map[string]string{},
					VCS:           map[string]string{},
				},
			},
		},
	}

	detector := NewDetector()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.parseGoVersionOutput(tt.input)

			if tt.expected == nil {
				assert.Nil(t, result)
				return
			}

			require.Len(t, result, len(tt.expected))

			for i, expected := range tt.expected {
				actual := result[i]
				assert.Equal(t, expected.Path, actual.Path, "Path mismatch for binary %d", i)
				assert.Equal(t, expected.GoVersion, actual.GoVersion, "GoVersion mismatch for binary %d", i)
				assert.Equal(t, expected.ModulePath, actual.ModulePath, "ModulePath mismatch for binary %d", i)
				assert.Equal(t, expected.Main, actual.Main, "Main mismatch for binary %d", i)
				assert.Equal(t, expected.Dependencies, actual.Dependencies, "Dependencies mismatch for binary %d", i)
				assert.Equal(t, expected.BuildSettings, actual.BuildSettings, "BuildSettings mismatch for binary %d", i)
				assert.Equal(t, expected.VCS, actual.VCS, "VCS mismatch for binary %d", i)
			}
		})
	}
}

func TestConvertBinaryInfoToBuildInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    *BinaryInfo
		expected *BuildInfo
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name: "full binary info",
			input: &BinaryInfo{
				Path:       "/coredns",
				GoVersion:  "go1.20.7",
				ModulePath: "github.com/coredns/coredns",
				Dependencies: map[string]string{
					"github.com/miekg/dns": "v1.1.55",
					"golang.org/x/net":     "v0.18.0",
				},
				BuildSettings: map[string]string{
					"CGO_ENABLED": "0",
					"GOOS":        "linux",
					"GOARCH":      "amd64",
					"-ldflags":    "-s -w",
				},
				VCS: map[string]string{
					"vcs.revision": "abc123def456",
				},
			},
			expected: &BuildInfo{
				GoVersion:  "1.20.7",
				ModulePath: "github.com/coredns/coredns",
				CGOEnabled: false,
				Dependencies: map[string]string{
					"github.com/miekg/dns": "v1.1.55",
					"golang.org/x/net":     "v0.18.0",
				},
				BuildFlags: []string{"-ldflags=-s -w"},
				BuildArgs: map[string]string{
					"GOOS":          "linux",
					"GOARCH":        "amd64",
					"_sourceCommit": "abc123def456",
					"_sourceRepo":   "https://github.com/coredns/coredns",
				},
			},
		},
		{
			name: "CGO enabled",
			input: &BinaryInfo{
				Path:       "/app",
				GoVersion:  "go1.21.0",
				ModulePath: "github.com/example/app",
				BuildSettings: map[string]string{
					"CGO_ENABLED": "1",
				},
				Dependencies: map[string]string{},
				VCS:          map[string]string{},
			},
			expected: &BuildInfo{
				GoVersion:    "1.21.0",
				ModulePath:   "github.com/example/app",
				CGOEnabled:   true,
				Dependencies: map[string]string{},
				BuildArgs: map[string]string{
					"_sourceRepo": "https://github.com/example/app",
				},
			},
		},
		{
			name: "k8s.io module path",
			input: &BinaryInfo{
				Path:          "/app",
				GoVersion:     "go1.21.0",
				ModulePath:    "k8s.io/autoscaler/cluster-autoscaler",
				Dependencies:  map[string]string{},
				BuildSettings: map[string]string{},
				VCS:           map[string]string{},
			},
			expected: &BuildInfo{
				GoVersion:    "1.21.0",
				ModulePath:   "k8s.io/autoscaler/cluster-autoscaler",
				CGOEnabled:   false,
				Dependencies: map[string]string{},
				BuildArgs: map[string]string{
					"_sourceRepo": "https://github.com/kubernetes/autoscaler",
				},
			},
		},
		{
			name: "golang.org/x module path",
			input: &BinaryInfo{
				Path:          "/app",
				GoVersion:     "go1.21.0",
				ModulePath:    "golang.org/x/tools/gopls",
				Dependencies:  map[string]string{},
				BuildSettings: map[string]string{},
				VCS:           map[string]string{},
			},
			expected: &BuildInfo{
				GoVersion:    "1.21.0",
				ModulePath:   "golang.org/x/tools/gopls",
				CGOEnabled:   false,
				Dependencies: map[string]string{},
				BuildArgs: map[string]string{
					"_sourceRepo": "https://github.com/golang/tools",
				},
			},
		},
	}

	detector := NewDetector()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.ConvertBinaryInfoToBuildInfo(tt.input)

			if tt.expected == nil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, tt.expected.GoVersion, result.GoVersion)
			assert.Equal(t, tt.expected.ModulePath, result.ModulePath)
			assert.Equal(t, tt.expected.CGOEnabled, result.CGOEnabled)
			assert.Equal(t, tt.expected.Dependencies, result.Dependencies)
			assert.Equal(t, tt.expected.BuildFlags, result.BuildFlags)

			// Check BuildArgs - expected values should be present
			for k, v := range tt.expected.BuildArgs {
				assert.Equal(t, v, result.BuildArgs[k], "BuildArgs[%s] mismatch", k)
			}
		})
	}
}

func TestRetryScript(t *testing.T) {
	script := retryScript("go mod download", 3)

	// Verify the script contains key elements
	assert.Contains(t, script, "max_retry=3")
	assert.Contains(t, script, "go mod download")
	assert.Contains(t, script, "sleep $delay")
	assert.Contains(t, script, "retry=$((retry+1))")
}
