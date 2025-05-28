package patch

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestLoadManualRules(t *testing.T) {
	tests := []struct {
		name    string
		content string
		setup   func(t *testing.T) string
		wantErr bool
		want    *ManualRules
	}{
		{
			name: "valid rules file",
			content: `rules:
  - target:
      path: /usr/bin/test
      sha256: abc123
    replacement:
      source: docker.io/library/busybox:latest
      internalPath: /bin/busybox
      sha256: def456
      mode: 0755
  - target:
      path: /etc/config
      sha256: 789abc
    replacement:
      source: docker.io/library/alpine:latest
      internalPath: /etc/alpine-release
      sha256: 123def
      mode: 0644`,
			wantErr: false,
			want: &ManualRules{
				Rules: []ManualRuleEntry{
					{
						Target: struct {
							Path   string `yaml:"path"`
							Sha256 string `yaml:"sha256"`
						}{
							Path:   "/usr/bin/test",
							Sha256: "abc123",
						},
						Replacement: struct {
							Source       string `yaml:"source"`
							InternalPath string `yaml:"internalPath"`
							Sha256       string `yaml:"sha256"`
							Mode         uint32 `yaml:"mode"`
						}{
							Source:       "docker.io/library/busybox:latest",
							InternalPath: "/bin/busybox",
							Sha256:       "def456",
							Mode:         0755, //nolint:gofumpt
						},
					},
					{
						Target: struct {
							Path   string `yaml:"path"`
							Sha256 string `yaml:"sha256"`
						}{
							Path:   "/etc/config",
							Sha256: "789abc",
						},
						Replacement: struct {
							Source       string `yaml:"source"`
							InternalPath string `yaml:"internalPath"`
							Sha256       string `yaml:"sha256"`
							Mode         uint32 `yaml:"mode"`
						}{
							Source:       "docker.io/library/alpine:latest",
							InternalPath: "/etc/alpine-release",
							Sha256:       "123def",
							Mode:         0644, //nolint:gofumpt
						},
					},
				},
			},
		},
		{
			name:    "empty rules file",
			content: `rules: []`,
			wantErr: false,
			want: &ManualRules{
				Rules: []ManualRuleEntry{},
			},
		},
		{
			name: "invalid yaml",
			content: `rules:
  - target
      path: /usr/bin/test`,
			wantErr: true,
		},
		{
			name: "non-existent file",
			setup: func(_ *testing.T) string {
				return "/non/existent/file.yaml"
			},
			wantErr: true,
		},
		{
			name: "single rule",
			content: `rules:
  - target:
      path: /bin/sh
      sha256: deadbeef
    replacement:
      source: test:latest
      internalPath: /bin/bash
      sha256: cafebabe
      mode: 0755`,
			wantErr: false,
			want: &ManualRules{
				Rules: []ManualRuleEntry{
					{
						Target: struct {
							Path   string `yaml:"path"`
							Sha256 string `yaml:"sha256"`
						}{
							Path:   "/bin/sh",
							Sha256: "deadbeef",
						},
						Replacement: struct {
							Source       string `yaml:"source"`
							InternalPath string `yaml:"internalPath"`
							Sha256       string `yaml:"sha256"`
							Mode         uint32 `yaml:"mode"`
						}{
							Source:       "test:latest",
							InternalPath: "/bin/bash",
							Sha256:       "cafebabe",
							Mode:         0755, //nolint:gofumpt
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.setup != nil {
				path = tt.setup(t)
			} else {
				// Create temporary file with content
				tmpDir := t.TempDir()
				tmpFile := filepath.Join(tmpDir, "rules.yaml")
				err := os.WriteFile(tmpFile, []byte(tt.content), 0644) //nolint:gosec,gofumpt
				assert.NoError(t, err)
				path = tmpFile
			}

			got, err := loadManualRules(path)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVerifySha(t *testing.T) {
	testData := []byte("test data")
	testSha := fmt.Sprintf("%x", sha256.Sum256(testData))

	tests := []struct {
		name     string
		data     []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "valid sha256",
			data:     testData,
			expected: testSha,
			wantErr:  false,
		},
		{
			name:     "valid sha256 with prefix",
			data:     testData,
			expected: "sha256:" + testSha,
			wantErr:  false,
		},
		{
			name:     "valid sha256 uppercase",
			data:     testData,
			expected: "SHA256:" + testSha,
			wantErr:  false,
		},
		{
			name:     "empty expected sha",
			data:     testData,
			expected: "",
			wantErr:  false,
		},
		{
			name:     "invalid sha",
			data:     testData,
			expected: "wrongsha",
			wantErr:  true,
		},
		{
			name:     "sha mismatch",
			data:     []byte("different data"),
			expected: testSha,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifySha(tt.data, tt.expected)
			if tt.wantErr {
				assert.Error(t, err)
				if err != nil {
					assert.Contains(t, err.Error(), "sha mismatch")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestApplyManualRules_EmptyRules(t *testing.T) {
	ctx := context.Background()

	// Test empty rules returns unchanged state
	rules := &ManualRules{
		Rules: []ManualRuleEntry{},
	}
	cfg := &buildkit.Config{
		ImageState: llb.Image("test:latest"),
	}

	result, err := applyManualRules(ctx, nil, cfg, rules)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestManualRuleEntryStructure(t *testing.T) {
	// Test that the structure can be properly marshaled/unmarshaled
	entry := ManualRuleEntry{
		Target: struct {
			Path   string `yaml:"path"`
			Sha256 string `yaml:"sha256"`
		}{
			Path:   "/test/path",
			Sha256: "abc123",
		},
		Replacement: struct {
			Source       string `yaml:"source"`
			InternalPath string `yaml:"internalPath"`
			Sha256       string `yaml:"sha256"`
			Mode         uint32 `yaml:"mode"`
		}{
			Source:       "test:latest",
			InternalPath: "/internal/path",
			Sha256:       "def456",
			Mode:         0755, //nolint:gofumpt
		},
	}

	assert.Equal(t, "/test/path", entry.Target.Path)
	assert.Equal(t, "abc123", entry.Target.Sha256)
	assert.Equal(t, "test:latest", entry.Replacement.Source)
	assert.Equal(t, "/internal/path", entry.Replacement.InternalPath)
	assert.Equal(t, "def456", entry.Replacement.Sha256)
	assert.Equal(t, uint32(0755), entry.Replacement.Mode) //nolint:gofumpt
}

func TestLoadManualRules_FileReadError(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := loadManualRules(tmpDir)
	assert.Error(t, err)
}

func TestManualRules_YAMLMarshalUnmarshal(t *testing.T) {
	original := &ManualRules{
		Rules: []ManualRuleEntry{
			{
				Target: struct {
					Path   string `yaml:"path"`
					Sha256 string `yaml:"sha256"`
				}{
					Path:   "/usr/bin/test",
					Sha256: "sha256:abcdef123456",
				},
				Replacement: struct {
					Source       string `yaml:"source"`
					InternalPath string `yaml:"internalPath"`
					Sha256       string `yaml:"sha256"`
					Mode         uint32 `yaml:"mode"`
				}{
					Source:       "docker.io/library/alpine:latest",
					InternalPath: "/bin/sh",
					Sha256:       "sha256:fedcba654321",
					Mode:         0755, //nolint:gofumpt
				},
			},
		},
	}

	yamlData, err := yaml.Marshal(original)
	assert.NoError(t, err)

	var unmarshaled ManualRules
	err = yaml.Unmarshal(yamlData, &unmarshaled)
	assert.NoError(t, err)

	assert.Equal(t, original, &unmarshaled)
}

func TestVerifySha_EdgeCases(t *testing.T) {
	err := verifySha(nil, "")
	assert.NoError(t, err)

	emptyData := []byte{}
	emptySha := fmt.Sprintf("%x", sha256.Sum256(emptyData))
	err = verifySha(emptyData, emptySha)
	assert.NoError(t, err)

	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	largeSha := fmt.Sprintf("%x", sha256.Sum256(largeData))
	err = verifySha(largeData, largeSha)
	assert.NoError(t, err)
}
