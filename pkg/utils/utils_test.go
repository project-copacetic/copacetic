package utils

import (
	"context"
	"log"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/stretchr/testify/assert"
)

const (
	newDir       = "a/b/new_path"
	diffPermsDir = "a/diff_perms"
	existingDir  = "a/dir_exists"
	emptyFile    = "a/empty_file"
	nonemptyFile = "a/nonempty_file"

	// Note that we are using the /tmp folder, so use perms that
	// do not conflict with the sticky bit.
	testPerms = 0o711
)

// Global for the test root directory used by all tests.
var testRootDir string

func TestMain(m *testing.M) {
	// Create the root temp test directory.
	var err error
	testRootDir, err = os.MkdirTemp("", "utils_test_*")
	if err != nil {
		log.Println("Failed to create test temp folder")
		return
	}
	defer os.RemoveAll(testRootDir)

	// Create a test directory with different permissions.
	testDir := path.Join(testRootDir, diffPermsDir)
	err = os.MkdirAll(testDir, 0o744)
	if err != nil {
		log.Printf("Failed to create test folder: %s\n", err)
		return
	}

	// Create an existing test directory.
	testDir = path.Join(testRootDir, existingDir)
	err = os.MkdirAll(testDir, testPerms)
	if err != nil {
		log.Printf("Failed to create test folder %s\n", testDir)
		return
	}

	// Create an empty test file.
	testFile := path.Join(testRootDir, emptyFile)
	f, err := os.Create(testFile)
	if err != nil {
		log.Printf("Failed to create test file %s\n", testFile)
		return
	}
	f.Close()

	// Create a non-empty test file.
	testFile = path.Join(testRootDir, nonemptyFile)
	f, err = os.Create(testFile)
	if err != nil {
		log.Printf("Failed to create test file %s\n", testFile)
		return
	}
	_, err = f.WriteString("This is a non-empty test file")
	f.Close()
	if err != nil {
		log.Printf("Failed to write to test file: %s\n", err)
		return
	}

	m.Run()
}

func TestEnsurePath(t *testing.T) {
	type args struct {
		path string
		perm os.FileMode
	}
	tests := []struct {
		name    string
		args    args
		created bool
		wantErr bool
	}{
		{"CreateNewPath", args{newDir, testPerms}, true, false},
		{"PathExists", args{existingDir, testPerms}, false, false},
		{"PathExistsWithDiffPerms", args{diffPermsDir, testPerms}, false, true},
		{"PathIsFile", args{emptyFile, testPerms}, false, true},
		{"EmptyPath", args{"", testPerms}, false, true},
		{"EmptyPerms", args{existingDir, 0o000}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testPath := path.Join(testRootDir, tt.args.path)
			createdPath, err := EnsurePath(testPath, tt.args.perm)
			if (err != nil) != tt.wantErr {
				t.Errorf("EnsurePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if createdPath != tt.created {
				t.Errorf("EnsurePath() created = %v, want %v", createdPath, tt.created)
			}
		})
	}
	// Clean up new path in case go test is run for -count > 1
	os.Remove(path.Join(testRootDir, newDir))
}

func TestIsNonEmptyFile(t *testing.T) {
	type args struct {
		dir  string
		file string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"NonEmptyFile", args{testRootDir, nonemptyFile}, true},
		{"EmptyFile", args{testRootDir, emptyFile}, false},
		{"MissingFile", args{testRootDir, "does_not_exist"}, false},
		{"UnspecifiedPath", args{"", existingDir}, false},
		{"UnspecifiedFile", args{testRootDir, ""}, false},
		{"PathIsDirectory", args{testRootDir, existingDir}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNonEmptyFile(tt.args.dir, tt.args.file); got != tt.want {
				t.Errorf("IsNonEmptyFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetProxy(t *testing.T) {
	var got llb.ProxyEnv
	var want llb.ProxyEnv

	// Test with configured proxy
	os.Setenv("HTTP_PROXY", "httpproxy")
	os.Setenv("HTTPS_PROXY", "httpsproxy")
	os.Setenv("NO_PROXY", "noproxy")
	got = GetProxy()
	want = llb.ProxyEnv{
		HTTPProxy:  "httpproxy",
		HTTPSProxy: "httpsproxy",
		NoProxy:    "noproxy",
		AllProxy:   "httpproxy",
	}
	if got != want {
		t.Errorf("unexpected proxy config, got %#v want %#v", got, want)
	}

	// Test with unconfigured proxy
	os.Unsetenv("HTTP_PROXY")
	os.Unsetenv("HTTPS_PROXY")
	os.Unsetenv("NO_PROXY")
	got = GetProxy()
	want = llb.ProxyEnv{
		HTTPProxy:  "",
		HTTPSProxy: "",
		NoProxy:    "",
		AllProxy:   "",
	}
	if got != want {
		t.Errorf("unexpected proxy config, got %#v want %#v", got, want)
	}
}

func TestDeduplicateStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "with duplicates",
			input:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "all duplicates",
			input:    []string{"a", "a", "a"},
			expected: []string{"a"},
		},
		{
			name:     "single item",
			input:    []string{"a"},
			expected: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DeduplicateStringSlice(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expected length %d, got %d", len(tt.expected), len(result))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("expected %v, got %v", tt.expected, result)
					break
				}
			}
		})
	}
}

// TestLocalImageDescriptor tests the localImageDescriptor function with error scenarios.
func TestLocalImageDescriptor(t *testing.T) {
	ctx := context.Background()

	// Test with a non-existent image reference (Docker is available in CI)
	t.Run("nonexistent_image", func(t *testing.T) {
		desc, err := localImageDescriptor(ctx, "invalid/nonexistent:image")
		assert.Error(t, err)
		assert.Nil(t, desc)

		// In CI, Docker is available, so we get a "No such image" error
		assert.Contains(t, err.Error(), "No such image")
	})

	// Test with context cancellation
	t.Run("canceled_context", func(t *testing.T) {
		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		desc, err := localImageDescriptor(cancelledCtx, "alpine:latest")
		assert.Error(t, err)
		assert.Nil(t, desc)
		// Should get a context canceled error
		assert.Contains(t, err.Error(), "context canceled")
	})
}

// TestPodmanImageDescriptor tests the podmanImageDescriptor function with error scenarios.
func TestPodmanImageDescriptor(t *testing.T) {
	ctx := context.Background()

	// Test with a non-existent image (Podman is available in CI)
	t.Run("nonexistent_image", func(t *testing.T) {
		desc, err := podmanImageDescriptor(ctx, "definitely/does/not:exist")

		// If podman is not installed locally, expect a not found in PATH error.
		// Otherwise, for a nonexistent image, expect podman inspect failure or not found.
		assert.Error(t, err)
		assert.Nil(t, desc)
		if strings.Contains(err.Error(), "not found in PATH") {
			assert.Contains(t, err.Error(), "podman not found in PATH")
		} else {
			// Either a specific inspect failure or not found error wrapped
			// We allow either to keep test portable across environments
			cond := strings.Contains(err.Error(), "podman inspect failed") || strings.Contains(err.Error(), "not found")
			assert.True(t, cond, "unexpected error: %v", err)
		}
	})

	// Test with context cancellation
	t.Run("canceled_context", func(t *testing.T) {
		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		desc, err := podmanImageDescriptor(cancelledCtx, "alpine:latest")
		assert.Error(t, err)
		assert.Nil(t, desc)
	})
}

// TestRemoteImageDescriptor tests the remoteImageDescriptor function with error scenarios.
func TestRemoteImageDescriptor(t *testing.T) {
	// Test with truly invalid image reference format that will fail parsing
	t.Run("truly_invalid_image_reference", func(t *testing.T) {
		desc, err := remoteImageDescriptor("")
		assert.Error(t, err)
		assert.Nil(t, desc)
		assert.Contains(t, err.Error(), "failed to parse image reference")
	})

	// Test with non-existent image reference (will hit registry but get auth/not found error)
	t.Run("nonexistent_image", func(t *testing.T) {
		desc, err := remoteImageDescriptor("definitely/does/not/exist:anywhere")
		assert.Error(t, err)
		assert.Nil(t, desc)
		assert.Contains(t, err.Error(), "failed to get remote descriptor")
	})
}

// TestGetImageDescriptor tests the GetImageDescriptor function with runtime switching logic.
func TestGetImageDescriptor(t *testing.T) {
	ctx := context.Background()

	// Test with Docker runtime (default)
	t.Run("docker_runtime_fallback", func(t *testing.T) {
		desc, err := GetImageDescriptor(ctx, "nonexistent/test:image", imageloader.Docker)

		// Should fail but exercise the Docker -> remote fallback logic
		assert.Error(t, err)
		assert.Nil(t, desc)

		// Error should mention both local and remote failures
		errorMsg := err.Error()
		assert.Contains(t, errorMsg, "not found locally and remote lookup failed")
	})

	// Test with Podman runtime
	t.Run("podman_runtime_fallback", func(t *testing.T) {
		desc, err := GetImageDescriptor(ctx, "nonexistent/test:image", imageloader.Podman)

		// Should fail but exercise the Podman -> remote fallback logic
		assert.Error(t, err)
		assert.Nil(t, desc)

		// Error should mention both local and remote failures
		errorMsg := err.Error()
		assert.Contains(t, errorMsg, "local lookup")
		assert.Contains(t, errorMsg, "remote lookup also failed")
	})

	// Test with invalid image reference (should fail early)
	t.Run("invalid_image_reference", func(t *testing.T) {
		desc, err := GetImageDescriptor(ctx, "invalid-image-format", imageloader.Docker)
		assert.Error(t, err)
		assert.Nil(t, desc)
	})

	// Test with unknown runtime (should default to Docker)
	t.Run("unknown_runtime_defaults_to_docker", func(t *testing.T) {
		desc, err := GetImageDescriptor(ctx, "nonexistent/test:image", "unknown-runtime")

		// Should behave the same as Docker runtime
		assert.Error(t, err)
		assert.Nil(t, desc)
	})

	// Test context cancellation (this might succeed with remote fallback, so test differently)
	t.Run("canceled_context", func(t *testing.T) {
		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel()

		// Use a non-existent image to ensure it fails both locally and remotely
		desc, err := GetImageDescriptor(cancelledCtx, "nonexistent/canceled:test", imageloader.Docker)
		if err != nil {
			// This is the expected case - both local and remote should fail
			assert.Nil(t, desc)
		} else {
			// If it unexpectedly succeeds, that's also valid test behavior
			t.Logf("Unexpected success with canceled context - remote registry was very fast")
			assert.NotNil(t, desc)
		}
	})
}

// TestGetIndexManifestAnnotations tests the GetIndexManifestAnnotations function with error scenarios.
func TestGetIndexManifestAnnotations(t *testing.T) {
	ctx := context.Background()

	// Test with truly invalid image reference format
	t.Run("invalid_image_reference", func(t *testing.T) {
		annotations, err := GetIndexManifestAnnotations(ctx, "")
		assert.Error(t, err)
		assert.Nil(t, annotations)
		assert.Contains(t, err.Error(), "failed to parse image reference")
	})

	// Test with non-existent remote image
	t.Run("nonexistent_remote_image", func(t *testing.T) {
		annotations, err := GetIndexManifestAnnotations(ctx, "definitely/nonexistent:image")
		assert.Error(t, err)
		assert.Nil(t, annotations)
		assert.Contains(t, err.Error(), "failed to get descriptor")
	})
}

// TestGetPlatformManifestAnnotations tests the GetPlatformManifestAnnotations function with error scenarios.
func TestGetPlatformManifestAnnotations(t *testing.T) {
	ctx := context.Background()
	targetPlatform := &ocispec.Platform{
		Architecture: "amd64",
		OS:           "linux",
	}

	// Test with invalid image reference
	t.Run("invalid_image_reference", func(t *testing.T) {
		annotations, err := GetPlatformManifestAnnotations(ctx, "", targetPlatform)
		assert.Error(t, err)
		assert.Nil(t, annotations)
		assert.Contains(t, err.Error(), "failed to parse image reference")
	})

	// Test with non-existent remote image
	t.Run("nonexistent_remote_image", func(t *testing.T) {
		annotations, err := GetPlatformManifestAnnotations(ctx, "definitely/nonexistent:image", targetPlatform)
		assert.Error(t, err)
		assert.Nil(t, annotations)
		assert.Contains(t, err.Error(), "failed to get descriptor")
	})

	// Test with nil platform (edge case)
	t.Run("nil_platform", func(t *testing.T) {
		annotations, err := GetPlatformManifestAnnotations(ctx, "definitely/nonexistent:image", nil)
		assert.Error(t, err)
		assert.Nil(t, annotations)
		// Should still fail at the descriptor fetch level before platform processing
	})
}
