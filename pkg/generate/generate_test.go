package generate

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/buildkit/client"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate_Timeout(t *testing.T) {
	ctx := context.Background()
	opts := &types.Options{
		Image:         "test:latest",
		Report:        "",
		PatchedTag:    "patched",
		Suffix:        "",
		WorkingFolder: "",
		Timeout:       1 * time.Millisecond, // Very short timeout
		Scanner:       "trivy",
		IgnoreError:   false,
		OutputContext: "",
	}

	// Mock buildkit client creation to simulate slow operation
	originalBkNewClient := bkNewClient
	bkNewClient = func(ctx context.Context, _ buildkit.Opts) (*client.Client, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
			return nil, nil
		}
	}
	defer func() {
		bkNewClient = originalBkNewClient
	}()

	err := Generate(ctx, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeded timeout")
}

func TestTarWriter(t *testing.T) {
	var closed bool
	tw := &tarWriter{
		Writer: &bytes.Buffer{},
		onClose: func() {
			closed = true
		},
	}

	// Test Write
	data := []byte("test data")
	n, err := tw.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)

	// Test Close
	err = tw.Close()
	assert.NoError(t, err)
	assert.True(t, closed, "onClose should have been called")
}

func TestCreateTarStream(t *testing.T) {
	// Create a minimal patch layer tar
	patchBuf := &bytes.Buffer{}
	patchTw := tar.NewWriter(patchBuf)

	// Add a test file
	testContent := []byte("test file content")
	hdr := &tar.Header{
		Name:     "etc/test.conf",
		Mode:     0o644,
		Size:     int64(len(testContent)),
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
	}
	err := patchTw.WriteHeader(hdr)
	require.NoError(t, err)
	_, err = patchTw.Write(testContent)
	require.NoError(t, err)

	// Add a hardlink
	linkHdr := &tar.Header{
		Name:     "etc/test.link",
		Mode:     0o644,
		Linkname: "etc/test.conf",
		Typeflag: tar.TypeLink,
	}
	err = patchTw.WriteHeader(linkHdr)
	require.NoError(t, err)

	err = patchTw.Close()
	require.NoError(t, err)

	// Test creating tar stream to a temporary file
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test-output.tar")

	err = createTarStream("ubuntu:22.04", patchBuf.Bytes(), outputPath)
	require.NoError(t, err)

	// Read the file back
	outputData, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	outputBuf := bytes.NewBuffer(outputData)

	// Verify the output tar
	tr := tar.NewReader(outputBuf)

	// First should be Dockerfile
	hdr, err = tr.Next()
	require.NoError(t, err)
	assert.Equal(t, "Dockerfile", hdr.Name)

	dockerfileContent := make([]byte, hdr.Size)
	_, err = io.ReadFull(tr, dockerfileContent)
	require.NoError(t, err)
	assert.Contains(t, string(dockerfileContent), "FROM ubuntu:22.04")
	assert.Contains(t, string(dockerfileContent), "COPY patch/ /")
	assert.Contains(t, string(dockerfileContent), "LABEL sh.copa.image.patched=")

	// Next should be our test file under patch/
	hdr, err = tr.Next()
	require.NoError(t, err)
	assert.Equal(t, "patch/etc/test.conf", hdr.Name)

	content := make([]byte, hdr.Size)
	_, err = io.ReadFull(tr, content)
	require.NoError(t, err)
	assert.Equal(t, testContent, content)

	// The hardlink should be converted to a regular file
	hdr, err = tr.Next()
	require.NoError(t, err)
	assert.Equal(t, "patch/etc/test.link", hdr.Name)
	assert.Equal(t, byte(tar.TypeReg), hdr.Typeflag)

	content = make([]byte, hdr.Size)
	_, err = io.ReadFull(tr, content)
	require.NoError(t, err)
	assert.Equal(t, testContent, content)
}

func TestCreateTarStream_OutputToFile(t *testing.T) {
	// Create a minimal patch layer tar
	patchBuf := &bytes.Buffer{}
	patchTw := tar.NewWriter(patchBuf)

	testContent := []byte("test file content")
	hdr := &tar.Header{
		Name:     "test.txt",
		Mode:     0o644,
		Size:     int64(len(testContent)),
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
	}
	err := patchTw.WriteHeader(hdr)
	require.NoError(t, err)
	_, err = patchTw.Write(testContent)
	require.NoError(t, err)
	err = patchTw.Close()
	require.NoError(t, err)

	// Test output to file
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.tar")

	err = createTarStream("alpine:3.18", patchBuf.Bytes(), outputPath)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(outputPath)
	require.NoError(t, err)

	// Read and verify the tar file
	f, err := os.Open(outputPath)
	require.NoError(t, err)
	defer f.Close()

	tr := tar.NewReader(f)

	// First should be Dockerfile
	hdr, err = tr.Next()
	require.NoError(t, err)
	assert.Equal(t, "Dockerfile", hdr.Name)
}

func TestCreateTarStream_LargeFile(t *testing.T) {
	// Test is simplified since we can't easily create a 2GB file in tests
	// The size check happens when reading the tar, not when creating it
	t.Skip("Skipping large file test - requires 2GB of data")
}

func TestGenerateWithContext_InvalidImage(t *testing.T) {
	ctx := context.Background()
	ch := make(chan error, 1)

	opts := &types.Options{
		Image: "invalid::image::ref",
	}
	err := generateWithContext(ctx, ch, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse reference")
}

func TestGenerateWithContext_NoTagNoDigest(t *testing.T) {
	ctx := context.Background()
	ch := make(chan error, 1)

	// Mock buildkit client
	originalBkNewClient := bkNewClient
	bkNewClient = func(_ context.Context, _ buildkit.Opts) (*client.Client, error) {
		// Return error to avoid nil client issues
		return nil, assert.AnError
	}
	defer func() {
		bkNewClient = originalBkNewClient
	}()

	// This should work and add "latest" tag
	opts := &types.Options{
		Image:   "ubuntu",
		Scanner: "trivy",
	}
	err := generateWithContext(ctx, ch, opts)
	// Will fail later in the process, but should get past reference parsing
	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "failed to parse reference")
}

func TestCreateTarStream_PathSanitization(t *testing.T) {
	// Create a patch layer with various path formats
	patchBuf := &bytes.Buffer{}
	patchTw := tar.NewWriter(patchBuf)

	testCases := []struct {
		inputPath    string
		expectedPath string
	}{
		{"/etc/config", "patch/etc/config"},
		{"etc/config", "patch/etc/config"},
		{"./etc/config", "patch/./etc/config"},
		{"//etc//config", "patch//etc//config"},
	}

	for _, tc := range testCases {
		content := []byte("content for " + tc.inputPath)
		hdr := &tar.Header{
			Name:     tc.inputPath,
			Mode:     0o644,
			Size:     int64(len(content)),
			ModTime:  time.Now(),
			Typeflag: tar.TypeReg,
		}
		err := patchTw.WriteHeader(hdr)
		require.NoError(t, err)
		_, err = patchTw.Write(content)
		require.NoError(t, err)
	}

	err := patchTw.Close()
	require.NoError(t, err)

	// Create tar stream to a file
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test-paths.tar")

	err = createTarStream("test:latest", patchBuf.Bytes(), outputPath)
	require.NoError(t, err)

	// Read the file back
	outputData, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	outputBuf := bytes.NewBuffer(outputData)

	// Verify paths in output
	tr := tar.NewReader(outputBuf)

	// Skip Dockerfile
	_, err = tr.Next()
	require.NoError(t, err)

	// Check each file
	for _, tc := range testCases {
		hdr, err := tr.Next()
		require.NoError(t, err)
		assert.Equal(t, tc.expectedPath, hdr.Name)

		// Verify content
		content := make([]byte, hdr.Size)
		_, err = io.ReadFull(tr, content)
		require.NoError(t, err)
		assert.Equal(t, "content for "+tc.inputPath, string(content))
	}
}
