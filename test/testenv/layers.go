package testenv

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

// ImageLayerInfo contains information about an image's layers.
type ImageLayerInfo struct {
	// LayerCount is the number of layers in the image.
	LayerCount int

	// DiffIDs are the content-addressable identifiers for each layer.
	DiffIDs []string

	// Platform is the platform of the image.
	Platform *specs.Platform
}

// GetOriginalImageLayerCount returns the number of layers in the original (unpatched) image.
// This uses the gateway client to resolve the image config and count layers.
// The imageName will be normalized to a fully qualified reference.
func GetOriginalImageLayerCount(ctx context.Context, c gwclient.Client, imageName string, platform *specs.Platform) (*ImageLayerInfo, error) {
	// Normalize the image reference to prevent URL parsing errors in BuildKit
	normalizedImageName := NormalizeImageRef(imageName)

	resolveOpt := sourceresolver.Opt{
		ImageOpt: &sourceresolver.ResolveImageOpt{
			ResolveMode: llb.ResolveModePreferLocal.String(),
		},
	}
	if platform != nil {
		resolveOpt.ImageOpt.Platform = platform
	}

	_, _, configData, err := c.ResolveImageConfig(ctx, normalizedImageName, resolveOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve image config: %w", err)
	}

	return parseImageLayerInfo(configData)
}

// parseImageLayerInfo parses image config data to extract layer information.
func parseImageLayerInfo(configData []byte) (*ImageLayerInfo, error) {
	var config struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		Variant      string `json:"variant,omitempty"`
	}

	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse image config: %w", err)
	}

	info := &ImageLayerInfo{
		LayerCount: len(config.RootFS.DiffIDs),
		DiffIDs:    config.RootFS.DiffIDs,
		Platform: &specs.Platform{
			OS:           config.OS,
			Architecture: config.Architecture,
			Variant:      config.Variant,
		},
	}

	return info, nil
}

// LayerCountTest is a test helper for verifying layer counts.
// It requires exporting the image to inspect the manifest.
type LayerCountTest struct {
	env       *TestEnv
	outputDir string
}

// NewLayerCountTest creates a new LayerCountTest helper.
// outputDir is the directory where the OCI layout will be exported for inspection.
func NewLayerCountTest(env *TestEnv, outputDir string) *LayerCountTest {
	return &LayerCountTest{
		env:       env,
		outputDir: outputDir,
	}
}

// ExportAndCountLayers exports an image state to OCI layout and counts the layers.
// This is necessary because layer information cannot be inspected without export.
func (l *LayerCountTest) ExportAndCountLayers(
	ctx context.Context,
	t *testing.T,
	state *llb.State,
	platform *specs.Platform,
) (*ImageLayerInfo, error) {
	t.Helper()

	// Get the BuildKit client
	bkClient, err := l.env.Client(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get buildkit client: %w", err)
	}

	// Create tarball path
	tarPath := filepath.Join(l.outputDir, "image.tar")
	defer os.Remove(tarPath)

	// Marshal the state
	def, err := state.Marshal(ctx, llb.Platform(*platform))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal state: %w", err)
	}

	// Create solve options with OCI export
	solveOpt := client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type: client.ExporterOCI,
			Attrs: map[string]string{
				"oci-mediatypes": "true",
			},
			Output: func(_ map[string]string) (io.WriteCloser, error) {
				return os.Create(tarPath)
			},
		}},
	}

	// Solve to export
	_, err = bkClient.Solve(ctx, def, solveOpt, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to solve/export: %w", err)
	}

	// Parse the OCI tar by streaming through it
	return l.parseOCITar(tarPath, platform)
}

// parseOCITar opens an OCI tar as an fs.FS and reads the manifest to count layers.
// Note: platform parameter is reserved for future multi-platform OCI layout support.
func (l *LayerCountTest) parseOCITar(tarPath string, _ *specs.Platform) (*ImageLayerInfo, error) {
	fsys, err := newTarFS(tarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read tar: %w", err)
	}

	// Read index.json
	indexData, err := fs.ReadFile(fsys, "index.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read index.json: %w", err)
	}

	var index struct {
		Manifests []struct {
			Digest    string `json:"digest"`
			MediaType string `json:"mediaType"`
		} `json:"manifests"`
	}

	if err := json.Unmarshal(indexData, &index); err != nil {
		return nil, fmt.Errorf("failed to parse index.json: %w", err)
	}

	if len(index.Manifests) == 0 {
		return nil, fmt.Errorf("no manifests in index.json")
	}

	// Read the manifest blob
	manifestDigest := index.Manifests[0].Digest
	manifestPath, err := digestToPath(manifestDigest)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest digest: %w", err)
	}

	manifestData, err := fs.ReadFile(fsys, filepath.Join("blobs", manifestPath))
	if err != nil {
		// Try alternate path with nested directories (blobs/sha256/ab/c123...)
		algo, hash, _ := parseDigest(manifestDigest)
		if len(hash) >= 2 {
			manifestData, err = fs.ReadFile(fsys, filepath.Join("blobs", algo, hash[:2], hash[2:]))
		}
		if err != nil {
			return nil, fmt.Errorf("manifest blob not found in tar: %w", err)
		}
	}

	var manifest struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}

	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	// Read config blob to get diff_ids
	configDigest := manifest.Config.Digest
	configPath, err := digestToPath(configDigest)
	if err != nil {
		return nil, fmt.Errorf("invalid config digest: %w", err)
	}

	configData, err := fs.ReadFile(fsys, filepath.Join("blobs", configPath))
	if err != nil {
		return nil, fmt.Errorf("config blob not found in tar: %w", err)
	}

	return parseImageLayerInfo(configData)
}

// tarFS implements io/fs.FS over a tar file by reading small metadata files into memory.
// Large entries (layer blobs) are skipped since we only need JSON metadata.
type tarFS struct {
	files map[string]*tarEntry
}

type tarEntry struct {
	data    []byte
	size    int64
	modTime time.Time
}

// newTarFS streams through a tar file and indexes small files (< 1MB) into memory.
func newTarFS(tarPath string) (*tarFS, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tfs := &tarFS{files: make(map[string]*tarEntry)}
	tr := tar.NewReader(f)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Skip large layer blobs — metadata files are small JSON
		const maxSize = 1 << 20 // 1MB
		if hdr.Size > maxSize {
			continue
		}

		name := filepath.Clean(hdr.Name)
		data, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return nil, err
		}

		tfs.files[name] = &tarEntry{
			data:    data,
			size:    hdr.Size,
			modTime: hdr.ModTime,
		}
	}

	return tfs, nil
}

// Open implements fs.FS.
func (tfs *tarFS) Open(name string) (fs.File, error) {
	name = filepath.Clean(name)
	entry, ok := tfs.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &tarFile{
		Reader: bytes.NewReader(entry.data),
		entry:  entry,
		name:   name,
	}, nil
}

// tarFile implements fs.File.
type tarFile struct {
	*bytes.Reader
	entry *tarEntry
	name  string
}

func (f *tarFile) Stat() (fs.FileInfo, error) {
	return &tarFileInfo{name: filepath.Base(f.name), entry: f.entry}, nil
}

func (f *tarFile) Close() error { return nil }

// tarFileInfo implements fs.FileInfo.
type tarFileInfo struct {
	name  string
	entry *tarEntry
}

func (fi *tarFileInfo) Name() string       { return fi.name }
func (fi *tarFileInfo) Size() int64        { return fi.entry.size }
func (fi *tarFileInfo) Mode() fs.FileMode  { return 0o444 }
func (fi *tarFileInfo) ModTime() time.Time { return fi.entry.modTime }
func (fi *tarFileInfo) IsDir() bool        { return false }
func (fi *tarFileInfo) Sys() any           { return nil }

// parseDigest parses a digest string (e.g., "sha256:abc123...") into algorithm and hash.
// Returns an error if the format is invalid.
func parseDigest(digest string) (algo, hash string, err error) {
	parts := splitDigest(digest)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid digest format: expected 'algorithm:hash', got %q", digest)
	}
	algo, hash = parts[0], parts[1]
	if algo == "" || hash == "" {
		return "", "", fmt.Errorf("invalid digest format: empty algorithm or hash in %q", digest)
	}
	return algo, hash, nil
}

// splitDigest splits a digest at the first colon.
func splitDigest(digest string) []string {
	idx := -1
	for i, c := range digest {
		if c == ':' {
			idx = i
			break
		}
	}
	if idx == -1 {
		return []string{digest}
	}
	return []string{digest[:idx], digest[idx+1:]}
}

// digestToPath converts a digest to a blob path (e.g., "sha256:abc123" -> "sha256/abc123").
func digestToPath(digest string) (string, error) {
	algo, hash, err := parseDigest(digest)
	if err != nil {
		return "", err
	}
	return filepath.Join(algo, hash), nil
}

// AssertLayerCount asserts that the patched image has the expected number of layers.
// expectedOriginal is the number of layers in the original image.
// expectedAdded is the number of layers that should be added by patching (typically 1).
func (l *LayerCountTest) AssertLayerCount(
	t *testing.T,
	originalLayers int,
	patchedLayers int,
	expectedAdded int,
) {
	t.Helper()
	expected := originalLayers + expectedAdded
	if patchedLayers != expected {
		t.Errorf("layer count mismatch: original=%d, patched=%d, expected=%d (added=%d)",
			originalLayers, patchedLayers, expected, expectedAdded)
	}
}

// CompareLayerCounts compares layer counts between original and patched images.
// Returns (originalCount, patchedCount, err).
// The originalImage reference will be normalized to a fully qualified reference.
func CompareLayerCounts(
	ctx context.Context,
	c gwclient.Client,
	originalImage string,
	patchedConfigData []byte,
	platform *specs.Platform,
) (int, int, error) {
	// Get original layer count (GetOriginalImageLayerCount already normalizes the image reference)
	originalInfo, err := GetOriginalImageLayerCount(ctx, c, originalImage, platform)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get original layer count: %w", err)
	}

	// Get patched layer count
	patchedInfo, err := parseImageLayerInfo(patchedConfigData)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get patched layer count: %w", err)
	}

	return originalInfo.LayerCount, patchedInfo.LayerCount, nil
}
