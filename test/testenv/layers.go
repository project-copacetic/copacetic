package testenv

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		resolveOpt.Platform = platform
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

	// Create temp directory for export
	exportDir := filepath.Join(l.outputDir, "oci-export")
	if err := os.MkdirAll(exportDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create export directory: %w", err)
	}
	defer os.RemoveAll(exportDir)

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

	// Extract and parse the OCI layout
	return l.parseOCITar(tarPath, platform)
}

// parseOCITar extracts an OCI tar and parses its manifest to count layers.
// Note: platform parameter is reserved for future multi-platform OCI layout support.
func (l *LayerCountTest) parseOCITar(tarPath string, _ *specs.Platform) (*ImageLayerInfo, error) {
	// Create temp directory for extraction
	extractDir := filepath.Join(l.outputDir, "extract")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create extract directory: %w", err)
	}
	defer os.RemoveAll(extractDir)

	// Extract tar using tar command
	// This is simpler than pulling in archive/tar
	if err := extractTar(tarPath, extractDir); err != nil {
		return nil, fmt.Errorf("failed to extract tar: %w", err)
	}

	// Read index.json
	indexPath := filepath.Join(extractDir, "index.json")
	indexData, err := os.ReadFile(indexPath)
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
	// Convert digest (sha256:abc123...) to blob path (blobs/sha256/abc123...)
	blobPath := filepath.Join(extractDir, "blobs", manifestDigest[7:9], manifestDigest[10:])

	// Try alternate path structure (blobs/sha256/abc123)
	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		blobPath = filepath.Join(extractDir, "blobs", "sha256", manifestDigest[7:])
	}

	manifestData, err := os.ReadFile(blobPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest blob: %w", err)
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
	configBlobPath := filepath.Join(extractDir, "blobs", "sha256", configDigest[7:])
	configData, err := os.ReadFile(configBlobPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config blob: %w", err)
	}

	return parseImageLayerInfo(configData)
}

// extractTar extracts a tar file to a directory.
// It validates all paths to prevent Zip Slip (path traversal) attacks.
func extractTar(tarPath, destDir string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("failed to open tar file: %w", err)
	}
	defer f.Close()

	// Get the absolute path of destDir for proper validation
	absDestDir, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path of destDir: %w", err)
	}

	tr := tar.NewReader(f)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Sanitize the target path to prevent path traversal (Zip Slip)
		// CodeQL: This is intentionally safe - sanitizeArchivePath validates the path
		target, err := sanitizeArchivePath(absDestDir, header.Name)
		if err != nil {
			return fmt.Errorf("invalid tar path %q: %w", header.Name, err)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}
			if err := extractFile(target, tr, header.Size); err != nil {
				return err
			}
		case tar.TypeSymlink:
			// For symlinks, validate the link target doesn't escape destDir
			if err := validateSymlinkTarget(absDestDir, target, header.Linkname); err != nil {
				// Skip invalid symlinks silently - they're not critical for OCI layer inspection
				continue
			}
			// Remove existing file/symlink if it exists
			_ = os.Remove(target)
			if err := os.Symlink(header.Linkname, target); err != nil {
				// Ignore symlink errors as they're not critical for our use case
				continue
			}
		}
	}
	return nil
}

// sanitizeArchivePath validates and sanitizes a path from an archive.
// It ensures the resulting path is within the destination directory,
// preventing Zip Slip / path traversal attacks.
//
// This function:
// 1. Cleans the entry name to normalize path separators and remove redundant elements
// 2. Rejects absolute paths
// 3. Rejects paths that start with ".." (attempt to escape)
// 4. Joins safely with destDir and verifies the result is still within destDir.
func sanitizeArchivePath(destDir, entryName string) (string, error) {
	// Clean the entry name to remove any . or .. components and normalize separators
	cleanName := filepath.Clean(entryName)

	// Reject absolute paths
	if filepath.IsAbs(cleanName) {
		return "", fmt.Errorf("absolute paths not allowed")
	}

	// Reject paths that try to escape with ..
	if strings.HasPrefix(cleanName, ".."+string(filepath.Separator)) || cleanName == ".." {
		return "", fmt.Errorf("path attempts to escape destination directory")
	}

	// Join with destination directory
	// filepath.Join also cleans the result
	target := filepath.Join(destDir, cleanName)

	// Final safety check: ensure the target is within destDir
	// This catches any edge cases the above checks might miss
	if !isSubPath(destDir, target) {
		return "", fmt.Errorf("path escapes destination directory")
	}

	return target, nil
}

// isSubPath checks if child is a subpath of parent.
// Both paths should be absolute and clean.
func isSubPath(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)

	// The child must either equal the parent or start with parent + separator
	if child == parent {
		return true
	}

	parentWithSep := parent + string(filepath.Separator)
	return strings.HasPrefix(child, parentWithSep)
}

// validateSymlinkTarget validates that a symlink's target doesn't escape the destination directory.
func validateSymlinkTarget(destDir, symlinkPath, linkTarget string) error {
	// Reject absolute symlink targets
	if filepath.IsAbs(linkTarget) {
		return fmt.Errorf("absolute symlink targets not allowed")
	}

	// Resolve the symlink target relative to the symlink's directory
	symlinkDir := filepath.Dir(symlinkPath)
	resolvedTarget := filepath.Join(symlinkDir, linkTarget)
	resolvedTarget = filepath.Clean(resolvedTarget)

	// Verify the resolved target is within destDir
	if !isSubPath(destDir, resolvedTarget) {
		return fmt.Errorf("symlink target escapes destination directory")
	}

	return nil
}

// extractFile extracts a single file from the tar reader to the target path.
// The target path must have been validated by sanitizeArchivePath before calling this.
func extractFile(target string, tr *tar.Reader, size int64) error {
	outFile, err := os.Create(target) // #nosec G304 -- path is validated by sanitizeArchivePath
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer outFile.Close()

	// Use io.Copy with a LimitReader to prevent decompression bombs
	if _, err := io.Copy(outFile, io.LimitReader(tr, size)); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
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
