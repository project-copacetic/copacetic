package frontend

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/containerd/platforms"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/util/bklog"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	copabuildkit "github.com/project-copacetic/copacetic/pkg/buildkit"
	copachisel "github.com/project-copacetic/copacetic/pkg/chisel"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

const (
	jsonExt = ".json"
)

// resultMetadataClient decorates the next Solve result with image config and
// package-manager annotations, then restores the original frontend client. The
// frontend currently builds a state first and solves it in its caller, so this
// keeps metadata coupled to that immediately following solve without changing
// the public buildPatchedImage signature.
type resultMetadataClient struct {
	gwclient.Client
	owner    *Frontend
	metadata map[string][]byte
}

//nolint:gocritic // The gateway Client interface requires SolveRequest by value.
func (c *resultMetadataClient) Solve(ctx context.Context, request gwclient.SolveRequest) (*gwclient.Result, error) {
	defer func() {
		if c.owner != nil && c.owner.client == c {
			c.owner.client = c.Client
		}
	}()

	result, err := c.Client.Solve(ctx, request)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("frontend solve returned a nil result")
	}
	for key, value := range c.metadata {
		result.AddMeta(key, append([]byte(nil), value...))
	}
	return result, nil
}

func copyFrontendResultMetadata(destination, source *gwclient.Result) {
	if destination == nil || source == nil {
		return
	}
	for key, value := range source.Metadata {
		destination.AddMeta(key, append([]byte(nil), value...))
	}
}

func rejectTargetedNativeChiselState(ctx context.Context, client gwclient.Client, state *llb.State, platform *ocispecs.Platform) error {
	manifestExists, err := common.StateFileExists(ctx, client, state, platform, pkgmgr.NativeChiselManifestPath)
	if err != nil {
		return errors.Wrap(err, "failed to inspect target image for native Chisel metadata")
	}
	if manifestExists {
		return errors.New(pkgmgr.NativeChiselTargetedPatchError)
	}
	return nil
}

// frontendResultAnnotations combines annotations produced by a successful
// package-manager run with Chisel provenance already recorded on the supplied
// image config. The supplied values are fallback-only: preserving an existing
// provenance assertion on an idempotent export does not claim that a skipped or
// ignored update remediated anything new.
func frontendResultAnnotations(configData []byte, managerAnnotations map[string]string) (map[string]string, error) {
	chiselProvenanceAnnotationKeys := [...]string{
		pkgmgr.ChiselReleaseAnnotation,
		pkgmgr.ChiselVersionAnnotation,
	}
	annotations := make(map[string]string, len(managerAnnotations)+len(chiselProvenanceAnnotationKeys))
	for key, value := range managerAnnotations {
		annotations[key] = value
	}

	needsSuppliedProvenance := false
	for _, key := range chiselProvenanceAnnotationKeys {
		if annotations[key] == "" {
			needsSuppliedProvenance = true
			break
		}
	}
	if needsSuppliedProvenance {
		var image ocispecs.Image
		if err := json.Unmarshal(configData, &image); err != nil {
			return nil, fmt.Errorf("parse supplied image config for Chisel provenance: %w", err)
		}
		for _, key := range chiselProvenanceAnnotationKeys {
			if annotations[key] != "" {
				continue
			}
			if value := image.Config.Labels[key]; value != "" {
				annotations[key] = value
			}
		}
	}

	if len(annotations) == 0 {
		return nil, nil
	}
	return annotations, nil
}

func frontendResultMetadata(configData, patchedConfigData []byte, platform *ocispecs.Platform, managerAnnotations map[string]string) (map[string][]byte, error) {
	if patchedConfigData != nil {
		merged, err := common.MergeImageRuntimeConfig(configData, patchedConfigData)
		if err != nil {
			return nil, err
		}
		configData = merged
	}

	resultAnnotations, err := frontendResultAnnotations(configData, managerAnnotations)
	if err != nil {
		return nil, err
	}
	// Only manager-produced annotations are written into the config. Existing
	// Chisel labels are already present and are merely mirrored back to the
	// manifest metadata on no-op exports.
	configData, err = common.AddImageConfigLabels(configData, managerAnnotations)
	if err != nil {
		return nil, err
	}

	configKey := exptypes.ExporterImageConfigKey
	if platform != nil {
		configKey += "/" + platforms.Format(*platform)
	}
	metadata := map[string][]byte{
		configKey: configData,
	}
	for key, value := range resultAnnotations {
		metadata[exptypes.AnnotationManifestKey(platform, key)] = []byte(value)
	}
	return metadata, nil
}

// ensureTempDir makes sure the directory returned by os.TempDir() exists
// before callers invoke os.MkdirTemp("", ...). Minimal frontend images must
// provide a writable temp base directory for report extraction.
func ensureTempDir() error {
	return os.MkdirAll(os.TempDir(), 0o1777)
}

// explicitNativeChiselOSInfo returns the Ubuntu OS metadata needed to select
// the DPKG manager when a native Chisel image has no /etc/os-release. It only
// bypasses normal OS detection when both an explicit release override and a
// native Chisel manifest are present.
func explicitNativeChiselOSInfo(
	ctx context.Context,
	client gwclient.Client,
	state *llb.State,
	platform *ocispecs.Platform,
	override string,
) (*common.OSInfo, error) {
	if override == "" {
		return nil, nil
	}

	manifestExists, err := common.StateFileExists(ctx, client, state, platform, pkgmgr.NativeChiselManifestPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to inspect target image for native Chisel metadata")
	}
	if !manifestExists {
		return nil, nil
	}

	release, err := copachisel.ParseRelease(override)
	if err != nil {
		return nil, errors.Wrap(err, "invalid Chisel release override")
	}

	version := ""
	if release.Kind == copachisel.ReleaseNamed {
		version = strings.TrimPrefix(release.Location, "ubuntu-")
	}
	return &common.OSInfo{Type: utils.OSTypeUbuntu, Version: version}, nil
}

// BuildPatchedImage builds a patched image using the Copa patching logic.
// This reuses the same components as the CLI to ensure consistency.
func (f *Frontend) buildPatchedImage(ctx context.Context, opts *types.Options, platform *ocispecs.Platform) (llb.State, error) {
	var inspectionState *llb.State
	if opts.Report != "" || opts.ChiselRelease != "" {
		imageOptions := []llb.ImageOption{
			llb.ResolveModePreferLocal,
			llb.WithMetaResolver(f.client),
		}
		if platform != nil {
			imageOptions = append(imageOptions, llb.Platform(*platform))
		}
		state := llb.Image(opts.Image, imageOptions...)
		inspectionState = &state
	}

	// Native Chisel manifests cannot be patched from a scanner report. Perform
	// this check before OS/package-manager setup so community images without
	// /etc/os-release return the targeted-patching error instead of an OS
	// detection error. This preflight is intentionally outside ignore-errors.
	if opts.Report != "" {
		if err := rejectTargetedNativeChiselState(ctx, f.client, inspectionState, platform); err != nil {
			return llb.State{}, err
		}
	}

	var osInfo *common.OSInfo
	if opts.ChiselRelease != "" {
		var err error
		osInfo, err = explicitNativeChiselOSInfo(ctx, f.client, inspectionState, platform, opts.ChiselRelease)
		if err != nil {
			return llb.State{}, err
		}
	}

	// Create package manager instance. A nil osInfo preserves normal target OS
	// detection for non-native images and native images without an override.
	config, pm, err := common.SetupBuildkitConfigAndManagerWithOptions(ctx, f.client, opts.Image, platform, "", osInfo, pkgmgr.PackageManagerOptions{
		ChiselRelease: opts.ChiselRelease,
	})
	if err != nil {
		return llb.State{}, errors.Wrap(err, "failed to set up buildkit config and package manager")
	}

	// Parse the vulnerability report if provided
	var um *unversioned.UpdateManifest
	reportPath := opts.Report
	if reportPath != "" {
		// For platform-specific builds, adjust the report path
		if platform != nil {
			// Check if the report path is a directory with platform-specific files
			if fi, err := os.Stat(reportPath); err == nil && fi.IsDir() {
				// Build platform-specific filename
				platformFile := fmt.Sprintf("%s-%s", platform.OS, platform.Architecture)
				if platform.Variant != "" {
					platformFile = fmt.Sprintf("%s-%s", platformFile, platform.Variant)
				}
				platformFile += jsonExt

				specificReportPath := filepath.Join(reportPath, platformFile)
				// Check if platform-specific report exists
				if _, err := os.Stat(specificReportPath); err == nil {
					reportPath = specificReportPath
				} else {
					bklog.G(ctx).WithField("component", "copa-frontend").
						WithField("platform", platformFile).
						Warn("No report found for platform, skipping patch")
					return config.ImageState, nil
				}
			}
		}

		bklog.G(ctx).WithField("component", "copa-frontend").
			WithField("reportPath", reportPath).
			Info("About to parse vulnerability report")

		var err error
		um, err = report.TryParseScanReport(reportPath, opts.Scanner, opts.PkgTypes, opts.LibraryPatchLevel)
		if err != nil {
			return llb.State{}, errors.Wrapf(err, "failed to parse vulnerability report from path: %s", reportPath)
		}
		targetPlatform := platform
		if targetPlatform == nil && strings.TrimSpace(um.Metadata.Config.Arch) != "" {
			resolvedPlatform, err := currentFrontendImageState(config).GetPlatform(ctx)
			if err != nil {
				return llb.State{}, errors.Wrap(err, "failed to resolve target platform for report validation")
			}
			targetPlatform = resolvedPlatform
		}
		if err := validateFrontendReportPlatform(um, targetPlatform); err != nil {
			return llb.State{}, err
		}
	}

	patchedState, updatesInstalled, err := installFrontendUpdates(ctx, config, pm, um, opts.IgnoreError)
	if err != nil {
		return llb.State{}, err
	}

	var managerAnnotations map[string]string
	if updatesInstalled {
		managerAnnotations = pkgmgr.GetPackageManagerAnnotations(pm)
	}
	metadata, err := frontendResultMetadata(config.ConfigData, config.PatchedConfigData, platform, managerAnnotations)
	if err != nil {
		return llb.State{}, errors.Wrap(err, "failed to prepare frontend image metadata")
	}
	f.client = &resultMetadataClient{
		Client:   f.client,
		owner:    f,
		metadata: metadata,
	}

	return patchedState, nil
}

func currentFrontendImageState(config *copabuildkit.Config) llb.State {
	if config.PatchedConfigData != nil {
		return config.PatchedImageState
	}
	return config.ImageState
}

func validateFrontendReportPlatforms(reportPath string, targetPlatforms []string) error {
	if reportPath == "" || len(targetPlatforms) <= 1 {
		return nil
	}
	reportInfo, err := os.Stat(reportPath)
	if err != nil {
		return fmt.Errorf("stat vulnerability report %q: %w", reportPath, err)
	}
	if reportInfo.IsDir() {
		return nil
	}
	return fmt.Errorf(
		"a single report file can target only one platform; got %d: %s",
		len(targetPlatforms),
		strings.Join(targetPlatforms, ", "),
	)
}

func validateFrontendReportPlatform(updates *unversioned.UpdateManifest, targetPlatform *ocispecs.Platform) error {
	if updates == nil {
		return nil
	}
	reportArchitecture := strings.TrimSpace(updates.Metadata.Config.Arch)
	if reportArchitecture == "" {
		return nil
	}
	if targetPlatform == nil {
		return errors.New("cannot validate scan report platform without a target platform")
	}

	target := platforms.Normalize(*targetPlatform)
	if target.OS == "" {
		target.OS = "linux"
	}
	reportPlatform := platforms.Normalize(ocispecs.Platform{
		OS:           target.OS,
		Architecture: reportArchitecture,
		Variant:      strings.TrimSpace(updates.Metadata.Config.Variant),
	})
	if reportPlatform.Architecture != target.Architecture || reportPlatform.Variant != target.Variant {
		return fmt.Errorf(
			"scan report platform %s does not match target platform %s; generate the report for the selected platform or choose a matching platform option",
			platforms.Format(reportPlatform),
			platforms.Format(target),
		)
	}
	return nil
}

// installFrontendUpdates applies OS updates and reports whether a new state was
// produced. Empty scanner reports retain their existing fast path, while the
// no-update sentinel is a successful idempotent result that returns the image
// the caller actually supplied (which may itself be a previously patched image).
func installFrontendUpdates(
	ctx context.Context,
	config *copabuildkit.Config,
	pm pkgmgr.PackageManager,
	manifest *unversioned.UpdateManifest,
	ignoreErrors bool,
) (llb.State, bool, error) {
	if manifest != nil && len(manifest.OSUpdates) == 0 && len(manifest.LangUpdates) == 0 {
		bklog.G(ctx).WithField("component", "copa-frontend").Info("No packages to update, returning current image")
		return currentFrontendImageState(config), false, nil
	}

	patchedState, _, err := pm.InstallUpdates(ctx, manifest, ignoreErrors)
	if errors.Is(err, types.ErrNoUpdatesFound) {
		bklog.G(ctx).WithField("component", "copa-frontend").Info("No package updates found, returning current image")
		return currentFrontendImageState(config), false, nil
	}
	if err != nil {
		if ignoreErrors {
			bklog.G(ctx).WithError(err).WithField("component", "copa-frontend").Warn("Failed to install updates (ignored)")
			return currentFrontendImageState(config), false, nil
		}
		return llb.State{}, false, errors.Wrap(err, "failed to install package updates")
	}

	return *patchedState, true, nil
}

// extractReportFromContext extracts a report file or directory from the BuildKit context.
// It automatically detects whether the report path is a file or directory and extracts accordingly.
// Returns the path to the extracted temp file/directory.
//
// To avoid gRPC message size limits (16MB), this function reads files in chunks when needed.
func extractReportFromContext(ctx context.Context, client gwclient.Client, reportPath string) (string, error) {
	if reportPath == "" {
		return "", nil
	}

	bklog.G(ctx).WithField("component", "copa-frontend").
		WithField("reportPath", reportPath).
		Info("Extracting report from context")

	// Create the local state to access the report context
	localState := llb.Local("report",
		llb.SharedKeyHint("local"),
		llb.WithCustomName("Loading vulnerability report"),
		llb.FollowPaths([]string{"."}),
	)

	def, err := localState.Marshal(ctx)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal local state")
	}

	res, err := client.Solve(ctx, gwclient.SolveRequest{Definition: def.ToPB()})
	if err != nil {
		return "", errors.Wrap(err, "failed to solve local state")
	}

	ref, err := res.SingleRef()
	if err != nil {
		return "", errors.Wrap(err, "failed to get single ref for local state")
	}

	// Check if this is a file or directory
	stat, statErr := ref.StatFile(ctx, gwclient.StatRequest{Path: reportPath})
	if statErr != nil {
		return "", errors.Wrapf(statErr, "failed to stat report path: %s", reportPath)
	}

	// Handle directory case
	if stat.IsDir() {
		return extractReportDirectory(ctx, ref, reportPath)
	}

	// Handle single file case - read in chunks if needed to avoid gRPC limits
	return extractReportFile(ctx, ref, reportPath, stat.Size)
}

// extractReportFile extracts a single report file, reading in chunks if it's larger than 8MB.
func extractReportFile(ctx context.Context, ref gwclient.Reference, reportPath string, fileSize int64) (string, error) {
	const chunkSize = 8 * 1024 * 1024 // 8MB chunks to stay well under 16MB gRPC limit

	if err := ensureTempDir(); err != nil {
		return "", errors.Wrap(err, "failed to ensure temp dir exists")
	}

	tmpDir, err := os.MkdirTemp("", "copa-frontend-report-")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp dir for report file")
	}

	filename := filepath.Base(reportPath)
	if filename == "" || filename == "." || filename == "/" {
		filename = "report" + jsonExt
	}
	tmpFile := filepath.Join(tmpDir, filename)

	// If file is small enough, read in one go
	if fileSize < chunkSize {
		data, err := ref.ReadFile(ctx, gwclient.ReadRequest{Filename: reportPath})
		if err != nil {
			os.RemoveAll(tmpDir)
			return "", errors.Wrapf(err, "failed to read report file: %s", reportPath)
		}

		if err := os.WriteFile(tmpFile, data, 0o600); err != nil {
			os.RemoveAll(tmpDir)
			return "", errors.Wrap(err, "failed to write report to temp file")
		}

		bklog.G(ctx).WithField("component", "copa-frontend").
			WithField("tempFile", tmpFile).
			WithField("size", fileSize).
			Debug("Extracted report file from context")

		return tmpFile, nil
	}

	// File is large - read in chunks
	bklog.G(ctx).WithField("component", "copa-frontend").
		WithField("size", fileSize).
		Info("Reading large report file in chunks")

	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", errors.Wrap(err, "failed to create temp file")
	}
	defer f.Close()

	var offset int64
	for offset < fileSize {
		length := chunkSize
		if offset+int64(length) > fileSize {
			length = int(fileSize - offset)
		}

		chunk, err := ref.ReadFile(ctx, gwclient.ReadRequest{
			Filename: reportPath,
			Range: &gwclient.FileRange{
				Offset: int(offset),
				Length: length,
			},
		})
		if err != nil {
			os.RemoveAll(tmpDir)
			return "", errors.Wrapf(err, "failed to read chunk at offset %d", offset)
		}

		if _, err := f.Write(chunk); err != nil {
			os.RemoveAll(tmpDir)
			return "", errors.Wrap(err, "failed to write chunk to temp file")
		}

		offset += int64(len(chunk))
	}

	bklog.G(ctx).WithField("component", "copa-frontend").
		WithField("tempFile", tmpFile).
		WithField("size", fileSize).
		WithField("chunks", (fileSize+chunkSize-1)/chunkSize).
		Debug("Extracted large report file in chunks")

	return tmpFile, nil
}

// extractReportDirectory extracts all JSON files from a report directory.
func extractReportDirectory(ctx context.Context, ref gwclient.Reference, reportPath string) (string, error) {
	entries, err := ref.ReadDir(ctx, gwclient.ReadDirRequest{
		Path:           reportPath,
		IncludePattern: "*" + jsonExt,
	})
	if err != nil {
		return "", errors.Wrapf(err, "failed to read report directory: %s", reportPath)
	}

	if len(entries) == 0 {
		return "", errors.Errorf("no JSON files found in report directory: %s", reportPath)
	}

	if err := ensureTempDir(); err != nil {
		return "", errors.Wrap(err, "failed to ensure temp dir exists")
	}

	tmpDir, err := os.MkdirTemp("", "copa-frontend-reports-")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp dir for report directory")
	}

	// Extract each JSON file
	for _, entry := range entries {
		if strings.HasSuffix(entry.GetPath(), jsonExt) {
			entryPath := filepath.Join(reportPath, filepath.Base(entry.GetPath()))

			// Read file (with chunking support for large files)
			extractedFile, err := extractReportFile(ctx, ref, entryPath, entry.Size)
			if err != nil {
				bklog.G(ctx).WithError(err).WithField("file", entryPath).Warn("Failed to extract report file from directory")
				continue
			}

			// Move to the reports directory
			destPath := filepath.Join(tmpDir, filepath.Base(entry.GetPath()))
			if err := os.Rename(extractedFile, destPath); err != nil {
				// If rename fails, try copy
				data, readErr := os.ReadFile(extractedFile)
				if readErr == nil {
					_ = os.WriteFile(destPath, data, 0o600)
				}
				os.RemoveAll(filepath.Dir(extractedFile))
			}
		}
	}

	bklog.G(ctx).WithField("component", "copa-frontend").
		WithField("tempDir", tmpDir).
		WithField("fileCount", len(entries)).
		Debug("Extracted report directory from context")

	return tmpDir, nil
}

const (
	chiselReleaseContextName       = "chisel-release"
	chiselReleaseExtractionDirName = "release"
	maxFrontendReleaseBytes        = 64 << 20
	maxFrontendReleaseFiles        = 10000
)

// extractChiselReleaseFromContext copies a local Chisel release directory from
// the dedicated BuildKit context into the frontend's temporary filesystem.
func extractChiselReleaseFromContext(ctx context.Context, client gwclient.Client, releasePath string) (string, error) {
	if releasePath == "" || filepath.IsAbs(releasePath) {
		return "", fmt.Errorf("local Chisel release path must be relative to the %q BuildKit context", chiselReleaseContextName)
	}
	cleaned := filepath.ToSlash(filepath.Clean(releasePath))
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("local Chisel release path %q escapes its BuildKit context", releasePath)
	}

	localState := llb.Local(chiselReleaseContextName,
		llb.SharedKeyHint(chiselReleaseContextName),
		llb.WithCustomName("Loading local Chisel release"),
		llb.FollowPaths([]string{"."}),
	)
	definition, err := localState.Marshal(ctx)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal Chisel release context")
	}
	result, err := client.Solve(ctx, gwclient.SolveRequest{Definition: definition.ToPB()})
	if err != nil {
		return "", errors.Wrap(err, "failed to solve Chisel release context")
	}
	reference, err := result.SingleRef()
	if err != nil {
		return "", errors.Wrap(err, "failed to get Chisel release context reference")
	}
	stat, err := reference.StatFile(ctx, gwclient.StatRequest{Path: cleaned})
	if err != nil {
		return "", errors.Wrapf(err, "failed to stat Chisel release directory %s", releasePath)
	}
	if !stat.IsDir() {
		return "", fmt.Errorf("local Chisel release path %q is not a directory", releasePath)
	}

	if err := ensureTempDir(); err != nil {
		return "", errors.Wrap(err, "failed to ensure temp dir exists")
	}
	tempDir, err := os.MkdirTemp("", "copa-frontend-chisel-release-")
	if err != nil {
		return "", errors.Wrap(err, "failed to create Chisel release temp directory")
	}
	releaseDir := filepath.Join(tempDir, chiselReleaseExtractionDirName)
	if err := os.Mkdir(releaseDir, 0o700); err != nil {
		os.RemoveAll(tempDir)
		return "", errors.Wrap(err, "failed to create extracted Chisel release directory")
	}
	fileCount := 0
	var totalBytes int64
	if err := extractFrontendContextDirectory(ctx, reference, cleaned, releaseDir, &fileCount, &totalBytes); err != nil {
		os.RemoveAll(tempDir)
		return "", err
	}
	return releaseDir, nil
}

func extractFrontendContextDirectory(ctx context.Context, reference gwclient.Reference, sourcePath, destinationPath string, fileCount *int, totalBytes *int64) error {
	if err := extractFrontendContextDirectoryWithinRoot(ctx, reference, sourcePath, destinationPath, destinationPath, fileCount, totalBytes); err != nil {
		return err
	}
	return validateExtractedChiselReleaseSymlinks(destinationPath)
}

func validateExtractedChiselReleaseSymlinks(rootPath string) error {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return errors.Wrap(err, "failed to open extracted Chisel release root")
	}
	defer root.Close()

	return fs.WalkDir(root.FS(), ".", func(relative string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if relative == "." || entry.Type()&os.ModeSymlink == 0 {
			return nil
		}
		// os.Root resolves the complete symlink chain and rejects traversal out
		// of the extracted directory, including escapes hidden behind another
		// in-tree symlink. Dangling links and cycles are rejected as well.
		if _, err := root.Stat(filepath.FromSlash(relative)); err != nil {
			return fmt.Errorf("local Chisel release symlink %q does not resolve safely within the release directory: %w", relative, err)
		}
		return nil
	})
}

func extractFrontendContextDirectoryWithinRoot(
	ctx context.Context,
	reference gwclient.Reference,
	sourcePath,
	destinationPath,
	destinationRoot string,
	fileCount *int,
	totalBytes *int64,
) error {
	entries, err := reference.ReadDir(ctx, gwclient.ReadDirRequest{Path: sourcePath})
	if err != nil {
		return errors.Wrapf(err, "failed to read Chisel release directory %s", sourcePath)
	}
	for _, entry := range entries {
		name := filepath.Base(entry.GetPath())
		if name == "." || name == ".." || name == "" {
			return fmt.Errorf("invalid entry %q in Chisel release context", entry.GetPath())
		}
		if name == ".git" {
			continue
		}
		*fileCount++
		if *fileCount > maxFrontendReleaseFiles {
			return fmt.Errorf("local Chisel release contains more than %d entries", maxFrontendReleaseFiles)
		}
		sourceEntry := filepath.Join(sourcePath, name)
		destinationEntry := filepath.Join(destinationPath, name)
		mode := os.FileMode(entry.Mode)
		switch {
		case mode.IsDir():
			if err := os.Mkdir(destinationEntry, mode.Perm()); err != nil {
				return errors.Wrapf(err, "failed to create local Chisel release directory %s", name)
			}
			if err := extractFrontendContextDirectoryWithinRoot(ctx, reference, sourceEntry, destinationEntry, destinationRoot, fileCount, totalBytes); err != nil {
				return err
			}
		case mode.IsRegular():
			if entry.Size < 0 || entry.Size > maxFrontendReleaseBytes || *totalBytes+entry.Size > maxFrontendReleaseBytes {
				return fmt.Errorf("local Chisel release exceeds the %d MiB size limit", maxFrontendReleaseBytes>>20)
			}
			remainingBytes := maxFrontendReleaseBytes - *totalBytes
			data, err := copabuildkit.ReadFileWithLimit(ctx, reference, sourceEntry, remainingBytes)
			if err != nil {
				return errors.Wrapf(err, "failed to read local Chisel release file %s", sourceEntry)
			}
			*totalBytes += int64(len(data))
			if err := os.WriteFile(destinationEntry, data, mode.Perm()); err != nil {
				return errors.Wrapf(err, "failed to write local Chisel release file %s", name)
			}
		case mode&os.ModeSymlink != 0:
			target := entry.Linkname
			if target == "" {
				return fmt.Errorf("local Chisel release symlink %q has an empty target", sourceEntry)
			}
			if path.IsAbs(target) {
				return fmt.Errorf("local Chisel release symlink %q has an absolute target", sourceEntry)
			}
			resolvedTarget := filepath.Clean(filepath.Join(filepath.Dir(destinationEntry), filepath.FromSlash(path.Clean(target))))
			relativeTarget, err := filepath.Rel(destinationRoot, resolvedTarget)
			if err != nil || relativeTarget == ".." || strings.HasPrefix(relativeTarget, ".."+string(filepath.Separator)) || filepath.IsAbs(relativeTarget) {
				return fmt.Errorf("local Chisel release symlink %q escapes the release directory", sourceEntry)
			}
			if err := os.Symlink(target, destinationEntry); err != nil {
				return errors.Wrapf(err, "failed to create local Chisel release symlink %s", name)
			}
		default:
			return fmt.Errorf("local Chisel release contains unsupported non-regular entry %q", sourceEntry)
		}
	}
	return nil
}
