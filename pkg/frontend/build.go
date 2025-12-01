package frontend

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/util/bklog"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

const (
	jsonExt = ".json"
)

// BuildPatchedImage builds a patched image using the Copa patching logic.
// This reuses the same components as the CLI to ensure consistency.
func (f *Frontend) buildPatchedImage(ctx context.Context, opts *types.Options, platform *ocispecs.Platform) (llb.State, error) {
	// Create package manager instance
	config, pm, err := common.SetupBuildkitConfigAndManager(ctx, f.client, opts.Image, platform, "", nil)
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
	}

	// Check if there are packages to update
	if um != nil && len(um.OSUpdates) == 0 && len(um.LangUpdates) == 0 {
		bklog.G(ctx).WithField("component", "copa-frontend").Info("No packages to update, returning original image")
		return config.ImageState, nil
	}

	// Apply package updates using the same logic as CLI
	patchedState, _, err := pm.InstallUpdates(ctx, um, opts.IgnoreError)
	if err != nil {
		if opts.IgnoreError {
			bklog.G(ctx).WithError(err).WithField("component", "copa-frontend").Warn("Failed to install updates (ignored)")
			return config.ImageState, nil
		}
		return llb.State{}, errors.Wrap(err, "failed to install package updates")
	}

	return *patchedState, nil
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

	// Ensure /tmp directory exists
	if err := os.MkdirAll("/tmp", 0o1777); err != nil {
		return "", errors.Wrap(err, "failed to create /tmp directory")
	}

	tmpDir, err := os.MkdirTemp("/", "copa-frontend-report-")
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
