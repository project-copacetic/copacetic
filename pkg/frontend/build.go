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
				platformFile += ".json"

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
		um, err = report.TryParseScanReport(reportPath, opts.Scanner)
		if err != nil {
			return llb.State{}, errors.Wrapf(err, "failed to parse vulnerability report from path: %s", reportPath)
		}
	}

	// Check if there are packages to update
	if um != nil && len(um.Updates) == 0 {
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

	// First, try to read as a single file
	data, fileErr := ref.ReadFile(ctx, gwclient.ReadRequest{Filename: reportPath})
	if fileErr == nil && len(data) > 0 {
		// It's a file - write to temp file
		tmpDir, err := os.MkdirTemp("", "copa-frontend-report-")
		if err != nil {
			return "", errors.Wrap(err, "failed to create temp dir for report file")
		}

		// Preserve the original filename for proper parsing
		filename := filepath.Base(reportPath)
		if filename == "" || filename == "." || filename == "/" {
			filename = "report.json"
		}
		tmpFile := filepath.Join(tmpDir, filename)

		if err := os.WriteFile(tmpFile, data, 0o600); err != nil {
			return "", errors.Wrap(err, "failed to write report to temp file")
		}

		bklog.G(ctx).WithField("component", "copa-frontend").
			WithField("tempFile", tmpFile).
			Debug("Extracted report file from context")

		return tmpFile, nil
	}

	// If reading as file failed, try as directory
	entries, dirErr := ref.ReadDir(ctx, gwclient.ReadDirRequest{
		Path:           reportPath,
		IncludePattern: "*.json",
	})

	if dirErr == nil && len(entries) > 0 {
		// It's a directory - extract all JSON files
		tmpDir, err := os.MkdirTemp("", "copa-frontend-reports-")
		if err != nil {
			return "", errors.Wrap(err, "failed to create temp dir for report directory")
		}

		// Extract each JSON file
		for _, entry := range entries {
			if strings.HasSuffix(entry.GetPath(), ".json") {
				filePath := filepath.Join(reportPath, filepath.Base(entry.GetPath()))
				fileData, err := ref.ReadFile(ctx, gwclient.ReadRequest{Filename: filePath})
				if err != nil {
					bklog.G(ctx).WithError(err).WithField("file", filePath).Warn("Failed to read report file from directory")
					continue
				}

				tmpFile := filepath.Join(tmpDir, filepath.Base(entry.GetPath()))
				if err := os.WriteFile(tmpFile, fileData, 0o600); err != nil {
					bklog.G(ctx).WithError(err).WithField("file", tmpFile).Warn("Failed to write report file")
					continue
				}
			}
		}

		bklog.G(ctx).WithField("component", "copa-frontend").
			WithField("tempDir", tmpDir).
			WithField("fileCount", len(entries)).
			Debug("Extracted report directory from context")

		return tmpDir, nil
	}

	// If both failed, return the more informative error
	if fileErr != nil {
		return "", errors.Wrapf(fileErr, "failed to read report from context: %s", reportPath)
	}
	return "", errors.Wrapf(dirErr, "failed to read report directory from context: %s", reportPath)
}
