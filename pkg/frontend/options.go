package frontend

import (
	"context"
	"os"
	"strings"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/util/bklog"
	"github.com/pkg/errors"

	"github.com/project-copacetic/copacetic/pkg/types"
)

const (
	trueStr = "true"
)

// ParseOptions parses the frontend options from the build context.
func ParseOptions(ctx context.Context, client gwclient.Client) (*types.Options, error) {
	opts := client.BuildOpts()

	options := &types.Options{
		Scanner: "trivy", // default scanner
	}

	// Helper function to get option value, checking both direct and build-arg prefixed keys
	getOpt := func(key string) (string, bool) {
		// First try direct key (buildctl style)
		if v, ok := opts.Opts[key]; ok {
			return v, true
		}
		// Then try build-arg prefixed key (docker buildx style)
		if v, ok := opts.Opts["build-arg:"+key]; ok {
			return v, true
		}
		return "", false
	}

	// Parse base image
	if v, ok := getOpt(keyImage); ok {
		options.Image = v
	} else {
		return nil, errors.New("base image reference required via --opt image=<ref>")
	}

	// Parse scanner type
	if v, ok := getOpt(keyScanner); ok {
		options.Scanner = v
	}

	// Parse ignore errors flag
	if v, ok := getOpt(keyIgnoreErrors); ok {
		options.IgnoreError = v == trueStr || v == "1"
	}

	// Parse platforms (as string slice for multiarch support)
	if v, ok := getOpt(keyPlatform); ok {
		// Split comma-separated platforms
		options.Platforms = strings.Split(v, ",")
		bklog.G(ctx).WithField("component", "copa-frontend").WithField("platforms", options.Platforms).Debug("Parsed platforms")
	}

	// Parse vulnerability report
	if reportPath, ok := getOpt(keyReport); ok {
		bklog.G(ctx).WithField("component", "copa-frontend").WithField("reportPath", reportPath).Info("Processing report option")

		// For BuildKit frontends, file paths need to be read from the build context
		// since the frontend runs in a container without access to host filesystem
		if err := processReportFromBuildContext(ctx, client, reportPath, options); err != nil {
			// If reading from build context fails, try using the path directly
			// This handles cases where the report might be mounted or available in the container
			bklog.G(ctx).WithField("component", "copa-frontend").WithField("reportPath", reportPath).Debug("Failed to read from build context, trying direct path")
			options.Report = reportPath
		} else {
			bklog.G(ctx).WithField("component", "copa-frontend").WithField("reportPath", options.Report).Info("Successfully read report from build context")
		}
	} else {
		// update all
		bklog.G(ctx).WithField("component", "copa-frontend").Info("No vulnerability report provided, using update-all mode")
	}

	// Parse patched tag
	if v, ok := getOpt(keyPatchedTag); ok {
		options.PatchedTag = v
	}

	// Parse suffix
	if v, ok := getOpt(keySuffix); ok {
		options.Suffix = v
	}

	// Parse output (for VEX document)
	if v, ok := getOpt(keyOutput); ok {
		options.Output = v
	}

	// Parse format (for VEX document)
	if v, ok := getOpt(keyFormat); ok {
		options.Format = v
	}

	return options, nil
}

// processReportFromBuildContext attempts to read a report (file or directory) from build contexts.
// It updates the options.Report field with the appropriate path.
func processReportFromBuildContext(ctx context.Context, client gwclient.Client, reportPath string, options *types.Options) error {
	// Get all available inputs (build contexts)
	inputs, err := client.Inputs(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get build inputs")
	}

	bklog.G(ctx).WithField("component", "copa-frontend").WithField("path", reportPath).Debug("Attempting to read report from build context")

	// Log available inputs for debugging
	var inputNames []string
	for name := range inputs {
		inputNames = append(inputNames, name)
	}
	bklog.G(ctx).WithField("component", "copa-frontend").WithField("inputs", inputNames).Debug("Available build contexts")

	// If no named inputs are available, use the default build context
	if len(inputs) == 0 {
		bklog.G(ctx).WithField("component", "copa-frontend").Debug("No named inputs available, using default build context")
		// Create a default context state for the build context directory with proper session and progress feedback
		defaultContext := llb.Local("context",
			llb.SessionID(client.BuildOpts().SessionID),
			llb.WithCustomName("Loading vulnerability report"))
		inputs = map[string]llb.State{
			"context": defaultContext,
		}
	}

	// First try to read as a single file from any context
	reportData, contextName, err := readFileFromBuildContexts(ctx, client, inputs, reportPath)
	if err == nil {
		// Successfully read as file - save to temp file
		tempFile, err := saveReportToTempFile(reportData)
		if err != nil {
			return errors.Wrap(err, "failed to save report to temp file")
		}
		options.Report = tempFile
		bklog.G(ctx).WithField("component", "copa-frontend").WithField("context", contextName).WithField("tempFile", tempFile).Info("Read report file from build context")
		return nil
	}

	// If single file read failed, try reading as directory
	tempDir, contextName, err := readDirectoryFromBuildContexts(ctx, client, inputs, reportPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read report '%s' as file or directory from build contexts %v", reportPath, inputNames)
	}

	options.Report = tempDir
	bklog.G(ctx).WithField("component", "copa-frontend").WithField("context", contextName).WithField("tempDir", tempDir).Info("Read report directory from build context")
	return nil
}

// readFileFromBuildContexts tries to read a file from any available build context.
func readFileFromBuildContexts(ctx context.Context, client gwclient.Client, inputs map[string]llb.State, filePath string) ([]byte, string, error) {
	// Try reading from each context
	for contextName, contextState := range inputs {
		data, err := readFileFromContext(ctx, client, &contextState, filePath)
		if err == nil {
			return data, contextName, nil
		}
		bklog.G(ctx).WithField("component", "copa-frontend").WithField("context", contextName).WithError(err).Debug("Failed to read file from context")
	}

	return nil, "", errors.Errorf("file not found in any build context: %s", filePath)
}

// readDirectoryFromBuildContexts tries to read a directory from any available build context.
func readDirectoryFromBuildContexts(ctx context.Context, client gwclient.Client, inputs map[string]llb.State, dirPath string) (string, string, error) {
	// Try reading from each context
	for contextName, contextState := range inputs {
		tempDir, err := readDirectoryFromContext(ctx, client, &contextState, dirPath)
		if err == nil {
			return tempDir, contextName, nil
		}
		bklog.G(ctx).WithField("component", "copa-frontend").WithField("context", contextName).WithError(err).Debug("Failed to read directory from context")
	}

	return "", "", errors.Errorf("directory not found in any build context: %s", dirPath)
}

// readFileFromContext reads a file from a specific build context.
func readFileFromContext(ctx context.Context, client gwclient.Client, contextState *llb.State, filePath string) ([]byte, error) {
	if contextState == nil {
		return nil, errors.New("context state is nil")
	}
	// Solve the context state to get a reference
	def, err := contextState.Marshal(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal context state")
	}

	res, err := client.Solve(ctx, gwclient.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to solve context state")
	}

	ref, err := res.SingleRef()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get context reference")
	}

	// Read the file from the context
	data, err := ref.ReadFile(ctx, gwclient.ReadRequest{
		Filename: filePath,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read file: %s", filePath)
	}

	return data, nil
}

// readDirectoryFromContext reads a directory from a specific build context.
func readDirectoryFromContext(ctx context.Context, client gwclient.Client, contextState *llb.State, dirPath string) (string, error) {
	if contextState == nil {
		return "", errors.New("context state is nil")
	}
	// Solve the context state to get a reference.
	def, err := contextState.Marshal(ctx)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal context state")
	}

	res, err := client.Solve(ctx, gwclient.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to solve context state")
	}

	ref, err := res.SingleRef()
	if err != nil {
		return "", errors.Wrap(err, "failed to get context reference")
	}

	// Create temporary directory for reports
	tempDir, err := os.MkdirTemp("", "copa-reports-*")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp directory")
	}

	// Read directory contents
	files, err := ref.ReadDir(ctx, gwclient.ReadDirRequest{
		Path: dirPath,
	})
	if err != nil {
		os.RemoveAll(tempDir)
		return "", errors.Wrapf(err, "failed to read directory: %s", dirPath)
	}

	// Copy each report file to temp directory
	hasReports := false
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Only copy JSON files (report files)
		if !strings.HasSuffix(file.GetPath(), ".json") {
			continue
		}

		filePath := file.GetPath()
		data, err := ref.ReadFile(ctx, gwclient.ReadRequest{
			Filename: filePath,
		})
		if err != nil {
			os.RemoveAll(tempDir)
			return "", errors.Wrapf(err, "failed to read file: %s", filePath)
		}

		// Write to temp directory with same filename
		fileName := strings.TrimPrefix(filePath, dirPath+"/")
		if fileName == filePath {
			// If dirPath wasn't a prefix, just use the basename
			parts := strings.Split(filePath, "/")
			fileName = parts[len(parts)-1]
		}

		tempFilePath := tempDir + "/" + fileName
		if err := os.WriteFile(tempFilePath, data, 0o600); err != nil {
			os.RemoveAll(tempDir)
			return "", errors.Wrapf(err, "failed to write file: %s", tempFilePath)
		}

		hasReports = true
		bklog.G(ctx).WithField("component", "copa-frontend").WithField("file", fileName).Debug("Copied report file from build context")
	}

	if !hasReports {
		os.RemoveAll(tempDir)
		return "", errors.Errorf("no report files found in directory: %s", dirPath)
	}

	return tempDir, nil
}

// saveReportToTempFile saves report data to a temporary file and returns the file path.
func saveReportToTempFile(data []byte) (string, error) {
	tempFile, err := os.CreateTemp("", "copa-report-*.json")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp file")
	}
	defer tempFile.Close()

	if _, err := tempFile.Write(data); err != nil {
		os.Remove(tempFile.Name())
		return "", errors.Wrap(err, "failed to write report data to temp file")
	}

	return tempFile.Name(), nil
}
