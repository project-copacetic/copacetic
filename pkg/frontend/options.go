package frontend

import (
	"context"
	"os"
	"strings"

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
		// Direct file path - same as patch command --report/-r
		options.Report = reportPath
	} else if reportPath, ok := getOpt(keyReportPath); ok {
		// Read report from build context and save to persistent location
		reportData, err := readReportFromContext(ctx, client, reportPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read report from context: %s", reportPath)
		}
		tempFile, err := saveReportToTempFile(reportData)
		if err != nil {
			return nil, errors.Wrap(err, "failed to save report to temp file")
		}
		options.Report = tempFile
	} else {
		// update all
		bklog.L.WithField("component", "copa-frontend").Info("No vulnerability report provided, using update-all mode")
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

// saveReportToTempFile saves report data to a temporary file and returns the file path.
// This matches the pkg/patch approach of working with file paths.
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

// readReportFromContext reads a file from the build context.
func readReportFromContext(ctx context.Context, client gwclient.Client, path string) ([]byte, error) {
	// Get the build context inputs
	inputs, err := client.Inputs(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get build inputs")
	}

	// Look for the context input (usually named "context")
	contextState, ok := inputs["context"]
	if !ok {
		// Debug: Print all available inputs
		var availableInputs []string
		for name := range inputs {
			availableInputs = append(availableInputs, name)
		}
		return nil, errors.Errorf("build context not found in inputs, available inputs: %v", availableInputs)
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

	// Read the file from the build context
	data, err := ref.ReadFile(ctx, gwclient.ReadRequest{
		Filename: path,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read file: %s", path)
	}

	return data, nil
}
