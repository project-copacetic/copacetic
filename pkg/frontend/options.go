package frontend

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/buildkit/frontend/dockerui"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/util/bklog"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"

	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

const (
	trueStr = "true"
)

// ParseOptions parses the frontend options from the build context.
func ParseOptions(ctx context.Context, client gwclient.Client) (*types.Options, error) {
	// Wrap the client with dockerui for better Docker CLI compatibility
	// This provides automatic dockerignore handling and named context support
	c, err := dockerui.NewClient(client)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create dockerui client")
	}

	opts := c.BuildOpts()

	options := &types.Options{
		Scanner:           "trivy", // default scanner
		PkgTypes:          "os",    // default to OS packages only
		LibraryPatchLevel: "patch", // default to patch-level updates for libraries
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
		bklog.G(ctx).WithField("component", "copa-frontend").WithField("reportPath", reportPath).Info("Vulnerability report provided, using report mode")

		// Extract the report from the BuildKit context
		extractedPath, err := extractReportFromContext(ctx, client, reportPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to extract report from context")
		}
		options.Report = extractedPath
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

	// Parse package types (experimental)
	if v, ok := getOpt(keyPkgTypes); ok {
		options.PkgTypes = v
		bklog.G(ctx).WithField("component", "copa-frontend").WithField("pkgTypes", v).Debug("Package types specified")
	}

	// Parse library patch level (experimental)
	if v, ok := getOpt(keyLibraryPatchLevel); ok {
		options.LibraryPatchLevel = v
		bklog.G(ctx).WithField("component", "copa-frontend").WithField("libraryPatchLevel", v).Debug("Library patch level specified")
	}

	// Validate library patch level
	if err := validateLibraryPatchLevel(options.LibraryPatchLevel, options.PkgTypes); err != nil {
		return nil, errors.Wrap(err, "invalid library patch level configuration")
	}

	// Validate that library package types require a report
	pkgTypesList, err := parsePkgTypes(options.PkgTypes)
	if err != nil {
		return nil, errors.Wrap(err, "invalid package types")
	}

	reportProvided := options.Report != ""
	if err := validateLibraryPkgTypesRequireReport(pkgTypesList, reportProvided); err != nil {
		return nil, errors.Wrap(err, "library package types validation failed")
	}

	return options, nil
}

// validateLibraryPatchLevel validates the library patch level flag and its usage.
func validateLibraryPatchLevel(libraryPatchLevel, pkgTypes string) error {
	// Valid library patch levels
	validLevels := map[string]bool{
		utils.PatchTypePatch: true,
		utils.PatchTypeMinor: true,
		utils.PatchTypeMajor: true,
	}

	// Check if the provided level is valid
	if !validLevels[libraryPatchLevel] {
		return fmt.Errorf("invalid library patch level '%s': must be one of 'patch', 'minor', or 'major'", libraryPatchLevel)
	}

	// If library patch level is specified and not the default, ensure library is in pkg-types
	if libraryPatchLevel != utils.PatchTypePatch && !strings.Contains(pkgTypes, utils.PkgTypeLibrary) {
		return fmt.Errorf("library-patch-level can only be used when 'library' is included in pkg-types")
	}

	return nil
}

// parsePkgTypes parses a comma-separated string of package types and validates them.
func parsePkgTypes(pkgTypesStr string) ([]string, error) {
	if pkgTypesStr == "" {
		return []string{utils.PkgTypeOS}, nil // default to OS
	}

	types := strings.Split(pkgTypesStr, ",")
	validTypes := []string{}

	for _, t := range types {
		t = strings.TrimSpace(t)
		if t == utils.PkgTypeOS || t == utils.PkgTypeLibrary {
			validTypes = append(validTypes, t)
		} else {
			return nil, fmt.Errorf("invalid package type '%s'. Valid types are: %s, %s", t, utils.PkgTypeOS, utils.PkgTypeLibrary)
		}
	}

	if len(validTypes) == 0 {
		return []string{utils.PkgTypeOS}, nil // default to OS
	}

	return validTypes, nil
}

// validateLibraryPkgTypesRequireReport validates that library package types require a scanner report.
func validateLibraryPkgTypesRequireReport(pkgTypes []string, reportProvided bool) error {
	if shouldIncludeLibraryUpdates(pkgTypes) && !reportProvided {
		return fmt.Errorf("library package types require a scanner report file to be provided")
	}
	return nil
}

// shouldIncludeLibraryUpdates returns true if library updates should be included based on package types.
func shouldIncludeLibraryUpdates(pkgTypes []string) bool {
	return slices.Contains(pkgTypes, utils.PkgTypeLibrary)
}
