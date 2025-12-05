package langmgr

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type dotnetManager struct {
	config        *buildkit.Config
	workingFolder string
}

// validDotnetPackageNamePattern defines the regex pattern for valid NuGet package names.
// Based on NuGet package naming conventions: https://learn.microsoft.com/en-us/nuget/create-packages/package-authoring-best-practices
var validDotnetPackageNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// validNuGetVersionPattern defines the regex pattern for valid NuGet versions.
// NuGet supports SemVer 2.0 plus a 4th "Revision" segment for System.Version compatibility.
// Format: Major.Minor.Patch[.Revision][-prerelease][+buildmetadata]
// See: https://learn.microsoft.com/en-us/nuget/concepts/package-versioning
var validNuGetVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(\.\d+)?(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?(\+[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$`)

// validateDotnetPackageName validates that a package name is safe for use in XML and shell commands.
func validateDotnetPackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name cannot be empty")
	}
	if len(name) > 128 {
		return fmt.Errorf("package name too long (max 128 characters): %s", name)
	}
	if !validDotnetPackageNamePattern.MatchString(name) {
		return fmt.Errorf("invalid .NET package name format: %s", name)
	}
	// Check for XML-unsafe characters and shell injection attempts
	if strings.ContainsAny(name, "<>&\"'`;|$(){}[]\\") {
		return fmt.Errorf("package name contains unsafe characters: %s", name)
	}
	return nil
}

// validateDotnetVersion validates that a version string is safe for use in XML and shell commands.
// It checks format validity, length limits, and unsafe characters.
func validateDotnetVersion(version string) error {
	if version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	if len(version) > 64 {
		return fmt.Errorf("version too long (max 64 characters): %s", version)
	}
	// Check if it's a valid NuGet version (supports 3 or 4 part versions with optional prerelease/metadata)
	if !isValidDotnetVersion(version) {
		return fmt.Errorf("invalid .NET version format: %s", version)
	}
	// Check for XML-unsafe characters and shell injection attempts
	if strings.ContainsAny(version, "<>&\"'`;|$(){}[]\\") {
		return fmt.Errorf("version contains unsafe characters: %s", version)
	}
	return nil
}

// escapeXMLAttribute escapes a string for safe use in an XML attribute value.
func escapeXMLAttribute(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(s)
}

// isValidDotnetVersion checks if a version string is a valid NuGet version.
// NuGet supports Major.Minor.Patch[.Revision][-prerelease][+buildmetadata].
func isValidDotnetVersion(v string) bool {
	if v == "" {
		return false
	}
	return validNuGetVersionPattern.MatchString(v)
}

// isLessThanDotnetVersion compares two NuGet version strings.
// It returns true if v1 is less than v2.
// For 4-part versions (Major.Minor.Patch.Revision), falls back to semver comparison
// of the first 3 parts if semver parsing fails.
func isLessThanDotnetVersion(v1, v2 string) bool {
	// Try standard semver comparison first
	ver1, err1 := semver.NewVersion(v1)
	ver2, err2 := semver.NewVersion(v2)
	if err1 == nil && err2 == nil {
		return ver1.LessThan(ver2)
	}

	// For 4-part NuGet versions, parse manually and compare
	parts1 := parseNuGetVersionParts(v1)
	parts2 := parseNuGetVersionParts(v2)
	if parts1 == nil || parts2 == nil {
		log.Warnf("Error parsing .NET version for comparison: '%s' vs '%s'", v1, v2)
		return false
	}

	// Compare each numeric part
	for i := 0; i < 4; i++ {
		if parts1[i] < parts2[i] {
			return true
		}
		if parts1[i] > parts2[i] {
			return false
		}
	}
	return false // versions are equal
}

// parseNuGetVersionParts extracts the numeric parts from a NuGet version string.
// Returns [Major, Minor, Patch, Revision] or nil if parsing fails.
func parseNuGetVersionParts(v string) []int {
	// Strip prerelease and build metadata
	if idx := strings.IndexAny(v, "-+"); idx != -1 {
		v = v[:idx]
	}

	parts := strings.Split(v, ".")
	if len(parts) < 3 || len(parts) > 4 {
		return nil
	}

	result := make([]int, 4)
	for i, p := range parts {
		var num int
		if _, err := fmt.Sscanf(p, "%d", &num); err != nil {
			return nil
		}
		result[i] = num
	}
	return result
}

func (dnm *dotnetManager) InstallUpdates(
	ctx context.Context,
	imageState *llb.State,
	manifest *unversioned.UpdateManifest,
	ignoreErrors bool,
) (*llb.State, []string, error) {
	var errPkgsReported []string // Packages that will be reported as problematic

	// Filter for .NET packages only
	var dotnetUpdates unversioned.LangUpdatePackages
	for _, pkg := range manifest.LangUpdates {
		if pkg.Type == "dotnet-core" {
			dotnetUpdates = append(dotnetUpdates, pkg)
		}
	}

	if len(dotnetUpdates) == 0 {
		log.Debug("No .NET packages found in language updates.")
		return imageState, []string{}, nil
	}

	log.Debugf("Found %d .NET packages to process: %v", len(dotnetUpdates), dotnetUpdates)

	dotnetComparer := VersionComparer{isValidDotnetVersion, isLessThanDotnetVersion}
	updatesToAttempt, err := GetUniqueLatestUpdates(dotnetUpdates, dotnetComparer, ignoreErrors)
	if err != nil {
		// Collect error packages when GetUniqueLatestUpdates fails
		for _, u := range dotnetUpdates {
			errPkgsReported = append(errPkgsReported, u.Name)
		}
		return imageState, errPkgsReported, fmt.Errorf("failed to determine unique latest .NET updates: %w", err)
	}

	if len(updatesToAttempt) == 0 {
		log.Warn("No .NET update packages were specified to apply.")
		return imageState, []string{}, nil
	}
	log.Debugf("Attempting to update latest unique .NET packages: %v", updatesToAttempt)

	// Perform the upgrade.
	updatedImageState, resultsBytes, upgradeErr := dnm.upgradePackages(ctx, imageState, updatesToAttempt, ignoreErrors)
	if upgradeErr != nil {
		log.Errorf("Failed to upgrade .NET packages: %v. Cannot proceed to validation.", upgradeErr)
		if !ignoreErrors {
			for _, u := range updatesToAttempt {
				errPkgsReported = append(errPkgsReported, u.Name)
			}
			return imageState, errPkgsReported, fmt.Errorf(".NET package upgrade operation failed: %w", upgradeErr)
		}
		log.Warnf(".NET package upgrade operation failed but errors are ignored. Original image state will be used.")
		for _, u := range updatesToAttempt {
			errPkgsReported = append(errPkgsReported, u.Name)
		}
		return imageState, errPkgsReported, nil
	}

	// If upgradePackages succeeded, upgradeErr is nil. Now validate.
	// Skip validation for runtime patching (results format is different)
	resultsString := string(resultsBytes)
	isRuntimePatch := resultsBytes != nil && strings.Contains(resultsString, "Runtime patching completed")

	log.Debugf("Validation check - resultsBytes length: %d, contains marker: %v", len(resultsBytes), isRuntimePatch)
	if len(resultsBytes) > 0 && len(resultsBytes) < 500 {
		log.Debugf("Results content: %s", resultsString)
	}

	var failedValidationPkgs []string
	var validationErr error

	if !isRuntimePatch {
		failedValidationPkgs, validationErr = dnm.validateDotnetPackageVersions(
			ctx, resultsBytes, updatesToAttempt, ignoreErrors)

		if len(failedValidationPkgs) > 0 {
			log.Warnf(".NET packages failed version validation: %v", failedValidationPkgs)
			for _, pkgName := range failedValidationPkgs {
				isAlreadyListed := false
				for _, p := range errPkgsReported {
					if p == pkgName {
						isAlreadyListed = true
						break
					}
				}
				if !isAlreadyListed {
					errPkgsReported = append(errPkgsReported, pkgName)
				}
			}
		}

		if validationErr != nil {
			log.Warnf(".NET package validation reported issues: %v", validationErr)
			if !ignoreErrors {
				return updatedImageState, errPkgsReported, fmt.Errorf(".NET package validation failed: %w", validationErr)
			}
			log.Warnf(".NET package validation issues were ignored. Problematic packages: %v", errPkgsReported)
		}
	} else {
		log.Info("Runtime patching used - skipping standard validation (DLL replacement verified)")
	}

	if len(errPkgsReported) > 0 {
		log.Infof(".NET packages reported as problematic (failed update or validation): %v", errPkgsReported)
	} else {
		log.Info("All .NET packages successfully updated and validated.")
	}

	return updatedImageState, errPkgsReported, nil
}

// validateDotnetPackageVersions checks if the installed packages match the expected versions.
// resultsBytes: content of 'dotnet list package' output for the relevant packages.
// expectedUpdates: list of packages that were attempted to be updated.
// ignoreErrors: if true, validation failures are logged as warnings instead of returning an error.
func (dnm *dotnetManager) validateDotnetPackageVersions(
	_ context.Context,
	resultsBytes []byte,
	expectedUpdates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) ([]string, error) {
	var failedPackages []string
	var validationIssues []string

	if resultsBytes == nil {
		if len(expectedUpdates) > 0 {
			log.Warn("validateDotnetPackageVersions: resultsBytes is nil, cannot validate package versions.")
			for _, pkgUpdate := range expectedUpdates {
				failedPackages = append(failedPackages, pkgUpdate.Name)
				validationIssues = append(validationIssues, fmt.Sprintf("package %s: no package list data to validate", pkgUpdate.Name))
			}
			if !ignoreErrors && len(failedPackages) > 0 {
				uniqueFailedPkgsList := utils.DeduplicateStringSlice(failedPackages)
				return uniqueFailedPkgsList, fmt.Errorf(
					"failed to validate .NET packages: %s", strings.Join(validationIssues, "; "))
			}
		}
		return failedPackages, nil
	}

	installedPkgs := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(resultsBytes)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip headers and empty lines
		if line == "" || strings.Contains(line, "Project") || strings.Contains(line, "----") ||
			strings.Contains(line, "Top-level Package") || strings.Contains(line, "Transitive Package") {
			continue
		}

		// Parse line format: "> PackageName   Version   Resolved"
		// Lines with package references start with ">"
		if strings.HasPrefix(line, ">") {
			// Remove the ">" and split by spaces
			line = strings.TrimPrefix(line, ">")
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				packageName := strings.TrimSpace(fields[0])
				version := strings.TrimSpace(fields[1])
				installedPkgs[packageName] = version
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error reading dotnet list package results: %v", err)
		for _, pkgUpdate := range expectedUpdates {
			failedPackages = append(failedPackages, pkgUpdate.Name)
		}
		uniqueFailedPkgsList := utils.DeduplicateStringSlice(failedPackages)
		return uniqueFailedPkgsList, fmt.Errorf("error reading dotnet list package results: %w", err)
	}

	for _, expectedPkg := range expectedUpdates {
		actualVersion, found := installedPkgs[expectedPkg.Name]
		if !found {
			errMsg := fmt.Sprintf("package %s was not found in dotnet list package output after update attempt", expectedPkg.Name)
			validationIssues = append(validationIssues, errMsg)
			failedPackages = append(failedPackages, expectedPkg.Name)
			log.Warnf("%s", errMsg)
			continue
		}

		if !isValidDotnetVersion(actualVersion) {
			errMsg := fmt.Sprintf("package %s has an invalid actual version format: %s", expectedPkg.Name, actualVersion)
			validationIssues = append(validationIssues, errMsg)
			failedPackages = append(failedPackages, expectedPkg.Name)
			log.Warnf("%s", errMsg)
			continue
		}

		if expectedPkg.FixedVersion != "" {
			if !isValidDotnetVersion(expectedPkg.FixedVersion) {
				errMsg := fmt.Sprintf("package %s has an invalid expected fixed version format: %s",
					expectedPkg.Name, expectedPkg.FixedVersion)
				validationIssues = append(validationIssues, errMsg)
				failedPackages = append(failedPackages, expectedPkg.Name)
				log.Warnf("%s", errMsg)
				continue
			}

			vActual, _ := semver.NewVersion(actualVersion)
			vExpected, _ := semver.NewVersion(expectedPkg.FixedVersion)

			if !vActual.Equal(vExpected) {
				errMsg := fmt.Sprintf("package %s: expected version %s, but found %s",
					expectedPkg.Name, expectedPkg.FixedVersion, actualVersion)
				validationIssues = append(validationIssues, errMsg)
				failedPackages = append(failedPackages, expectedPkg.Name)
				log.Warnf("%s", errMsg)
			}
		} else {
			if expectedPkg.InstalledVersion != "" && isValidDotnetVersion(expectedPkg.InstalledVersion) {
				vActual, _ := semver.NewVersion(actualVersion)
				vInstalled, errInstalled := semver.NewVersion(expectedPkg.InstalledVersion)
				if errInstalled == nil {
					switch {
					case vActual.LessThan(vInstalled):
						errMsg := fmt.Sprintf(
							"package %s: upgraded to version %s, which is older than installed version %s",
							expectedPkg.Name, actualVersion, expectedPkg.InstalledVersion)
						validationIssues = append(validationIssues, errMsg)
						failedPackages = append(failedPackages, expectedPkg.Name)
						log.Warnf("%s", errMsg)
					case vActual.Equal(vInstalled):
						log.Infof("Package %s version %s remained unchanged after upgrade attempt.", expectedPkg.Name, actualVersion)
					default:
						log.Infof("Package %s successfully upgraded from %s to %s.",
							expectedPkg.Name, expectedPkg.InstalledVersion, actualVersion)
					}
				} else {
					log.Infof("Package %s updated to %s (InstalledVersion %s was not parsable for comparison).",
						expectedPkg.Name, actualVersion, expectedPkg.InstalledVersion)
				}
			} else {
				log.Infof("Package %s updated to %s (no valid InstalledVersion for comparison or no FixedVersion specified).",
					expectedPkg.Name, actualVersion)
			}
		}
	}

	uniqueFailedPkgsList := utils.DeduplicateStringSlice(failedPackages)

	if len(validationIssues) > 0 {
		summaryError := errors.New(strings.Join(validationIssues, "; "))
		if !ignoreErrors {
			return uniqueFailedPkgsList, summaryError
		}
		log.Warnf(".NET package validation issues (ignored): %v", summaryError)
	}

	return uniqueFailedPkgsList, nil
}

func (dnm *dotnetManager) upgradePackages(
	ctx context.Context,
	imageState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, []byte, error) {
	if len(updates) == 0 {
		log.Info("No .NET packages to install or upgrade.")
		return imageState, []byte{}, nil
	}

	// Find project files and deps.json in the image, and check for SDK availability
	// This single command does all discovery needed for routing
	discoveryCmd := `sh -c 'find / -name "*.csproj" -o -name "*.fsproj" -o -name "*.vbproj" 2>/dev/null | ` +
		`head -1 > /tmp/project_file; ` +
		`find / -name "*.deps.json" 2>/dev/null | grep -v "/usr/share/dotnet" | ` +
		`grep -v "/usr/local/share/dotnet" | head -1 > /tmp/deps_file; ` +
		`if command -v dotnet >/dev/null 2>&1 && dotnet --list-sdks 2>/dev/null | grep -q "[0-9]"; ` +
		`then echo "sdk" > /tmp/has_sdk; else echo "no-sdk" > /tmp/has_sdk; fi; exit 0'`

	projectDiscoveryState := imageState.Run(
		llb.Shlex(discoveryCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Check if this is an SDK image (has dotnet SDK available) or runtime-only image
	// Also check if there are project files to work with
	hasSdk := dnm.checkForSDK(ctx, &projectDiscoveryState)
	hasProjectFile := dnm.checkForProjectFile(ctx, &projectDiscoveryState)

	// If SDK and project files exist, update the .csproj first (for consistency and compile-time checks)
	currentImageState := imageState
	if hasSdk && hasProjectFile {
		log.Info("SDK and project files detected - updating .csproj before runtime patching")
		updatedState, err := dnm.updateProjectFile(ctx, imageState, &projectDiscoveryState, updates, ignoreErrors)
		if err != nil {
			if !ignoreErrors {
				return nil, nil, fmt.Errorf("failed to update project file: %w", err)
			}
			log.Warnf("Failed to update project file (continuing with runtime patching): %v", err)
		} else {
			currentImageState = updatedState
		}
	}

	// Always use runtime patching to replace DLLs in-place
	log.Info("Applying runtime patching to replace DLLs in-place")
	return dnm.patchRuntimeImage(ctx, currentImageState, &projectDiscoveryState, updates, ignoreErrors)
}

// checkForSDK checks if the image has the .NET SDK installed by checking if dotnet --list-sdks returns any SDKs.
func (dnm *dotnetManager) checkForSDK(ctx context.Context, imageState *llb.State) bool {
	// Try to run dotnet --list-sdks to check if SDK is available
	// Runtime-only images have dotnet command but --list-sdks returns empty
	checkSDKState := imageState.Run(
		llb.Shlex(`sh -c 'if dotnet --list-sdks 2>/dev/null | grep -q "[0-9]"; then echo "sdk" > /tmp/has_sdk; else echo "no-sdk" > /tmp/has_sdk; fi'`),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Extract the result
	hasSdkBytes, err := buildkit.ExtractFileFromState(ctx, dnm.config.Client, &checkSDKState, "/tmp/has_sdk")
	if err != nil {
		log.Debugf("Could not check for SDK: %v, assuming no SDK", err)
		return false
	}

	result := strings.TrimSpace(string(hasSdkBytes))
	log.Debugf("SDK check result: %s", result)
	return result == "sdk"
}

// checkForProjectFile checks if the image has .NET project files (.csproj, .fsproj, .vbproj).
func (dnm *dotnetManager) checkForProjectFile(ctx context.Context, discoveryState *llb.State) bool {
	// Extract the /tmp/project_file which was set during discovery
	projectFileBytes, err := buildkit.ExtractFileFromState(ctx, dnm.config.Client, discoveryState, "/tmp/project_file")
	if err != nil {
		log.Debugf("Could not check for project file: %v", err)
		return false
	}

	projectFile := strings.TrimSpace(string(projectFileBytes))
	hasProject := len(projectFile) > 0
	log.Debugf("Project file check: found=%v, path=%s", hasProject, projectFile)
	return hasProject
}

// updateProjectFile updates the .csproj file with new package versions and rebuilds.
// This is called before runtime patching when SDK and project files are available.
// Returns the updated image state with the modified .csproj.
func (dnm *dotnetManager) updateProjectFile(
	ctx context.Context,
	imageState *llb.State,
	discoveryState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, error) {
	log.Info("Updating proj file with new package versions")

	// Find the project file directory (where .csproj is located)
	projectFileBytes, err := buildkit.ExtractFileFromState(ctx, dnm.config.Client, discoveryState, "/tmp/project_file")
	if err != nil {
		return nil, fmt.Errorf("could not find project file in SDK image: %w", err)
	}

	projectFilePath := strings.TrimSpace(string(projectFileBytes))
	workDir := filepath.Dir(projectFilePath)
	log.Infof("Project directory: %s (project file: %s)", workDir, filepath.Base(projectFilePath))

	// Start with merged state (original image + discovery results)
	mergedState := llb.Merge([]llb.State{*imageState, *discoveryState})

	// Apply package updates by modifying project file
	currentState := mergedState
	for _, u := range updates {
		if u.FixedVersion == "" {
			continue
		}

		// Remove old version and add new version
		updateCmd := fmt.Sprintf(`sh -c 'cd %s && dotnet remove package %s 2>/dev/null || true && dotnet add package %s --version %s'`,
			workDir, u.Name, u.Name, u.FixedVersion)
		currentState = currentState.Run(
			llb.Shlex(updateCmd),
			llb.WithProxy(utils.GetProxy()),
		).Root()

		log.Infof("Updated .csproj: %s -> %s", u.Name, u.FixedVersion)
	}

	// Build to verify changes compile successfully
	buildCmd := fmt.Sprintf(`sh -c 'cd %s && dotnet build -c Release'`, workDir)
	builtState := currentState.Run(
		llb.Shlex(buildCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	log.Info(".csproj updated and build verified successfully")
	return &builtState, nil
}

// patchRuntimeImage patches a .NET image by extracting DLLs from NuGet packages.
// This works for both SDK and runtime-only images.
func (dnm *dotnetManager) patchRuntimeImage(
	ctx context.Context,
	imageState *llb.State,
	discoveryState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, []byte, error) {
	log.Info("[EXPERIMENTAL] Runtime patching enabled - attempting to patch runtime-only .NET image")

	// Detect .NET framework version from deps.json
	detectFrameworkCmd := `sh -c 'if [ -s /tmp/deps_file ]; then ` +
		`DEPS_FILE=$(cat /tmp/deps_file); ` +
		`FRAMEWORK=$(grep -o "Microsoft.NETCore.App/[0-9.]*" "$DEPS_FILE" | head -1 | cut -d "/" -f2 || echo "8.0"); ` +
		`echo "$FRAMEWORK" > /tmp/framework_version; ` +
		`echo "Detected .NET framework version: $FRAMEWORK"; ` +
		`else echo "8.0" > /tmp/framework_version; echo "Could not detect framework, defaulting to 8.0"; fi'`

	frameworkDetected := discoveryState.Run(
		llb.Shlex(detectFrameworkCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Discover DLL locations in runtime image and check for multiple deps.json files
	discoverDLLsCmd := `sh -c 'if [ -s /tmp/deps_file ]; then ` +
		`DEPS_FILE=$(cat /tmp/deps_file); ` +
		`APP_DIR=$(dirname "$DEPS_FILE"); ` +
		`echo "$APP_DIR" > /tmp/app_dir; ` +
		`echo "$DEPS_FILE" > /tmp/deps_file_path; ` +
		`echo "Runtime patching - Application directory: $APP_DIR"; ` +
		`echo "Runtime patching - Application deps.json: $DEPS_FILE"; ` +
		`DLL_COUNT=$(ls "$APP_DIR"/*.dll 2>/dev/null | wc -l); ` +
		`echo "Runtime patching - Found $DLL_COUNT DLL files in application directory"; ` +
		`ls "$APP_DIR"/*.dll 2>/dev/null | head -5 || echo "No DLLs found"; ` +
		`DEPS_COUNT=$(find / -name "*.deps.json" 2>/dev/null | grep -v "/usr/share/dotnet" | grep -v "/usr/local/share/dotnet" | wc -l); ` +
		`echo "$DEPS_COUNT" > /tmp/deps_count; ` +
		`if [ "$DEPS_COUNT" -gt 1 ]; then echo "WARNING: Found $DEPS_COUNT deps.json files - only patching first one"; fi; ` +
		`else echo "/app" > /tmp/app_dir; echo "WARNING: No deps.json found, defaulting to /app"; fi'`

	dllsDiscovered := frameworkDetected.Run(
		llb.Shlex(discoverDLLsCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Extract the detected framework version to use the correct SDK image
	frameworkVersionBytes, err := buildkit.ExtractFileFromState(ctx, dnm.config.Client, &dllsDiscovered, "/tmp/framework_version")
	if err != nil {
		log.Warnf("Could not extract framework version: %v, defaulting to 8.0", err)
		frameworkVersionBytes = []byte("8.0")
	}
	frameworkVersion := strings.TrimSpace(string(frameworkVersionBytes))
	if frameworkVersion == "" {
		frameworkVersion = "8.0"
	}

	// Use the detected framework version to select the appropriate SDK image
	sdkImage := fmt.Sprintf("mcr.microsoft.com/dotnet/sdk:%s", frameworkVersion)
	log.Infof("Using SDK image: %s (detected framework: %s)", sdkImage, frameworkVersion)

	// Build SDK image options - use target platform to ensure native deps match target architecture
	sdkImageOpts := []llb.ImageOption{
		llb.ResolveModePreferLocal,
		llb.WithMetaResolver(dnm.config.Client),
	}
	if dnm.config.Platform != nil {
		sdkImageOpts = append(sdkImageOpts, llb.Platform(*dnm.config.Platform))
		log.Infof("Running SDK container with target platform: %s/%s", dnm.config.Platform.OS, dnm.config.Platform.Architecture)
	}

	// Use the SDK image for patching - runs under target architecture via QEMU if needed
	sdkState := llb.Image(sdkImage, sdkImageOpts...)

	// Create minimal project file for patching - build it as a single complete file
	// Validate and escape all package names and versions before constructing XML
	var packageRefs strings.Builder
	for _, u := range updates {
		if u.FixedVersion != "" {
			// Validate package name and version to prevent XML injection
			if err := validateDotnetPackageName(u.Name); err != nil {
				log.Warnf("Skipping invalid package name: %v", err)
				continue
			}
			if err := validateDotnetVersion(u.FixedVersion); err != nil {
				log.Warnf("Skipping invalid version for package %s: %v", u.Name, err)
				continue
			}
			// Escape values for safe XML attribute usage (defense in depth)
			safeName := escapeXMLAttribute(u.Name)
			safeVersion := escapeXMLAttribute(u.FixedVersion)
			packageRefs.WriteString(fmt.Sprintf(`    <PackageReference Include="%s" Version="%s" />
`, safeName, safeVersion))
		}
	}

	// Convert framework version (e.g., "8.0.11") to TFM format (e.g., "net8.0")
	// Extract major.minor from the detected version for the TargetFramework
	tfmVersion := frameworkVersion
	parts := strings.Split(frameworkVersion, ".")
	if len(parts) >= 2 {
		tfmVersion = parts[0] + "." + parts[1]
	}
	targetFramework := fmt.Sprintf("net%s", tfmVersion)

	// Create complete project file in one command
	createProjectCmd := fmt.Sprintf(`sh -c 'mkdir -p /patch && cat > /patch/patch.csproj << "EOF"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>%s</TargetFramework>
    <OutputType>Library</OutputType>
  </PropertyGroup>
  <ItemGroup>
%s  </ItemGroup>
</Project>
EOF
cat /patch/patch.csproj'`, targetFramework, packageRefs.String())

	projectCreated := sdkState.Run(
		llb.Shlex(createProjectCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Restore and publish to extract the fixed DLLs
	restoreAndPublishCmd := `sh -c 'cd /patch && dotnet restore && dotnet publish -c Release -o /output'`
	publishedDLLs := projectCreated.Run(
		llb.Shlex(restoreAndPublishCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Copy the patched DLLs and native dependencies back to the runtime image
	// We need to read the app directory from the discovery state
	copyDLLsScript := `sh -c '
APP_DIR=$(cat /tmp/app_dir 2>/dev/null || echo "/app")
DEPS_FILE=$(cat /tmp/deps_file_path 2>/dev/null)
echo "Copying patched DLLs and native dependencies to $APP_DIR"

# Copy DLL files
cd /output
for dll in *.dll; do
	if [ -f "$dll" ] && [ "$dll" != "patch.dll" ]; then
		TARGET="$APP_DIR/$dll"
		if [ -f "$TARGET" ]; then
			echo "Replacing $dll in $APP_DIR"
			cp -f "$dll" "$TARGET"
		else
			echo "WARN: $dll not found in runtime image, skipping"
		fi
	fi
done

# Copy native dependencies if they exist (runtimes/ folder)
if [ -d "/output/runtimes" ]; then
	echo "Copying native dependencies from runtimes/ folder"
	if [ -d "$APP_DIR/runtimes" ]; then
		cp -rf /output/runtimes/* "$APP_DIR/runtimes/"
		echo "Native dependencies copied to $APP_DIR/runtimes/"
	else
		cp -rf /output/runtimes "$APP_DIR/"
		echo "Native dependencies folder created at $APP_DIR/runtimes/"
	fi
else
	echo "No native dependencies found (no runtimes/ folder)"
fi

echo "DLL patching complete"
'`

	// Mount the published DLLs and copy them to the runtime image
	// We need to merge the original image state with the discovery state to have /tmp files
	mergedState := llb.Merge([]llb.State{*imageState, dllsDiscovered})

	patchedState := mergedState.Run(
		llb.AddMount("/output", publishedDLLs, llb.SourcePath("/output"), llb.Readonly),
		llb.Shlex(copyDLLsScript),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Update deps.json to reflect patched versions
	updateDepsJsonScript := dnm.buildUpdateDepsJsonScript(updates)
	log.Debugf("deps.json update script length: %d characters", len(updateDepsJsonScript))
	log.Debugf("Number of updates to apply to deps.json: %d", len(updates))
	for _, u := range updates {
		log.Debugf("Update for deps.json: %s %s -> %s", u.Name, u.InstalledVersion, u.FixedVersion)
	}
	log.Debugf("Full deps.json update script:\n%s", updateDepsJsonScript)
	if len(updateDepsJsonScript) < 500 {
		log.Warnf("deps.json update script seems too short, may be missing sed commands")
	}
	depsUpdatedState := patchedState.Run(
		llb.Args([]string{"sh", "-c", updateDepsJsonScript}),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Generate validation output
	validateCmd := `sh -c 'APP_DIR=$(cat /tmp/app_dir 2>/dev/null || echo "/app"); ` +
		`echo "Runtime patching completed" > /tmp/validation.txt; ` +
		`echo "" >> /tmp/validation.txt; ` +
		`echo "Patched DLLs in $APP_DIR:" >> /tmp/validation.txt; ` +
		`ls -lh "$APP_DIR"/*.dll >> /tmp/validation.txt 2>&1 || echo "No DLLs found" >> /tmp/validation.txt; ` +
		`cat /tmp/validation.txt'`
	validatedState := depsUpdatedState.Run(
		llb.Shlex(validateCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Extract validation results
	mkFolders := validatedState.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true)))
	resultsWriteCmd := fmt.Sprintf(`sh -c 'cp /tmp/validation.txt %s/runtime_patch_results.txt'`,
		resultsPath)
	resultsWritten := mkFolders.Dir(resultsPath).Run(llb.Shlex(resultsWriteCmd)).Root()
	resultsDiff := llb.Diff(validatedState, resultsWritten)

	resultsBytes, err := buildkit.ExtractFileFromState(
		ctx, dnm.config.Client, &resultsDiff, filepath.Join(resultsPath, "runtime_patch_results.txt"))
	if err != nil {
		log.Warnf("Could not extract runtime patch results: %v", err)
		resultsBytes = []byte("Runtime patching completed (validation unavailable)")
	}

	log.Infof("Runtime patching completed - results bytes length: %d", len(resultsBytes))
	if len(resultsBytes) > 0 && len(resultsBytes) < 1000 {
		log.Infof("Runtime patch results: %s", string(resultsBytes))
	}

	return &validatedState, resultsBytes, nil
}

// buildUpdateDepsJsonScript creates a shell script to update deps.json with patched package versions.
func (dnm *dotnetManager) buildUpdateDepsJsonScript(updates unversioned.LangUpdatePackages) string {
	if len(updates) == 0 {
		return `echo "No updates to apply to deps.json"`
	}

	var script strings.Builder
	script.WriteString(`
DEPS_FILE=$(cat /tmp/deps_file_path 2>/dev/null)

if [ -z "$DEPS_FILE" ] || [ ! -f "$DEPS_FILE" ]; then
	echo "WARNING: deps.json file not found, skipping metadata update"
	exit 0
fi

echo "Updating deps.json: $DEPS_FILE"
echo "Original deps.json first line:"
head -1 "$DEPS_FILE"

# Check for multiple deps.json files and warn
DEPS_COUNT=$(cat /tmp/deps_count 2>/dev/null || echo "1")
if [ "$DEPS_COUNT" -gt 1 ]; then
	echo "WARNING: Found $DEPS_COUNT deps.json files in image - only updating first one ($DEPS_FILE)"
	echo "Multi-app container detected - other apps may still reference old versions"
fi

# Create backup
cp "$DEPS_FILE" "${DEPS_FILE}.backup"
echo "Backup created: ${DEPS_FILE}.backup"

`)

	// For each package update, add sed commands to replace version references
	for _, update := range updates {
		if update.InstalledVersion == "" || update.FixedVersion == "" {
			continue
		}

		packageName := update.Name
		oldVersion := update.InstalledVersion
		newVersion := update.FixedVersion

		// Escape dots for sed regex (only needed for old version pattern matching)
		oldVersionEscaped := strings.ReplaceAll(oldVersion, ".", "\\.")

		script.WriteString(fmt.Sprintf(`# Update %s from %s to %s
echo "Updating %s: %s -> %s"
echo "Before update:"
grep -c "%s/%s" "$DEPS_FILE" || echo "Pattern not found"
`, packageName, oldVersion, newVersion, packageName, oldVersion, newVersion, packageName, oldVersionEscaped))

		// Use a temp file approach for safer sed operations
		script.WriteString(fmt.Sprintf(`sed 's|"%s/%s"|"%s/%s"|g' "$DEPS_FILE" > "${DEPS_FILE}.tmp1" && mv "${DEPS_FILE}.tmp1" "$DEPS_FILE"
`, packageName, oldVersionEscaped, packageName, newVersion))

		script.WriteString(fmt.Sprintf(`sed 's|"%s":[[:space:]]*"%s"|"%s": "%s"|g' "$DEPS_FILE" > "${DEPS_FILE}.tmp2" && mv "${DEPS_FILE}.tmp2" "$DEPS_FILE"
`, packageName, oldVersionEscaped, packageName, newVersion))

		// Replace in libraries section path: "packagename/oldversion" -> "packagename/newversion" (lowercase)
		packageNameLower := strings.ToLower(packageName)
		script.WriteString(fmt.Sprintf(`sed 's|"%s/%s"|"%s/%s"|g' "$DEPS_FILE" > "${DEPS_FILE}.tmp3" && mv "${DEPS_FILE}.tmp3" "$DEPS_FILE"
`, packageNameLower, oldVersionEscaped, packageNameLower, newVersion))

		script.WriteString(fmt.Sprintf(`echo "After update:"
grep -c "%s/%s" "$DEPS_FILE" || echo "New pattern not found yet"
`, packageName, newVersion))
		script.WriteString("\n")
	}

	script.WriteString(`
echo "deps.json updated successfully"
echo "Verifying updates:"
`)

	for _, update := range updates {
		if update.FixedVersion != "" {
			script.WriteString(fmt.Sprintf(`grep -o '"%s/[0-9.]*"' "$DEPS_FILE" | head -1 || echo "  WARNING: %s not found in deps.json"
`, update.Name, update.Name))
		}
	}

	script.WriteString(`
echo "deps.json update complete"
`)

	return script.String()
}
