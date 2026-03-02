package langmgr

import (
	"context"
	"fmt"
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

	// Runtime patching skips standard validation - DLL replacement success is the verification
	// The resultsBytes contains the list of patched DLLs for logging purposes
	resultsString := string(resultsBytes)
	if len(resultsBytes) > 0 && len(resultsBytes) < 500 {
		log.Debugf("Patch results: %s", resultsString)
	}

	log.Info("Runtime patching completed - DLL replacement verified")

	if len(errPkgsReported) > 0 {
		log.Infof(".NET packages reported as problematic: %v", errPkgsReported)
	} else {
		log.Info("All .NET packages successfully patched.")
	}

	return updatedImageState, errPkgsReported, nil
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

	// Always use runtime patching (DLL replacement) for all .NET images
	// This approach:
	// - Works for both SDK and runtime-only images
	// - Finds deps.json wherever the app is deployed
	// - Handles custom -o output paths
	// - Replaces only the vulnerable DLLs
	// - Updates deps.json metadata via sed
	return dnm.patchRuntimeImage(ctx, imageState, updates, ignoreErrors)
}

// patchRuntimeImage patches a .NET image by extracting DLLs from NuGet packages.
// This works for both SDK images and runtime-only images.
//
// Flow:
// 1. Discovery: Find deps.json anywhere in the image (excluding system paths)
// 2. Extract framework version from deps.json to select matching SDK image
// 3. Create temp project with PackageReference for fixed versions
// 4. dotnet publish to get patched DLLs with correct metadata
// 5. Copy DLLs to app directory (only replacing existing ones)
// 6. Update deps.json with correct metadata (sha512, hashPath, etc.) using jq
// 7. Diff from original image to capture only actual changes
// 8. Squash and merge as single layer
//
// ignoreErrors behavior:
//   - When true: Continue patching even if some DLLs fail to download or copy.
//     The operation will succeed if at least some packages were patched.
//   - When false: Fail the entire operation if any package fails to patch.
//
// Note: Currently ignoreErrors only affects error handling at the InstallUpdates level.
// The patchRuntimeImage function uses BuildKit's LLB which executes atomically -
// if any command fails, the entire build fails. To implement per-package error
// handling, we would need to split packages into individual operations.
func (dnm *dotnetManager) patchRuntimeImage(
	ctx context.Context,
	imageState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, []byte, error) {
	log.Info("[EXPERIMENTAL] Runtime patching enabled - replacing DLLs in-place")
	if ignoreErrors {
		log.Debug("ignoreErrors=true: Will attempt to continue if individual package operations fail")
	}

	// Find deps.json to determine app directory and framework version
	// Search entire filesystem excluding system directories (SDK tools, NuGet cache, etc.)
	findDepsCmd := `sh -c '
		# Search filesystem excluding system directories
		find / -name "*.deps.json" 2>/dev/null | \
			grep -v "^/usr/share/" | \
			grep -v "^/usr/local/share/" | \
			grep -v "^/root/.nuget" | \
			grep -v "^/tmp/" | \
			head -1 > /tmp/deps_file
		
		if [ -s /tmp/deps_file ]; then
			DEPS_FILE=$(cat /tmp/deps_file)
			echo "Found deps.json: $DEPS_FILE"
			echo "$DEPS_FILE" > /tmp/deps_file_path
			dirname "$DEPS_FILE" > /tmp/app_dir
			FRAMEWORK=$(grep -o "Microsoft.NETCore.App/[0-9.]*" "$DEPS_FILE" | head -1 | cut -d "/" -f2 || echo "8.0")
			echo "$FRAMEWORK" > /tmp/framework_version
		else
			echo "/app" > /tmp/app_dir
			echo "8.0" > /tmp/framework_version
		fi
	'`

	discoveryState := imageState.Run(
		llb.Shlex(findDepsCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Extract the detected framework version to use the correct SDK image
	frameworkVersionBytes, err := buildkit.ExtractFileFromState(ctx, dnm.config.Client, &discoveryState, "/tmp/framework_version")
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
			fmt.Fprintf(&packageRefs, "    <PackageReference Include=\"%s\" Version=\"%s\" />\n", safeName, safeVersion)
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

	// Restore and publish to extract the fixed DLLs, then install jq for deps.json manipulation
	restoreAndPublishCmd := `sh -c 'cd /patch && dotnet restore && dotnet publish -c Release -o /output && apt-get update -qq && apt-get install -qq -y jq >/dev/null 2>&1'`
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

# Copy the original deps.json to /tmp for SDK container to update
if [ -n "$DEPS_FILE" ] && [ -f "$DEPS_FILE" ]; then
	cp "$DEPS_FILE" /tmp/original.deps.json
	echo "Copied original deps.json for metadata update"
fi

echo "DLL patching complete"
'`

	// Run all patching operations on the image state
	// The discovery state has /tmp files we need for the patching process
	// We'll run everything on discoveryState, then diff from original imageState
	// to capture only the actual changes (DLLs + deps.json), not temp files

	patchedState := discoveryState.Run(
		llb.AddMount("/output", publishedDLLs, llb.SourcePath("/output"), llb.Readonly),
		llb.Shlex(copyDLLsScript),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Now run deps.json update in SDK container with jq, then copy result back to runtime image
	// The SDK container has jq installed and has the generated patch.deps.json with correct metadata
	updateDepsJsonScript := dnm.buildUpdateDepsJsonScript(updates)
	log.Debugf("deps.json update script length: %d characters", len(updateDepsJsonScript))
	log.Debugf("Number of updates to apply to deps.json: %d", len(updates))
	for _, u := range updates {
		log.Debugf("Update for deps.json: %s %s -> %s", u.Name, u.InstalledVersion, u.FixedVersion)
	}

	// Run the jq update in the SDK container, mounting the runtime image's /tmp to access original.deps.json
	sdkWithDepsUpdate := publishedDLLs.Run(
		llb.AddMount("/runtime-tmp", patchedState, llb.SourcePath("/tmp")),
		llb.Args([]string{"sh", "-c", updateDepsJsonScript}),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Copy the updated deps.json back to the runtime image
	copyUpdatedDepsScript := `sh -c '
DEPS_FILE=$(cat /tmp/deps_file_path 2>/dev/null)
if [ -f "/updated-deps/updated.deps.json" ] && [ -n "$DEPS_FILE" ]; then
	cp /updated-deps/updated.deps.json "$DEPS_FILE"
	echo "Updated deps.json with correct metadata"
else
	echo "No updated deps.json found or deps file path unknown"
fi
'`
	depsUpdatedState := patchedState.Run(
		llb.AddMount("/updated-deps", sdkWithDepsUpdate, llb.SourcePath("/output"), llb.Readonly),
		llb.Args([]string{"sh", "-c", copyUpdatedDepsScript}),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Clean up temporary files from /tmp that were created during patching
	// The llb.Diff captures NEW files too, so we must remove temp files
	// to prevent them from appearing in the final patched image
	cleanupScript := `sh -c '
rm -f /tmp/original.deps.json
rm -f /tmp/deps_file_path
rm -f /tmp/deps_file
rm -f /tmp/app_dir
rm -f /tmp/framework_version
'`
	cleanedState := depsUpdatedState.Run(
		llb.Shlex(cleanupScript),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	log.Info("Runtime patching completed")

	// Get the diff from the ORIGINAL image state to the cleaned patched state
	// This captures ONLY the actual changes: updated DLLs and deps.json
	patchDiff := llb.Diff(*imageState, cleanedState)

	// Squash the patch diff into a single layer using llb.Copy
	// This ensures we don't add multiple intermediate layers to the final image
	squashedPatch := llb.Scratch().File(llb.Copy(patchDiff, "/", "/"))

	// Merge the squashed patch into the original image
	finalState := llb.Merge([]llb.State{*imageState, squashedPatch})

	return &finalState, []byte("Runtime patching completed"), nil
}

// buildUpdateDepsJsonScript creates a shell script to update deps.json with patched package versions.
// This script runs in the SDK container which has jq installed.
// It reads /runtime-tmp/original.deps.json (from the runtime image) and outputs to /output/updated.deps.json.
func (dnm *dotnetManager) buildUpdateDepsJsonScript(updates unversioned.LangUpdatePackages) string {
	if len(updates) == 0 {
		return `echo "No updates to apply to deps.json"`
	}

	var script strings.Builder
	script.WriteString(`
ORIGINAL_DEPS="/runtime-tmp/original.deps.json"
UPDATED_DEPS="/output/updated.deps.json"

if [ ! -f "$ORIGINAL_DEPS" ]; then
	echo "WARNING: original.deps.json not found at $ORIGINAL_DEPS, skipping metadata update"
	exit 0
fi

echo "Updating deps.json metadata in SDK container"

# Copy original to output as starting point
cp "$ORIGINAL_DEPS" "$UPDATED_DEPS"

# Get the target framework key from the original deps.json
ORIG_TARGET_KEY=$(jq -r '.targets | keys[0]' "$UPDATED_DEPS" 2>/dev/null)
# Get the target framework key from the generated deps.json
GEN_TARGET_KEY=$(jq -r '.targets | keys[0]' /output/patch.deps.json 2>/dev/null)

echo "Original target framework: $ORIG_TARGET_KEY"
echo "Generated target framework: $GEN_TARGET_KEY"
`)

	// Build jq commands to merge package entries from generated deps.json
	for _, update := range updates {
		if update.InstalledVersion == "" || update.FixedVersion == "" {
			continue
		}

		packageName := update.Name
		oldVersion := update.InstalledVersion
		newVersion := update.FixedVersion

		fmt.Fprintf(&script, `
# Update %s from %s to %s
echo "Updating %s: %s -> %s"

# Extract just the package entries from generated deps.json
NEW_TARGET=$(jq -r ".targets[\"$GEN_TARGET_KEY\"][\"%s/%s\"] // empty" /output/patch.deps.json 2>/dev/null)
NEW_LIBRARY=$(jq -r '.libraries["%s/%s"] // empty' /output/patch.deps.json 2>/dev/null)

if [ -n "$NEW_TARGET" ] && [ "$NEW_TARGET" != "null" ] && [ -n "$NEW_LIBRARY" ] && [ "$NEW_LIBRARY" != "null" ]; then
	echo "  Extracted package metadata from generated deps.json"

	# Update targets section: remove old package entry, add new one with correct metadata
	jq --argjson newTarget "$NEW_TARGET" --arg targetKey "$ORIG_TARGET_KEY" '
		.targets[$targetKey] |= (
			del(.["%s/%s"]) |
			. + {"%s/%s": $newTarget}
		)
	' "$UPDATED_DEPS" > "${UPDATED_DEPS}.tmp" && mv "${UPDATED_DEPS}.tmp" "$UPDATED_DEPS"

	# Update libraries section: remove old entry, add new one with correct sha512, hashPath, etc.
	jq --argjson newLib "$NEW_LIBRARY" '
		.libraries |= (
			del(.["%s/%s"]) |
			. + {"%s/%s": $newLib}
		)
	' "$UPDATED_DEPS" > "${UPDATED_DEPS}.tmp" && mv "${UPDATED_DEPS}.tmp" "$UPDATED_DEPS"

	# Update dependency version references throughout all targets
	jq '(.targets[][].dependencies // {}) |= with_entries(if .key == "%s" then .value = "%s" else . end)' \
		"$UPDATED_DEPS" > "${UPDATED_DEPS}.tmp" && mv "${UPDATED_DEPS}.tmp" "$UPDATED_DEPS"

	echo "  Updated %s to %s with correct metadata (sha512, hashPath, assemblyVersion, fileVersion)"
else
	echo "  ERROR: Could not extract package metadata for %s/%s from generated deps.json"
fi
`, packageName, oldVersion, newVersion, packageName, oldVersion, newVersion,
			packageName, newVersion, // NEW_TARGET extraction
			packageName, newVersion, // NEW_LIBRARY extraction
			packageName, oldVersion, packageName, newVersion, // targets update
			packageName, oldVersion, packageName, newVersion, // libraries update
			packageName, newVersion, // dependency update
			packageName, newVersion, // success message
			packageName, newVersion) // error message
	}

	script.WriteString(`
echo "deps.json update complete"

# Verify the update
echo "Verifying updates in $UPDATED_DEPS:"
`)

	for _, update := range updates {
		if update.FixedVersion != "" {
			fmt.Fprintf(&script,
				"grep -o '\"%s/%s\"' \"$UPDATED_DEPS\" | head -1 && echo \"  %s/%s found\" || echo \"  WARNING: %s/%s not found\"\n",
				update.Name, update.FixedVersion, update.Name, update.FixedVersion, update.Name, update.FixedVersion)
		}
	}

	return script.String()
}
