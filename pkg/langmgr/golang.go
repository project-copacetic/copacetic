package langmgr

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/provenance"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"
)

const (
	goInstallTimeoutSeconds = 600
	goCheckFile             = "/copa-go-check"
	goModDetectFile         = "/copa-go-mod-paths"
	goWorkDetectFile        = "/copa-go-work-path"
	goVendorDetectFile      = "/copa-go-vendor-check"
	goBinaryPathFile        = "/copa-go-binary-path"
	goBuildInfoFile         = "/copa-go-buildinfo"
	goVersionFile           = "/copa-go-version"
	defaultToolingGoTag     = "1.23-alpine"
	toolingGoTemplate       = "docker.io/library/golang:%s"
)

type golangManager struct {
	config        *buildkit.Config
	workingFolder string
}

// validateGoPackageName validates a Go module name for safety and correctness.
// Go module names are import paths that should contain at least one slash.
func validateGoPackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name cannot be empty")
	}

	// Skip "stdlib" - this represents Go standard library vulnerabilities
	// which can only be fixed by upgrading Go itself, not by updating dependencies
	if name == "stdlib" {
		return fmt.Errorf("stdlib vulnerabilities require Go version upgrade, not supported: %s", name)
	}

	// Go module names should contain at least one slash (e.g., github.com/user/repo)
	if !strings.Contains(name, "/") {
		return fmt.Errorf("invalid Go module name (must be an import path): %s", name)
	}

	// Check for shell injection characters
	if strings.ContainsAny(name, ";&|`$(){}[]<>\"'\\*?!~#") {
		return fmt.Errorf("package name contains unsafe characters: %s", name)
	}

	// Basic validation: module paths should not have spaces
	if strings.ContainsAny(name, " \t\n\r") {
		return fmt.Errorf("package name contains whitespace: %s", name)
	}

	return nil
}

// validateGoVersion validates a Go version string using semver rules.
// Go versions should follow semantic versioning (e.g., v1.2.3, v0.0.0-20230101120000-abcdef123456).
func validateGoVersion(version string) error {
	if version == "" {
		return fmt.Errorf("version cannot be empty")
	}

	// Ensure version has 'v' prefix for semver validation
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	if !semver.IsValid(version) {
		return fmt.Errorf("invalid Go version format: %s", version)
	}

	// Check for shell injection characters
	if strings.ContainsAny(version, ";&|`$(){}[]<>\"'\\*?!~#") {
		return fmt.Errorf("version contains unsafe characters: %s", version)
	}

	return nil
}

// isValidGoVersion checks if a version string is valid according to semver.
func isValidGoVersion(v string) bool {
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return semver.IsValid(v)
}

// isLessThanGoVersion compares two Go version strings using semver.
func isLessThanGoVersion(v1, v2 string) bool {
	if !strings.HasPrefix(v1, "v") {
		v1 = "v" + v1
	}
	if !strings.HasPrefix(v2, "v") {
		v2 = "v" + v2
	}
	return semver.Compare(v1, v2) < 0
}

// cleanGoVersion extracts the first valid version from a comma-separated list.
// This handles cases where Trivy returns multiple versions.
func cleanGoVersion(version string) string {
	if version == "" {
		return ""
	}

	// Handle comma-separated versions
	versions := strings.Split(version, ",")
	for _, v := range versions {
		v = strings.TrimSpace(v)
		if v != "" {
			// Ensure 'v' prefix
			if !strings.HasPrefix(v, "v") {
				v = "v" + v
			}
			if isValidGoVersion(v) {
				return v
			}
		}
	}

	return ""
}

// filterGoPackages filters for Go module and binary packages.
func filterGoPackages(langUpdates unversioned.LangUpdatePackages) unversioned.LangUpdatePackages {
	var goPackages unversioned.LangUpdatePackages
	for _, pkg := range langUpdates {
		if pkg.Type == utils.GoModules || pkg.Type == utils.GoBinary {
			// Skip stdlib - these are Go standard library vulnerabilities that
			// can only be fixed by upgrading Go itself, not by updating dependencies
			if pkg.Name == "stdlib" {
				log.Warnf("Skipping stdlib vulnerability (requires Go version upgrade): %s → %s", pkg.InstalledVersion, pkg.FixedVersion)
				continue
			}
			goPackages = append(goPackages, pkg)
		}
	}
	return goPackages
}

// InstallUpdates is the main entry point for patching Go module vulnerabilities.
// It handles both go.mod updates and binary rebuilding where possible.
func (gm *golangManager) InstallUpdates(
	ctx context.Context,
	currentState *llb.State,
	manifest *unversioned.UpdateManifest,
	ignoreErrors bool,
) (*llb.State, []string, error) {
	var errPkgsReported []string

	// Filter for Go packages only
	goUpdates := filterGoPackages(manifest.LangUpdates)
	if len(goUpdates) == 0 {
		log.Debug("No Go packages found to update.")
		return currentState, []string{}, nil
	}

	log.Infof("Found %d Go package updates to process", len(goUpdates))

	// Get unique latest updates using Go version comparer
	goComparer := VersionComparer{isValidGoVersion, isLessThanGoVersion}
	updatesToAttempt, err := GetUniqueLatestUpdates(goUpdates, goComparer, ignoreErrors)
	if err != nil {
		log.Errorf("Failed to determine unique latest Go updates: %v", err)
		for _, u := range goUpdates {
			errPkgsReported = append(errPkgsReported, u.Name)
		}
		if !ignoreErrors {
			return currentState, errPkgsReported, fmt.Errorf("failed to determine unique latest Go updates: %w", err)
		}
		log.Warn("Continuing despite errors in determining unique updates")
	}

	if len(updatesToAttempt) == 0 {
		log.Warn("No Go update packages were specified to apply after deduplication.")
		return currentState, []string{}, nil
	}

	log.Debugf("Attempting to update %d unique Go modules: %v", len(updatesToAttempt), getPackageNames(updatesToAttempt))

	// Validate all packages before attempting updates
	for _, u := range updatesToAttempt {
		if err := validateGoPackageName(u.Name); err != nil {
			log.Errorf("Invalid package name %s: %v", u.Name, err)
			errPkgsReported = append(errPkgsReported, u.Name)
			if !ignoreErrors {
				return currentState, errPkgsReported, fmt.Errorf("package name validation failed: %w", err)
			}
			continue
		}

		if u.FixedVersion != "" {
			// Clean version (handle comma-separated)
			cleanVersion := cleanGoVersion(u.FixedVersion)
			if cleanVersion == "" {
				log.Errorf("Could not extract valid version from %s for package %s", u.FixedVersion, u.Name)
				errPkgsReported = append(errPkgsReported, u.Name)
				if !ignoreErrors {
					return currentState, errPkgsReported, fmt.Errorf("version extraction failed for %s", u.Name)
				}
				continue
			}
			u.FixedVersion = cleanVersion

			if err := validateGoVersion(u.FixedVersion); err != nil {
				log.Errorf("Invalid version %s for package %s: %v", u.FixedVersion, u.Name, err)
				errPkgsReported = append(errPkgsReported, u.Name)
				if !ignoreErrors {
					return currentState, errPkgsReported, fmt.Errorf("version validation failed: %w", err)
				}
				continue
			}
		}
	}

	// Perform the upgrade
	updatedImageState, failedPkgs, upgradeErr := gm.upgradePackages(ctx, currentState, updatesToAttempt, ignoreErrors)
	if upgradeErr != nil {
		log.Errorf("Failed to upgrade Go packages: %v", upgradeErr)
		errPkgsReported = append(errPkgsReported, failedPkgs...)
		if !ignoreErrors {
			return currentState, errPkgsReported, fmt.Errorf("go package upgrade operation failed: %w", upgradeErr)
		}
		log.Warnf("Go package upgrade operation failed but errors are ignored.")
		return updatedImageState, errPkgsReported, nil
	}

	errPkgsReported = append(errPkgsReported, failedPkgs...)

	if len(errPkgsReported) > 0 {
		log.Infof("Go packages with issues: %v", errPkgsReported)
	} else {
		log.Info("All Go packages successfully updated.")
	}

	return updatedImageState, errPkgsReported, nil
}

// getPackageNames extracts package names from update packages for logging.
func getPackageNames(updates unversioned.LangUpdatePackages) []string {
	names := make([]string, len(updates))
	for i, u := range updates {
		names[i] = u.Name
	}
	return names
}

// detectGo checks if the Go toolchain is available in the target image.
func (gm *golangManager) detectGo(ctx context.Context, currentState *llb.State) (bool, error) {
	checkCmd := `sh -c 'if command -v go >/dev/null 2>&1; then echo ok > ` + goCheckFile + `; fi'`
	checked := currentState.Run(
		llb.Shlex(checkCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	_, err := buildkit.ExtractFileFromState(ctx, gm.config.Client, &checked, goCheckFile)
	if err != nil {
		log.Debugf("Go toolchain not found in image: %v", err)
		return false, nil
	}

	log.Debug("Go toolchain detected in target image")
	return true, nil
}

// detectGoModules searches for go.mod files in common Go project locations.
func (gm *golangManager) detectGoModules(ctx context.Context, currentState *llb.State) ([]string, error) {
	// Strategy: Check common locations first, then do a broader search if needed
	findCmd := `sh -c 'paths=""; ` +
		// First, check common locations for go.mod
		`for dir in /app /go/src /usr/src/app /workspace /src /opt/app; do ` +
		`if [ -f "$dir/go.mod" ]; then paths="$paths $dir"; fi; ` +
		`done; ` +
		// If no go.mod found in common locations, do a broader search
		`if [ -z "$paths" ]; then ` +
		`paths=$(find /app /go /usr /opt /workspace /src -maxdepth 5 -name "go.mod" 2>/dev/null | ` +
		`xargs -r dirname | sort -u | tr "\n" " "); ` +
		`fi; ` +
		`if [ -n "$paths" ]; then echo "$paths" > ` + goModDetectFile + `; fi'`

	detected := currentState.Run(
		llb.Shlex(findCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	pathBytes, err := buildkit.ExtractFileFromState(ctx, gm.config.Client, &detected, goModDetectFile)
	if err != nil {
		log.Debug("No go.mod files detected in image")
		return nil, nil
	}

	pathsStr := strings.TrimSpace(string(pathBytes))
	if pathsStr == "" {
		return nil, nil
	}

	paths := strings.Fields(pathsStr)
	log.Infof("Detected go.mod files in: %v", paths)
	return paths, nil
}

// detectGoWorkspace checks for go.work files (Go 1.18+ workspaces).
func (gm *golangManager) detectGoWorkspace(ctx context.Context, currentState *llb.State) (string, error) {
	findCmd := `sh -c 'for dir in /app /go/src /usr/src/app /workspace /src /opt/app; do ` +
		`if [ -f "$dir/go.work" ]; then echo "$dir" > ` + goWorkDetectFile + `; exit 0; fi; ` +
		`done'`

	detected := currentState.Run(
		llb.Shlex(findCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	pathBytes, err := buildkit.ExtractFileFromState(ctx, gm.config.Client, &detected, goWorkDetectFile)
	if err != nil {
		log.Debug("No go.work file detected")
		return "", nil
	}

	workPath := strings.TrimSpace(string(pathBytes))
	if workPath != "" {
		log.Infof("Detected go.work workspace at: %s", workPath)
	}
	return workPath, nil
}

// detectVendor checks if a vendor directory exists at the given module path.
func (gm *golangManager) detectVendor(ctx context.Context, currentState *llb.State, modPath string) (bool, error) {
	checkCmd := fmt.Sprintf(`sh -c 'if [ -d "%s/vendor" ]; then echo ok > %s; fi'`, modPath, goVendorDetectFile)
	checked := currentState.Run(
		llb.Shlex(checkCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	_, err := buildkit.ExtractFileFromState(ctx, gm.config.Client, &checked, goVendorDetectFile)
	if err != nil {
		return false, nil
	}

	log.Debugf("Vendor directory detected at %s/vendor", modPath)
	return true, nil
}

// detectGoVersion attempts to detect the Go version from the binary or go.mod.
func (gm *golangManager) detectGoVersion(ctx context.Context, currentState *llb.State) string {
	// Try to get Go version from 'go version' command
	versionCmd := `sh -c 'go version 2>/dev/null | grep -oP "go[0-9]+\.[0-9]+" | sed "s/go//" > ` + goVersionFile + `'`
	versionState := currentState.Run(
		llb.Shlex(versionCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	versionBytes, err := buildkit.ExtractFileFromState(ctx, gm.config.Client, &versionState, goVersionFile)
	if err == nil {
		version := strings.TrimSpace(string(versionBytes))
		if version != "" {
			log.Infof("Detected Go version: %s", version)
			return version
		}
	}

	log.Debug("Could not detect Go version, using default for tooling")
	// Extract version from default tooling tag (e.g., "1.23-alpine" -> "1.23")
	parts := strings.Split(defaultToolingGoTag, "-")
	return parts[0]
}

// upgradePackages handles the main upgrade logic, choosing between in-image and tooling strategies.
func (gm *golangManager) upgradePackages(
	ctx context.Context,
	currentState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, []string, error) {
	var failedPackages []string

	// Check if binary rebuilding is enabled (experimental feature)
	if gm.config.EnableGoBinaryPatch {
		log.Info("Go binary rebuilding is enabled (experimental)")
		rebuiltState, rebuildFailedPkgs, rebuildErr := gm.attemptBinaryRebuild(ctx, currentState, updates, ignoreErrors)
		if rebuildErr == nil {
			log.Info("Successfully rebuilt Go binaries with updated dependencies")
			return rebuiltState, rebuildFailedPkgs, nil
		}
		log.Warnf("Binary rebuild failed, falling back to go.mod/go.sum updates: %v", rebuildErr)
		// Continue with standard go.mod update approach as fallback
	}

	// Detect if Go toolchain exists in the target image
	goExists, err := gm.detectGo(ctx, currentState)
	if err != nil {
		log.Warnf("Go detection encountered an issue; proceeding assuming Go absent: %v", err)
		goExists = false
	}

	if !goExists {
		log.Info("Go toolchain not found in target image. Using tooling container strategy.")
		return gm.upgradePackagesWithTooling(ctx, currentState, updates, ignoreErrors)
	}

	log.Info("Go toolchain found in target image. Updating modules in-place.")

	// Detect go.mod locations
	goModPaths, err := gm.detectGoModules(ctx, currentState)
	if err != nil || len(goModPaths) == 0 {
		log.Warn("No go.mod files detected in image")
		if !ignoreErrors {
			for _, u := range updates {
				failedPackages = append(failedPackages, u.Name)
			}
			return currentState, failedPackages, fmt.Errorf("no Go modules found to patch")
		}
		return currentState, failedPackages, nil
	}

	// Check for workspace
	workspacePath, _ := gm.detectGoWorkspace(ctx, currentState)

	state := *currentState

	// If workspace exists, update from workspace root
	if workspacePath != "" {
		log.Infof("Updating Go workspace at %s", workspacePath)
		state, err = gm.updateGoModule(ctx, &state, workspacePath, updates, true, ignoreErrors)
		if err != nil {
			log.Errorf("Failed to update workspace: %v", err)
			if !ignoreErrors {
				for _, u := range updates {
					failedPackages = append(failedPackages, u.Name)
				}
				return currentState, failedPackages, err
			}
		}
	} else {
		// Update each module independently
		for _, modPath := range goModPaths {
			log.Infof("Updating Go module at %s", modPath)
			newState, modErr := gm.updateGoModule(ctx, &state, modPath, updates, false, ignoreErrors)
			if modErr != nil {
				log.Errorf("Failed to update module at %s: %v", modPath, modErr)
				if !ignoreErrors {
					for _, u := range updates {
						failedPackages = append(failedPackages, u.Name)
					}
					return currentState, failedPackages, modErr
				}
				continue
			}
			state = newState
		}
	}

	return &state, failedPackages, nil
}

// attemptBinaryRebuild attempts to rebuild Go binaries using heuristic binary detection.
func (gm *golangManager) attemptBinaryRebuild(
	ctx context.Context,
	currentState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, []string, error) {
	var failedPackages []string

	log.Info("Attempting Go binary rebuild via heuristic detection")

	// Create rebuilder and detector
	rebuilder := provenance.NewRebuilder()
	detector := provenance.NewDetector()

	// Initialize rebuild context
	rebuildCtx := &provenance.RebuildContext{
		Strategy: provenance.RebuildStrategyNone,
	}

	// Detect Go binaries using go version -m
	binaries, detectErr := detector.DetectGoBinaries(ctx, gm.config.Client, currentState)
	if detectErr != nil {
		log.Debugf("Binary detection failed: %v", detectErr)
	} else if len(binaries) > 0 {
		log.Infof("Detected %d Go binaries via go version -m", len(binaries))

		// Log what we found
		for _, bi := range binaries {
			log.Infof("  Found: %s (%s, %d deps)", bi.Path, bi.GoVersion, len(bi.Dependencies))
			if cgo, ok := bi.BuildSettings["CGO_ENABLED"]; ok {
				log.Debugf("    CGO_ENABLED=%s", cgo)
			}
			if ldflags, ok := bi.BuildSettings["-ldflags"]; ok {
				log.Debugf("    ldflags=%s", ldflags)
			}
		}

		// Convert binary info to build info
		rebuildCtx.BinaryInfo = binaries
		rebuildCtx.BuildInfo = detector.ConvertBinaryInfoToBuildInfo(binaries[0])
		rebuildCtx.Strategy = provenance.RebuildStrategyHeuristic
	}

	// Check if we have enough information to rebuild
	if rebuildCtx.Strategy == provenance.RebuildStrategyNone {
		return currentState, failedPackages, fmt.Errorf("no Go binaries detected in image")
	}

	// Log what information we have
	if rebuildCtx.BuildInfo != nil {
		log.Infof("Build info: Go %s, module: %s, CGO: %v",
			rebuildCtx.BuildInfo.GoVersion,
			rebuildCtx.BuildInfo.ModulePath,
			rebuildCtx.BuildInfo.CGOEnabled)
	}

	log.Infof("Using rebuild strategy: %s", rebuildCtx.Strategy)

	// Convert updates to module->version map
	// Filter out packages that have complex dependency management
	updateMap := make(map[string]string)
	for _, update := range updates {
		if update.FixedVersion == "" {
			log.Debugf("Skipping %s: no fixed version available", update.Name)
			continue
		}

		// k8s.io/kubernetes has hundreds of replace directives and requires
		// careful version coordination - skip for now
		if strings.HasPrefix(update.Name, "k8s.io/kubernetes") {
			log.Warnf("Skipping %s: k8s.io/kubernetes requires careful version coordination", update.Name)
			continue
		}

		updateMap[update.Name] = update.FixedVersion
		log.Infof("Will update %s to %s", update.Name, update.FixedVersion)
	}

	if len(updateMap) == 0 {
		return currentState, failedPackages, fmt.Errorf("no version updates to apply")
	}

	// Attempt to rebuild binary
	newState, result, err := rebuilder.RebuildBinary(rebuildCtx, updateMap)
	if err != nil {
		for module := range updateMap {
			failedPackages = append(failedPackages, module)
		}
		return currentState, failedPackages, fmt.Errorf("binary rebuild failed: %w", err)
	}

	if !result.Success {
		for module := range updateMap {
			failedPackages = append(failedPackages, module)
		}
		return currentState, failedPackages, fmt.Errorf("binary rebuild unsuccessful: %v", result.Error)
	}

	log.Infof("Binary rebuild successful: %d binaries rebuilt", result.BinariesRebuilt)
	return &newState, failedPackages, nil
}

// updateGoModule updates a single Go module or workspace.
func (gm *golangManager) updateGoModule(
	ctx context.Context,
	currentState *llb.State,
	modPath string,
	updates unversioned.LangUpdatePackages,
	isWorkspace bool,
	ignoreErrors bool,
) (llb.State, error) {
	state := *currentState

	// Build list of 'go get' commands
	var getCommands []string
	for _, u := range updates {
		if u.FixedVersion != "" {
			// Ensure version has 'v' prefix
			version := u.FixedVersion
			if !strings.HasPrefix(version, "v") {
				version = "v" + version
			}
			spec := fmt.Sprintf("%s@%s", u.Name, version)
			getCommands = append(getCommands, fmt.Sprintf("go get %s", spec))
		} else {
			log.Warnf("No fixed version for %s, skipping", u.Name)
		}
	}

	if len(getCommands) == 0 {
		log.Debug("No package updates to apply")
		return state, nil
	}

	// Execute all 'go get' commands
	allGetCmd := strings.Join(getCommands, " && ")

	// Add 'go mod tidy' after updates
	updateCmd := fmt.Sprintf(`sh -c 'cd %s && %s && go mod tidy'`, modPath, allGetCmd)

	log.Debugf("Executing Go module updates: %s", updateCmd)

	state = state.Run(
		llb.Shlex(updateCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Check for vendor directory and update if present
	hasVendor, _ := gm.detectVendor(ctx, &state, modPath)
	if hasVendor {
		log.Infof("Vendor directory detected, running 'go mod vendor' at %s", modPath)
		vendorCmd := fmt.Sprintf(`sh -c 'cd %s && go mod vendor'`, modPath)
		state = state.Run(
			llb.Shlex(vendorCmd),
			llb.WithProxy(utils.GetProxy()),
		).Root()
	}

	// TODO: Handle binary rebuilding
	// This would require:
	// 1. Detecting binary locations from vulnerability PkgPath
	// 2. Extracting buildinfo using 'go version -m'
	// 3. Determining main package location
	// 4. Running 'go build' with appropriate flags
	// For now, we log a warning about binaries not being rebuilt

	log.Warn("Note: Go binaries are not automatically rebuilt. Updated go.mod/go.sum only.")

	return state, nil
}

// upgradePackagesWithTooling handles Go module updates when the Go toolchain is not in the target image.
// This uses a golang:alpine tooling container to perform the updates.
func (gm *golangManager) upgradePackagesWithTooling(
	ctx context.Context,
	currentState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, []string, error) {
	var failedPackages []string

	// Detect go.mod locations
	goModPaths, err := gm.detectGoModules(ctx, currentState)
	if err != nil || len(goModPaths) == 0 {
		log.Warn("No go.mod files detected in image for tooling container strategy")
		if !ignoreErrors {
			for _, u := range updates {
				failedPackages = append(failedPackages, u.Name)
			}
			return currentState, failedPackages, fmt.Errorf("no Go modules found to patch")
		}
		return currentState, failedPackages, nil
	}

	// Detect Go version (or use default)
	goVersion := gm.detectGoVersion(ctx, currentState)
	toolingImage := fmt.Sprintf(toolingGoTemplate, goVersion+"-alpine")

	log.Infof("Using tooling container: %s", toolingImage)

	state := *currentState

	// Process each module path
	for _, modPath := range goModPaths {
		log.Infof("Updating Go module at %s using tooling container", modPath)

		// Create tooling container state
		toolingState := llb.Image(toolingImage)

		// Copy go.mod, go.sum, and go.work if exists from target to tooling
		toolingState = toolingState.File(
			llb.Copy(state, modPath+"/go.mod", "/workspace/go.mod", &llb.CopyInfo{
				CreateDestPath: true,
			}),
		)

		// Copy go.sum if it exists
		copyGoSum := llb.Copy(state, modPath+"/go.sum", "/workspace/go.sum", &llb.CopyInfo{
			AllowWildcard:  true,
			CreateDestPath: true,
		})
		toolingState = toolingState.File(copyGoSum)

		// Build update commands
		var getCommands []string
		for _, u := range updates {
			if u.FixedVersion != "" {
				version := u.FixedVersion
				if !strings.HasPrefix(version, "v") {
					version = "v" + version
				}
				spec := fmt.Sprintf("%s@%s", u.Name, version)
				getCommands = append(getCommands, fmt.Sprintf("go get %s", spec))
			}
		}

		if len(getCommands) == 0 {
			continue
		}

		allGetCmd := strings.Join(getCommands, " && ")
		updateCmd := fmt.Sprintf(`sh -c 'cd /workspace && %s && go mod tidy'`, allGetCmd)

		log.Debugf("Executing in tooling container: %s", updateCmd)

		toolingState = toolingState.Dir("/workspace").Run(
			llb.Shlex(updateCmd),
			llb.WithProxy(utils.GetProxy()),
		).Root()

		// Check if vendor exists in original and update if so
		hasVendor, _ := gm.detectVendor(ctx, &state, modPath)
		if hasVendor {
			log.Info("Vendor directory detected, running 'go mod vendor' in tooling container")
			vendorCmd := `sh -c 'cd /workspace && go mod vendor'`
			toolingState = toolingState.Dir("/workspace").Run(
				llb.Shlex(vendorCmd),
				llb.WithProxy(utils.GetProxy()),
			).Root()

			// Copy vendor directory back
			state = state.File(
				llb.Copy(toolingState, "/workspace/vendor", modPath+"/vendor", &llb.CopyInfo{
					CopyDirContentsOnly: true,
					CreateDestPath:      true,
				}),
			)
		}

		// Copy updated go.mod and go.sum back to target
		state = state.File(
			llb.Copy(toolingState, "/workspace/go.mod", modPath+"/go.mod", &llb.CopyInfo{}),
		)
		state = state.File(
			llb.Copy(toolingState, "/workspace/go.sum", modPath+"/go.sum", &llb.CopyInfo{
				AllowWildcard: true,
			}),
		)
	}

	log.Warn("Note: Go binaries are not automatically rebuilt in tooling container strategy. Updated go.mod/go.sum only.")

	return &state, failedPackages, nil
}
