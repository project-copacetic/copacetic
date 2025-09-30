package langmgr

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const (
	npmInstallTimeoutSeconds    = 600
	npmCheckFile                = "/copa-npm-check"
	packageJSONDetectFile       = "/copa-package-json-path"
	globalNodeModulesDetectFile = "/copa-global-node-modules-path"
	defaultToolingNodeTag       = "18-alpine" // fallback tooling image tag if version can't be inferred
	toolingNodeTemplate         = "docker.io/library/node:%s"
)

type nodejsManager struct {
	config        *buildkit.Config
	workingFolder string
}

// validNodePackageNamePattern defines the regex pattern for valid npm package names
// Based on npm package naming rules: https://docs.npmjs.com/cli/v7/configuring-npm/package-json#name
var validNodePackageNamePattern = regexp.MustCompile(`^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$`)

// validateNodePackageName validates that a package name is safe for use in shell commands.
func validateNodePackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name cannot be empty")
	}
	if len(name) > 214 {
		return fmt.Errorf("package name too long (max 214 characters)")
	}
	if !validNodePackageNamePattern.MatchString(name) {
		return fmt.Errorf("invalid package name format: %s", name)
	}
	// Additional safety checks for shell injection
	if strings.ContainsAny(name, ";&|`$(){}[]<>\"'\\") {
		return fmt.Errorf("package name contains unsafe characters: %s", name)
	}
	return nil
}

// validateNodeVersion validates that a version string is safe for use in shell commands.
func validateNodeVersion(version string) error {
	if version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	// Check if it's a valid semver version
	if !isValidNodeVersion(version) {
		return fmt.Errorf("invalid version format: %s", version)
	}
	// Additional safety checks for shell injection
	if strings.ContainsAny(version, ";&|`$(){}[]<>\"'\\") {
		return fmt.Errorf("version contains unsafe characters: %s", version)
	}
	return nil
}

// isValidNodeVersion checks if a version string is a valid semver version.
func isValidNodeVersion(v string) bool {
	// Remove any leading 'v'
	v = strings.TrimPrefix(v, "v")
	_, err := semver.NewVersion(v)
	return err == nil
}

// isLessThanNodeVersion compares two semver version strings.
// It returns true if v1 is less than v2, and false if there's an error.
func isLessThanNodeVersion(v1, v2 string) bool {
	// Remove any leading 'v'
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	ver1, err1 := semver.NewVersion(v1)
	if err1 != nil {
		log.Warnf("Error parsing Node version '%s': %v", v1, err1)
		return false
	}
	ver2, err2 := semver.NewVersion(v2)
	if err2 != nil {
		log.Warnf("Error parsing Node version '%s': %v", v2, err2)
		return false
	}
	return ver1.LessThan(ver2)
}

// filterNodePackages returns only the packages that are Node.js packages.
func filterNodePackages(langUpdates unversioned.LangUpdatePackages) unversioned.LangUpdatePackages {
	var nodePackages unversioned.LangUpdatePackages
	for _, pkg := range langUpdates {
		if pkg.Type == utils.NodePackages {
			nodePackages = append(nodePackages, pkg)
		}
	}
	return nodePackages
}

// InstallUpdates installs Node.js package updates using npm.
func (nm *nodejsManager) InstallUpdates(
	ctx context.Context,
	currentState *llb.State,
	manifest *unversioned.UpdateManifest,
	ignoreErrors bool,
) (*llb.State, []string, error) {
	var errPkgsReported []string

	// Filter for Node.js packages only
	nodeUpdates := filterNodePackages(manifest.LangUpdates)
	if len(nodeUpdates) == 0 {
		log.Debug("No Node.js packages found to update.")
		return currentState, []string{}, nil
	}

	nodeComparer := VersionComparer{isValidNodeVersion, isLessThanNodeVersion}
	updatesToAttempt, err := GetUniqueLatestUpdates(nodeUpdates, nodeComparer, ignoreErrors)
	if err != nil {
		for _, u := range nodeUpdates {
			errPkgsReported = append(errPkgsReported, u.Name)
		}
		return currentState, errPkgsReported, fmt.Errorf("failed to determine unique latest Node updates: %w", err)
	}

	if len(updatesToAttempt) == 0 {
		log.Warn("No Node.js update packages were specified to apply.")
		return currentState, []string{}, nil
	}
	log.Debugf("Attempting to update latest unique npm packages: %v", updatesToAttempt)

	// Perform the upgrade
	updatedImageState, upgradeErr := nm.upgradePackages(ctx, currentState, updatesToAttempt, ignoreErrors)
	if upgradeErr != nil {
		log.Errorf("Failed to upgrade Node.js packages: %v", upgradeErr)
		if !ignoreErrors {
			for _, u := range updatesToAttempt {
				errPkgsReported = append(errPkgsReported, u.Name)
			}
			return currentState, errPkgsReported, fmt.Errorf("nodejs package upgrade operation failed: %w", upgradeErr)
		}
		log.Warnf("Node.js package upgrade operation failed but errors are ignored.")
		for _, u := range updatesToAttempt {
			errPkgsReported = append(errPkgsReported, u.Name)
		}
		return currentState, errPkgsReported, nil
	}

	if len(errPkgsReported) > 0 {
		log.Infof("Node.js packages reported as problematic: %v", errPkgsReported)
	} else {
		log.Info("All Node.js packages successfully updated.")
	}

	return updatedImageState, errPkgsReported, nil
}

func (nm *nodejsManager) upgradePackages(
	ctx context.Context,
	currentState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, error) {
	// Validate all package names and versions first
	for _, u := range updates {
		if err := validateNodePackageName(u.Name); err != nil {
			log.Errorf("Invalid package name %s: %v", u.Name, err)
			if !ignoreErrors {
				return nil, fmt.Errorf("package name validation failed for %s: %w", u.Name, err)
			}
			continue
		}

		if u.FixedVersion != "" {
			if err := validateNodeVersion(u.FixedVersion); err != nil {
				log.Errorf("Invalid version %s for package %s: %v", u.FixedVersion, u.Name, err)
				if !ignoreErrors {
					return nil, fmt.Errorf("version validation failed for %s: %w", u.Name, err)
				}
				continue
			}
		}
	}

	// Detect if npm exists in the target image
	npmExists, detectErr := nm.detectNpm(ctx, currentState)
	if detectErr != nil {
		log.Warnf("npm detection encountered an issue; proceeding assuming npm absent: %v", detectErr)
	}

	if !npmExists {
		log.Infof("npm not found in target image. Falling back to tooling container strategy for Node.js updates.")
		return nm.upgradePackagesWithTooling(ctx, currentState, updates, ignoreErrors)
	}

	// Detect package.json locations in the target image
	pkgJSONPaths, detectErr := nm.detectPackageJSON(ctx, currentState)
	hasUserApp := detectErr == nil && len(pkgJSONPaths) > 0

	updatedState := *currentState

	if hasUserApp {
		log.Infof("Detected package.json locations: %v", pkgJSONPaths)

		// Install updates for each package.json location
		for _, pkgPath := range pkgJSONPaths {
			log.Infof("Updating packages in %s", pkgPath)
			updatedState = nm.installNodePackages(&updatedState, pkgPath, updates, ignoreErrors)
		}
	} else {
		log.Warnf("No user Node.js applications detected in image (no package.json found in app directories)")
	}

	// Always check for and patch globally installed npm packages (when npm exists)
	log.Info("Checking for globally installed Node.js packages with vulnerable dependencies...")
	globalPatchedState, globalErr := nm.upgradeGlobalPackages(ctx, &updatedState, updates, ignoreErrors)
	if globalErr != nil {
		if !ignoreErrors {
			return nil, fmt.Errorf("failed to patch global packages: %w", globalErr)
		}
		log.Warnf("Failed to patch global packages but continuing due to ignore-errors: %v", globalErr)
	} else {
		updatedState = *globalPatchedState
	}

	return &updatedState, nil
}

// installNodePackages installs Node.js packages in a specific directory.
func (nm *nodejsManager) installNodePackages(
	currentState *llb.State,
	workDir string,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) llb.State {
	if len(updates) == 0 {
		return *currentState
	}

	state := *currentState

	if ignoreErrors {
		// Install each package individually with error handling
		for _, u := range updates {
			if u.FixedVersion == "" {
				continue
			}
			pkgSpec := fmt.Sprintf("%s@%s", u.Name, u.FixedVersion)
			installCmd := fmt.Sprintf(
				`sh -c 'cd %s && npm install --save --save-exact --no-audit --loglevel=error --timeout=%d "%s" || printf "WARN: npm install failed for %s\n"'`,
				workDir, npmInstallTimeoutSeconds, pkgSpec, u.Name)
			state = state.Run(
				llb.Shlex(installCmd),
				llb.WithProxy(utils.GetProxy()),
			).Root()
		}
	} else {
		// Install all packages in a single command
		var pkgSpecs []string
		for _, u := range updates {
			if u.FixedVersion != "" {
				pkgSpecs = append(pkgSpecs, fmt.Sprintf("%s@%s", u.Name, u.FixedVersion))
			}
		}
		if len(pkgSpecs) > 0 {
			installCmd := fmt.Sprintf(
				`sh -c 'cd %s && npm install --save --save-exact --no-audit --loglevel=error --timeout=%d %s'`,
				workDir, npmInstallTimeoutSeconds, strings.Join(pkgSpecs, " "))
			state = state.Run(
				llb.Shlex(installCmd),
				llb.WithProxy(utils.GetProxy()),
			).Root()
		}
	}

	// Update package-lock.json
	updateLockCmd := fmt.Sprintf(`sh -c 'cd %s && npm install --package-lock-only --no-audit'`, workDir)
	state = state.Run(llb.Shlex(updateLockCmd), llb.WithProxy(utils.GetProxy())).Root()

	return state
}

// detectNpm checks if npm exists in the target image.
func (nm *nodejsManager) detectNpm(ctx context.Context, currentState *llb.State) (bool, error) {
	checkCmd := `sh -c 'if command -v npm >/dev/null 2>&1; then echo ok > ` + npmCheckFile + `; fi'`
	checked := currentState.Run(llb.Shlex(checkCmd)).Root()
	_, err := buildkit.ExtractFileFromState(ctx, nm.config.Client, &checked, npmCheckFile)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// detectPackageJSON finds package.json files in the target image.
// It looks in common application directories and excludes node_modules.
func (nm *nodejsManager) detectPackageJSON(ctx context.Context, currentState *llb.State) ([]string, error) {
	// Common application locations to check
	candidatePaths := []string{
		"/app",
		"/usr/src/app",
		"/opt/app",
		"/workspace",
	}

	// Build find command to locate package.json files (excluding node_modules)
	var findCmd strings.Builder
	findCmd.WriteString(`sh -c 'paths=""; for dir in`)
	for _, p := range candidatePaths {
		findCmd.WriteString(fmt.Sprintf(" %s", p))
	}
	findCmd.WriteString(`; do if [ -f "$dir/package.json" ] && [ -f "$dir/package-lock.json" ]; then paths="$paths $dir"; fi; done; if [ -n "$paths" ]; then echo "$paths" > `)
	findCmd.WriteString(packageJSONDetectFile)
	findCmd.WriteString(`; fi'`)

	detected := currentState.Run(llb.Shlex(findCmd.String())).Root()
	pathBytes, err := buildkit.ExtractFileFromState(ctx, nm.config.Client, &detected, packageJSONDetectFile)
	if err != nil {
		return nil, fmt.Errorf("failed to detect package.json files: %w", err)
	}

	pathsStr := strings.TrimSpace(string(pathBytes))
	if pathsStr == "" {
		return nil, nil
	}

	return strings.Fields(pathsStr), nil
}

// detectGlobalNodeModules finds globally installed npm packages in the target image.
// It looks for the global node_modules directory and returns root-level package paths.
func (nm *nodejsManager) detectGlobalNodeModules(ctx context.Context, currentState *llb.State) ([]string, error) {
	// Find global node_modules path using npm root -g
	// Then find all root-level packages (depth 1) with package.json
	findCmd := fmt.Sprintf(
		`sh -c 'if command -v npm >/dev/null 2>&1; then globalRoot=$(npm root -g 2>/dev/null); `+
			`if [ -d "$globalRoot" ]; then find "$globalRoot" -mindepth 1 -maxdepth 1 -type d `+
			`-exec sh -c "[ -f \"{}/package.json\" ] && echo \"{} \"" \; | tr -d \"\\n\" > %s; fi; fi'`,
		globalNodeModulesDetectFile,
	)

	detected := currentState.Run(llb.Shlex(findCmd)).Root()
	pathBytes, err := buildkit.ExtractFileFromState(ctx, nm.config.Client, &detected, globalNodeModulesDetectFile)
	if err != nil {
		return nil, fmt.Errorf("failed to detect global node_modules: %w", err)
	}

	pathsStr := strings.TrimSpace(string(pathBytes))
	if pathsStr == "" {
		return nil, nil
	}

	return strings.Fields(pathsStr), nil
}

// upgradePackagesWithTooling performs Node.js package upgrades using an external tooling container.
func (nm *nodejsManager) upgradePackagesWithTooling(
	ctx context.Context,
	currentState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, error) {
	// Try to detect package.json locations even without npm
	pkgJSONPaths, err := nm.detectPackageJSON(ctx, currentState)
	if err != nil || len(pkgJSONPaths) == 0 {
		// If we can't detect any package.json files, this image doesn't have a Node.js app
		// But we should still check for globally installed packages
		log.Warn("No Node.js application detected in image (no package.json found).")
		log.Info("Checking for globally installed Node.js packages...")

		// Try to patch global packages even without an app
		globalState, globalErr := nm.upgradeGlobalPackages(ctx, currentState, updates, ignoreErrors)
		if globalErr != nil {
			if !ignoreErrors {
				return nil, fmt.Errorf("failed to patch global packages: %w", globalErr)
			}
			log.Warnf("Failed to patch global packages: %v", globalErr)
		}
		return globalState, nil
	}

	toolingImage := fmt.Sprintf(toolingNodeTemplate, defaultToolingNodeTag)
	log.Infof("Using tooling image %s for Node.js package operations", toolingImage)

	state := *currentState

	// For each package.json location, use a tooling container to update packages
	for _, pkgPath := range pkgJSONPaths {
		log.Infof("Attempting to update packages in %s using tooling container", pkgPath)

		// Build install command in tooling container
		var pkgSpecs []string
		for _, u := range updates {
			if u.FixedVersion != "" {
				pkgSpecs = append(pkgSpecs, fmt.Sprintf("%s@%s", u.Name, u.FixedVersion))
			}
		}

		if len(pkgSpecs) == 0 {
			continue
		}

		// Copy package.json and package-lock.json to tooling container, install, then copy back
		toolingInstallCmd := fmt.Sprintf(
			`sh -c 'npm install --save --save-exact --no-audit --timeout=%d %s && npm install --package-lock-only --no-audit'`,
			npmInstallTimeoutSeconds, strings.Join(pkgSpecs, " "))

		// Create a tooling state that copies the package files, installs, and we copy back
		toolingState := llb.Image(toolingImage)
		toolingState = toolingState.File(
			llb.Copy(state, pkgPath+"/package.json", "/app/package.json", &llb.CopyInfo{}),
		)
		toolingState = toolingState.File(
			llb.Copy(state, pkgPath+"/package-lock.json", "/app/package-lock.json", &llb.CopyInfo{}),
		)
		toolingState = toolingState.Dir("/app").Run(
			llb.Shlex(toolingInstallCmd),
			llb.WithProxy(utils.GetProxy()),
		).Root()

		// Copy the updated node_modules and package files back
		state = state.File(
			llb.Copy(toolingState, "/app/node_modules", pkgPath+"/node_modules", &llb.CopyInfo{CopyDirContentsOnly: false, CreateDestPath: true}),
		)
		state = state.File(
			llb.Copy(toolingState, "/app/package.json", pkgPath+"/package.json", &llb.CopyInfo{}),
		)
		state = state.File(
			llb.Copy(toolingState, "/app/package-lock.json", pkgPath+"/package-lock.json", &llb.CopyInfo{}),
		)
	}

	return &state, nil
}

// upgradeGlobalPackages patches globally installed npm packages (like eslint, pnpm) that have vulnerable dependencies.
// This handles packages in the global node_modules directory (e.g., /usr/local/share/npm-global/lib/node_modules/).
func (nm *nodejsManager) upgradeGlobalPackages(
	ctx context.Context,
	currentState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, error) {
	// Detect global node_modules packages
	globalPkgPaths, err := nm.detectGlobalNodeModules(ctx, currentState)
	if err != nil || len(globalPkgPaths) == 0 {
		log.Debug("No global Node.js packages detected, skipping global patching")
		return currentState, nil
	}

	log.Infof("Detected %d globally installed Node.js package(s): %v", len(globalPkgPaths), globalPkgPaths)

	// Get unique updates
	nodeComparer := VersionComparer{isValidNodeVersion, isLessThanNodeVersion}
	uniqueUpdates, err := GetUniqueLatestUpdates(updates, nodeComparer, ignoreErrors)
	if err != nil && !ignoreErrors {
		return nil, fmt.Errorf("failed to get unique updates for global packages: %w", err)
	}
	if len(uniqueUpdates) == 0 {
		log.Info("No valid Node.js package updates to apply to global packages")
		return currentState, nil
	}

	state := *currentState
	toolingImage := fmt.Sprintf(toolingNodeTemplate, defaultToolingNodeTag)

	// For each globally installed package (like eslint, pnpm), update its vulnerable dependencies
	for _, pkgPath := range globalPkgPaths {
		pkgName := strings.TrimPrefix(pkgPath, strings.TrimSuffix(pkgPath, "/node_modules/")+"/node_modules/")
		if idx := strings.LastIndex(pkgPath, "/"); idx != -1 {
			pkgName = pkgPath[idx+1:]
		}

		log.Infof("Attempting to update vulnerable dependencies in globally installed package: %s", pkgName)

		// Build package specs for updates
		var pkgSpecs []string
		for _, u := range uniqueUpdates {
			if u.FixedVersion != "" {
				if err := validateNodePackageName(u.Name); err != nil {
					log.Warnf("Skipping invalid package name %s: %v", u.Name, err)
					continue
				}
				if err := validateNodeVersion(u.FixedVersion); err != nil {
					log.Warnf("Skipping invalid version %s for package %s: %v", u.FixedVersion, u.Name, err)
					continue
				}
				pkgSpecs = append(pkgSpecs, fmt.Sprintf("%s@%s", u.Name, u.FixedVersion))
			}
		}

		if len(pkgSpecs) == 0 {
			continue
		}

		// Strategy: Copy package.json to tooling, install updates, copy node_modules back
		toolingState := llb.Image(toolingImage)
		// Create /app directory in tooling image
		toolingState = toolingState.File(llb.Mkdir("/app", 0o755, llb.WithParents(true)))
		toolingState = toolingState.File(
			llb.Copy(state, pkgPath+"/package.json", "/app/package.json", &llb.CopyInfo{}),
		)

		// Install the specific package updates
		// Use --ignore-scripts to avoid node-gyp/Python issues with native modules
		// Use || true to continue even if some packages fail
		installCmd := fmt.Sprintf(
			`sh -c 'cd /app && (npm install --no-save --ignore-scripts --no-audit --loglevel=error --timeout=%d %s 2>&1 | `+
				`grep -v "^npm warn" || echo "Some packages failed to install") && `+
				`if [ -d /app/node_modules ]; then touch /copa-install-success; fi'`,
			npmInstallTimeoutSeconds,
			strings.Join(pkgSpecs, " "),
		)

		toolingState = toolingState.Dir("/app").Run(
			llb.Shlex(installCmd),
			llb.WithProxy(utils.GetProxy()),
		).Root()

		// Check if install was successful by checking for the marker file
		_, checkErr := buildkit.ExtractFileFromState(ctx, nm.config.Client, &toolingState, "/copa-install-success")
		if checkErr != nil {
			log.Warnf("npm install may have failed for %s, skipping node_modules copy", pkgName)
			continue
		}

		// Copy updated node_modules back to the global package
		state = state.File(
			llb.Copy(toolingState, "/app/node_modules", pkgPath+"/node_modules", &llb.CopyInfo{
				CopyDirContentsOnly: true,
				CreateDestPath:      false,
			}),
		)

		log.Infof("Updated vulnerable dependencies in global package: %s", pkgName)
	}

	return &state, nil
}
