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
	npmInstallTimeoutSeconds = 600
	npmCheckFile             = "/copa-npm-check"
	packageJSONDetectFile    = "/copa-package-json-path"
	defaultToolingNodeTag    = "18-alpine" // fallback tooling image tag if version can't be inferred
	toolingNodeTemplate      = "docker.io/library/node:%s"
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
	if detectErr != nil || len(pkgJSONPaths) == 0 {
		log.Warnf("No package.json files detected in target image: %v", detectErr)
		// Try tooling container as fallback
		return nm.upgradePackagesWithTooling(ctx, currentState, updates, ignoreErrors)
	}

	log.Infof("Detected package.json locations: %v", pkgJSONPaths)

	// Install updates for each package.json location
	updatedState := *currentState
	for _, pkgPath := range pkgJSONPaths {
		log.Infof("Updating packages in %s", pkgPath)
		updatedState = nm.installNodePackages(&updatedState, pkgPath, updates, ignoreErrors)
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

// upgradePackagesWithTooling performs Node.js package upgrades using an external tooling container.
func (nm *nodejsManager) upgradePackagesWithTooling(
	ctx context.Context,
	currentState *llb.State,
	updates unversioned.LangUpdatePackages,
	_ bool,
) (*llb.State, error) {
	// Try to detect package.json locations even without npm
	pkgJSONPaths, _ := nm.detectPackageJSON(ctx, currentState)
	if len(pkgJSONPaths) == 0 {
		// Default to common paths if detection fails
		pkgJSONPaths = []string{"/app", "/usr/src/app"}
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
