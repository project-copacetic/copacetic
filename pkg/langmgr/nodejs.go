package langmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
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
	defaultToolingNodeTag       = "lts-alpine" // Latest Active LTS (automatically tracks current LTS version)
	toolingNodeTemplate         = "docker.io/library/node:%s"
	npmVersionLatest            = "latest" // Fallback npm version when Node.js version is unknown
)

type nodejsManager struct {
	config        *buildkit.Config
	workingFolder string
}

// validNodePackageNamePattern defines the regex pattern for valid npm package names
// Based on npm package naming rules: https://docs.npmjs.com/cli/v7/configuring-npm/package-json#name
var validNodePackageNamePattern = regexp.MustCompile(`^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$`)

// getPackageBaseName returns the base name of an npm package for tarball URLs.
// For scoped packages like "@babel/core", the tarball is named "core-1.0.0.tgz".
// For unscoped packages like "lodash", the tarball is named "lodash-1.0.0.tgz".
func getPackageBaseName(name string) string {
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

// getNpmTarballURL returns a shell expression that resolves the npm registry tarball URL for a package.
// It respects custom npm registries configured via .npmrc or NPM_CONFIG_REGISTRY.
// Scoped packages like "@babel/core" use URL encoding: @babel%2Fcore.
func getNpmTarballURL(name, version string) string {
	encodedName := name
	if strings.HasPrefix(name, "@") {
		encodedName = strings.Replace(name, "/", "%2F", 1)
	}
	return fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz", encodedName, getPackageBaseName(name), version)
}

// nodeDownloadScript returns a shell snippet that uses Node.js to download a URL to a file.
// This is used instead of wget/curl which may not be available in all images.
// Uses the same '\”...'\” quoting pattern as the rest of the codebase for single quotes
// inside sh -c '...' commands. Returns non-zero exit code on download failure.
func nodeDownloadScript(url, destFile string) string {
	return fmt.Sprintf(
		`node -e "var h=require('\''https'\''),f=require('\''fs'\'');`+
			`function dl(u){h.get(u,function(r){`+
			`if(r.statusCode>300&&r.statusCode<400){dl(r.headers.location)}`+
			`else if(r.statusCode!==200){console.error('\''HTTP '\''+r.statusCode+'\'' for '\''+u);process.exit(1)}`+
			`else{r.pipe(f.createWriteStream('\''%s'\'')).on('\''finish'\'',function(){process.exit(0)})}`+
			`}).on('\''error'\'',function(e){console.error(e);process.exit(1)})}`+
			`dl('\''%s'\'')"`,
		destFile, url,
	)
}

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
	// Trivy can return a list like "1.2.3, 2.0.0". We just need one to be valid.
	parts := strings.Split(v, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		trimmed = strings.TrimPrefix(trimmed, "v")
		if _, err := semver.NewVersion(trimmed); err == nil {
			return true // Found at least one valid version.
		}
	}
	return false
}

// cleanAndGetFirstVersion extracts the first valid version from a potentially comma-separated string.
func cleanAndGetFirstVersion(v string) string {
	parts := strings.Split(v, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		trimmed = strings.TrimPrefix(trimmed, "v")
		if _, err := semver.NewVersion(trimmed); err == nil {
			return trimmed // Return the first one that's valid.
		}
	}
	return v // Fallback to original if none are valid
}

// isLessThanNodeVersion compares two semver version strings.
// It returns true if v1 is less than v2, and false if there's an error.
func isLessThanNodeVersion(v1, v2 string) bool {
	// Clean the version strings to get a single, valid version for comparison.
	cleanV1 := cleanAndGetFirstVersion(v1)
	cleanV2 := cleanAndGetFirstVersion(v2)

	ver1, err1 := semver.NewVersion(cleanV1)
	if err1 != nil {
		log.Warnf("Error parsing Node version '%s' from '%s': %v", cleanV1, v1, err1)
		return false
	}
	ver2, err2 := semver.NewVersion(cleanV2)
	if err2 != nil {
		log.Warnf("Error parsing Node version '%s' from '%s': %v", cleanV2, v2, err2)
		return false
	}
	return ver1.LessThan(ver2)
}

// getDirectDependencies reads a package.json from the image state and returns a set of its direct dependencies.
func getDirectDependencies(ctx context.Context, c gwclient.Client, st *llb.State, workDir string) (map[string]bool, error) {
	deps := make(map[string]bool)
	pkgJSONPath := filepath.Join(workDir, "package.json")

	reader := st.File(llb.Copy(*st, pkgJSONPath, "/tmp/package.json.out", &llb.CopyInfo{AllowWildcard: true}))

	def, err := reader.Marshal(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal state for reading package.json: %w", err)
	}

	// Step 1: Solve the state to get a result.
	result, err := c.Solve(ctx, gwclient.SolveRequest{Definition: def.ToPB()})
	if err != nil {
		return nil, fmt.Errorf("could not solve for package.json in %s: %w", workDir, err)
	}

	// Step 2: Get the file reference from the result.
	ref, err := result.SingleRef()
	if err != nil {
		return nil, fmt.Errorf("failed to get reference from solved package.json: %w", err)
	}

	// Step 3: Read the file from the reference.
	data, err := ref.ReadFile(ctx, gwclient.ReadRequest{Filename: "/tmp/package.json.out"})
	if err != nil {
		return nil, fmt.Errorf("could not read package.json from %s: %w", workDir, err)
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("could not parse package.json from %s: %w", workDir, err)
	}

	for dep := range pkg.Dependencies {
		deps[dep] = true
	}
	for dep := range pkg.DevDependencies {
		deps[dep] = true
	}

	return deps, nil
}

// hasNpmVulnerabilities checks if any updates target npm's dependencies.
// Returns true if any vulnerability is in npm's dependency tree.
func hasNpmVulnerabilities(updates unversioned.LangUpdatePackages) bool {
	for _, u := range updates {
		if strings.Contains(u.PkgPath, "/node_modules/npm/") {
			return true
		}
	}
	return false
}

// selectNpmVersionForNode returns the appropriate npm version for a given Node.js major version.
// This ensures compatibility between npm and Node.js versions.
func selectNpmVersionForNode(nodeVersion string) string { //nolint:unused // kept for potential future use
	if nodeVersion == "" {
		return npmVersionLatest // Fallback when Node version unknown
	}

	parts := strings.Split(nodeVersion, ".")
	if len(parts) == 0 {
		return npmVersionLatest
	}

	majorVersion, err := strconv.Atoi(parts[0])
	if err != nil {
		return npmVersionLatest
	}

	switch {
	case majorVersion >= 23:
		return "^11.0.0" // Future versions use npm 11+
	case majorVersion == 22:
		return "^10.0.0" // Node 22 can use npm 10 or 11, use 10 for safety
	case majorVersion >= 18:
		return "^10.0.0" // Node 18-21 use npm 10
	case majorVersion >= 14:
		return "^9.0.0" // Node 14-17 use npm 9
	default:
		return npmVersionLatest // Old versions: best effort
	}
}

// selectToolingNodeVersion selects the appropriate Node.js tooling image version.
// It uses the detected version from the image if available, otherwise falls back to latest Active LTS.
// Returns a tag like "18-alpine" or "22-alpine".
func selectToolingNodeVersion(detectedVersion string) string {
	if detectedVersion == "" {
		log.Debugf("No Node.js version detected from image, using latest LTS: %s", defaultToolingNodeTag)
		return defaultToolingNodeTag
	}

	// Extract major version from detected version (e.g., "18" from "18.20.3")
	parts := strings.Split(detectedVersion, ".")
	if len(parts) == 0 {
		log.Warnf("Invalid Node.js version format '%s', using default: %s", detectedVersion, defaultToolingNodeTag)
		return defaultToolingNodeTag
	}

	majorVersion := parts[0]

	// Validate it's a number
	if _, err := strconv.Atoi(majorVersion); err != nil {
		log.Warnf("Invalid major version '%s' in detected version '%s', using default: %s",
			majorVersion, detectedVersion, defaultToolingNodeTag)
		return defaultToolingNodeTag
	}

	toolingTag := fmt.Sprintf("%s-alpine", majorVersion)
	log.Infof("Using Node.js tooling image version %s (detected from image: %s)", toolingTag, detectedVersion)
	return toolingTag
}

// extractAppPathsFromUpdates derives application directories from vulnerability PkgPath fields.
// Example: "var/lib/ghost/versions/6.2.0/node_modules/@babel/runtime/package.json"
//
//	-> "/var/lib/ghost/versions/6.2.0".
func extractAppPathsFromUpdates(updates unversioned.LangUpdatePackages) []string {
	pathMap := make(map[string]bool)

	for _, u := range updates {
		if u.PkgPath == "" {
			continue
		}

		if strings.Count(u.PkgPath, "/node_modules/") > 1 {
			// This is likely a dependency of a global package, not a user app.
			// Let the upgradeGlobalPackages function handle it.
			continue
		}

		// Ensure leading slash
		pkgPath := u.PkgPath
		if !strings.HasPrefix(pkgPath, "/") {
			pkgPath = "/" + pkgPath
		}

		// Find node_modules in path and extract everything before it
		if idx := strings.Index(pkgPath, "/node_modules/"); idx != -1 {
			appPath := pkgPath[:idx]
			pathMap[appPath] = true
		}
	}

	var paths []string
	for p := range pathMap {
		paths = append(paths, p)
	}
	return paths
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
	updatedImageState, upgradeErr := nm.upgradePackages(ctx, currentState, &manifest.Metadata, updatesToAttempt, ignoreErrors)
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
	metadata *unversioned.Metadata,
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
		return nm.upgradePackagesWithTooling(ctx, currentState, metadata, updates, ignoreErrors)
	}

	// Separate vulnerabilities into two lists
	var userAppUpdates unversioned.LangUpdatePackages
	var globalUpdates unversioned.LangUpdatePackages

	// Get the global root path to distinguish between global and app vulnerabilities.
	globalNodeModules, _ := nm.detectGlobalNodeModules(ctx, currentState)
	globalPathSet := make(map[string]bool)
	for _, p := range globalNodeModules {
		globalPathSet[p] = true
	}

	for _, u := range updates {
		isGlobal := false
		// Normalize the package path to ensure it has a leading slash
		pkgPath := u.PkgPath
		if !strings.HasPrefix(pkgPath, "/") {
			pkgPath = "/" + pkgPath
		}

		for pathPrefix := range globalPathSet {
			if strings.HasPrefix(pkgPath, pathPrefix) || strings.Contains(pkgPath, "/node_modules/npm/") {
				globalUpdates = append(globalUpdates, u)
				isGlobal = true
				break
			}
		}
		if !isGlobal {
			userAppUpdates = append(userAppUpdates, u)
		}
	}

	updatedState := *currentState

	appPaths := extractAppPathsFromUpdates(userAppUpdates)
	if len(appPaths) > 0 {
		log.Infof("Detected Node.js application paths from vulnerability report: %v", appPaths)
		for _, appPath := range appPaths {
			if _, err := getDirectDependencies(ctx, nm.config.Client, &updatedState, appPath); err != nil {
				log.Warnf("Path %s does not appear to be a valid Node.js project (missing package.json?), skipping.", appPath)
				continue
			}
			log.Infof("Updating packages in %s", appPath)
			// Pass ONLY the user app updates to the installer.
			updatedState = nm.installNodePackages(ctx, &updatedState, appPath, userAppUpdates)
		}
	} else {
		log.Debug("No user application vulnerabilities found to patch.")
	}

	// --- Process Global Vulnerabilities ---
	if len(globalUpdates) > 0 {
		log.Info("Checking for globally installed Node.js packages with vulnerable dependencies...")
		// Pass ONLY the global updates to the global patcher.
		globalPatchedState, globalErr := nm.upgradeGlobalPackages(ctx, &updatedState, metadata, globalUpdates, ignoreErrors)
		if globalErr != nil {
			if !ignoreErrors {
				return nil, fmt.Errorf("failed to patch global packages: %w", globalErr)
			}
			log.Warnf("Failed to patch global packages but continuing due to ignore-errors: %v", globalErr)
		} else {
			updatedState = *globalPatchedState
		}
	} else {
		log.Debug("No global package vulnerabilities found to patch.")
	}

	// Clean up npm cache and remove old vulnerable package tarballs
	// This is crucial to prevent Trivy from detecting old cached vulnerable packages
	log.Info("Aggressively cleaning npm cache and removing all cached package files")
	cleanupCmd := `sh -c '` +
		// Run npm cache clean (may fail if npm not available, that's ok)
		`npm cache clean --force 2>&1 || echo "WARN: npm cache clean command failed"; ` +
		// Find and remove ALL .npm cache directories across the entire filesystem
		`find / -type d -path "*/.npm/_cacache" -prune -exec rm -rf {} \; 2>&1 || echo "WARN: find command for .npm/_cacache failed"; ` +
		// Also target common known cache locations explicitly
		`rm -rf /root/.npm 2>&1 || echo "WARN: Failed to remove /root/.npm"; ` +
		`rm -rf ~/.npm 2>&1 || echo "WARN: Failed to remove ~/.npm"; ` +
		`rm -rf /home/*/.npm 2>&1 || echo "WARN: Failed to remove /home/*/.npm"; ` +
		// Remove npm's global cache if it exists
		`rm -rf /tmp/npm-* 2>&1 || echo "WARN: Failed to remove /tmp/npm-*"'`
	updatedState = updatedState.Run(llb.Shlex(cleanupCmd), llb.WithProxy(utils.GetProxy())).Root()

	return &updatedState, nil
}

// shellQuote wraps s in single quotes and escapes embedded single quotes so it can be
// safely passed as a shell argument.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// installNodePackages updates both direct and transitive dependencies.
// It uses npm install for direct dependencies and npm overrides for transitive dependencies.
func (nm *nodejsManager) installNodePackages(
	ctx context.Context,
	currentState *llb.State,
	workDir string,
	updates unversioned.LangUpdatePackages,
) llb.State {
	if len(updates) == 0 {
		return *currentState
	}

	// Get the direct dependencies from the app's package.json
	directDeps, err := getDirectDependencies(ctx, nm.config.Client, currentState, workDir)
	if err != nil {
		log.Warnf("Could not determine direct dependencies for %s, proceeding without filtering: %v", workDir, err)
	}

	state := *currentState

	// Remove devDependencies from package.json to prevent them from being installed
	// This ensures production images don't include development dependencies
	log.Debugf("Removing devDependencies from package.json in %s", workDir)
	removeDevDepsCmd := fmt.Sprintf(
		`sh -c 'cd -- "$1" && `+
			`node -e "const fs=require('\''fs'\''); const pkg=JSON.parse(fs.readFileSync('\''package.json'\'')); `+
			`delete pkg.devDependencies; fs.writeFileSync('\''package.json'\'', JSON.stringify(pkg, null, 2));"' -- %s`,
		shellQuote(workDir),
	)
	state = state.Run(llb.Shlex(removeDevDepsCmd), llb.WithProxy(utils.GetProxy())).Root()

	var transitiveUpdates unversioned.LangUpdatePackages

	// == Step 1: Replace Direct Dependencies via Tarball Download ==
	// Use direct tarball replacement instead of npm install to avoid
	// re-resolving the dependency tree and introducing new vulnerabilities.
	log.Infof("Processing direct dependency updates for %s...", workDir)
	for _, u := range updates {
		if directDeps[u.Name] {
			if u.FixedVersion == "" {
				continue
			}

			tarballURL := getNpmTarballURL(u.Name, u.FixedVersion)
			tarballFile := fmt.Sprintf("/tmp/%s-%s.tgz", getPackageBaseName(u.Name), u.FixedVersion)
			downloadScript := nodeDownloadScript(tarballURL, tarballFile)

			replaceCmd := fmt.Sprintf(
				`sh -c 'cd -- "$1" && `+
					`PKG_DIR="node_modules/%s" && `+
					`if [ -d "$PKG_DIR" ]; then `+
					`  echo "INFO: Replacing direct dependency %s with version %s" && `+
					`  if %s; then `+
					`    rm -rf "$PKG_DIR" && mkdir -p "$PKG_DIR" && `+
					`    tar xzf %s --strip-components=1 -C "$PKG_DIR" && `+
					`    rm -f %s && `+
					`    if [ ! -f "$PKG_DIR/package.json" ]; then echo "ERROR: extraction failed for %s" >&2; exit 1; fi; `+
					`  else `+
					`    echo "WARN: failed to download %s@%s, skipping"; `+
					`  fi; `+
					`else `+
					`  echo "WARN: %s not found in node_modules, skipping"; `+
					`fi' -- %s`,
				u.Name,
				u.Name, u.FixedVersion,
				downloadScript,
				tarballFile,
				tarballFile,
				u.Name,
				u.Name, u.FixedVersion,
				u.Name,
				shellQuote(workDir),
			)

			log.Infof("Replacing direct dependency %s@%s in %s", u.Name, u.FixedVersion, workDir)
			state = state.Run(
				llb.Shlex(replaceCmd),
				llb.WithProxy(utils.GetProxy()),
			).Root()
		} else {
			transitiveUpdates = append(transitiveUpdates, u)
		}
	}

	// == Step 2: Replace Transitive Dependencies via Direct Tarball Download ==
	// Instead of using npm overrides + npm install (which re-resolves the entire
	// dependency tree and can introduce new vulnerabilities), we directly download
	// and extract package tarballs from the npm registry into node_modules.
	if len(transitiveUpdates) > 0 {
		log.Infof("Processing %d transitive dependency update(s) for %s via direct tarball replacement...", len(transitiveUpdates), workDir)

		for _, u := range transitiveUpdates {
			if u.FixedVersion == "" {
				continue
			}

			// Download the tarball once, then find and replace all instances of this
			// package in the node_modules tree.
			// Use -path (not -name) to correctly handle scoped packages like @babel/core.
			tarballURL := getNpmTarballURL(u.Name, u.FixedVersion)
			tarballFile := fmt.Sprintf("/tmp/%s-%s.tgz", getPackageBaseName(u.Name), u.FixedVersion)
			downloadScript := nodeDownloadScript(tarballURL, tarballFile)

			replaceCmd := fmt.Sprintf(
				`sh -c 'cd -- "$1" && `+
					`if %s; then `+
					`  PKG_NAME="%s" && `+
					`  FOUND=0 && `+
					`  for dir in $(find node_modules -type d -path "*/node_modules/$PKG_NAME" 2>/dev/null); do `+
					`    if [ -f "$dir/package.json" ]; then `+
					`      echo "INFO: Replacing $PKG_NAME in $dir with version %s" && `+
					`      rm -rf "$dir" && mkdir -p "$dir" && `+
					`      tar xzf %s --strip-components=1 -C "$dir" && `+
					`      if [ ! -f "$dir/package.json" ]; then echo "ERROR: extraction failed for $PKG_NAME in $dir" >&2; exit 1; fi && `+
					`      FOUND=$((FOUND+1)); `+
					`    fi; `+
					`  done && `+
					`  rm -f %s && `+
					`  if [ "$FOUND" -eq 0 ]; then echo "WARN: %s not found in node_modules"; fi; `+
					`else `+
					`  echo "WARN: failed to download %s@%s, skipping"; `+
					`fi' -- %s`,
				downloadScript,
				u.Name,
				u.FixedVersion,
				tarballFile,
				tarballFile,
				u.Name,
				u.Name, u.FixedVersion,
				shellQuote(workDir),
			)

			log.Infof("Replacing transitive dependency %s@%s in %s", u.Name, u.FixedVersion, workDir)
			state = state.Run(
				llb.Shlex(replaceCmd),
				llb.WithProxy(utils.GetProxy()),
			).Root()
		}
	}

	// == Step 3: Final Cleanup ==
	log.Infof("Running final cleanup for %s...", workDir)
	cleanupCmd := fmt.Sprintf(
		`sh -c 'cd -- "$1" && `+
			`npm prune --omit=dev --legacy-peer-deps 2>&1 | grep -v "^npm warn" || true && `+
			`npm dedupe --omit=dev --legacy-peer-deps 2>&1 | grep -v "^npm warn" || true && `+
			`(rm -rf /root/.npm ~/.npm /home/*/.npm /tmp/npm-* 2>&1 || echo "WARN: Cache cleanup failed")' -- %s`,
		shellQuote(workDir),
	)
	state = state.Run(
		llb.Shlex(cleanupCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

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
// It uses a two-phase approach:
// 1. First check common application directories (fast).
// 2. If nothing found, do a broader filesystem search (slower but comprehensive).
func (nm *nodejsManager) detectPackageJSON(ctx context.Context, currentState *llb.State) ([]string, error) {
	// Phase 1: Check common application locations (fast path)
	candidatePaths := []string{
		"/app",
		"/usr/src/app",
		"/opt/app",
		"/workspace",
		"/home/node/app",
		"/usr/local/lib/node",
	}

	var findCmd strings.Builder
	findCmd.WriteString(`sh -c 'paths=""; for dir in`)
	for _, p := range candidatePaths {
		fmt.Fprintf(&findCmd, " %s", p)
	}
	findCmd.WriteString(`; do if [ -f "$dir/package.json" ]; then paths="$paths $dir"; fi; done; `)

	// Phase 2: If no candidate paths found, do a broader search
	// Search common root directories but exclude node_modules, .npm cache, etc.
	findCmd.WriteString(`if [ -z "$paths" ]; then `)
	findCmd.WriteString(`paths=$(find /var /home /usr /opt -maxdepth 6 -type f -name "package.json" 2>/dev/null | `)
	findCmd.WriteString(`grep -v "/node_modules/" | grep -v "/.npm/" | grep -v "/test/" | grep -v "/tests/" | `)
	findCmd.WriteString(`xargs -r dirname | sort -u | tr "\\n" " "); `)
	findCmd.WriteString(`fi; `)

	findCmd.WriteString(`if [ -n "$paths" ]; then echo "$paths" > `)
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
	metadata *unversioned.Metadata,
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
		globalState, globalErr := nm.upgradeGlobalPackages(ctx, currentState, metadata, updates, ignoreErrors)
		if globalErr != nil {
			if !ignoreErrors {
				return nil, fmt.Errorf("failed to patch global packages: %w", globalErr)
			}
			log.Warnf("Failed to patch global packages: %v", globalErr)
		}
		return globalState, nil
	}

	// Select tooling image version based on detected Node.js version
	toolingTag := selectToolingNodeVersion(metadata.NodeVersion)
	toolingImage := fmt.Sprintf(toolingNodeTemplate, toolingTag)
	if metadata.NodeVersion != "" {
		log.Infof("Using tooling image %s for Node.js package operations (detected version: %s)", toolingImage, metadata.NodeVersion)
	} else {
		log.Infof("Using tooling image %s for Node.js package operations (no version detected, using LTS)", toolingImage)
	}

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
// This handles packages in the global node_modules directory (e.g., /usr/local/lib/node_modules/).
//
// Strategy: Replace vulnerable packages by downloading fixed-version tarballs from the npm registry
// and extracting them directly into node_modules, avoiding npm install which re-resolves the
// dependency tree and can introduce new vulnerabilities.
func (nm *nodejsManager) upgradeGlobalPackages(
	ctx context.Context,
	currentState *llb.State,
	metadata *unversioned.Metadata,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, error) {
	state := *currentState

	// Check if npm itself has vulnerabilities - if so, replace the specific vulnerable
	// packages within npm's node_modules via direct tarball download, instead of
	// upgrading npm entirely (which re-resolves npm's dependency tree and can
	// introduce new vulnerabilities).
	if hasNpmVulnerabilities(updates) {
		log.Info("Detected vulnerabilities in npm dependencies. Replacing vulnerable packages within npm...")

		// Filter out npm-internal vulnerable packages for tarball replacement
		var npmUpdates unversioned.LangUpdatePackages
		var nonNpmUpdates unversioned.LangUpdatePackages
		for _, u := range updates {
			if strings.Contains(u.PkgPath, "/node_modules/npm/") {
				npmUpdates = append(npmUpdates, u)
			} else {
				nonNpmUpdates = append(nonNpmUpdates, u)
			}
		}

		// Replace vulnerable packages within npm's node_modules
		for _, u := range npmUpdates {
			if u.FixedVersion == "" {
				continue
			}

			// Download tarball, then find and replace all instances within npm's
			// node_modules. Use -path (not -name) for scoped packages.
			tarballURL := getNpmTarballURL(u.Name, u.FixedVersion)
			tarballFile := fmt.Sprintf("/tmp/%s-%s.tgz", getPackageBaseName(u.Name), u.FixedVersion)
			downloadScript := nodeDownloadScript(tarballURL, tarballFile)

			replaceCmd := fmt.Sprintf(
				`sh -c 'NPM_ROOT=$(npm root -g) && `+
					`if %s; then `+
					`  PKG_NAME="%s" && `+
					`  FOUND=0 && `+
					`  for dir in $(find "$NPM_ROOT/npm" -type d -path "*/node_modules/$PKG_NAME" 2>/dev/null); do `+
					`    if [ -f "$dir/package.json" ]; then `+
					`      echo "INFO: Replacing $PKG_NAME in $dir with version %s" && `+
					`      rm -rf "$dir" && mkdir -p "$dir" && `+
					`      tar xzf %s --strip-components=1 -C "$dir" && `+
					`      if [ ! -f "$dir/package.json" ]; then echo "ERROR: extraction failed for $PKG_NAME in $dir" >&2; exit 1; fi && `+
					`      FOUND=$((FOUND+1)); `+
					`    fi; `+
					`  done && `+
					`  rm -f %s && `+
					`  if [ "$FOUND" -eq 0 ]; then echo "WARN: %s not found in npm node_modules"; fi; `+
					`else `+
					`  echo "WARN: failed to download %s@%s, skipping"; `+
					`fi'`,
				downloadScript,
				u.Name,
				u.FixedVersion,
				tarballFile,
				tarballFile,
				u.Name,
				u.Name, u.FixedVersion,
			)

			log.Infof("Replacing %s@%s within npm's node_modules", u.Name, u.FixedVersion)
			state = state.Run(
				llb.Shlex(replaceCmd),
				llb.WithProxy(utils.GetProxy()),
			).Root()
		}

		updates = nonNpmUpdates

		// If no more updates after filtering npm, we're done
		if len(updates) == 0 {
			log.Info("All vulnerabilities were in npm dependencies, which have been addressed by upgrading npm")
			return &state, nil
		}
	}

	// Detect global node_modules packages
	globalPkgPaths, err := nm.detectGlobalNodeModules(ctx, &state)
	if err != nil || len(globalPkgPaths) == 0 {
		log.Debug("No global Node.js packages detected, skipping global patching")
		return &state, nil
	}

	log.Infof("Detected %d globally installed Node.js package(s): %v", len(globalPkgPaths), globalPkgPaths)

	var filteredGlobalPkgPaths []string
	for _, pkgPath := range globalPkgPaths {
		pkgName := filepath.Base(pkgPath)
		if pkgName == "npm" || pkgName == "corepack" {
			log.Infof("Skipping patching of core Node.js infrastructure package: %s", pkgName)
			continue
		}
		filteredGlobalPkgPaths = append(filteredGlobalPkgPaths, pkgPath)
	}
	if len(filteredGlobalPkgPaths) == 0 {
		log.Debug("No user-installed global packages to patch.")
		return &state, nil
	}

	// Get unique updates
	nodeComparer := VersionComparer{isValidNodeVersion, isLessThanNodeVersion}
	uniqueUpdates, err := GetUniqueLatestUpdates(updates, nodeComparer, ignoreErrors)
	if err != nil && !ignoreErrors {
		return nil, fmt.Errorf("failed to get unique updates for global packages: %w", err)
	}
	if len(uniqueUpdates) == 0 {
		log.Info("No valid Node.js package updates to apply to global packages")
		return &state, nil
	}

	// For each globally installed package, handle both direct and transitive dependencies
	for _, pkgPath := range filteredGlobalPkgPaths {
		pkgName := ""
		if idx := strings.LastIndex(pkgPath, "/"); idx != -1 {
			pkgName = pkgPath[idx+1:]
		}

		log.Infof("Updating vulnerable dependencies in global package: %s at %s", pkgName, pkgPath)

		// Get direct dependencies for this specific global package
		directDeps, err := getDirectDependencies(ctx, nm.config.Client, &state, pkgPath)
		if err != nil {
			log.Warnf("Could not determine direct dependencies for global package %s, proceeding without filtering.", pkgName)
		}

		// Remove devDependencies from package.json to prevent them from being installed
		// This ensures global packages don't include development dependencies
		log.Debugf("Removing devDependencies from package.json for global package %s", pkgName)
		removeDevDepsCmd := fmt.Sprintf(
			`sh -c 'cd -- "$1" && `+
				`node -e "const fs=require('\''fs'\''); const pkg=JSON.parse(fs.readFileSync('\''package.json'\'')); `+
				`delete pkg.devDependencies; fs.writeFileSync('\''package.json'\'', JSON.stringify(pkg, null, 2));"' -- %s`,
			shellQuote(pkgPath),
		)
		state = state.Run(llb.Shlex(removeDevDepsCmd), llb.WithProxy(utils.GetProxy())).Root()

		// Separate into direct and transitive updates
		var directUpdates unversioned.LangUpdatePackages
		var transitiveUpdates unversioned.LangUpdatePackages

		for _, u := range uniqueUpdates {
			if directDeps[u.Name] {
				directUpdates = append(directUpdates, u)
			} else {
				transitiveUpdates = append(transitiveUpdates, u)
			}
		}

		// First, replace direct dependency updates for global package via tarball download
		if len(directUpdates) > 0 {
			log.Infof("Replacing %d direct dependency update(s) for global package '%s' via tarball download", len(directUpdates), pkgName)

			for _, u := range directUpdates {
				if u.FixedVersion == "" {
					continue
				}

				tarballURL := getNpmTarballURL(u.Name, u.FixedVersion)
				tarballFile := fmt.Sprintf("/tmp/%s-%s.tgz", getPackageBaseName(u.Name), u.FixedVersion)
				downloadScript := nodeDownloadScript(tarballURL, tarballFile)

				replaceCmd := fmt.Sprintf(
					`sh -c 'cd -- "$1" && `+
						`PKG_DIR="node_modules/%s" && `+
						`if [ -d "$PKG_DIR" ]; then `+
						`  echo "INFO: Replacing direct dependency %s with version %s" && `+
						`  if %s; then `+
						`    rm -rf "$PKG_DIR" && mkdir -p "$PKG_DIR" && `+
						`    tar xzf %s --strip-components=1 -C "$PKG_DIR" && `+
						`    rm -f %s && `+
						`    if [ ! -f "$PKG_DIR/package.json" ]; then echo "ERROR: extraction failed for %s" >&2; exit 1; fi; `+
						`  else `+
						`    echo "WARN: failed to download %s@%s, skipping"; `+
						`  fi; `+
						`else `+
						`  echo "WARN: %s not found in node_modules, skipping"; `+
						`fi' -- %s`,
					u.Name,
					u.Name, u.FixedVersion,
					downloadScript,
					tarballFile,
					tarballFile,
					u.Name,
					u.Name, u.FixedVersion,
					u.Name,
					shellQuote(pkgPath),
				)

				log.Infof("Replacing direct dependency %s@%s in global package %s", u.Name, u.FixedVersion, pkgName)
				state = state.Run(
					llb.Shlex(replaceCmd),
					llb.WithProxy(utils.GetProxy()),
				).Root()
			}
		}

		// Then, replace transitive dependencies via direct tarball download
		// instead of using npm overrides which re-resolves the entire tree
		if len(transitiveUpdates) > 0 {
			log.Infof("Replacing %d transitive dependency(ies) in global package '%s' via direct tarball download...", len(transitiveUpdates), pkgName)

			for _, u := range transitiveUpdates {
				if u.FixedVersion == "" {
					continue
				}

				tarballURL := getNpmTarballURL(u.Name, u.FixedVersion)
				tarballFile := fmt.Sprintf("/tmp/%s-%s.tgz", getPackageBaseName(u.Name), u.FixedVersion)
				downloadScript := nodeDownloadScript(tarballURL, tarballFile)

				replaceCmd := fmt.Sprintf(
					`sh -c 'cd -- "$1" && `+
						`if %s; then `+
						`  PKG_NAME="%s" && `+
						`  FOUND=0 && `+
						`  for dir in $(find node_modules -type d -path "*/node_modules/$PKG_NAME" 2>/dev/null); do `+
						`    if [ -f "$dir/package.json" ]; then `+
						`      echo "INFO: Replacing $PKG_NAME in $dir with version %s" && `+
						`      rm -rf "$dir" && mkdir -p "$dir" && `+
						`      tar xzf %s --strip-components=1 -C "$dir" && `+
						`      if [ ! -f "$dir/package.json" ]; then echo "ERROR: extraction failed for $PKG_NAME in $dir" >&2; exit 1; fi && `+
						`      FOUND=$((FOUND+1)); `+
						`    fi; `+
						`  done && `+
						`  rm -f %s && `+
						`  if [ "$FOUND" -eq 0 ]; then echo "WARN: %s not found in node_modules"; fi; `+
						`else `+
						`  echo "WARN: failed to download %s@%s, skipping"; `+
						`fi' -- %s`,
					downloadScript,
					u.Name,
					u.FixedVersion,
					tarballFile,
					tarballFile,
					u.Name,
					u.Name, u.FixedVersion,
					shellQuote(pkgPath),
				)

				log.Infof("Replacing transitive dependency %s@%s in global package %s", u.Name, u.FixedVersion, pkgName)
				state = state.Run(
					llb.Shlex(replaceCmd),
					llb.WithProxy(utils.GetProxy()),
				).Root()
			}
		}

		if len(directUpdates) > 0 || len(transitiveUpdates) > 0 {
			log.Infof("Successfully updated dependencies in global package: %s", pkgName)
		} else {
			log.Infof("No applicable dependency updates for global package '%s'", pkgName)
		}
	}

	return &state, nil
}
