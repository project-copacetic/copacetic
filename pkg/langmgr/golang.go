package langmgr

import (
	"context"
	"encoding/json"
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

// shellUnsafeChars are characters that must not appear in values interpolated into shell commands.
const shellUnsafeChars = ";&|`$(){}[]<>\"'\\*?!~#\t\n\r"

// OCI annotation keys for source provenance (https://github.com/opencontainers/image-spec/blob/main/annotations.md).
const (
	ociAnnotationSource   = "org.opencontainers.image.source"
	ociAnnotationRevision = "org.opencontainers.image.revision"
)

const (
	goCheckFile        = "/copa-go-check"
	goModDetectFile    = "/copa-go-mod-paths"
	goWorkDetectFile   = "/copa-go-work-path"
	goVendorDetectFile = "/copa-go-vendor-check"
	goVersionFile      = "/copa-go-version"
	// defaultToolingGoTag is the fallback Docker tag when Go version can't be
	// detected from the image. Uses "1" to always get the latest stable Go 1.x.
	defaultToolingGoTag = "1"
	toolingGoTemplate   = "docker.io/library/golang:%s"
)

type golangManager struct {
	config              *buildkit.Config
	workingFolder       string
	toolchainPatchLevel string
	goVCSURL            string
	imageRef            string
	goBinaryPaths       []string // binary paths from all gobinary updates (including stdlib)
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

	// Module names must not start with '-' to prevent go tool flag injection.
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("package name cannot start with '-': %s", name)
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
// Returns the non-stdlib Go packages and the minimum Go version needed to fix
// stdlib vulnerabilities (empty string if none). Stdlib vulns are fixed by
// rebuilding with a newer Go compiler, not by go get.
func filterGoPackages(langUpdates unversioned.LangUpdatePackages) (unversioned.LangUpdatePackages, string) {
	var goPackages unversioned.LangUpdatePackages
	stdlibFixedVersion := ""
	for _, pkg := range langUpdates {
		if pkg.Type == utils.GoModules || pkg.Type == utils.GoBinary {
			if pkg.Name == "stdlib" {
				fixVer := cleanGoVersion(pkg.FixedVersion)
				if fixVer != "" && (stdlibFixedVersion == "" || isLessThanGoVersion(stdlibFixedVersion, fixVer)) {
					stdlibFixedVersion = fixVer
				}
				log.Debugf("Found stdlib vulnerability: %s → %s (will fix via Go compiler upgrade)", pkg.InstalledVersion, pkg.FixedVersion)
				continue
			}
			goPackages = append(goPackages, pkg)
		}
	}
	return goPackages, stdlibFixedVersion
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
	goUpdates, stdlibFixedVersion := filterGoPackages(manifest.LangUpdates)
	hasStdlib := stdlibFixedVersion != ""

	// Collect binary paths from ALL gobinary updates (including stdlib) for
	// the synthetic binary fallback on distroless images where detection fails.
	gm.goBinaryPaths = collectGoBinaryPaths(manifest.LangUpdates)

	// Only act on stdlib vulns if user explicitly opted in via --toolchain-patch-level
	if hasStdlib && gm.toolchainPatchLevel == "" {
		log.Warnf("Stdlib vulnerabilities found (requires Go >= %s) but --toolchain-patch-level not set. "+
			"These vulnerabilities require rebuilding binaries with an updated Go compiler. "+
			"Use --toolchain-patch-level=patch|minor|major to fix them.", stdlibFixedVersion)
		if len(goUpdates) == 0 {
			log.Warn("Only stdlib vulnerabilities detected — patching will have no effect without --toolchain-patch-level.")
		}
		hasStdlib = false
		stdlibFixedVersion = ""
	}

	if len(goUpdates) == 0 && !hasStdlib {
		log.Debug("No Go packages found to update.")
		return currentState, []string{}, nil
	}

	if hasStdlib {
		log.Debugf("Stdlib vulnerabilities detected - binaries built with Go < %s will be rebuilt", stdlibFixedVersion)
	}

	log.Debugf("Found %d Go package updates to process (stdlib=%v)", len(goUpdates), hasStdlib)

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

	if len(updatesToAttempt) == 0 && !hasStdlib {
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
	updatedImageState, failedPkgs, upgradeErr := gm.upgradePackages(ctx, currentState, updatesToAttempt, ignoreErrors, stdlibFixedVersion)
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
		log.Debugf("Go packages with issues: %v", errPkgsReported)
	} else {
		log.Debug("All Go packages prepared for update.")
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
	log.Debugf("Detected go.mod files in: %v", paths)
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
		log.Debugf("Detected go.work workspace at: %s", workPath)
	}
	return workPath, nil
}

// detectVendor checks if a vendor directory exists at the given module path.
func (gm *golangManager) detectVendor(ctx context.Context, currentState *llb.State, modPath string) (bool, error) {
	// Defense-in-depth: validate modPath even though callers should also validate.
	if strings.ContainsAny(modPath, shellUnsafeChars) {
		return false, fmt.Errorf("modPath contains unsafe characters: %s", modPath)
	}
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
	versionCmd := `sh -c 'go version 2>/dev/null | grep -oE "go[0-9]+\.[0-9]+" | sed "s/go//" > ` + goVersionFile + `'`
	versionState := currentState.Run(
		llb.Shlex(versionCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	versionBytes, err := buildkit.ExtractFileFromState(ctx, gm.config.Client, &versionState, goVersionFile)
	if err == nil {
		version := strings.TrimSpace(string(versionBytes))
		if version != "" {
			log.Debugf("Detected Go version: %s", version)
			return version
		}
	}

	log.Debug("Could not detect Go version, using default for tooling")
	return defaultToolingGoTag
}

// upgradePackages handles the main upgrade logic, choosing between in-image and tooling strategies.
func (gm *golangManager) upgradePackages(
	ctx context.Context,
	currentState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
	stdlibFixedVersion string,
) (*llb.State, []string, error) {
	var failedPackages []string

	// Attempt binary rebuild for GoBinary packages. If it fails, fall back to
	// go.mod/go.sum updates which is the standard approach for GoModules packages.
	log.Debug("Attempting Go binary rebuild with updated dependencies")
	rebuiltState, rebuildFailedPkgs, rebuildErr := gm.attemptBinaryRebuild(ctx, currentState, updates, stdlibFixedVersion)
	if rebuildErr == nil {
		log.Debug("Go binary rebuild LLB graph constructed successfully")
		return rebuiltState, rebuildFailedPkgs, nil
	}

	// If the only updates are stdlib vulns (which require binary rebuild), don't
	// fall back to go.mod updates — they can't fix compiled binaries.
	if len(updates) == 0 && stdlibFixedVersion != "" {
		log.Warnf("Binary rebuild failed and only stdlib updates were requested: %v", rebuildErr)
		return currentState, rebuildFailedPkgs, rebuildErr
	}

	// Check if rebuild failed due to missing source provenance
	if strings.Contains(rebuildErr.Error(), "no source commit available") ||
		strings.Contains(rebuildErr.Error(), "no VCS commit info") {
		log.Warn("Binary rebuild failed because image binaries lack source provenance (no VCS info and no OCI labels). " +
			"Falling back to go.mod/go.sum updates, which may not fix all vulnerabilities.")
	} else {
		log.Warnf("Binary rebuild failed, falling back to go.mod/go.sum updates: %v", rebuildErr)
	}

	// Detect if Go toolchain exists in the target image
	goExists, err := gm.detectGo(ctx, currentState)
	if err != nil {
		log.Warnf("Go detection encountered an issue; proceeding assuming Go absent: %v", err)
		goExists = false
	}

	if !goExists {
		log.Debug("Go toolchain not found in target image. Using tooling container strategy.")
		return gm.upgradePackagesWithTooling(ctx, currentState, updates, ignoreErrors)
	}

	log.Debug("Go toolchain found in target image. Updating modules in-place.")

	// Detect go.mod locations
	goModPaths, err := gm.detectGoModules(ctx, currentState)
	if err != nil || len(goModPaths) == 0 {
		log.Warn("No go.mod files detected in image")
		for _, u := range updates {
			failedPackages = append(failedPackages, u.Name)
		}
		return currentState, failedPackages, fmt.Errorf("no go.mod files detected in image; cannot update Go modules")
	}

	// Check for workspace
	workspacePath, _ := gm.detectGoWorkspace(ctx, currentState)

	state := *currentState

	// If workspace exists, update from workspace root
	if workspacePath != "" {
		log.Debugf("Updating Go workspace at %s", workspacePath)
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
			log.Debugf("Updating Go module at %s", modPath)
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

// rebuildFailure captures a single Go binary rebuild failure with the
// binary path and failure reason as separate fields. Using a struct
// rather than a []string of "path: reason" strings avoids fragile
// string parsing in downstream consumers.
type rebuildFailure struct {
	binaryPath string
	reason     string
}

// String implements fmt.Stringer so that slices of rebuildFailure
// produce the same "path: reason" format as the previous []string
// accumulator when formatted with %v.
func (f rebuildFailure) String() string {
	return fmt.Sprintf("%s: %s", f.binaryPath, f.reason)
}

// collectGoBinaryPaths extracts unique binary paths from all gobinary updates,
// including stdlib entries that filterGoPackages strips out. These paths are needed
// for the synthetic binary fallback when go version -m detection fails.
func collectGoBinaryPaths(langUpdates unversioned.LangUpdatePackages) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, u := range langUpdates {
		if (u.Type == utils.GoBinary || u.Type == utils.GoModules) && u.PkgPath != "" && !seen[u.PkgPath] {
			seen[u.PkgPath] = true
			paths = append(paths, u.PkgPath)
		}
	}
	return paths
}

// buildSyntheticBinaryInfo constructs BinaryInfo entries from collected binary paths
// when go version -m detection fails (e.g., distroless/scratch images without a shell).
// binaryPaths comes from collectGoBinaryPaths which includes paths from ALL gobinary
// updates (including stdlib entries stripped by filterGoPackages).
func buildSyntheticBinaryInfo(binaryPaths []string, goVCSURL string) []*provenance.BinaryInfo {
	var binaries []*provenance.BinaryInfo

	for _, p := range binaryPaths {
		path := p
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		// Derive module path from VCS URL (e.g., "https://github.com/org/repo@ref" -> "github.com/org/repo")
		modulePath := ""
		if i := strings.LastIndex(goVCSURL, "@"); i > 0 {
			modulePath = strings.TrimPrefix(goVCSURL[:i], "https://")
		}

		log.Infof("  Synthetic binary: %s (module: %s)", path, modulePath)
		binaries = append(binaries, &provenance.BinaryInfo{
			Path:          path,
			ModulePath:    modulePath,
			Dependencies:  make(map[string]string),
			BuildSettings: map[string]string{"CGO_ENABLED": "0"},
			VCS:           make(map[string]string),
			FileMode:      "0755",
			FileOwner:     "0:0",
		})
	}
	return binaries
}

// attemptBinaryRebuild attempts to rebuild Go binaries using heuristic binary detection.
// When stdlibFixedVersion is set, only binaries built with a Go version older than
// that version are rebuilt for stdlib fixes. Binaries already on a new enough Go
// version are skipped unless they also have dependency updates.
func (gm *golangManager) attemptBinaryRebuild(
	ctx context.Context,
	currentState *llb.State,
	updates unversioned.LangUpdatePackages,
	stdlibFixedVersion string,
) (*llb.State, []string, error) {
	var failedPackages []string

	log.Debug("Attempting Go binary rebuild via heuristic detection")

	// Create rebuilder and detector
	rebuilder := provenance.NewRebuilder()
	detector := provenance.NewDetector()

	// Detect Go binaries using go version -m
	binaries, detectErr := detector.DetectGoBinaries(ctx, gm.config.Client, currentState, gm.config.Platform)
	if detectErr != nil {
		log.Debugf("Binary detection failed: %v", detectErr)
	}

	// Fallback: when detection fails but --go-vcs-url is provided,
	// construct synthetic BinaryInfo from Trivy report data (PkgPath field).
	// This enables Go binary patching on distroless/scratch images where
	// `go version -m` cannot run due to missing shell.
	if (detectErr != nil || len(binaries) == 0) && gm.goVCSURL != "" {
		log.Info("Binary detection unavailable (distroless/scratch image?), falling back to Trivy report + --go-vcs-url")
		binaries = buildSyntheticBinaryInfo(gm.goBinaryPaths, gm.goVCSURL)
		if len(binaries) > 0 {
			log.Infof("Constructed %d synthetic binary entries from Trivy report", len(binaries))
		}
	}

	if len(binaries) == 0 {
		if detectErr != nil {
			return currentState, failedPackages, fmt.Errorf("binary detection failed: %w", detectErr)
		}
		return currentState, failedPackages, fmt.Errorf("no Go binaries detected in image")
	}

	log.Infof("Processing %d Go binaries for rebuild", len(binaries))

	// Log what we found
	for _, bi := range binaries {
		log.Debugf("  Found: %s (%s, %d deps)", bi.Path, bi.GoVersion, len(bi.Dependencies))
		if cgo, ok := bi.BuildSettings["CGO_ENABLED"]; ok {
			log.Debugf("    CGO_ENABLED=%s", cgo)
		}
		if ldflags, ok := bi.BuildSettings["-ldflags"]; ok {
			log.Debugf("    ldflags=%s", ldflags)
		}
	}

	// Build update map from updates (shared across all binaries)
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
	}

	if len(updateMap) == 0 && stdlibFixedVersion == "" {
		return currentState, failedPackages, fmt.Errorf("no version updates to apply")
	}

	if stdlibFixedVersion != "" {
		log.Debugf("Stdlib fix requires Go >= %s - will check each binary individually", stdlibFixedVersion)
	}

	// Track overall results
	state := currentState
	totalRebuilt := 0
	totalAttempted := 0
	var rebuildFailures []rebuildFailure

	// Process each detected binary
	for i, binaryInfo := range binaries {
		binaryPath := binaryInfo.Path
		log.Debugf("Processing binary %d/%d: %s", i+1, len(binaries), binaryPath)

		// Convert this binary's info to build info, using OCI labels as fallback
		// for source identification when VCS info is missing (e.g. -trimpath builds).
		buildInfo := detector.ConvertBinaryInfoToBuildInfoWithLabels(binaryInfo, gm.config.ImageLabels)
		if buildInfo == nil {
			log.Warnf("Could not extract build info for %s, skipping", binaryPath)
			rebuildFailures = append(rebuildFailures, rebuildFailure{binaryPath: binaryPath, reason: "no build info"})
			continue
		}

		// Skip if this is a main module update (can't update the module we're building)
		mainModule := buildInfo.ModulePath
		filteredUpdateMap := make(map[string]string)
		for module, version := range updateMap {
			if module == mainModule || strings.HasPrefix(module, mainModule+"/") {
				log.Debugf("Skipping %s for binary %s: cannot update main module", module, binaryPath)
				continue
			}
			filteredUpdateMap[module] = version
		}

		// Check if this specific binary needs stdlib upgrade by comparing its
		// Go version against the required fix version
		binaryNeedsStdlib := false
		if stdlibFixedVersion != "" {
			binaryGoVersion := strings.TrimPrefix(binaryInfo.GoVersion, "go")
			if isValidGoVersion(binaryGoVersion) && isLessThanGoVersion(binaryGoVersion, stdlibFixedVersion) {
				binaryNeedsStdlib = true
				log.Debugf("  Binary %s (Go %s) needs stdlib upgrade to >= %s", binaryPath, binaryGoVersion, stdlibFixedVersion)
			} else {
				log.Debugf("  Binary %s (Go %s) already has stdlib >= %s, no stdlib rebuild needed", binaryPath, binaryGoVersion, stdlibFixedVersion)
			}
		}

		if len(filteredUpdateMap) == 0 && !binaryNeedsStdlib {
			log.Debugf("No applicable updates for binary %s, skipping", binaryPath)
			continue
		}

		// Log what information we have for this binary
		log.Debugf("  Build info: Go %s, module: %s, CGO: %v",
			buildInfo.GoVersion,
			buildInfo.ModulePath,
			buildInfo.CGOEnabled)

		// Resolve source repository and commit for cloning.
		// Primary: VCS metadata embedded in binary (go version -m).
		// Fallback: OCI standard image labels, already extracted once into gm.config.ImageLabels
		// by buildkit.Config setup — avoid re-parsing the raw image config here.
		sourceRepo := buildInfo.BuildArgs["_sourceRepo"]
		sourceCommit := buildInfo.BuildArgs["_sourceCommit"]
		if sourceCommit == "" && gm.config.ImageLabels != nil {
			ociRevision := gm.config.ImageLabels[ociAnnotationRevision]
			ociSource := gm.config.ImageLabels[ociAnnotationSource]
			if ociRevision != "" {
				log.Infof("  Binary %s has no VCS info; using OCI image label revision: %s", binaryPath, ociRevision)
				sourceCommit = ociRevision
				buildInfo.BuildArgs["_sourceCommit"] = ociRevision
				if sourceRepo == "" && ociSource != "" {
					sourceRepo = ociSource
					buildInfo.BuildArgs["_sourceRepo"] = ociSource
				}
			}
		}

		switch {
		case sourceCommit == "":
			log.Warnf("  Binary %s has no VCS commit info and no OCI revision label. "+
				"Cannot rebuild without source.", binaryPath)
			rebuildFailures = append(rebuildFailures, rebuildFailure{binaryPath: binaryPath, reason: "no source commit available"})
			continue
		case sourceRepo == "":
			log.Warnf("  Binary %s has commit %s but no source repo could be derived. "+
				"Cannot rebuild without source.", binaryPath, sourceCommit)
			rebuildFailures = append(rebuildFailures, rebuildFailure{binaryPath: binaryPath, reason: "no source repo"})
			continue
		default:
			log.Debugf("  Source: %s @ %s", sourceRepo, sourceCommit)
		}

		for module, version := range filteredUpdateMap {
			log.Debugf("  Will update %s to %s", module, version)
		}

		// Create rebuild context for this binary
		rebuildCtx := &provenance.RebuildContext{
			Strategy:         provenance.RebuildStrategyHeuristic,
			BuildInfo:        buildInfo,
			BinaryInfo:       []*provenance.BinaryInfo{binaryInfo},
			ImageLabels:      gm.config.ImageLabels,
			ImageRef:         gm.imageRef,
			GoVCSURL:         gm.goVCSURL,
			ImageSourceLabel: extractOCISourceLabel(gm.config),
		}

		// Attempt to rebuild this binary and merge into current state
		totalAttempted++
		newState, result, err := rebuilder.RebuildBinary(rebuildCtx, filteredUpdateMap, gm.config.Platform, state, binaryPath)
		if err != nil {
			log.Warnf("Failed to rebuild %s (skipping): %v", binaryPath, err)
			rebuildFailures = append(rebuildFailures, rebuildFailure{binaryPath: binaryPath, reason: fmt.Sprintf("%v", err)})
			continue
		}

		if !result.Success {
			log.Warnf("Rebuild unsuccessful for %s (skipping): %v", binaryPath, result.Error)
			rebuildFailures = append(rebuildFailures, rebuildFailure{binaryPath: binaryPath, reason: fmt.Sprintf("%v", result.Error)})
			continue
		}

		// Success - update state for next iteration
		state = &newState
		totalRebuilt++
		log.Debugf("Prepared rebuild for binary: %s", binaryPath)
	}

	// Check if we rebuilt anything
	if totalRebuilt == 0 {
		for module := range updateMap {
			failedPackages = append(failedPackages, module)
		}
		if len(rebuildFailures) > 0 {
			return currentState, failedPackages, fmt.Errorf("no binaries were successfully rebuilt: %v", rebuildFailures)
		}
		return currentState, failedPackages, fmt.Errorf("no binaries were successfully rebuilt")
	}

	if totalRebuilt < totalAttempted {
		log.Warnf("Partial patch: %d/%d attempted binaries rebuilt. Failed: %v", totalRebuilt, totalAttempted, rebuildFailures)
		for _, f := range rebuildFailures {
			failedPackages = append(failedPackages, f.binaryPath)
		}
	} else {
		log.Infof("Prepared rebuild for %d/%d Go binaries", totalRebuilt, totalAttempted)
	}

	return state, failedPackages, nil
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

	// Validate modPath before shell interpolation (comes from target image filesystem)
	if strings.ContainsAny(modPath, shellUnsafeChars) {
		return state, fmt.Errorf("go.mod path contains unsafe characters: %s", modPath)
	}

	// Build list of 'go get' commands with input validation
	var getCommands []string
	for _, u := range updates {
		if u.FixedVersion != "" {
			if strings.ContainsAny(u.Name, shellUnsafeChars) {
				return state, fmt.Errorf("package name contains unsafe characters: %s", u.Name)
			}
			if strings.HasPrefix(u.Name, "-") {
				return state, fmt.Errorf("package name cannot start with '-': %s", u.Name)
			}
			if strings.ContainsAny(u.FixedVersion, shellUnsafeChars) {
				return state, fmt.Errorf("version contains unsafe characters: %s for package %s", u.FixedVersion, u.Name)
			}
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
		log.Debugf("Vendor directory detected, running 'go mod vendor' at %s", modPath)
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
// This uses a golang tooling container to perform the updates.
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
		for _, u := range updates {
			failedPackages = append(failedPackages, u.Name)
		}
		return currentState, failedPackages, fmt.Errorf("no go.mod files detected in image; cannot update Go modules")
	}

	// Detect Go version (or use default)
	goVersion := gm.detectGoVersion(ctx, currentState)
	toolingImage := fmt.Sprintf(toolingGoTemplate, goVersion)

	log.Debugf("Using tooling container: %s", toolingImage)

	state := *currentState

	// Process each module path
	for _, modPath := range goModPaths {
		if strings.ContainsAny(modPath, shellUnsafeChars) {
			return currentState, nil, fmt.Errorf("go.mod path contains unsafe characters: %s", modPath)
		}
		log.Debugf("Updating Go module at %s using tooling container", modPath)

		// Create tooling container state with target platform
		var toolingState llb.State
		if gm.config.Platform != nil {
			toolingState = llb.Image(toolingImage, llb.Platform(*gm.config.Platform))
		} else {
			toolingState = llb.Image(toolingImage)
		}

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

		// Build update commands with input validation
		var getCommands []string
		for _, u := range updates {
			if u.FixedVersion != "" {
				if strings.ContainsAny(u.Name, shellUnsafeChars) {
					return currentState, nil, fmt.Errorf("package name contains unsafe characters: %s", u.Name)
				}
				if strings.HasPrefix(u.Name, "-") {
					return currentState, nil, fmt.Errorf("package name cannot start with '-': %s", u.Name)
				}
				if strings.ContainsAny(u.FixedVersion, shellUnsafeChars) {
					return currentState, nil, fmt.Errorf("version contains unsafe characters: %s for package %s", u.FixedVersion, u.Name)
				}
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
			log.Debug("Vendor directory detected, running 'go mod vendor' in tooling container")
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

// extractOCISourceLabel reads org.opencontainers.image.source from the image's OCI config labels.
// Returns empty string if the label is not present or the config can't be parsed.
func extractOCISourceLabel(config *buildkit.Config) string {
	if config == nil || len(config.ConfigData) == 0 {
		return ""
	}

	var imageConfig struct {
		Config struct {
			Labels map[string]string `json:"labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(config.ConfigData, &imageConfig); err != nil {
		log.Debugf("Could not parse image config for OCI labels: %v", err)
		return ""
	}

	source := imageConfig.Config.Labels["org.opencontainers.image.source"]
	if source != "" {
		log.Debugf("Found OCI label org.opencontainers.image.source: %s", source)
	}
	return source
}
