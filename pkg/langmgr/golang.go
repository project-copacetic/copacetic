package langmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/provenance"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

const goStdlibPackage = "stdlib"

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
	goBinaryGoVersion   string   // Go version from stdlib entries (e.g., "1.26.0")
}

// validateGoPackageName validates a Go module name for safety and correctness.
// Go module names are import paths that should contain at least one slash.
func validateGoPackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name cannot be empty")
	}

	// Skip "stdlib" - this represents Go standard library vulnerabilities
	// which can only be fixed by upgrading Go itself, not by updating dependencies
	if name == goStdlibPackage {
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

// filterGoDowngrades drops updates whose reported fixed version is not newer than
// the installed version. A stale advisory would otherwise downgrade a module that
// has already been patched. Updates with missing or unparsable versions are kept
// so that existing behavior is unchanged. The names of the skipped updates are
// returned so callers can report them as unpatched: the image is left unchanged
// for those modules, so they must not end up in the validated updates that feed
// the VEX document.
func filterGoDowngrades(updates unversioned.LangUpdatePackages) (unversioned.LangUpdatePackages, []string) {
	filtered := make(unversioned.LangUpdatePackages, 0, len(updates))
	var skipped []string
	for _, u := range updates {
		if u.InstalledVersion != "" && u.FixedVersion != "" &&
			isValidGoVersion(u.InstalledVersion) && isValidGoVersion(u.FixedVersion) &&
			!isLessThanGoVersion(u.InstalledVersion, u.FixedVersion) {
			log.Warnf("Skipping Go module %s: installed version %s is not older than fixed version %s", u.Name, u.InstalledVersion, u.FixedVersion)
			skipped = append(skipped, u.Name)
			continue
		}
		filtered = append(filtered, u)
	}
	return filtered, skipped
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

// appendIncompatibleIfNeeded adds the "+incompatible" build tag that `go get`
// requires for pre-modules dependencies released at major version 2 or higher
// whose module path carries no /vN suffix (github.com/docker/docker@v28.0.0,
// for example). Scanner reports commonly omit the tag and `go get` rejects the
// bare version outright. Versions that already carry build metadata are left
// alone: semver allows a single '+' component, so appending here would produce
// an invalid version such as v2.0.0+build1+incompatible.
func appendIncompatibleIfNeeded(modulePath, version string) string {
	if !semver.IsValid(version) || strings.Contains(version, "+") {
		return version
	}

	switch semver.Major(version) {
	case "v0", "v1":
		return version
	}

	// A path major suffix (/v2, /v3, ...) means the dependency is modules-aware,
	// so the version is used as-is.
	if _, pathMajor, ok := module.SplitPathVersion(modulePath); !ok || pathMajor != "" {
		return version
	}

	return version + "+incompatible"
}

// buildGoUpdateCmd assembles the shell command run inside the build container
// to apply `go get` version bumps and then run `go mod tidy -e`. The -e flag
// causes tidy to proceed past errors loading packages so a CVE patch is not
// blocked by unrelated upstream go.mod hygiene issues; the subsequent build
// step still fails loudly if the patched module graph cannot produce a
// working binary.
func buildGoUpdateCmd(modPath, allGetCmd string) string {
	return fmt.Sprintf(`sh -c 'cd %s && %s && go mod tidy -e'`, modPath, allGetCmd)
}

// verifyGoModUpdates confirms that the requested version bumps are reflected in
// the module metadata produced by the update step. `go mod tidy -e` removes
// requirements for modules that are no longer imported by reachable code, so a
// successful `go get` can be silently reverted and the package still reported as
// patched. Modules before go 1.17 record only direct requirements in go.mod, so
// an indirect dependency falls back to the version go.sum says the build
// downloads. workReplaces carries the replace directives of the go.work file
// governing this module, if any: a workspace replacement overrides the member
// module's own metadata, so it decides what the build compiles. A replacement
// that hides the module behind unversioned local contents or a different module
// path leaves the requested version unprovable and is reported as a failure
// rather than assumed patched.
func verifyGoModUpdates(goModContent, goSumContent []byte, workReplaces []*modfile.Replace, updates unversioned.LangUpdatePackages) error {
	hasTargets := false
	for _, u := range updates {
		if u.FixedVersion != "" {
			hasTargets = true
			break
		}
	}
	if !hasTargets {
		return nil
	}

	f, err := modfile.Parse("go.mod", goModContent, nil)
	if err != nil {
		return fmt.Errorf("failed to parse go.mod after update: %w", err)
	}

	required := make(map[string]string, len(f.Require))
	for _, r := range f.Require {
		if r != nil && r.Mod.Path != "" {
			required[r.Mod.Path] = r.Mod.Version
		}
	}
	builtVersions := goSumBuiltVersions(goSumContent)

	for _, u := range updates {
		if u.FixedVersion == "" {
			continue
		}

		requiredVersion, inGoMod := required[u.Name]

		// A go.work replace overrides every member module, so it governs what
		// the workspace build compiles no matter what the member's go.mod says.
		if rep := governingReplacement(workReplaces, u.Name, requiredVersion); rep != nil {
			if err := verifyReplacementVersion(rep, "go.work", u.Name, u.FixedVersion); err != nil {
				return err
			}
			continue
		}

		if !inGoMod {
			if err := verifyGoSumVersions(builtVersions[u.Name], u.Name, u.FixedVersion); err != nil {
				return err
			}
			continue
		}

		if rep := governingReplacement(f.Replace, u.Name, requiredVersion); rep != nil {
			if err := verifyReplacementVersion(rep, "go.mod", u.Name, u.FixedVersion); err != nil {
				return err
			}
			continue
		}
		if isLessThanGoVersion(requiredVersion, u.FixedVersion) {
			return fmt.Errorf("module %s is at %s in go.mod after update, expected %s or newer", u.Name, requiredVersion, u.FixedVersion)
		}
	}

	return nil
}

// verifyReplacementVersion confirms that the code a replacement substitutes can
// be shown to carry the fix. Unversioned local contents and a different module
// path both leave the requested version unprovable, so they are reported as
// failures instead of assumed patched. file names the file the directive came
// from so the failure points at the metadata that has to change.
func verifyReplacementVersion(rep *modfile.Replace, file, modPath, fixedVersion string) error {
	switch {
	case rep.New.Version == "":
		return fmt.Errorf("module %s is replaced in %s by %s, whose contents are unversioned; cannot verify that requested version %s was applied", modPath, file, rep.New.Path, fixedVersion)
	case rep.New.Path != modPath:
		return fmt.Errorf("module %s is replaced in %s by %s@%s; a different module path cannot prove that requested version %s was applied", modPath, file, rep.New.Path, rep.New.Version, fixedVersion)
	case isLessThanGoVersion(rep.New.Version, fixedVersion):
		return fmt.Errorf("module %s is replaced in %s by %s@%s after update, expected %s or newer", modPath, file, rep.New.Path, rep.New.Version, fixedVersion)
	}
	return nil
}

// verifyGoSumVersions checks a module that go.mod does not require against the
// versions go.sum records full contents for. Those are the versions the build
// downloads, so every one of them must carry the fix.
func verifyGoSumVersions(builtVersions []string, modPath, fixedVersion string) error {
	if len(builtVersions) == 0 {
		return fmt.Errorf("module %s not found in go.mod or go.sum after update; the requested version %s was not applied or was removed by 'go mod tidy'", modPath, fixedVersion)
	}
	for _, version := range builtVersions {
		if isLessThanGoVersion(version, fixedVersion) {
			return fmt.Errorf("module %s is at %s in go.sum after update, expected %s or newer", modPath, version, fixedVersion)
		}
	}
	return nil
}

// governingReplacement returns the replace directive that controls modPath at
// selectedVersion, or nil when none applies. Mirroring go.mod resolution, a
// directive pinned to the selected version wins over a path-wide directive.
func governingReplacement(replacements []*modfile.Replace, modPath, selectedVersion string) *modfile.Replace {
	var pinned, pathWide *modfile.Replace
	for _, rep := range replacements {
		if rep == nil || rep.Old.Path != modPath {
			continue
		}
		switch rep.Old.Version {
		case "":
			if pathWide == nil {
				pathWide = rep
			}
		case selectedVersion:
			if pinned == nil {
				pinned = rep
			}
		}
	}
	if pinned != nil {
		return pinned
	}
	return pathWide
}

// goSumBuiltVersions maps module paths to the versions go.sum records full
// module contents for. A "/go.mod" line names a version that exists in the
// module graph without contributing code to the build, so it proves nothing
// about the code in the image.
func goSumBuiltVersions(goSumContent []byte) map[string][]string {
	if len(goSumContent) == 0 {
		return nil
	}
	versions := make(map[string][]string)
	for line := range strings.SplitSeq(string(goSumContent), "\n") {
		modPath, rest, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		version, hash, ok := strings.Cut(rest, " ")
		if !ok || hash == "" || strings.HasSuffix(version, "/go.mod") {
			continue
		}
		versions[modPath] = append(versions[modPath], version)
	}
	return versions
}

// filterUpdatesInGoMod narrows updates to the modules the given module already
// referenced. The update step runs the same `go get` list against every module
// in the image, so verifying all of them against one module would fail modules
// that never depended on the vulnerable package. Modules before go 1.17 keep
// indirect dependencies out of go.mod, so those fall back to go.sum: dropping
// them would leave them unverified while still reported as patched. Callers pass
// the pre-update files so that requirements removed by the update are still
// verified rather than silently excused.
func filterUpdatesInGoMod(goModContent, goSumContent []byte, updates unversioned.LangUpdatePackages) (unversioned.LangUpdatePackages, error) {
	f, err := modfile.Parse("go.mod", goModContent, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}

	present := make(map[string]struct{}, len(f.Require)+len(f.Replace))
	for _, r := range f.Require {
		if r != nil && r.Mod.Path != "" {
			present[r.Mod.Path] = struct{}{}
		}
	}
	for _, rep := range f.Replace {
		if rep != nil && rep.Old.Path != "" {
			present[rep.Old.Path] = struct{}{}
		}
	}
	// From go 1.17 on go.mod records every dependency of the build, so a go.sum
	// entry that go.mod never mentions is a stale checksum rather than a
	// dependency. Counting it would demand a version bump from a module that
	// does not use the package.
	if !goModListsAllDependencies(f) {
		for modPath := range goSumBuiltVersions(goSumContent) {
			present[modPath] = struct{}{}
		}
	}

	var applicable unversioned.LangUpdatePackages
	for _, u := range updates {
		if _, ok := present[u.Name]; ok {
			applicable = append(applicable, u)
		}
	}
	return applicable, nil
}

// goModListsAllDependencies reports whether the module's go directive selects
// the module graph pruning added in go 1.17, from which go.mod records every
// dependency of the build, direct and indirect. Before that only direct
// requirements appear, leaving go.sum as the sole record of the rest.
func goModListsAllDependencies(f *modfile.File) bool {
	if f == nil || f.Go == nil || f.Go.Version == "" {
		return false
	}
	return !isLessThanGoVersion(f.Go.Version, "1.17")
}

// unverifiedUpdateNames returns the names of every requested update that is not
// proven yet. pendingProofs holds, per package, the number of modules
// accountable for it that still have to be checked; a package missing from the
// map was never observed in any module and is unproven as well. A verification
// step that cannot finish must report all of them, since an unproven package
// left out of the failure list is reported as remediated.
func unverifiedUpdateNames(updates unversioned.LangUpdatePackages, pendingProofs map[string]int) []string {
	names := make([]string, 0, len(updates))
	for _, u := range updates {
		if remaining, tracked := pendingProofs[u.Name]; tracked && remaining <= 0 {
			continue
		}
		names = append(names, u.Name)
	}
	return names
}

// goWorkspace holds the parts of a go.work file that decide what a workspace
// build compiles: the member modules and the replacements the workspace forces
// on all of them.
type goWorkspace struct {
	memberDirs   []string
	replacements []*modfile.Replace
}

// parseGoWorkspace resolves the directory of every module listed by a go.work
// file, relative to the workspace root, along with the workspace-wide replace
// directives. A workspace root has no authoritative go.mod of its own:
// requirements land in the member modules, so those are the modules to verify.
// The replacements travel with them because a go.work replace overrides the
// member modules and decides which code the build uses, so a module redirected
// there cannot be proven patched from a member's go.mod alone.
func parseGoWorkspace(goWorkContent []byte, workRoot string) (*goWorkspace, error) {
	f, err := modfile.ParseWork("go.work", goWorkContent, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.work: %w", err)
	}

	ws := &goWorkspace{replacements: f.Replace}
	for _, use := range f.Use {
		if use == nil || use.Path == "" {
			continue
		}
		dir := use.Path
		if !path.IsAbs(dir) {
			dir = path.Join(workRoot, dir)
		}
		ws.memberDirs = append(ws.memberDirs, path.Clean(dir))
	}
	if len(ws.memberDirs) == 0 {
		return nil, fmt.Errorf("go.work at %s lists no module directories; cannot verify Go module updates", workRoot)
	}
	return ws, nil
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
			if pkg.Name == goStdlibPackage {
				fixVer := cleanGoVersion(pkg.FixedVersion)
				if fixVer != "" && (stdlibFixedVersion == "" || isLessThanGoVersion(stdlibFixedVersion, fixVer)) {
					stdlibFixedVersion = fixVer
				}
				log.Debugf("Found stdlib vulnerability: %s → %s (will fix via Go compiler upgrade)", pkg.InstalledVersion, pkg.FixedVersion)
				continue
			}
			goPackages = append(goPackages, pkg)
			log.Debugf("filterGoPackages: keeping %s@%s → %s (type=%s, path=%s)", pkg.Name, pkg.InstalledVersion, pkg.FixedVersion, pkg.Type, pkg.PkgPath)
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
	gm.goBinaryPaths, gm.goBinaryGoVersion = collectGoBinaryInfo(manifest.LangUpdates)

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

	updatesToAttempt, skippedDowngrades := filterGoDowngrades(updatesToAttempt)
	// Skipped downgrades leave the module untouched in the image, so report them
	// as unpatched to keep them out of the validated updates used for VEX.
	errPkgsReported = append(errPkgsReported, skippedDowngrades...)
	if len(updatesToAttempt) == 0 && !hasStdlib {
		log.Warn("No Go update packages remain to apply after filtering out non-newer fixed versions.")
		return currentState, errPkgsReported, nil
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
		var modFailedPkgs []string
		state, modFailedPkgs, err = gm.updateGoModule(ctx, &state, workspacePath, updates, true, ignoreErrors)
		if err != nil {
			log.Errorf("Failed to update workspace: %v", err)
			// Report the affected packages either way: with errors ignored they
			// must still surface as unpatched instead of being claimed as fixed.
			failedPackages = append(failedPackages, modFailedPkgs...)
			if !ignoreErrors {
				return currentState, failedPackages, err
			}
		}
	} else {
		// Update each module independently
		for _, modPath := range goModPaths {
			log.Debugf("Updating Go module at %s", modPath)
			newState, modFailedPkgs, modErr := gm.updateGoModule(ctx, &state, modPath, updates, false, ignoreErrors)
			if modErr != nil {
				log.Errorf("Failed to update module at %s: %v", modPath, modErr)
				failedPackages = append(failedPackages, modFailedPkgs...)
				if !ignoreErrors {
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

// collectGoBinaryInfo extracts unique binary paths and the installed Go version
// from all gobinary updates, including stdlib entries that filterGoPackages strips.
func collectGoBinaryInfo(langUpdates unversioned.LangUpdatePackages) (paths []string, goVersion string) {
	seen := make(map[string]bool)
	for _, u := range langUpdates {
		// Only gobinary entries carry binary paths via PkgPath. GoModules entries' PkgPath
		// points at go.mod/go.sum locations which are not useful for synthetic BinaryInfo.
		if u.Type != utils.GoBinary {
			continue
		}
		// Extract Go version from stdlib entries (e.g., "v1.26.0" -> "1.26.0").
		if u.Name == goStdlibPackage && goVersion == "" && u.InstalledVersion != "" {
			goVersion = strings.TrimPrefix(u.InstalledVersion, "v")
		}
		if u.PkgPath != "" && !seen[u.PkgPath] {
			seen[u.PkgPath] = true
			paths = append(paths, u.PkgPath)
		}
	}
	return
}

// buildSyntheticBinaryInfo constructs BinaryInfo entries from collected binary paths
// when go version -m detection fails (e.g., distroless/scratch images without a shell).
// binaryPaths comes from collectGoBinaryPaths which includes paths from ALL gobinary
// updates (including stdlib entries stripped by filterGoPackages).
func buildSyntheticBinaryInfo(binaryPaths []string, goVCSURL string, goVersion string) []*provenance.BinaryInfo {
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
			GoVersion:     goVersion, // from stdlib InstalledVersion or empty
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

// buildBinaryUpdateMap collects the module requirements shared across every
// binary rebuilt from an image. Versions are normalized the same way the
// in-image `go get` path normalizes them: a missing 'v' prefix is added and
// pre-modules major>=2 dependencies gain the +incompatible build tag, since the
// rebuild writes these values straight into go.mod requirements.
func buildBinaryUpdateMap(updates unversioned.LangUpdatePackages) map[string]string {
	updateMap := make(map[string]string)
	log.Debugf("[updateMap] building from %d updates", len(updates))
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

		version := update.FixedVersion
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
		updateMap[update.Name] = appendIncompatibleIfNeeded(update.Name, version)
	}
	return updateMap
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
		binaries = buildSyntheticBinaryInfo(gm.goBinaryPaths, gm.goVCSURL, gm.goBinaryGoVersion)
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

	updateMap := buildBinaryUpdateMap(updates)

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

	// Image-level metadata reused across every binary in this image. Parse once to avoid
	// re-unmarshalling the OCI config for every binary.
	imageSourceLabel := extractOCISourceLabel(gm.config)

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
			switch {
			case binaryGoVersion == "":
				// Synthetic binaries from distroless fallback have no Go version info.
				// Assume they need stdlib rebuild since we can't prove otherwise.
				binaryNeedsStdlib = true
				log.Infof("  Binary %s has unknown Go version (synthetic), assuming stdlib rebuild needed", binaryPath)
			case isValidGoVersion(binaryGoVersion) && isLessThanGoVersion(binaryGoVersion, stdlibFixedVersion):
				binaryNeedsStdlib = true
				log.Infof("  Binary %s (Go %s) needs stdlib upgrade to >= %s", binaryPath, binaryGoVersion, stdlibFixedVersion)
			default:
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

		// Resolution paths cloneSourceCode supports: VCS metadata (sourceCommit + sourceRepo),
		// --go-vcs-url override, OCI source label + image tag, or image-tag heuristic. Only
		// fail-fast here when none of these can fire; otherwise let cloneSourceCode try and
		// produce its specific error if every fallback ultimately fails.
		hasFallback := gm.goVCSURL != "" || imageSourceLabel != "" || gm.imageRef != ""
		switch {
		case sourceCommit == "" && sourceRepo == "" && !hasFallback:
			log.Warnf("  Binary %s has no VCS info, no --go-vcs-url, no OCI source label, "+
				"and no image tag. Cannot rebuild without source.", binaryPath)
			rebuildFailures = append(rebuildFailures, rebuildFailure{binaryPath: binaryPath, reason: "no source resolution path"})
			continue
		case sourceCommit != "" && sourceRepo == "" && !hasFallback:
			log.Warnf("  Binary %s has commit %s but no source repo and no fallback. "+
				"Cannot rebuild without source.", binaryPath, sourceCommit)
			rebuildFailures = append(rebuildFailures, rebuildFailure{binaryPath: binaryPath, reason: "no source repo"})
			continue
		default:
			if sourceCommit != "" && sourceRepo != "" {
				log.Debugf("  Source: %s @ %s", sourceRepo, sourceCommit)
			} else {
				log.Debugf("  Source: deferring resolution to cloneSourceCode (fallback path)")
			}
		}

		for module, version := range filteredUpdateMap {
			log.Debugf("  Will update %s to %s", module, version)
		}

		rebuildCtx := &provenance.RebuildContext{
			Strategy:         provenance.RebuildStrategyHeuristic,
			BuildInfo:        buildInfo,
			BinaryInfo:       []*provenance.BinaryInfo{binaryInfo},
			ImageLabels:      gm.config.ImageLabels,
			ImageRef:         gm.imageRef,
			GoVCSURL:         gm.goVCSURL,
			ImageSourceLabel: imageSourceLabel,
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

		// Verify the rebuild actually works by doing an intermediate Solve.
		// RebuildBinary only constructs the LLB graph — it doesn't execute it.
		// Without this check, Copa logs success but the build may fail later.
		verifyDef, verifyErr := newState.Marshal(ctx)
		if verifyErr != nil {
			log.Warnf("Failed to marshal rebuild state for %s (skipping): %v", binaryPath, verifyErr)
			rebuildFailures = append(rebuildFailures, rebuildFailure{binaryPath: binaryPath, reason: fmt.Sprintf("marshal error: %v", verifyErr)})
			continue
		}
		_, solveErr := gm.config.Client.Solve(ctx, gwclient.SolveRequest{
			Definition: verifyDef.ToPB(),
		})
		if solveErr != nil {
			log.Warnf("Binary rebuild for %s built LLB successfully but execution failed (skipping): %v", binaryPath, solveErr)
			rebuildFailures = append(rebuildFailures, rebuildFailure{binaryPath: binaryPath, reason: fmt.Sprintf("build execution failed: %v", solveErr)})
			continue
		}

		// Verified — update state for next iteration
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

// goVerifyTarget pairs a module's metadata files with the subset of requested
// updates that module is accountable for, captured before the update step
// mutates them. workReplaces holds the replace directives of the go.work file
// governing the module, if any, because they override the module's own metadata.
type goVerifyTarget struct {
	goModPath    string
	goSumPath    string
	workReplaces []*modfile.Replace
	updates      unversioned.LangUpdatePackages
}

// readOptionalGoSum returns the contents of goSumPath, or nil when the module
// has no go.sum. A module without external dependencies ships none, so absence
// is not a failure, while a broken solve still surfaces as an error.
func (gm *golangManager) readOptionalGoSum(ctx context.Context, state *llb.State, goSumPath string) ([]byte, error) {
	exists, err := common.StateFileExists(ctx, gm.config.Client, state, gm.config.Platform, goSumPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat %s: %w", goSumPath, err)
	}
	if !exists {
		return nil, nil
	}
	return buildkit.ExtractFileFromState(ctx, gm.config.Client, state, goSumPath)
}

// collectGoVerifyTargets records which modules to verify after the update and,
// for each, the updates it already referenced. For a workspace the go.work root
// has no authoritative go.mod, so every member module is collected instead,
// carrying the workspace replacements that override them.
// Reading the pre-update files matters twice over: it scopes verification to
// modules that actually depended on the vulnerable package, and it still catches
// requirements that the update step dropped.
func (gm *golangManager) collectGoVerifyTargets(
	ctx context.Context,
	state *llb.State,
	modPath string,
	isWorkspace bool,
	updates unversioned.LangUpdatePackages,
) ([]goVerifyTarget, error) {
	modDirs := []string{modPath}
	var workReplaces []*modfile.Replace
	if isWorkspace {
		goWorkBytes, err := buildkit.ExtractFileFromState(ctx, gm.config.Client, state, modPath+"/go.work")
		if err != nil {
			return nil, fmt.Errorf("failed to read %s/go.work: %w", modPath, err)
		}
		ws, err := parseGoWorkspace(goWorkBytes, modPath)
		if err != nil {
			return nil, err
		}
		modDirs, workReplaces = ws.memberDirs, ws.replacements
	}

	targets := make([]goVerifyTarget, 0, len(modDirs))
	for _, modDir := range modDirs {
		goModPath, goSumPath := modDir+"/go.mod", modDir+"/go.sum"
		goModBytes, err := buildkit.ExtractFileFromState(ctx, gm.config.Client, state, goModPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s before update: %w", goModPath, err)
		}
		goSumBytes, err := gm.readOptionalGoSum(ctx, state, goSumPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s before update: %w", goSumPath, err)
		}
		applicable, err := filterUpdatesInGoMod(goModBytes, goSumBytes, updates)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", goModPath, err)
		}
		if len(applicable) == 0 {
			log.Debugf("No requested Go updates apply to %s, skipping verification", goModPath)
			continue
		}
		targets = append(targets, goVerifyTarget{
			goModPath:    goModPath,
			goSumPath:    goSumPath,
			workReplaces: workReplaces,
			updates:      applicable,
		})
	}
	return targets, nil
}

// updateGoModule updates a single Go module or workspace. On failure it returns
// the names of the packages left unpatched so callers can report them.
func (gm *golangManager) updateGoModule(
	ctx context.Context,
	currentState *llb.State,
	modPath string,
	updates unversioned.LangUpdatePackages,
	isWorkspace bool,
	ignoreErrors bool,
) (llb.State, []string, error) {
	state := *currentState

	// Validate modPath before shell interpolation (comes from target image filesystem)
	if strings.ContainsAny(modPath, shellUnsafeChars) {
		return state, getPackageNames(updates), fmt.Errorf("go.mod path contains unsafe characters: %s", modPath)
	}

	// Build list of 'go get' commands with input validation
	var getCommands []string
	for _, u := range updates {
		if u.FixedVersion != "" {
			if strings.ContainsAny(u.Name, shellUnsafeChars) {
				return state, getPackageNames(updates), fmt.Errorf("package name contains unsafe characters: %s", u.Name)
			}
			if strings.HasPrefix(u.Name, "-") {
				return state, getPackageNames(updates), fmt.Errorf("package name cannot start with '-': %s", u.Name)
			}
			if strings.ContainsAny(u.FixedVersion, shellUnsafeChars) {
				return state, getPackageNames(updates), fmt.Errorf("version contains unsafe characters: %s for package %s", u.FixedVersion, u.Name)
			}
			// Ensure version has 'v' prefix
			version := u.FixedVersion
			if !strings.HasPrefix(version, "v") {
				version = "v" + version
			}
			version = appendIncompatibleIfNeeded(u.Name, version)
			spec := fmt.Sprintf("%s@%s", u.Name, version)
			getCommands = append(getCommands, fmt.Sprintf("go get %s", spec))
		} else {
			log.Warnf("No fixed version for %s, skipping", u.Name)
		}
	}

	if len(getCommands) == 0 {
		log.Debug("No package updates to apply")
		return state, nil, nil
	}

	// Record what to verify while the pre-update go.mod files are still intact.
	verifyTargets, err := gm.collectGoVerifyTargets(ctx, &state, modPath, isWorkspace, updates)
	if err != nil {
		return state, getPackageNames(updates), err
	}

	// Execute all 'go get' commands
	allGetCmd := strings.Join(getCommands, " && ")

	// Add 'go mod tidy -e' after updates. The -e flag tolerates broken
	// upstream go.mod files (missing transitive packages, stale module
	// paths) so a CVE patch is not blocked by unrelated upstream module
	// hygiene issues. The subsequent `go build` will still fail loudly
	// if the patched module graph cannot produce a working binary.
	updateCmd := buildGoUpdateCmd(modPath, allGetCmd)

	log.Debugf("Executing Go module updates: %s", updateCmd)

	state = state.Run(
		llb.Shlex(updateCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Confirm the bumps survived 'go mod tidy -e' instead of trusting the exit
	// code. A workspace runs the same `go get` list in every member module, so a
	// package is proven only once every member accountable for it has been
	// checked: proving it in one member says nothing about another member that
	// still requires the vulnerable version. Any failure reports every update
	// still lacking proof, since a workspace aborts with later members unread and
	// an unreported package is treated as remediated.
	pendingProofs := make(map[string]int, len(updates))
	for _, target := range verifyTargets {
		for _, u := range target.updates {
			pendingProofs[u.Name]++
		}
	}
	for _, target := range verifyTargets {
		goModBytes, extractErr := buildkit.ExtractFileFromState(ctx, gm.config.Client, &state, target.goModPath)
		if extractErr != nil {
			return state, unverifiedUpdateNames(updates, pendingProofs), fmt.Errorf("failed to read %s after update: %w", target.goModPath, extractErr)
		}
		goSumBytes, goSumErr := gm.readOptionalGoSum(ctx, &state, target.goSumPath)
		if goSumErr != nil {
			return state, unverifiedUpdateNames(updates, pendingProofs), fmt.Errorf("failed to read %s after update: %w", target.goSumPath, goSumErr)
		}
		if verifyErr := verifyGoModUpdates(goModBytes, goSumBytes, target.workReplaces, target.updates); verifyErr != nil {
			return state, unverifiedUpdateNames(updates, pendingProofs), fmt.Errorf("go module update verification failed for %s: %w", target.goModPath, verifyErr)
		}
		for _, u := range target.updates {
			pendingProofs[u.Name]--
		}
	}

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

	return state, nil, nil
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

	// Validate every module path before one of them is interpolated into a shell
	// command further down.
	for _, modPath := range goModPaths {
		if strings.ContainsAny(modPath, shellUnsafeChars) {
			return currentState, getPackageNames(updates), fmt.Errorf("go.mod path contains unsafe characters: %s", modPath)
		}
	}

	// Record which updates each module is accountable for before any module is
	// touched. The same `go get` list runs against every module in the image, so
	// verifying all of them against one module would fail a module that never
	// depended on the vulnerable package. Collecting up front also keeps
	// reporting honest: a failure partway through leaves the remaining modules
	// unprocessed, and the packages they carry must still be reported as
	// unpatched instead of assumed remediated.
	accountableUpdates := make(map[string]unversioned.LangUpdatePackages, len(goModPaths))
	pendingProofs := make(map[string]int, len(updates))
	for _, modPath := range goModPaths {
		targets, targetErr := gm.collectGoVerifyTargets(ctx, currentState, modPath, false, updates)
		if targetErr != nil {
			return currentState, getPackageNames(updates), targetErr
		}
		for _, target := range targets {
			accountableUpdates[modPath] = target.updates
			for _, u := range target.updates {
				pendingProofs[u.Name]++
			}
		}
	}

	// Process each module path
	for _, modPath := range goModPaths {
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
					return currentState, getPackageNames(updates), fmt.Errorf("package name contains unsafe characters: %s", u.Name)
				}
				if strings.HasPrefix(u.Name, "-") {
					return currentState, getPackageNames(updates), fmt.Errorf("package name cannot start with '-': %s", u.Name)
				}
				if strings.ContainsAny(u.FixedVersion, shellUnsafeChars) {
					return currentState, getPackageNames(updates), fmt.Errorf("version contains unsafe characters: %s for package %s", u.FixedVersion, u.Name)
				}
				version := u.FixedVersion
				if !strings.HasPrefix(version, "v") {
					version = "v" + version
				}
				version = appendIncompatibleIfNeeded(u.Name, version)
				spec := fmt.Sprintf("%s@%s", u.Name, version)
				getCommands = append(getCommands, fmt.Sprintf("go get %s", spec))
			}
		}

		if len(getCommands) == 0 {
			continue
		}

		moduleUpdates := accountableUpdates[modPath]

		allGetCmd := strings.Join(getCommands, " && ")
		// -e tolerates broken upstream go.mod files; see comment in the
		// primary updateCmd above.
		updateCmd := buildGoUpdateCmd("/workspace", allGetCmd)

		log.Debugf("Executing in tooling container: %s", updateCmd)

		toolingState = toolingState.Dir("/workspace").Run(
			llb.Shlex(updateCmd),
			llb.WithProxy(utils.GetProxy()),
		).Root()

		// Confirm the bumps survived 'go mod tidy -e' instead of trusting the
		// exit code. A failure reports every update still lacking proof: the
		// modules queued behind this one are never processed, so their packages
		// must not be claimed as remediated. The tooling container is handed only
		// this module's go.mod and go.sum, so no workspace replacements apply.
		if len(moduleUpdates) > 0 {
			goModBytes, extractErr := buildkit.ExtractFileFromState(ctx, gm.config.Client, &toolingState, "/workspace/go.mod")
			if extractErr != nil {
				return currentState, unverifiedUpdateNames(updates, pendingProofs), fmt.Errorf("failed to read go.mod after update at %s: %w", modPath, extractErr)
			}
			goSumBytes, goSumErr := gm.readOptionalGoSum(ctx, &toolingState, "/workspace/go.sum")
			if goSumErr != nil {
				return currentState, unverifiedUpdateNames(updates, pendingProofs), fmt.Errorf("failed to read go.sum after update at %s: %w", modPath, goSumErr)
			}
			if verifyErr := verifyGoModUpdates(goModBytes, goSumBytes, nil, moduleUpdates); verifyErr != nil {
				return currentState, unverifiedUpdateNames(updates, pendingProofs), fmt.Errorf("go module update verification failed at %s: %w", modPath, verifyErr)
			}
			for _, u := range moduleUpdates {
				pendingProofs[u.Name]--
			}
		}

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
