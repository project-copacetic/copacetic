package langmgr

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const defaultPipInstallTimeoutSeconds = 300
const pipCheckFile = "/copa-pip-check"
const sitePackagesDetectFile = "/copa-site-packages-path"
const defaultToolingPythonTag = "3-slim" // fallback tooling image tag if version can't be inferred
const toolingImageTemplate = "docker.io/library/python:%s"

type pythonManager struct {
	config        *buildkit.Config
	workingFolder string
}

// validPythonPackageNamePattern defines the regex pattern for valid Python package names
// Based on PEP 508: https://www.python.org/dev/peps/pep-0508/
var validPythonPackageNamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// validatePythonPackageName validates that a package name is safe for use in shell commands.
func validatePythonPackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name cannot be empty")
	}
	if len(name) > 214 {
		return fmt.Errorf("package name too long (max 214 characters)")
	}
	if !validPythonPackageNamePattern.MatchString(name) {
		return fmt.Errorf("invalid package name format: %s", name)
	}
	// Additional safety checks for shell injection
	if strings.ContainsAny(name, ";&|`$(){}[]<>\"'\\") {
		return fmt.Errorf("package name contains unsafe characters: %s", name)
	}
	return nil
}

// validatePythonVersion validates that a version string is safe for use in shell commands.
func validatePythonVersion(version string) error {
	if version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	// Check if it's a valid PEP440 version
	if !isValidPythonVersion(version) {
		return fmt.Errorf("invalid version format: %s", version)
	}
	// Additional safety checks for shell injection
	if strings.ContainsAny(version, ";&|`$(){}[]<>\"'\\") {
		return fmt.Errorf("version contains unsafe characters: %s", version)
	}
	return nil
}

// isValidPythonVersion checks if a version string is a valid PEP440 version.
func isValidPythonVersion(v string) bool {
	_, err := pep440.Parse(v)
	return err == nil
}

// isLessThanPythonVersion compares two PEP440 version strings.
// It returns true if v1 is less than v2, and false if there's an error.
func isLessThanPythonVersion(v1, v2 string) bool {
	ver1, err1 := pep440.Parse(v1)
	if err1 != nil {
		log.Warnf("Error parsing Python version '%s': %v", v1, err1)
		return false
	}
	ver2, err2 := pep440.Parse(v2)
	if err2 != nil {
		log.Warnf("Error parsing Python version '%s': %v", v2, err2)
		return false
	}
	return ver1.LessThan(ver2)
}

// filterPythonPackages returns only the packages that are Python packages.
func filterPythonPackages(langUpdates unversioned.LangUpdatePackages) unversioned.LangUpdatePackages {
	var pythonPackages unversioned.LangUpdatePackages
	for _, pkg := range langUpdates {
		if pkg.Type == utils.PythonPackages {
			pythonPackages = append(pythonPackages, pkg)
		}
	}
	return pythonPackages
}

func (pm *pythonManager) InstallUpdates(
	ctx context.Context,
	currentState *llb.State,
	manifest *unversioned.UpdateManifest,
	ignoreErrors bool,
) (*llb.State, []string, error) {
	var errPkgsReported []string // Packages that will be reported as problematic

	// Filter for Python packages only
	pythonUpdates := filterPythonPackages(manifest.LangUpdates)
	if len(pythonUpdates) == 0 {
		log.Debug("No Python packages found to update.")
		return currentState, []string{}, nil
	}

	pythonComparer := VersionComparer{isValidPythonVersion, isLessThanPythonVersion}
	updatesToAttempt, err := GetUniqueLatestUpdates(pythonUpdates, pythonComparer, ignoreErrors)
	if err != nil {
		// Collect error packages when GetUniqueLatestUpdates fails
		for _, u := range pythonUpdates {
			errPkgsReported = append(errPkgsReported, u.Name)
		}
		return currentState, errPkgsReported, fmt.Errorf("failed to determine unique latest Python updates: %w", err)
	}

	if len(updatesToAttempt) == 0 {
		log.Warn("No Python update packages were specified to apply.")
		return currentState, []string{}, nil
	}
	log.Debugf("Attempting to update latest unique pips: %v", updatesToAttempt)

	// Perform the upgrade.
	updatedImageState, resultsBytes, upgradeErr := pm.upgradePackages(ctx, currentState, updatesToAttempt, ignoreErrors)
	if upgradeErr != nil {
		log.Errorf("Failed to upgrade Python packages: %v. Cannot proceed to validation.", upgradeErr)
		if !ignoreErrors {
			for _, u := range updatesToAttempt {
				errPkgsReported = append(errPkgsReported, u.Name)
			}
			return currentState, errPkgsReported, fmt.Errorf("python package upgrade operation failed: %w", upgradeErr)
		}
		log.Warnf("Python package upgrade operation failed but errors are ignored. Original image state will be used.")
		for _, u := range updatesToAttempt {
			errPkgsReported = append(errPkgsReported, u.Name)
		}
		return currentState, errPkgsReported, nil
	}

	// If upgradePackages succeeded, upgradeErr is nil. Now validate.
	failedValidationPkgs, validationErr := pm.validatePythonPackageVersions(
		ctx, resultsBytes, updatesToAttempt, ignoreErrors)

	if len(failedValidationPkgs) > 0 {
		log.Warnf("Python packages failed version validation: %v", failedValidationPkgs)
		for _, pkgName := range failedValidationPkgs {
			if !slices.Contains(errPkgsReported, pkgName) {
				errPkgsReported = append(errPkgsReported, pkgName)
			}
		}
	}

	if validationErr != nil {
		log.Warnf("Python package validation reported issues: %v", validationErr)
		if !ignoreErrors {
			return updatedImageState, errPkgsReported, fmt.Errorf("python package validation failed: %w", validationErr)
		}
		log.Warnf("Python package validation issues were ignored. Problematic packages: %v", errPkgsReported)
	}

	if len(errPkgsReported) > 0 {
		log.Infof("Python packages reported as problematic (failed update or validation): %v", errPkgsReported)
	} else {
		log.Info("All Python packages successfully updated and validated.")
	}

	return updatedImageState, errPkgsReported, nil
}

// validatePythonPackageVersions checks if the installed packages match the expected versions.
// resultsBytes: content of 'pip freeze' for the relevant packages.
// expectedUpdates: list of packages that were attempted to be updated.
// ignoreErrors: if true, validation failures are logged as warnings instead of returning an error.
func (pm *pythonManager) validatePythonPackageVersions(
	_ context.Context,
	resultsBytes []byte,
	expectedUpdates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) ([]string, error) {
	var failedPackages []string
	var validationIssues []string

	if resultsBytes == nil {
		if len(expectedUpdates) > 0 {
			log.Warn("validatePythonPackageVersions: resultsBytes is nil, cannot validate package versions.")
			for _, pkgUpdate := range expectedUpdates {
				failedPackages = append(failedPackages, pkgUpdate.Name)
				validationIssues = append(validationIssues, fmt.Sprintf("package %s: no freeze data to validate", pkgUpdate.Name))
			}
			if !ignoreErrors && len(failedPackages) > 0 {
				uniqueFailedPkgsList := utils.DeduplicateStringSlice(failedPackages)
				return uniqueFailedPkgsList, fmt.Errorf(
					"failed to validate python packages: %s", strings.Join(validationIssues, "; "))
			}
		}
		return failedPackages, nil
	}

	installedPkgs := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(resultsBytes)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Handle strict package==version format first
		if parts := strings.SplitN(line, "==", 2); len(parts) == 2 {
			pkgName := strings.TrimSpace(parts[0])
			version := strings.TrimSpace(parts[1])
			installedPkgs[pkgName] = version
		} else {
			// Handle other formats that might be encountered in pip freeze output
			// Examples: "package>=1.0", "package~=1.0", etc.
			// For compatibility, we'll extract the package name but skip version parsing
			// since we only care about packages with exact version matches (==)
			log.Debugf("Skipping line without strict '==' format in pip freeze output: %s", line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error reading pip freeze results: %v", err)
		for _, pkgUpdate := range expectedUpdates {
			failedPackages = append(failedPackages, pkgUpdate.Name)
		}
		// Create a unique list of failed packages
		uniqueFailedPkgsList := utils.DeduplicateStringSlice(failedPackages)
		return uniqueFailedPkgsList, fmt.Errorf("error reading pip freeze results: %w", err)
	}

	for _, expectedPkg := range expectedUpdates {
		actualVersion, found := installedPkgs[expectedPkg.Name]
		if !found {
			errMsg := fmt.Sprintf("package %s was not found in pip freeze output after update attempt", expectedPkg.Name)
			validationIssues = append(validationIssues, errMsg)
			failedPackages = append(failedPackages, expectedPkg.Name)
			log.Warnf("%s", errMsg)
			continue
		}

		if !isValidPythonVersion(actualVersion) {
			errMsg := fmt.Sprintf("package %s has an invalid actual version format: %s", expectedPkg.Name, actualVersion)
			validationIssues = append(validationIssues, errMsg)
			failedPackages = append(failedPackages, expectedPkg.Name)
			log.Warnf("%s", errMsg)
			continue
		}

		if expectedPkg.FixedVersion != "" {
			if !isValidPythonVersion(expectedPkg.FixedVersion) {
				errMsg := fmt.Sprintf("package %s has an invalid expected fixed version format: %s",
					expectedPkg.Name, expectedPkg.FixedVersion)
				validationIssues = append(validationIssues, errMsg)
				failedPackages = append(failedPackages, expectedPkg.Name)
				log.Warnf("%s", errMsg)
				continue
			}

			vActual, _ := pep440.Parse(actualVersion)
			vExpected, _ := pep440.Parse(expectedPkg.FixedVersion)

			if !vActual.Equal(vExpected) {
				errMsg := fmt.Sprintf("package %s: expected version %s, but found %s",
					expectedPkg.Name, expectedPkg.FixedVersion, actualVersion)
				validationIssues = append(validationIssues, errMsg)
				failedPackages = append(failedPackages, expectedPkg.Name)
				log.Warnf("%s", errMsg)
			}
		} else {
			if expectedPkg.InstalledVersion != "" && isValidPythonVersion(expectedPkg.InstalledVersion) {
				vActual, _ := pep440.Parse(actualVersion)
				vInstalled, errInstalled := pep440.Parse(expectedPkg.InstalledVersion)
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

	var uniqueFailedPkgsList []string
	if len(failedPackages) > 0 {
		uniqueFailedPkgsList = utils.DeduplicateStringSlice(failedPackages)
	}

	if len(validationIssues) > 0 {
		summaryError := errors.New(strings.Join(validationIssues, "; "))
		if !ignoreErrors {
			return uniqueFailedPkgsList, summaryError
		}
		log.Warnf("Python package validation issues (ignored): %v", summaryError)
	}

	return uniqueFailedPkgsList, nil
}

func (pm *pythonManager) upgradePackages(
	ctx context.Context,
	currentState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, []byte, error) {
	var installPkgSpecs []string
	for _, u := range updates {
		// Validate package name for security
		if err := validatePythonPackageName(u.Name); err != nil {
			log.Errorf("Invalid package name %s: %v", u.Name, err)
			if !ignoreErrors {
				return nil, nil, fmt.Errorf("package name validation failed for %s: %w", u.Name, err)
			}
			continue
		}

		if u.FixedVersion != "" {
			// Validate version for security
			if err := validatePythonVersion(u.FixedVersion); err != nil {
				log.Errorf("Invalid version %s for package %s: %v", u.FixedVersion, u.Name, err)
				if !ignoreErrors {
					return nil, nil, fmt.Errorf("version validation failed for %s: %w", u.Name, err)
				}
				continue
			}
			// Use validated package name and version to create spec
			installPkgSpecs = append(installPkgSpecs, u.Name+"=="+u.FixedVersion)
		}
	}

	if len(installPkgSpecs) == 0 {
		log.Info("No Python packages to install or upgrade.")
		return currentState, []byte{}, nil
	}

	// First, detect if pip (or pip3) exists in the target image. If not, use tooling container fallback.
	pipExists, detectErr := pm.detectPip(ctx, currentState)
	if detectErr != nil {
		log.Warnf("pip detection encountered an issue; proceeding assuming pip absent: %v", detectErr)
	}

	if !pipExists {
		log.Infof("pip not found in target image. Falling back to tooling container strategy for Python updates.")
		return pm.upgradePackagesWithTooling(ctx, currentState, installPkgSpecs)
	}

	// Install all requested update packages using validated package specifications directly in target image
	pipInstalled := pm.installPythonPackages(currentState, installPkgSpecs, ignoreErrors)

	// Write updates-manifest to host for post-patch validation (pip freeze)
	const outputResultsTemplate = `sh -c 'pip freeze --all > %s; if [ $? -ne 0 ]; then echo "WARN: pip freeze returned $?"; fi'`
	outputResultsCmd := fmt.Sprintf(outputResultsTemplate, resultManifest)
	mkFolders := pipInstalled.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true)))
	resultsWritten := mkFolders.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).Root()
	resultsDiff := llb.Diff(pipInstalled, resultsWritten)

	resultsBytes, err := buildkit.ExtractFileFromState(ctx, pm.config.Client, &resultsDiff, filepath.Join(resultsPath, resultManifest))
	if err != nil {
		return nil, nil, err
	}
	return &pipInstalled, resultsBytes, nil
}

// installPythonPackages installs packages; if ignoreErrors is true, each package is attempted individually.
func (pm *pythonManager) installPythonPackages(currentState *llb.State, packageSpecs []string, ignoreErrors bool) llb.State {
	if len(packageSpecs) == 0 {
		return *currentState
	}
	if ignoreErrors {
		var installCommands []string
		for _, spec := range packageSpecs {
			installCommands = append(installCommands,
				fmt.Sprintf(`pip install --timeout %d '%s' || printf "WARN: pip install failed for %s\n"`,
					defaultPipInstallTimeoutSeconds, spec, spec))
		}
		installCmd := fmt.Sprintf(`sh -c '%s'`, strings.Join(installCommands, "; "))
		return currentState.Run(
			llb.Shlex(installCmd),
			llb.WithProxy(utils.GetProxy()),
		).Root()
	}
	// Standard single command install (fail-fast)
	args := []string{"pip", "install", fmt.Sprintf("--timeout=%d", defaultPipInstallTimeoutSeconds)}
	args = append(args, packageSpecs...)
	return currentState.Run(
		llb.Args(args),
		llb.WithProxy(utils.GetProxy()),
	).Root()
}

// detectPip checks if pip or pip3 exists in the target image by creating a marker file if found.
func (pm *pythonManager) detectPip(ctx context.Context, currentState *llb.State) (bool, error) {
	checkCmd := `sh -c 'if command -v pip >/dev/null 2>&1; then echo ok > ` + pipCheckFile + `; elif command -v pip3 >/dev/null 2>&1; then echo ok > ` + pipCheckFile + `; fi'`
	checked := currentState.Run(llb.Shlex(checkCmd)).Root()
	_, err := buildkit.ExtractFileFromState(ctx, pm.config.Client, &checked, pipCheckFile)
	if err != nil {
		// File not found implies pip absent; treat other errors the same for now
		return false, nil
	}
	return true, nil
}

// upgradePackagesWithTooling performs Python package upgrades using an external tooling container when pip is absent in target image.
// Strategy:
// 1. Detect an appropriate site-packages directory in target image from a list of candidate paths.
// 2. Infer Python version from detected path (pattern pythonX.Y) to select a matching tooling image; fallback to default tag.
// 3. In tooling image, pip install packages into /copa-pkgs using --target (no deps, expect fixed versions).
// 4. Copy installed package contents into detected site-packages path in target image state.
// 5. Synthesize a pip freeze style resultsBytes for validation (package==version per line) since pip isn't present in target.
func (pm *pythonManager) upgradePackagesWithTooling(
	ctx context.Context,
	currentState *llb.State,
	installPkgSpecs []string,
) (*llb.State, []byte, error) {
	// Candidate site-packages paths (we'll choose the path that already contains the most target packages)
	candidatePaths := []string{
		"/usr/local/lib/python*/site-packages",
		"/usr/lib/python*/site-packages",
		"/opt/python*/site-packages",
		"/usr/lib/az/lib/python*/site-packages", // Az CLI custom path
	}

	// Build list of package base names (lowercase, normalize underscores to hyphens) for detection heuristics
	var pkgBaseNames []string
	for _, spec := range installPkgSpecs {
		parts := strings.SplitN(spec, "==", 2)
		name := parts[0]
		name = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		pkgBaseNames = append(pkgBaseNames, name)
	}

	// Shell logic to pick directory with highest match count of existing packages
	detectScriptBuilder := strings.Builder{}
	detectScriptBuilder.WriteString("set -e; best=''; bestc=-1; pkgs=\"")
	for i, n := range pkgBaseNames {
		if i > 0 {
			detectScriptBuilder.WriteString(" ")
		}
		detectScriptBuilder.WriteString(n)
	}
	detectScriptBuilder.WriteString("\"; for pattern in")
	for _, p := range candidatePaths {
		detectScriptBuilder.WriteString(fmt.Sprintf(" '%s'", p))
	}
	detectScriptBuilder.WriteString("; do for d in $pattern; do [ -d \"$d\" ] || continue; c=0; for p in $pkgs; do if [ -d \"$d/$p\" ] || ls \"$d\" 2>/dev/null | grep -i -q \"^$p-.*\\.dist-info$\"; then c=$((c+1)); fi; done; if [ $c -gt $bestc ]; then bestc=$c; best=$d; fi; done; done; if [ -n \"$best\" ]; then echo $best > ")
	detectScriptBuilder.WriteString(sitePackagesDetectFile)
	detectScriptBuilder.WriteString("; else for pattern in")
	for _, p := range candidatePaths {
		detectScriptBuilder.WriteString(fmt.Sprintf(" '%s'", p))
	}
	detectScriptBuilder.WriteString("; do for d in $pattern; do if [ -d \"$d\" ]; then echo $d > ")
	detectScriptBuilder.WriteString(sitePackagesDetectFile)
	detectScriptBuilder.WriteString("; exit 0; fi; done; done; fi")

	detectCmd := fmt.Sprintf("sh -c '%s'", detectScriptBuilder.String())
	detected := currentState.Run(llb.Shlex(detectCmd)).Root()
	pathBytes, _ := buildkit.ExtractFileFromState(ctx, pm.config.Client, &detected, sitePackagesDetectFile)
	sitePkgsPath := strings.TrimSpace(string(pathBytes))
	if sitePkgsPath == "" {
		return nil, nil, fmt.Errorf("unable to locate site-packages directory in target image (searched: %v)", candidatePaths)
	}
	log.Infof("Detected Python site-packages path: %s", sitePkgsPath)

	// Infer python version from path
	versionRegex := regexp.MustCompile(`python(\d+\.\d+)`)
	pyVersion := ""
	if m := versionRegex.FindStringSubmatch(sitePkgsPath); len(m) == 2 {
		pyVersion = m[1]
	}

	toolingTag := defaultToolingPythonTag
	if pyVersion != "" {
		// produce e.g. 3.12-slim
		toolingTag = fmt.Sprintf("%s-slim", pyVersion)
	}
	toolingImage := fmt.Sprintf(toolingImageTemplate, toolingTag)
	log.Infof("Using tooling image %s for Python package operations", toolingImage)

	// Build install command in tooling image
	toolingInstallCmd := fmt.Sprintf("sh -c 'pip install --no-cache-dir --disable-pip-version-check --no-deps --target /copa-pkgs %s'", strings.Join(installPkgSpecs, " "))
	toolingState := llb.Image(toolingImage).Run(
		llb.Shlex(toolingInstallCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Clean old versions of these packages in the detected site-packages path before copying new ones
	cleanScriptBuilder := strings.Builder{}
	cleanScriptBuilder.WriteString("set -e; sp=\"" + sitePkgsPath + "\"; pkgs=\"")
	for i, n := range pkgBaseNames {
		if i > 0 {
			cleanScriptBuilder.WriteString(" ")
		}
		cleanScriptBuilder.WriteString(n)
	}
	cleanScriptBuilder.WriteString("\"; if [ -n \"$pkgs\" ]; then for p in $pkgs; do rm -rf \"$sp/$p\" 2>/dev/null || true; for d in $sp/$p-*.dist-info; do [ -d \"$d\" ] && rm -rf \"$d\" || true; done; done; fi")
	cleanCmd := fmt.Sprintf("sh -c '%s'", cleanScriptBuilder.String())
	cleaned := currentState.Run(llb.Shlex(cleanCmd)).Root()

	// Copy installed packages into target site-packages path after cleanup
	merged := cleaned.File(
		llb.Copy(toolingState, "/copa-pkgs/", sitePkgsPath+"/", &llb.CopyInfo{CopyDirContentsOnly: true, CreateDestPath: true}),
	)

	// Synthesize resultsBytes (freeze-like) from requested specs (only those with version pins)
	var resultsLines []string
	for _, spec := range installPkgSpecs {
		parts := strings.SplitN(spec, "==", 2)
		if len(parts) == 2 {
			resultsLines = append(resultsLines, spec)
		}
	}
	resultsBytes := []byte(strings.Join(resultsLines, "\n"))

	return &merged, resultsBytes, nil
}
