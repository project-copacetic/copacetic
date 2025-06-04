package langmgr

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type pythonManager struct {
	config        *buildkit.Config
	workingFolder string
}

// isValidPythonVersion checks if a version string is a valid PEP440 version.
func isValidPythonVersion(v string) bool {
	_, err := pep440.Parse(v)
	return err == nil
}

// isLessThanPythonVersion compares two PEP440 version strings.
// It returns true if v1 is less than v2.
func isLessThanPythonVersion(v1, v2 string) bool {
	ver1, err1 := pep440.Parse(v1)
	if err1 != nil {
		log.Warnf("Error parsing Python version '%s': %v", v1, err1)
		return false // Or handle error as appropriate
	}
	ver2, err2 := pep440.Parse(v2)
	if err2 != nil {
		log.Warnf("Error parsing Python version '%s': %v", v2, err2)
		return false // Or handle error as appropriate
	}
	return ver1.LessThan(ver2)
}

func (pm *pythonManager) InstallUpdates(ctx context.Context, manifest *unversioned.UpdateManifest, ignoreErrors bool) (*llb.State, []string, error) {
	var errPkgsReported []string // Packages that will be reported as problematic

	pythonComparer := VersionComparer{isValidPythonVersion, isLessThanPythonVersion}
	updatesToAttempt, err := GetUniqueLatestUpdates(manifest.LangUpdates, pythonComparer, ignoreErrors)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine unique latest Python updates: %w", err)
	}

	if len(updatesToAttempt) == 0 {
		log.Warn("No Python update packages were specified to apply.")
		return &pm.config.ImageState, nil, nil
	}
	log.Debugf("Attempting to update latest unique pips: %v", updatesToAttempt)

	// Perform the upgrade.
	updatedImageState, resultsBytes, upgradeErr := pm.upgradePackages(ctx, updatesToAttempt, ignoreErrors)
	if upgradeErr != nil {
		log.Errorf("Failed to upgrade Python packages: %v. Cannot proceed to validation.", upgradeErr)
		if !ignoreErrors {
			for _, u := range updatesToAttempt {
				errPkgsReported = append(errPkgsReported, u.Name)
			}
			return &pm.config.ImageState, errPkgsReported, fmt.Errorf("python package upgrade operation failed: %w", upgradeErr)
		}
		log.Warnf("Python package upgrade operation failed but errors are ignored. Original image state will be used.")
		for _, u := range updatesToAttempt {
			errPkgsReported = append(errPkgsReported, u.Name)
		}
		return &pm.config.ImageState, errPkgsReported, nil
	}

	// If upgradePackages succeeded, upgradeErr is nil. Now validate.
	failedValidationPkgs, validationErr := pm.validatePythonPackageVersions(ctx, resultsBytes, updatesToAttempt, ignoreErrors)

	if len(failedValidationPkgs) > 0 {
		log.Warnf("Python packages failed version validation: %v", failedValidationPkgs)
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
func (pm *pythonManager) validatePythonPackageVersions(ctx context.Context, resultsBytes []byte, expectedUpdates unversioned.LangUpdatePackages, ignoreErrors bool) ([]string, error) {
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
				// Create a unique list of failed packages before returning
				uniqueFailedPkgsMap := make(map[string]bool)
				var uniqueFailedPkgsList []string
				for _, pkgName := range failedPackages {
					if !uniqueFailedPkgsMap[pkgName] {
						uniqueFailedPkgsMap[pkgName] = true
						uniqueFailedPkgsList = append(uniqueFailedPkgsList, pkgName)
					}
				}
				return uniqueFailedPkgsList, fmt.Errorf("failed to validate python packages: %s", strings.Join(validationIssues, "; "))
			}
		}
		return failedPackages, nil
	}

	installedPkgs := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(resultsBytes)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "==", 2)
		if len(parts) == 2 {
			installedPkgs[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		} else {
			log.Debugf("Skipping unparsable line in pip freeze output: %s", line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error reading pip freeze results: %v", err)
		for _, pkgUpdate := range expectedUpdates {
			failedPackages = append(failedPackages, pkgUpdate.Name)
		}
		// Create a unique list of failed packages
		uniqueFailedPkgsMap := make(map[string]bool)
		var uniqueFailedPkgsList []string
		for _, pkgName := range failedPackages {
			if !uniqueFailedPkgsMap[pkgName] {
				uniqueFailedPkgsMap[pkgName] = true
				uniqueFailedPkgsList = append(uniqueFailedPkgsList, pkgName)
			}
		}
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
				errMsg := fmt.Sprintf("package %s has an invalid expected fixed version format: %s", expectedPkg.Name, expectedPkg.FixedVersion)
				validationIssues = append(validationIssues, errMsg)
				failedPackages = append(failedPackages, expectedPkg.Name)
				log.Warnf("%s", errMsg)
				continue
			}

			vActual, _ := pep440.Parse(actualVersion)
			vExpected, _ := pep440.Parse(expectedPkg.FixedVersion)

			if !vActual.Equal(vExpected) {
				errMsg := fmt.Sprintf("package %s: expected version %s, but found %s", expectedPkg.Name, expectedPkg.FixedVersion, actualVersion)
				validationIssues = append(validationIssues, errMsg)
				failedPackages = append(failedPackages, expectedPkg.Name)
				log.Warnf("%s", errMsg)
			}
		} else {
			if expectedPkg.InstalledVersion != "" && isValidPythonVersion(expectedPkg.InstalledVersion) {
				vActual, _ := pep440.Parse(actualVersion)
				vInstalled, errInstalled := pep440.Parse(expectedPkg.InstalledVersion)
				if errInstalled == nil {
					if vActual.LessThan(vInstalled) {
						errMsg := fmt.Sprintf("package %s: upgraded to version %s, which is older than installed version %s", expectedPkg.Name, actualVersion, expectedPkg.InstalledVersion)
						validationIssues = append(validationIssues, errMsg)
						failedPackages = append(failedPackages, expectedPkg.Name)
						log.Warnf("%s", errMsg)
					} else if vActual.Equal(vInstalled) {
						log.Infof("Package %s version %s remained unchanged after upgrade attempt.", expectedPkg.Name, actualVersion)
					} else {
						log.Infof("Package %s successfully upgraded from %s to %s.", expectedPkg.Name, expectedPkg.InstalledVersion, actualVersion)
					}
				} else {
					log.Infof("Package %s updated to %s (InstalledVersion %s was not parsable for comparison).", expectedPkg.Name, actualVersion, expectedPkg.InstalledVersion)
				}
			} else {
				log.Infof("Package %s updated to %s (no valid InstalledVersion for comparison or no FixedVersion specified).", expectedPkg.Name, actualVersion)
			}
		}
	}

	uniqueFailedPkgsMap := make(map[string]bool)
	var uniqueFailedPkgsList []string
	if len(failedPackages) > 0 {
		for _, pkgName := range failedPackages {
			if !uniqueFailedPkgsMap[pkgName] {
				uniqueFailedPkgsMap[pkgName] = true
				uniqueFailedPkgsList = append(uniqueFailedPkgsList, pkgName)
			}
		}
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

func (pm *pythonManager) upgradePackages(ctx context.Context, updates unversioned.LangUpdatePackages, ignoreErrors bool) (*llb.State, []byte, error) {
	installPkgArgs := []string{}
	for _, u := range updates {
		if u.FixedVersion != "" {
			installPkgArgs = append(installPkgArgs, fmt.Sprintf("%s==%s", u.Name, u.FixedVersion))
		} else {
			// Fallback if FixedVersion is not available, though ideally it should always be.
			// Or, decide if this case should error out or skip the package.
			// For now, let's assume we want to upgrade it if no specific version is pinned.
			installPkgArgs = append(installPkgArgs, u.Name)
			log.Warnf("No FixedVersion available for Python package %s, attempting upgrade.", u.Name)
		}
	}

	if len(installPkgArgs) == 0 {
		log.Info("No Python packages to install or upgrade.")
		return &pm.config.ImageState, nil, nil
	}

	// Install all requested update packages
	var pipInstalled llb.State

	if ignoreErrors {
		// When ignoring errors, install packages individually in a single layer
		var installCommands []string
		for _, pkgArg := range installPkgArgs {
			installCommands = append(installCommands, fmt.Sprintf(`pip install %s || echo "WARN: pip install failed for %s"`, pkgArg, pkgArg))
		}
		installCmd := fmt.Sprintf(`sh -c '%s'`, strings.Join(installCommands, "; "))
		pipInstalled = pm.config.ImageState.Run(
			llb.Shlex(installCmd),
			llb.WithProxy(utils.GetProxy()),
		).Root()
	} else {
		// Normal pip install that will fail on errors - install all packages at once
		const pipInstallTemplate = `pip install %s`
		installCmd := fmt.Sprintf(pipInstallTemplate, strings.Join(installPkgArgs, " "))
		pipInstalled = pm.config.ImageState.Run(
			llb.Shlex(installCmd),
			llb.WithProxy(utils.GetProxy()),
		).Root()
	}

	// Write updates-manifest to host for post-patch validation
	const outputResultsTemplate = `sh -c 'pip freeze --all > %s; if [ $? -ne 0 ]; then echo "WARN: pip freeze returned $?"; fi'`

	outputResultsCmd := fmt.Sprintf(outputResultsTemplate, resultManifest)
	mkFolders := pipInstalled.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true)))
	resultsWritten := mkFolders.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).Root()
	resultsDiff := llb.Diff(pipInstalled, resultsWritten)

	resultsBytes, err := buildkit.ExtractFileFromState(ctx, pm.config.Client, &resultsDiff, filepath.Join(resultsPath, resultManifest))
	if err != nil {
		return nil, nil, err
	}

	// Diff the installed updates and merge that into the target image
	patchDiff := llb.Diff(pm.config.ImageState, pipInstalled)
	patchMerge := llb.Merge([]llb.State{pm.config.ImageState, patchDiff})
	return &patchMerge, resultsBytes, nil
}
