package langmgr

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"path/filepath"
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

// isValidDotnetVersion checks if a version string is a valid semantic version.
func isValidDotnetVersion(v string) bool {
	_, err := semver.NewVersion(v)
	return err == nil
}

// isLessThanDotnetVersion compares two semantic version strings.
// It returns true if v1 is less than v2.
func isLessThanDotnetVersion(v1, v2 string) bool {
	ver1, err1 := semver.NewVersion(v1)
	if err1 != nil {
		log.Warnf("Error parsing .NET version '%s': %v", v1, err1)
		return false
	}
	ver2, err2 := semver.NewVersion(v2)
	if err2 != nil {
		log.Warnf("Error parsing .NET version '%s': %v", v2, err2)
		return false
	}
	return ver1.LessThan(ver2)
}

func (dnm *dotnetManager) InstallUpdates(
	ctx context.Context,
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
		return &dnm.config.ImageState, []string{}, nil
	}

	log.Debugf("Found %d .NET packages to process: %v", len(dotnetUpdates), dotnetUpdates)

	dotnetComparer := VersionComparer{isValidDotnetVersion, isLessThanDotnetVersion}
	updatesToAttempt, err := GetUniqueLatestUpdates(dotnetUpdates, dotnetComparer, ignoreErrors)
	if err != nil {
		// Collect error packages when GetUniqueLatestUpdates fails
		for _, u := range dotnetUpdates {
			errPkgsReported = append(errPkgsReported, u.Name)
		}
		return &dnm.config.ImageState, errPkgsReported, fmt.Errorf("failed to determine unique latest .NET updates: %w", err)
	}

	if len(updatesToAttempt) == 0 {
		log.Warn("No .NET update packages were specified to apply.")
		return &dnm.config.ImageState, []string{}, nil
	}
	log.Debugf("Attempting to update latest unique .NET packages: %v", updatesToAttempt)

	// Perform the upgrade.
	updatedImageState, resultsBytes, upgradeErr := dnm.upgradePackages(ctx, updatesToAttempt, ignoreErrors)
	if upgradeErr != nil {
		log.Errorf("Failed to upgrade .NET packages: %v. Cannot proceed to validation.", upgradeErr)
		if !ignoreErrors {
			for _, u := range updatesToAttempt {
				errPkgsReported = append(errPkgsReported, u.Name)
			}
			return &dnm.config.ImageState, errPkgsReported, fmt.Errorf(".NET package upgrade operation failed: %w", upgradeErr)
		}
		log.Warnf(".NET package upgrade operation failed but errors are ignored. Original image state will be used.")
		for _, u := range updatesToAttempt {
			errPkgsReported = append(errPkgsReported, u.Name)
		}
		return &dnm.config.ImageState, errPkgsReported, nil
	}

	// If upgradePackages succeeded, upgradeErr is nil. Now validate.
	failedValidationPkgs, validationErr := dnm.validateDotnetPackageVersions(
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
				// Create a unique list of failed packages before returning
				uniqueFailedPkgsMap := make(map[string]bool)
				var uniqueFailedPkgsList []string
				for _, pkgName := range failedPackages {
					if !uniqueFailedPkgsMap[pkgName] {
						uniqueFailedPkgsMap[pkgName] = true
						uniqueFailedPkgsList = append(uniqueFailedPkgsList, pkgName)
					}
				}
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
		// Create a unique list of failed packages
		uniqueFailedPkgsMap := make(map[string]bool)
		var uniqueFailedPkgsList []string
		for _, pkgName := range failedPackages {
			if !uniqueFailedPkgsMap[pkgName] {
				uniqueFailedPkgsMap[pkgName] = true
				uniqueFailedPkgsList = append(uniqueFailedPkgsList, pkgName)
			}
		}
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
		log.Warnf(".NET package validation issues (ignored): %v", summaryError)
	}

	return uniqueFailedPkgsList, nil
}

func (dnm *dotnetManager) upgradePackages(
	ctx context.Context,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, []byte, error) {
	if len(updates) == 0 {
		log.Info("No .NET packages to install or upgrade.")
		return &dnm.config.ImageState, []byte{}, nil
	}

	// Start with dotnet clean to ensure clean state
	dotnetState := dnm.config.ImageState.Run(
		llb.Shlex("dotnet clean"),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	for _, u := range updates {
		var baseCmd string
		if u.FixedVersion != "" {
			addCmd := fmt.Sprintf("dotnet add package %s --version %s", u.Name, u.FixedVersion)

			if ignoreErrors {
				// Suppress errors and log a warning if the command fails
				baseCmd = fmt.Sprintf(`sh -c '%s || echo "WARN: failed to update %s to %s"'`,
					addCmd, u.Name, u.FixedVersion)
			} else {
				// Use the command directly when not ignoring errors
				baseCmd = addCmd
			}
		} else {
			addCmd := fmt.Sprintf("dotnet add package %s", u.Name)
			log.Warnf("No FixedVersion available for .NET package %s, attempting upgrade without specific version.", u.Name)

			if ignoreErrors {
				baseCmd = fmt.Sprintf(`sh -c '%s || echo "WARN: dotnet add package failed for %s"'`, addCmd, u.Name)
			} else {
				baseCmd = addCmd
			}
		}

		log.Debugf("Executing .NET package update command: %s", baseCmd)
		dotnetState = dotnetState.Run(
			llb.Shlex(baseCmd),
			llb.WithProxy(utils.GetProxy()),
		).Root()
	}

	// Run dotnet restore with options to handle conflicts
	log.Debug("Running dotnet restore with conflict resolution options")
	restoreCmd := "dotnet restore --force --no-cache --nologo"
	if ignoreErrors {
		restoreCmd = fmt.Sprintf(`sh -c '%s || echo "WARN: dotnet restore had issues but continuing"'`, restoreCmd)
	}

	restoredState := dotnetState.Run(
		llb.Shlex(restoreCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Run dotnet build to build the project
	log.Debug("Running dotnet build")
	buildCmd := "dotnet build --no-restore --nologo"
	if ignoreErrors {
		buildCmd = fmt.Sprintf(`sh -c '%s || echo "WARN: dotnet build had issues but continuing"'`, buildCmd)
	}

	builtState := restoredState.Run(
		llb.Shlex(buildCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// NOTES
	// Question: should we run dotnet publish also? "dontnet publish -c Release -o /app/out"? but we may not know the output path
	// problem with dotnet/sdk image is it doesn't have an app
	// problem with an image like dontnet/aspnet is its a runtime image so upgrade commands wont work - can consider mounting the image to a dotnet sdk

	// Write package list to host for post-patch validation
	const outputResultsTemplate = `sh -c 'dotnet list package > %s; ` +
		`if [ $? -ne 0 ]; then echo "WARN: dotnet list package returned $?"; fi'`

	outputResultsCmd := fmt.Sprintf(outputResultsTemplate, resultManifest)
	mkFolders := builtState.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true)))
	resultsWritten := mkFolders.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).Root()
	resultsDiff := llb.Diff(builtState, resultsWritten)

	resultsBytes, err := buildkit.ExtractFileFromState(
		ctx, dnm.config.Client, &resultsDiff, filepath.Join(resultsPath, resultManifest))
	if err != nil {
		return nil, nil, err
	}

	// Diff the installed updates and merge that into the target image
	patchDiff := llb.Diff(dnm.config.ImageState, builtState)
	patchMerge := llb.Merge([]llb.State{dnm.config.ImageState, patchDiff})
	return &patchMerge, resultsBytes, nil
}
