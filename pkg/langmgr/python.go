package langmgr

import (
	"context"
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
	// Resolve set of unique packages to update
	apkComparer := VersionComparer{isValidPythonVersion, isLessThanPythonVersion}
	updates, err := GetUniqueLatestUpdates(manifest.LangUpdates, apkComparer, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}
	if len(updates) == 0 {
		log.Warn("No update packages were specified to apply")
		return &pm.config.ImageState, nil, nil
	}
	log.Debugf("latest unique pips: %v", updates)

	updatedImageState, _, err := pm.upgradePackages(ctx, updates, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}

	// TODO(sertac): validatePythonPackageVersions

	return updatedImageState, nil, nil
}

func (pm *pythonManager) upgradePackages(ctx context.Context, updates unversioned.LangUpdatePackages, ignoreErrors bool) (*llb.State, []byte, error) {
	installPkgArgs := []string{}
	freezePkgNames := []string{}
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
		freezePkgNames = append(freezePkgNames, u.Name)
	}

	if len(installPkgArgs) == 0 {
		log.Info("No Python packages to install or upgrade.")
		return &pm.config.ImageState, nil, nil
	}

	// Install all requested update packages
	// The template now expects package arguments like "package1==1.0.0 package2==2.0.0"
	const pipInstallTemplate = `pip install %s`
	installCmd := fmt.Sprintf(pipInstallTemplate, strings.Join(installPkgArgs, " "))
	pipInstalled := pm.config.ImageState.Run(llb.Shlex(installCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Write updates-manifest to host for post-patch validation
	// pip freeze should use just the package names for filtering, if desired.
	const outputResultsTemplate = `sh -c 'pip freeze %s > %s; if [ $? -ne 0 ]; then echo "WARN: pip freeze returned $?"; fi'`
	pkgsForFreeze := strings.Join(freezePkgNames, " ")
	// If freezePkgNames is empty, pip freeze will list all packages.
	// If we want to ensure it only freezes the packages we touched, and freezePkgNames could be empty
	// (e.g. if installPkgArgs was empty and we returned early), this part might need adjustment
	// or ensure freezePkgNames is appropriately populated even if installPkgArgs is empty.
	// However, given the check `if len(installPkgArgs) == 0`, this path won't be hit with empty pkgsForFreeze
	// unless installPkgArgs was populated but freezePkgNames was not (which current logic prevents).

	outputResultsCmd := fmt.Sprintf(outputResultsTemplate, pkgsForFreeze, resultManifest)
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
