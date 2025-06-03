package langmgr

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	apkVer "github.com/knqyf263/go-apk-version"
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

// TODO(sertac): implement Python version comparison rules
// This is a placeholder for Python version comparison logic.
// Depending on go-apk-version lib for APK version comparison rules.
func isValidAPKVersion(v string) bool {
	return apkVer.Valid(v)
}

func isLessThanAPKVersion(v1, v2 string) bool {
	apkV1, _ := apkVer.NewVersion(v1)
	apkV2, _ := apkVer.NewVersion(v2)
	return apkV1.LessThan(apkV2)
}

func (pm *pythonManager) InstallUpdates(ctx context.Context, manifest *unversioned.UpdateManifest, ignoreErrors bool) (*llb.State, []string, error) {
	// Resolve set of unique packages to update
	apkComparer := VersionComparer{isValidAPKVersion, isLessThanAPKVersion}
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
	pkgStrings := []string{}
	for _, u := range updates {
		pkgStrings = append(pkgStrings, u.Name)
	}

	// Install all requested update packages
	// TODO(sertac): handle pip versioning and pinning
	// Do we go for the latest version of each package or opt to fix to a closest version?
	// Would there be a setting for this?

	const pipInstallTemplate = `pip install --upgrade %s`
	installCmd := fmt.Sprintf(pipInstallTemplate, strings.Join(pkgStrings, " "))
	pipInstalled := pm.config.ImageState.Run(llb.Shlex(installCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Write updates-manifest to host for post-patch validation
	const outputResultsTemplate = `sh -c 'pip freeze %s > %s; if [ $? -ne 0 ]; then echo "WARN: pip freeze returned $?"; fi'`
	pkgs := strings.Trim(fmt.Sprintf("%s", pkgStrings), "[]")
	outputResultsCmd := fmt.Sprintf(outputResultsTemplate, pkgs, resultManifest)
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