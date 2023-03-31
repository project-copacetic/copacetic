// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package pkgmgr

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	apkVer "github.com/knqyf263/go-apk-version"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type apkManager struct {
	config        *buildkit.Config
	workingFolder string
}

// Depending on go-apk-version lib for APK version comparison rules.
func isValidAPKVersion(v string) bool {
	return apkVer.Valid(v)
}

func isLessThanAPKVersion(v1, v2 string) bool {
	apkV1, _ := apkVer.NewVersion(v1)
	apkV2, _ := apkVer.NewVersion(v2)
	return apkV1.LessThan(apkV2)
}

func apkReadResultsManifest(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		log.Errorf("%s could not be opened", path)
		return nil, err
	}
	defer f.Close()

	var lines []string
	fs := bufio.NewScanner(f)
	for fs.Scan() {
		lines = append(lines, fs.Text())
	}

	return lines, nil
}

func validateAPKPackageVersions(updates types.UpdatePackages, cmp VersionComparer, resultsPath string) error {
	lines, err := apkReadResultsManifest(resultsPath)
	if err != nil {
		return err
	}

	// Assert apk info list doesn't contain more entries than expected
	if len(lines) > len(updates) {
		err = fmt.Errorf("expected %d updates, installed %d", len(updates), len(lines))
		log.Error(err)
		return err
	}

	// Not strictly necessary, but sort the two lists to not take a dependency on the
	// ordering behavior of apk info output
	sort.SliceStable(updates, func(i, j int) bool {
		return updates[i].Name < updates[j].Name
	})
	log.Debugf("Required updates: %s", updates)

	sort.SliceStable(lines, func(i, j int) bool {
		return lines[i] < lines[j]
	})
	log.Debugf("Resulting updates: %s", lines)

	// Walk files and check update name is prefix for file name
	// results.manifest file is expected to the `apk info --installed -v <packages ...>` output for the
	// specified packages in the order they were specified in:
	//
	// <package name>-<version>
	// ...
	var allErrors *multierror.Error
	lineIndex := 0
	for _, update := range updates {
		expectedPrefix := update.Name + "-"
		if lineIndex >= len(lines) || !strings.HasPrefix(lines[lineIndex], expectedPrefix) {
			log.Warnf("Package %s is not installed, may have been uninstalled during upgrade", update.Name)
			continue
		}

		// Found a match, trim prefix- to get version string
		version := strings.TrimPrefix(lines[lineIndex], expectedPrefix)
		lineIndex++

		if !cmp.IsValid(version) {
			err := fmt.Errorf("invalid version %s found for package %s", version, update.Name)
			log.Error(err)
			allErrors = multierror.Append(allErrors, err)
			continue
		}
		if cmp.LessThan(version, update.Version) {
			err = fmt.Errorf("downloaded package %s version %s lower than required %s for update", update.Name, version, update.Version)
			log.Error(err)
			allErrors = multierror.Append(allErrors, err)
			continue
		}
		log.Infof("Validated package %s version %s meets requested version %s", update.Name, version, update.Version)
	}

	return allErrors.ErrorOrNil()
}

func (am *apkManager) InstallUpdates(ctx context.Context, manifest *types.UpdateManifest) (*llb.State, error) {
	// Resolve set of unique packages to update
	apkComparer := VersionComparer{isValidAPKVersion, isLessThanAPKVersion}
	updates, err := GetUniqueLatestUpdates(manifest.Updates, apkComparer)
	if err != nil {
		return nil, err
	}
	if len(updates) == 0 {
		log.Warn("No update packages were specified to apply")
		return &am.config.ImageState, nil
	}
	log.Debugf("latest unique APKs: %v", updates)

	updatedImageState, err := am.upgradePackages(ctx, updates)
	if err != nil {
		return nil, err
	}

	// Validate that the deployed packages are of the requested version or better
	resultManifestPath := filepath.Join(am.workingFolder, resultsPath, resultManifest)
	if err := validateAPKPackageVersions(updates, apkComparer, resultManifestPath); err != nil {
		return nil, err
	}

	return updatedImageState, nil
}

// Patch a regular alpine image with:
//   - sh and apk installed on the image
//   - valid apk db state on the image
//
// TODO: support "distroless" Alpine images (e.g. APKO images)
// Still assumes that APK exists in the target image and is pathed, which can be addressed by
// mounting a copy of apk-tools-static into the image and invoking apk-static directly.
func (am *apkManager) upgradePackages(ctx context.Context, updates types.UpdatePackages) (*llb.State, error) {
	// TODO: Add support for custom APK config
	apkUpdated := am.config.ImageState.Run(llb.Shlex("apk update"), llb.WithProxy(utils.GetProxy())).Root()

	// Add all requested update packages
	// This works around cases where some packages (for example, tiff) require other packages in it's dependency tree to be updated
	const apkAddTemplate = `apk add --no-cache %s`
	pkgStrings := []string{}
	for _, u := range updates {
		pkgStrings = append(pkgStrings, u.Name)
	}
	addCmd := fmt.Sprintf(apkAddTemplate, strings.Join(pkgStrings, " "))
	apkAdded := apkUpdated.Run(llb.Shlex(addCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Install all requested update packages without specifying the version. This works around:
	//  - Reports being slightly out of date, where a newer security revision has displaced the one specified leading to not found errors.
	//  - Reports not specifying version epochs correct (e.g. bsdutils=2.36.1-8+deb11u1 instead of with epoch as 1:2.36.1-8+dev11u1)
	// Note that this keeps the log files from the operation, which we can consider removing as a size optimization in the future.
	const apkInstallTemplate = `apk upgrade --no-cache %s`
	installCmd := fmt.Sprintf(apkInstallTemplate, strings.Join(pkgStrings, " "))
	apkInstalled := apkAdded.Run(llb.Shlex(installCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Write updates-manifest to host for post-patch validation
	const outputResultsTemplate = `sh -c 'apk info --installed -v %s > %s; if [[ $? -ne 0 ]]; then echo "WARN: apk info --installed returned $?"; fi'`
	pkgs := strings.Trim(fmt.Sprintf("%s", pkgStrings), "[]")
	outputResultsCmd := fmt.Sprintf(outputResultsTemplate, pkgs, resultManifest)
	mkFolders := apkInstalled.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true)))
	resultsWritten := mkFolders.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).Root()
	resultsDiff := llb.Diff(apkInstalled, resultsWritten)

	if err := buildkit.SolveToLocal(ctx, am.config.Client, &resultsDiff, am.workingFolder); err != nil {
		return nil, err
	}

	// Diff the installed updates and merge that into the target image
	patchDiff := llb.Diff(apkUpdated, apkInstalled)
	patchMerge := llb.Merge([]llb.State{am.config.ImageState, patchDiff})
	return &patchMerge, nil
}
