package pkgmgr

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/moby/buildkit/client/llb"
	pacmanVer "github.com/parthivsaikia/go-pacman-version"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type pacmanManager struct {
	config        *buildkit.Config
	workingFolder string
}

func isValidPacmanVersion(v string) bool {
	return pacmanVer.IsValid(v)
}

func isLessThanPacmanVersion(v1, v2 string) bool {
	return pacmanVer.LessThan(v1, v2)
}

func pacmanReadResultsManifest(b []byte) ([]string, error) {
	if b == nil {
		return nil, fmt.Errorf("nil buffer provided")
	}
	buf := bytes.NewBuffer(b)
	var lines []string
	fs := bufio.NewScanner(buf)
	for fs.Scan() {
		lines = append(lines, fs.Text())
	}
	return lines, nil
}

func validatePacmanPackageVersions(updates unversioned.UpdatePackages, cmp VersionComparer, resultBytes []byte, ignoreErrors bool) ([]string, error) {
	lines, err := pacmanReadResultsManifest(resultBytes)
	if err != nil {
		return nil, err
	}

	if len(lines) > len(updates) {
		err = fmt.Errorf("expected %d updates, installed %d", len(updates), len(lines))
		log.Error(err)
		return nil, err
	}

	sort.SliceStable(updates, func(i, j int) bool {
		return updates[i].Name < updates[j].Name
	})
	log.Debugf("Required updates: %s", updates)

	sort.SliceStable(lines, func(i, j int) bool {
		return lines[i] < lines[j]
	})
	log.Debugf("Resulting updates: %s", lines)

	lineIndex := 0
	var errorPkgs []string
	var allErrors []error

	for _, update := range updates {
		expectedPrefix := update.Name + " "
		if lineIndex >= len(lines) || !strings.HasPrefix(lines[lineIndex], expectedPrefix) {
			log.Warnf("Package %s is not installed, may have been uninstalled during upgrade", update.Name)
			continue
		}

		version := strings.TrimPrefix(lines[lineIndex], expectedPrefix)
		lineIndex++

		if !cmp.IsValid(version) {
			err := fmt.Errorf("invalid version %s found for package %s", version, update.Name)
			log.Error(err)
			errorPkgs = append(errorPkgs, update.Name)
			allErrors = append(allErrors, err)
			continue
		}

		if cmp.LessThan(version, update.FixedVersion) {
			err := fmt.Errorf("downloaded package %s version %s lower than required %s for update", update.Name, version, update.FixedVersion)
			log.Error(err)
			errorPkgs = append(errorPkgs, update.Name)
			allErrors = append(allErrors, err)
			continue
		}

		log.Infof("Validated package %s version %s meets requested version %s", update.Name, version, update.FixedVersion)
	}

	if ignoreErrors {
		return errorPkgs, nil
	}

	return errorPkgs, errors.Join(allErrors...)
}

func (pm *pacmanManager) InstallUpdates(ctx context.Context, manifest *unversioned.UpdateManifest, ignoreErrors bool) (*llb.State, []string, error) {
	if manifest == nil {
		updatedImageState, _, err := pm.upgradePackages(ctx, nil, ignoreErrors)
		if err != nil {
			return updatedImageState, nil, err
		}
		return updatedImageState, nil, nil
	}

	pacmanComparer := VersionComparer{isValidPacmanVersion, isLessThanPacmanVersion}
	updates, err := GetUniqueLatestUpdates(manifest.OSUpdates, pacmanComparer, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}

	if len(updates) == 0 {
		log.Warn("No update packages were specified to apply")
		return &pm.config.ImageState, nil, nil
	}
	log.Debugf("latest unique pacman packages: %v", updates)

	updatedImageState, resultBytes, err := pm.upgradePackages(ctx, updates, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}

	errPkgs, err := validatePacmanPackageVersions(updates, pacmanComparer, resultBytes, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}

	return updatedImageState, errPkgs, nil
}

func (pm *pacmanManager) upgradePackages(ctx context.Context, updates unversioned.UpdatePackages, ignoreErrors bool) (*llb.State, []byte, error) {
	imageStateCurrent := pm.config.ImageState
	if pm.config.PatchedConfigData != nil {
		imageStateCurrent = pm.config.PatchedImageState
	}

	pacmanUpdated := imageStateCurrent.Run(
		llb.Shlex("pacman -Sy"),
		llb.WithProxy(utils.GetProxy()),
		llb.IgnoreCache,
		llb.WithCustomName("Updating package database"),
	).Root()

	if updates == nil {
		const updatesAvailableMarker = "/updates.txt"
		checkUpgradable := fmt.Sprintf(`sh -c 'if pacman -Qu > /dev/null 2 &1; then touch %s; fi'`, updatesAvailableMarker)
		stateWithCheck := pacmanUpdated.Run(
			llb.Shlex(checkUpgradable),
			llb.WithCustomName("Checking for available updates"),
		).Root()

		_, err := buildkit.ExtractFileFromState(ctx, pm.config.Client, &stateWithCheck, updatesAvailableMarker)
		if err != nil {
			log.Info("No upgradable packages found for this image.")
			return nil, nil, types.ErrNoUpdatesFound
		}
	}

	var pacmanInstalled llb.State
	var resultManifestBytes []byte
	var err error
	if updates != nil {
		pkgStrings := []string{}
		for _, u := range updates {
			pkgStrings = append(pkgStrings, u.Name)
		}
		const pacmanInstallTemplate = `pacman -S --noconfirm %s`
		installCmd := fmt.Sprintf(pacmanInstallTemplate, strings.Join(pkgStrings, " "))
		pacmanInstalled.Run(
			llb.Shlex(installCmd),
			llb.WithProxy(utils.GetProxy()),
			llb.WithCustomName(fmt.Sprintf("Upgrading %d security updates", len(pkgStrings))),
		).Root()

		const outputResultsTemplate = `sh -c 'pacman -Q %s > %s; if [[ $? -ne 0 ]]; then echo "WARN: pacman -Q returned $?"; fi'`
		pkgs := strings.Trim(fmt.Sprintf("%s", pkgStrings), "[]")
		outputResultsCmd := fmt.Sprintf(outputResultsTemplate, pkgs, resultManifest)
		mkFolders := pacmanInstalled.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true)))
		resultDiff := mkFolders.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).AddMount(resultsPath, llb.Scratch())

		resultManifestBytes, err = buildkit.ExtractFileFromState(ctx, pm.config.Client, &resultDiff, resultManifest)
		if err != nil {
			return nil, nil, err
		}

	} else {
		installCmd := `output=$(pacman -Su --noconfirm 2>&1); if [ $? -ne 0 ]; then echo "$output" >> error_log.txt; fi`
		pacmanInstalled = pacmanUpdated.Run(
			buildkit.Sh(installCmd),
			llb.WithProxy(utils.GetProxy()),
			llb.WithCustomName("Upgrading all packages"),
		).Root()

		if !ignoreErrors {
			pacmanInstalled = pacmanUpdated.Run(
				buildkit.Sh("if [ -s error_log.txt ]; then cat error_log.txt; exit 1; fi"),
				llb.WithCustomName("Validating package updates"),
			).Root()
		}
	}

	if pm.config.PatchedConfigData != nil {
		prevPatchDiff := llb.Diff(pm.config.ImageState, pm.config.PatchedImageState)
		newPatchDiff := llb.Diff(pacmanUpdated, pacmanInstalled)
		combinedPatch := llb.Merge([]llb.State{prevPatchDiff, newPatchDiff})
		squashedPatch := llb.Scratch().File(llb.Copy(combinedPatch, "/", "/"))
		completePatchMerge := llb.Merge([]llb.State{pm.config.ImageState, squashedPatch})
		return &completePatchMerge, resultManifestBytes, nil
	}

	patchDiff := llb.Diff(pacmanUpdated, pacmanInstalled)
	patchMerge := llb.Merge([]llb.State{pm.config.ImageState, patchDiff})
	return &patchMerge, resultManifestBytes, nil
}

func (pm *pacmanManager) GetPackageType() string {
	return "pacman"
}
