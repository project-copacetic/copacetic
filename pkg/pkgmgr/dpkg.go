package pkgmgr

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	debVer "github.com/knqyf263/go-deb-version"
	"github.com/moby/buildkit/client/llb"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

//go:embed scripts/apt_get_download.sh
var aptGetDownloadScript string

const (
	dpkgLibPath      = "/var/lib/dpkg"
	dpkgStatusPath   = dpkgLibPath + "/status"
	dpkgStatusFolder = dpkgLibPath + "/status.d"
	dpkgDownloadPath = "/var/cache/apt/archives"

	statusdOutputFilename = "statusd_type"
)

type dpkgManager struct {
	config         *buildkit.Config
	workingFolder  string
	isDistroless   bool
	statusdNames   string
	packageInfo    map[string]string
	statusdFileMap map[string]string // Maps package names to their status.d filenames
	osVersion      string
	osType         string
	tempStatusFile string
}

type dpkgStatusType uint

const (
	DPKGStatusNone dpkgStatusType = iota
	DPKGStatusFile
	DPKGStatusDirectory
	DPKGStatusMixed

	DPKGStatusInvalid // must always be the last listed
)

func (st dpkgStatusType) String() string {
	switch st {
	case DPKGStatusNone:
		return "DPKGStatusNone"
	case DPKGStatusFile:
		return "DPKGStatusFile"
	case DPKGStatusDirectory:
		return "DPKGStatusDirectory"
	case DPKGStatusMixed:
		return "DPKGStatusMixed"
	}
	return "Undefined dpkgStatusType"
}

// Depending on go-deb-version lib for debian version comparison rules.
// See https://manpages.debian.org/testing/dpkg-dev/deb-version.7.en.html
// describing format: "[epoch:]upstream-version[-debian-revision]".
func isValidDebianVersion(v string) bool {
	return debVer.Valid(v)
}

func isLessThanDebianVersion(v1, v2 string) bool {
	debV1, _ := debVer.NewVersion(v1)
	debV2, _ := debVer.NewVersion(v2)
	return debV1.LessThan(debV2)
}

// Map the target image OSType & OSVersion to an appropriate tooling image.
func getAPTImageName(manifest *unversioned.UpdateManifest, osVersion string, useCachePrefix bool) string {
	version := osVersion
	osType := utils.OSTypeDebian

	if manifest == nil || manifest.Metadata.OS.Type == utils.OSTypeDebian {
		if version > "12" {
			version = strings.Split("stable", ".")[0] + "-slim"
		} else {
			version = strings.Split(version, ".")[0] + "-slim"
		}
	} else {
		osType = manifest.Metadata.OS.Type
	}

	log.Debugf("Using %s:%s as basis for tooling image", osType, version)
	if !useCachePrefix {
		return fmt.Sprintf("%s:%s", osType, version)
	}
	return fmt.Sprintf("%s/%s:%s", imageCachePrefix, osType, version)
}

func getDPKGStatusType(b []byte) dpkgStatusType {
	if len(b) == 0 {
		return DPKGStatusNone
	}

	st, err := strconv.ParseUint(string(b), 10, 32)
	if err != nil {
		st = uint64(DPKGStatusNone)
	}

	// convert ascii digit to byte
	statusType := dpkgStatusType(st)
	if statusType >= DPKGStatusInvalid {
		return DPKGStatusInvalid
	}

	return statusType
}

func (dm *dpkgManager) InstallUpdates(ctx context.Context, manifest *unversioned.UpdateManifest, ignoreErrors bool) (*llb.State, []string, error) {
	imagePlatform, err := dm.config.ImageState.GetPlatform(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get image platform %w", err)
	}

	// Probe for additional information to execute the appropriate update install graphs
	toolImageName := getAPTImageName(manifest, dm.osVersion, true) // check if we can resolve the tool image
	if _, err := tryImage(ctx, toolImageName, dm.config.Client, imagePlatform); err != nil {
		toolImageName = getAPTImageName(manifest, dm.osVersion, false)
	}
	if err := dm.probeDPKGStatus(ctx, toolImageName, imagePlatform); err != nil {
		return nil, nil, err
	}

	// If manifest nil, update all packages
	if manifest == nil {
		if dm.isDistroless {
			updatedImageState, _, err := dm.unpackAndMergeUpdates(ctx, nil, toolImageName, ignoreErrors)
			if err != nil {
				return updatedImageState, nil, err
			}
			return updatedImageState, nil, nil
		}

		updatedImageState, _, err := dm.installUpdates(ctx, nil, ignoreErrors)
		if err != nil {
			return updatedImageState, nil, err
		}
		return updatedImageState, nil, nil
	}

	// Else update according to specified updates
	// Validate and extract unique updates listed in input manifest
	debComparer := VersionComparer{isValidDebianVersion, isLessThanDebianVersion}
	updates, err := GetUniqueLatestUpdates(manifest.OSUpdates, debComparer, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}
	if len(updates) == 0 {
		log.Warn("No update packages were specified to apply")
		return &dm.config.ImageState, nil, nil
	}

	var updatedImageState *llb.State
	var resultManifestBytes []byte
	if dm.isDistroless {
		updatedImageState, resultManifestBytes, err = dm.unpackAndMergeUpdates(ctx, updates, toolImageName, ignoreErrors)
		if err != nil {
			return nil, nil, err
		}
	} else {
		updatedImageState, resultManifestBytes, err = dm.installUpdates(ctx, updates, ignoreErrors)
		if err != nil {
			return nil, nil, err
		}
	}

	// Validate that the deployed packages are of the requested version or better
	errPkgs, err := validateDebianPackageVersions(updates, debComparer, resultManifestBytes, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}

	return updatedImageState, errPkgs, nil
}

// Probe the target image for:
// - DPKG status type to distinguish between regular and distroless images.
// - Whether status.d contains base64-encoded package names.
func (dm *dpkgManager) probeDPKGStatus(ctx context.Context, toolImage string, platform *ocispecs.Platform) error {
	imageStateCurrent := dm.config.ImageState
	if dm.config.PatchedConfigData != nil {
		imageStateCurrent = dm.config.PatchedImageState
	}

	// Spin up a build tooling container to pull and unpack packages to create patch layer.
	toolingBase := llb.Image(toolImage,
		llb.Platform(*platform),
		llb.ResolveModeDefault,
	)
	updated := toolingBase.Run(
		llb.Shlex("apt-get -o Acquire::Retries=3 update"),
		llb.WithProxy(utils.GetProxy()),
		llb.IgnoreCache,
		llb.WithCustomName("Updating package database"),
	).Root()

	const installBusyBoxCmd = "apt-get -o Acquire::Retries=3 install busybox-static"
	busyBoxInstalled := updated.Run(
		llb.Shlex(installBusyBoxCmd),
		llb.WithProxy(utils.GetProxy()),
		llb.WithCustomName("Installing busybox")).Root()
	busyBoxApplied := imageStateCurrent.File(llb.Copy(busyBoxInstalled, "/bin/busybox", "/bin/busybox"))
	mkFolders := busyBoxApplied.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true)))

	resultsState := mkFolders.Run(
		llb.AddEnv("DPKG_STATUS_PATH", dpkgStatusPath),
		llb.AddEnv("RESULTS_PATH", resultsPath),
		llb.AddEnv("DPKG_STATUS_FOLDER", dpkgStatusFolder),
		llb.AddEnv("RESULT_STATUSD_PATH", filepath.Join(resultsPath, "status.d")),
		llb.AddEnv("DPKG_STATUS_IS_DIRECTORY", fmt.Sprintf("%d", DPKGStatusDirectory)),
		llb.AddEnv("DPKG_STATUS_IS_FILE", fmt.Sprintf("%d", DPKGStatusFile)),
		llb.AddEnv("DPKG_STATUS_IS_UNKNOWN", fmt.Sprintf("%d", DPKGStatusNone)),
		llb.AddEnv("STATUSD_OUTPUT_FILENAME", statusdOutputFilename),
		llb.Args([]string{
			`/bin/busybox`, `sh`, `-c`, `
                status="$DPKG_STATUS_IS_UNKNOWN"
                if [ -f "$DPKG_STATUS_PATH" ]; then
                    status="$DPKG_STATUS_IS_FILE"
                    cp "$DPKG_STATUS_PATH" "$RESULTS_PATH"
                elif [ -d "$DPKG_STATUS_FOLDER" ]; then
                    status="$DPKG_STATUS_IS_DIRECTORY"
                    ls -1 "$DPKG_STATUS_FOLDER" > "$RESULT_STATUSD_PATH"
                    mv "$DPKG_STATUS_FOLDER"/* "$RESULTS_PATH"
                fi
                echo -n "$status" > "${RESULTS_PATH}/${STATUSD_OUTPUT_FILENAME}"
        `,
		})).AddMount(resultsPath, llb.Scratch())

	typeBytes, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, &resultsState, statusdOutputFilename)
	if err != nil {
		return err
	}

	dpkgStatus := getDPKGStatusType(typeBytes)
	switch dpkgStatus {
	case DPKGStatusFile:
		return nil
	case DPKGStatusDirectory:
		statusdNamesBytes, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, &resultsState, "status.d")
		if err != nil {
			return err
		}

		dm.statusdNames = strings.ReplaceAll(string(statusdNamesBytes), "\n", " ")
		dm.statusdNames = strings.TrimSpace(dm.statusdNames)

		// Use bufio.Scanner with bytes.NewReader to avoid duplicating the list in memory
		scanner := bufio.NewScanner(bytes.NewReader(statusdNamesBytes))
		packageInfo := make(map[string]string)
		statusdFileMap := make(map[string]string)
		var buffer bytes.Buffer

		for scanner.Scan() {
			name := scanner.Text()
			fileBytes, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, &resultsState, name)
			if err != nil {
				return err
			}

			if !strings.HasSuffix(name, ".md5sums") {
				pkgName, pkgVersion, err := GetPackageInfo(string(fileBytes))
				if err != nil {
					return err
				}

				buffer.Write(fileBytes)
				buffer.WriteString("\n")

				packageInfo[pkgName] = pkgVersion
				statusdFileMap[pkgName] = name
			}
		}

		if err := scanner.Err(); err != nil {
			return err
		}

		dm.tempStatusFile = buffer.String()
		dm.packageInfo = packageInfo
		dm.statusdFileMap = statusdFileMap

		log.Infof("Processed status.d: %s", dm.statusdNames)
		dm.isDistroless = true
		return nil
	default:
		err := fmt.Errorf("could not infer DPKG status of target image: %v", dpkgStatus)
		log.Error(err)
		return err
	}
}

func GetPackageInfo(file string) (string, string, error) {
	var packageName string
	var packageVersion string

	packagePattern := regexp.MustCompile(`^Package:\s*(.*)`)
	match := packagePattern.FindStringSubmatch(file)
	if len(match) > 1 {
		packageName = match[1]
	} else {
		return "", "", fmt.Errorf("no package name found for package")
	}

	versionPattern := regexp.MustCompile(`Version:\s*(.*)`)
	match = versionPattern.FindStringSubmatch(file)
	if len(match) > 1 {
		packageVersion = match[1]
	} else {
		return "", "", fmt.Errorf("no version found for package")
	}

	return packageName, packageVersion, nil
}

// Patch a regular debian image with:
//   - sh and apt-get installed on the image
//   - valid dpkg status on the image
//
// Images with neither (i.e. Google Debian Distroless) should be patched with unpackAndMergeUpdates.
func (dm *dpkgManager) installUpdates(ctx context.Context, updates unversioned.UpdatePackages, ignoreErrors bool) (*llb.State, []byte, error) {
	imageStateCurrent := dm.config.ImageState
	if dm.config.PatchedConfigData != nil {
		imageStateCurrent = dm.config.PatchedImageState
	}

	aptGetUpdated := imageStateCurrent.Run(
		llb.Shlex("apt-get -o Acquire::Retries=3 update"),
		llb.WithProxy(utils.GetProxy()),
		llb.IgnoreCache,
		llb.WithCustomName("Updating package database"),
	).Root()

	// Only check for upgradable packages when updating all (no specific updates list).
	if updates == nil {
		const updatesAvailableMarker = "/updates.txt"
		checkUpgradable := fmt.Sprintf(`sh -c 'if apt-get -s upgrade 2>/dev/null | grep -q "^Inst"; then touch %s; fi'`, updatesAvailableMarker)
		aptGetUpdated = aptGetUpdated.Run(
			llb.Shlex(checkUpgradable),
			llb.WithCustomName("Checking for upgradable packages"),
		).Root()

		_, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, &aptGetUpdated, updatesAvailableMarker)
		if err != nil {
			log.Info("No upgradable packages found for this image.")
			return nil, nil, types.ErrNoUpdatesFound
		}
	}

	// detect held packages and log them
	checkHeldCmd := `sh -c "apt-mark showhold | tee /held.txt"`
	heldState := aptGetUpdated.Run(
		llb.Shlex(checkHeldCmd),
		llb.WithCustomName("Checking held packages"),
	).Root()

	// read that file from the solve output
	heldBytes, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, &heldState, "/held.txt")
	if err == nil && len(heldBytes) > 0 {
		lines := strings.Split(strings.TrimSpace(string(heldBytes)), "\n")
		if len(lines) > 0 && lines[0] != "" {
			log.Warnf("apt-held packages found, not patched by Copa: %v", lines)
		}
	}

	// Install all requested update packages without specifying the version. This works around:
	//  - Reports being slightly out of date, where a newer security revision has displaced the one specified leading to not found errors.
	//  - Reports not specifying version epochs correct (e.g. bsdutils=2.36.1-8+deb11u1 instead of with epoch as 1:2.36.1-8+dev11u1)
	// Note that this keeps the log files from the operation, which we can consider removing as a size optimization in the future.

	var installCmd string
	if updates != nil {
		aptGetInstallTemplate := `sh -c "apt-get -o Acquire::Retries=3 install --no-install-recommends -y %s && apt-get clean -y"`
		pkgStrings := []string{}
		for _, u := range updates {
			pkgStrings = append(pkgStrings, u.Name)
		}
		installCmd = fmt.Sprintf(aptGetInstallTemplate, strings.Join(pkgStrings, " "))
	} else {
		// if updates is not specified, update all packages
		installCmd = `sh -c "output=$(apt-get -o Acquire::Retries=3 upgrade -y && apt-get clean -y && apt-get autoremove -y 2>&1); if [ $? -ne 0 ]; then echo "$output" >>error_log.txt; fi"`
	}

	var customName string
	if updates != nil {
		customName = fmt.Sprintf("Installing %d security updates", len(updates))
	} else {
		customName = "Upgrading all packages"
	}
	aptGetInstalled := aptGetUpdated.Run(
		llb.Shlex(installCmd),
		llb.WithProxy(utils.GetProxy()),
		llb.WithCustomName(customName),
	).Root()

	// Validate no errors were encountered if updating all
	if updates == nil && !ignoreErrors {
		aptGetInstalled = aptGetInstalled.Run(
			buildkit.Sh("if [ -s error_log.txt ]; then cat error_log.txt; exit 1; fi"),
			llb.WithCustomName("Validating package updates"),
		).Root()
	}

	// Write results.manifest to host for post-patch validation
	const outputResultsTemplate = `sh -c 'grep "^Package:\|^Version:" "%s" >> "%s"'`
	outputResultsCmd := fmt.Sprintf(outputResultsTemplate, dpkgStatusPath, resultManifest)
	resultsWritten := aptGetInstalled.Dir(resultsPath).Run(
		llb.Shlex(outputResultsCmd),
		llb.WithCustomName("Generating package manifest"),
	).Root()
	resultsDiff := llb.Diff(aptGetInstalled, resultsWritten)

	resultsBytes, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, &resultsDiff, filepath.Join(resultsPath, resultManifest))
	if err != nil {
		return nil, nil, err
	}

	// If the image has been patched before, diff the base image and patched image to retain previous patches
	if dm.config.PatchedConfigData != nil {
		// Diff the base image and patched image to get previous patches
		prevPatchDiff := llb.Diff(dm.config.ImageState, dm.config.PatchedImageState)

		// Diff the base image and new patches
		newPatchDiff := llb.Diff(aptGetUpdated, aptGetInstalled)

		// Merging these two diffs will discard everything in the filesystem that hasn't changed
		// Doing llb.Scratch ensures we can keep everything in the filesystem that has not changed
		combinedPatch := llb.Merge([]llb.State{prevPatchDiff, newPatchDiff})
		squashedPatch := llb.Scratch().File(llb.Copy(combinedPatch, "/", "/"))

		// Merge previous and new patches into the base image
		completePatchMerge := llb.Merge([]llb.State{dm.config.ImageState, squashedPatch})

		return &completePatchMerge, resultsBytes, nil
	}

	// Diff the installed updates and merge that into the target image
	patchDiff := llb.Diff(aptGetUpdated, aptGetInstalled)
	patchMerge := llb.Merge([]llb.State{dm.config.ImageState, patchDiff})

	return &patchMerge, resultsBytes, nil
}

func (dm *dpkgManager) unpackAndMergeUpdates(ctx context.Context, updates unversioned.UpdatePackages, toolImage string, ignoreErrors bool) (*llb.State, []byte, error) {
	imagePlatform, err := dm.config.ImageState.GetPlatform(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get image platform %w", err)
	}

	// Spin up a build tooling container to fetch and unpack packages to create patch layer.
	// Pull family:version -> need to create version to base image map

	// First try with the specified platform, fallback to host platform if it fails
	toolingBase, err := tryImage(ctx, toolImage, dm.config.Client, imagePlatform)
	if err != nil {
		log.Debugf("Failed to resolve tooling image %s with platform %v, falling back to host platform: %v", toolImage, imagePlatform, err)
		// Try again without platform specification (uses host platform)
		toolingBase, err = tryImage(ctx, toolImage, dm.config.Client, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve tooling image %s even with host platform fallback: %w", toolImage, err)
		}
		log.Debugf("Successfully resolved tooling image %s using host platform", toolImage)
	}

	// Run apt-get update && apt-get download list of updates to target folder
	updated := toolingBase.Run(
		llb.Shlex("apt-get -o Acquire::Retries=3 update"),
		llb.WithProxy(utils.GetProxy()),
		llb.IgnoreCache,
		llb.WithCustomName("Updating package database in tooling container"),
	).Root()

	// Retrieve all package info from image to be patched.
	jsonPackageData, err := getJSONPackageData(dm.packageInfo)
	if err != nil {
		return nil, nil, err
	}

	// In the case of update all packages, only update packages that are not already latest version. Store these packages in packages.txt.
	if updates == nil {
		updated = updated.Run(
			llb.AddEnv("PACKAGES_PRESENT", string(jsonPackageData)),
			llb.Args([]string{
				`bash`, `-c`, `
                            json_str=$PACKAGES_PRESENT
                            update_packages=""

                            while IFS=':' read -r package version; do
                                pkg_name=$(echo "$package" | sed 's/^"\(.*\)"$/\1/')
                                pkg_version=$(echo "$version" | sed 's/^"\(.*\)"$/\1/')
                                latest_version=$(apt show $pkg_name 2>/dev/null | awk -F ': ' '/Version:/{print $2}')

                                if [ "$latest_version" != "$pkg_version" ]; then
                                    update_packages="$update_packages $pkg_name"
                                fi
                            done <<< "$(echo "$json_str" | tr -d '{}\n' | tr ',' '\n')"

                            if [ -n "$update_packages" ]; then
                                mkdir -p /var/cache/apt/archives
                                cd /var/cache/apt/archives
                                echo "$update_packages" > packages.txt
                                touch /updates.txt
                            fi
                    `,
			}),
			llb.WithCustomName("Analyzing packages for updates"),
		).Root()
		if _, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, &updated, "/updates.txt"); err != nil {
			log.Info("No upgradable packages found for this image (distroless path).")
			return nil, nil, types.ErrNoUpdatesFound
		}
	}

	// Replace status file in tooling image with new status file with relevant pacakges from image to be patched.
	// Regenerate /var/lib/dpkg/info files based on relevant pacakges from image to be patched.
	dpkgdb := updated.Run(
		llb.AddEnv("PACKAGES_PRESENT_ALL", string(jsonPackageData)),
		llb.AddEnv("STATUS_FILE", dm.tempStatusFile),
		llb.Args([]string{
			`bash`, `-xec`, `
							set -ex

							json_str=$PACKAGES_PRESENT_ALL

							rm -r /var/lib/dpkg/info
							mkdir -p /var/lib/dpkg/info

							apt-get -o Acquire::Retries=3 update

							while IFS=':' read -r package version; do
								pkg_name=$(echo "$package" | sed 's/^"\(.*\)"$/\1/')
								apt-get -o Acquire::Retries=3 install --reinstall -y $pkg_name
							done <<< "$(echo "$json_str" | tr -d '{}\n' | tr ',' '\n')"

							apt --fix-broken install
							dpkg --configure -a
							apt-get check

							echo "$STATUS_FILE" > /var/lib/dpkg/status
							ls -lh /var/lib/dpkg
						`,
		}),
		llb.WithCustomName("Setting up package database in tooling container"),
	).Root()

	// Download all requested update packages without specifying the version. This works around:
	//  - Reports being slightly out of date, where a newer security revision has displaced the one specified leading to not found errors.
	//  - Reports not specifying version epochs correct (e.g. bsdutils=2.36.1-8+deb11u1 instead of with epoch as 1:2.36.1-8+dev11u1)
	var downloadCmd string
	pkgStrings := []string{}
	var updateAll string
	if updates != nil {
		for _, u := range updates {
			pkgStrings = append(pkgStrings, u.Name)
		}
		downloadCmd = fmt.Sprintf(aptGetDownloadScript, strings.Join(pkgStrings, " "))
		updateAll = "false"
	} else {
		downloadCmd = aptGetDownloadScript
		updateAll = "true"
	}

	errorValidation := "false"
	if ignoreErrors {
		errorValidation = "true"
	}

	jsonStatusdFileMap, err := getJSONStatusdFileMap(dm.statusdFileMap)
	if err != nil {
		return nil, nil, err
	}

	updated = updated.File(llb.Mkfile("download.sh", 0o777, []byte(downloadCmd)))

	withDPkgStatus := dm.config.ImageState.
		File(llb.Rm("/var/lib/dpkg")).
		File(
			llb.Copy(dpkgdb, "/var/lib/dpkg", "/var/lib/dpkg"),
		)

	// Mount image rootfs into tooling image.
	// Now, when Copa does dpkg install into the temp rootfs, it wont get override any config files since they are already there.
	var downloadCustomName string
	if updates != nil {
		downloadCustomName = fmt.Sprintf("Downloading and installing %d security updates", len(updates))
	} else {
		downloadCustomName = "Downloading and installing all package updates"
	}
	downloaded := updated.Run(
		llb.AddEnv("IGNORE_ERRORS", errorValidation),
		llb.AddEnv("UPDATE_ALL", updateAll),
		llb.AddEnv("STATUSD_FILE_MAP", string(jsonStatusdFileMap)),
		buildkit.Sh(`./download.sh`),
		llb.WithProxy(utils.GetProxy()),
		llb.WithCustomName(downloadCustomName),
	).AddMount("/tmp/debian-rootfs", withDPkgStatus)

	resultBytes, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, &downloaded, "/manifest")
	if err != nil {
		return nil, nil, err
	}

	withoutManifest := downloaded.File(llb.Rm("/manifest"))
	diffBase := llb.Diff(dm.config.ImageState, withoutManifest)
	downloaded = llb.Merge([]llb.State{diffBase, withoutManifest})

	// If the image has been patched before, diff the base image and patched image to retain previous patches
	if dm.config.PatchedConfigData != nil {
		// Diff the base image and patched image to get previous patches
		prevPatchDiff := llb.Diff(dm.config.ImageState, dm.config.PatchedImageState)

		// Merging these two diffs will discard everything in the filesystem that hasn't changed
		// Doing llb.Scratch ensures we can keep everything in the filesystem that has not changed
		combinedPatch := llb.Merge([]llb.State{prevPatchDiff, downloaded})
		squashedPatch := llb.Scratch().File(llb.Copy(combinedPatch, "/", "/"))

		// Merge previous and new patches into the base image
		completePatchMerge := llb.Merge([]llb.State{dm.config.ImageState, squashedPatch})

		return &completePatchMerge, resultBytes, nil
	}

	unpacked := llb.Diff(updated, downloaded)
	merged := llb.Merge([]llb.State{llb.Scratch(), dm.config.ImageState, unpacked})

	return &merged, resultBytes, nil
}

func (dm *dpkgManager) GetPackageType() string {
	return "deb"
}

func dpkgParseResultsManifest(b []byte) (map[string]string, error) {
	buf := bytes.NewBuffer(b)

	// results.manifest file is expected to be subset of DPKG status or debian info format
	// consisting of repeating consecutive blocks of:
	//
	// Package: <package name>
	// Version: <version value>
	// ...
	updateMap := map[string]string{}
	fs := bufio.NewScanner(buf)
	var packageName string
	for fs.Scan() {
		kv := strings.Split(fs.Text(), " ")
		if len(kv) != 2 {
			err := fmt.Errorf("unexpected %s file entry: %s", resultManifest, fs.Text())
			log.Error(err)
			return nil, err
		}
		switch {
		case kv[0] == "Package:":
			if packageName != "" {
				log.Debugf("ignoring held or not-installed Package without Version: %s", packageName)
			}
			packageName = kv[1]
		case kv[0] == "Version:" && packageName != "":
			updateMap[packageName] = kv[1]
			packageName = ""
		default:
			err := fmt.Errorf("unexpected field found: %s", fs.Text())
			log.Error(err)
			return nil, err
		}
	}
	if packageName != "" {
		log.Debugf("ignoring held or not-installed Package without Version: %s", packageName)
	}

	return updateMap, nil
}

func validateDebianPackageVersions(updates unversioned.UpdatePackages, cmp VersionComparer, results []byte, ignoreErrors bool) ([]string, error) {
	// Load file into map[string]string for package:version lookup
	updateMap, err := dpkgParseResultsManifest(results)
	if err != nil {
		return nil, err
	}

	// for each target package, validate version is mapped version is >= requested version
	var allErrors *multierror.Error
	errorPkgs := []string{}
	for _, update := range updates {
		version, ok := updateMap[update.Name]
		if !ok {
			log.Warnf("Package %s is not installed, may have been uninstalled during upgrade", update.Name)
			continue
		}
		if !cmp.IsValid(version) {
			err := fmt.Errorf("invalid version %s found for package %s", version, update.Name)
			log.Error(err)
			errorPkgs = append(errorPkgs, update.Name)
			allErrors = multierror.Append(allErrors, err)
			continue
		}
		if cmp.LessThan(version, update.FixedVersion) {
			err = fmt.Errorf("downloaded package %s version %s lower than required %s for update", update.Name, version, update.FixedVersion)
			log.Error(err)
			errorPkgs = append(errorPkgs, update.Name)
			allErrors = multierror.Append(allErrors, err)
			continue
		}
		log.Infof("Validated package %s version %s meets requested version %s", update.Name, version, update.FixedVersion)
	}

	if ignoreErrors {
		return errorPkgs, nil
	}

	return errorPkgs, allErrors.ErrorOrNil()
}

func getJSONStatusdFileMap(statusdFileMap map[string]string) ([]byte, error) {
	jsonBytes, err := json.Marshal(statusdFileMap)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal statusd file map to JSON: %w", err)
	}
	return jsonBytes, nil
}
