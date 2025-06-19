package pkgmgr

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/hashicorp/go-multierror"
	rpmVer "github.com/knqyf263/go-rpm-version"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	rpmToolsFile        = "rpmTools"
	rpmDBFile           = "rpmDB"
	rpmLibPath          = "/var/lib/rpm"
	rpmSQLLiteDB        = "rpmdb.sqlite"
	rpmNDB              = "Packages.db"
	rpmBDB              = "Packages"
	rpmManifestPath     = "/var/lib/rpmmanifest"
	rpmManifest1        = "container-manifest-1"
	rpmManifest2        = "container-manifest-2"
	rpmManifestWildcard = "container-manifest-*"
	falseConst          = "false"
	trueConst           = "true"

	resultQueryFormat = "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"
)

type rpmToolPaths map[string]string

type rpmManager struct {
	config        *buildkit.Config
	workingFolder string
	rpmTools      rpmToolPaths
	isDistroless  bool
	packageInfo   map[string]string
	osType        string
	osVersion     string
}

type rpmDBType uint

const (
	RPMDBNone rpmDBType = iota
	RPMDBBerkley
	RPMDBNative
	RPMDBSqlLite
	RPMDBManifests
	RPMDBMixed
	RPMDBInvalid // must be the last in the list

	RPMDBSize = RPMDBInvalid
)

func (st rpmDBType) String() string {
	switch st {
	case RPMDBNone:
		return "RPMDBNone"
	case RPMDBBerkley:
		return "RPMDBBerkley"
	case RPMDBNative:
		return "RPMDBNative"
	case RPMDBSqlLite:
		return "RPMDBSqlLite"
	case RPMDBManifests:
		return "RPMDBManifests"
	case RPMDBMixed:
		return "RPMDBMixed"
	}
	return "Undefined rpmDBType"
}

// Depending on go-rpm-version lib for RPM version comparison rules.
func isValidRPMVersion(v string) bool { // nolint:revive
	err := isValidVersion(v)
	return err == nil
}

func isValidVersion(ver string) error {
	if !unicode.IsDigit(rune(ver[0])) {
		return errors.New("upstream_version must start with digit")
	}

	allowedSymbols := ".-+~:_"
	for _, s := range ver {
		if !unicode.IsDigit(s) && !unicode.IsLetter(s) && !strings.ContainsRune(allowedSymbols, s) {
			return fmt.Errorf("upstream_version %s includes invalid character %q", ver, s)
		}
	}
	return nil
}

func isLessThanRPMVersion(v1, v2 string) bool {
	rpmV1 := rpmVer.NewVersion(v1)
	rpmV2 := rpmVer.NewVersion(v2)
	return rpmV1.LessThan(rpmV2)
}

// Map the target image OSType & OSVersion to an appropriate tooling image.
func getRPMImageName(manifest *unversioned.UpdateManifest, osType string, osVersion string, useCachePrefix bool) string {
	var image, version string

	if osType == "azurelinux" {
		image = "azurelinux/base/core"
		version = osVersion
	} else {
		// Standardize on cbl-mariner as tooling image base as redhat/ubi does not provide static busybox binary
		image = "cbl-mariner/base/core"
		version = "2.0"

		if manifest != nil && manifest.Metadata.OS.Type == "cbl-mariner" {
			vers := strings.Split(manifest.Metadata.OS.Version, ".")
			if len(vers) < 2 {
				vers = append(vers, "0")
			}
			version = fmt.Sprintf("%s.%s", vers[0], vers[1])
		}
	}

	log.Debugf("Using %s:%s as basis for tooling image", image, version)

	imagePrefix := "mcr.microsoft.com"
	if useCachePrefix {
		imagePrefix = imageCachePrefix
	}
	return fmt.Sprintf("%s/%s:%s", imagePrefix, image, version)
}

func parseRPMTools(b []byte) (rpmToolPaths, error) {
	buf := bytes.NewBuffer(b)
	// rpmTools file is expected contain a string map in the format of:
	// <tool name>:<tool path | `notfound`>
	// ...
	rpmTools := rpmToolPaths{}
	fs := bufio.NewScanner(buf)
	for fs.Scan() {
		kv := strings.Split(fs.Text(), `:`)
		if len(kv) != 2 {
			err := fmt.Errorf("unexpected %s file entry: %s", rpmToolsFile, fs.Text())
			log.Error(err)
			return nil, err
		}
		if kv[1] != "notfound" && kv[1] != "" {
			rpmTools[kv[0]] = kv[1]
		}
	}
	return rpmTools, nil
}

// Check the RPM DB type given image probe results.
func getRPMDBType(b []byte) rpmDBType {
	buf := bytes.NewBuffer(b)
	s := bufio.NewScanner(buf)

	set := sets.New[string]()
	for s.Scan() {
		fullPath := s.Text()
		base := filepath.Base(fullPath)
		set.Insert(base)
	}

	rpmDBs := make([]rpmDBType, 0, RPMDBSize)

	if set.Has(rpmBDB) {
		rpmDBs = append(rpmDBs, RPMDBBerkley)
	}

	if set.Has(rpmNDB) {
		rpmDBs = append(rpmDBs, RPMDBNative)
	}

	if set.Has(rpmSQLLiteDB) {
		rpmDBs = append(rpmDBs, RPMDBSqlLite)
	}

	if set.Has(rpmManifest1) && set.Has(rpmManifest2) {
		rpmDBs = append(rpmDBs, RPMDBManifests)
	}

	switch len(rpmDBs) {
	case 0:
		return RPMDBNone
	case 1:
		return rpmDBs[0]
	default:
		return RPMDBMixed
	}
}

func (rm *rpmManager) InstallUpdates(ctx context.Context, manifest *unversioned.UpdateManifest, ignoreErrors bool) (*llb.State, []string, error) {
	// Resolve set of unique packages to update if UpdateManifest provided, else update all
	var updates unversioned.UpdatePackages
	var rpmComparer VersionComparer
	var err error

	if manifest != nil {
		if manifest.Metadata.OS.Type == "oracle" && !ignoreErrors {
			err = errors.New("detected Oracle image passed in\n" +
				"Please read https://project-copacetic.github.io/copacetic/website/troubleshooting before patching your Oracle image")
			return &rm.config.ImageState, nil, err
		}

		rpmComparer = VersionComparer{isValidRPMVersion, isLessThanRPMVersion}
		updates, err = GetUniqueLatestUpdates(manifest.Updates, rpmComparer, ignoreErrors)
		if err != nil {
			return nil, nil, err
		}
		if len(updates) == 0 {
			log.Warn("No update packages were specified to apply")
			return &rm.config.ImageState, nil, nil
		}
		log.Debugf("latest unique RPMs: %v", updates)
	}

	toolImageName := getRPMImageName(manifest, rm.osType, rm.osVersion, true)
	// check if we can resolve the tool image
	if _, err := tryImage(ctx, toolImageName, rm.config.Client); err != nil {
		toolImageName = getRPMImageName(manifest, rm.osType, rm.osVersion, false)
	}

	if err := rm.probeRPMStatus(ctx, toolImageName); err != nil {
		return nil, nil, err
	}

	var updatedImageState *llb.State
	var resultManifestBytes []byte
	if rm.isDistroless {
		updatedImageState, resultManifestBytes, err = rm.unpackAndMergeUpdates(ctx, updates, toolImageName, ignoreErrors)
		if err != nil {
			return nil, nil, err
		}
	} else {
		updatedImageState, resultManifestBytes, err = rm.installUpdates(ctx, updates, ignoreErrors)
		if err != nil {
			return nil, nil, err
		}
	}

	var errPkgs []string
	if manifest != nil {
		// Validate that the deployed packages are of the requested version or better
		errPkgs, err = validateRPMPackageVersions(updates, rpmComparer, resultManifestBytes, ignoreErrors)
		if err != nil {
			return nil, nil, err
		}
	}

	return updatedImageState, errPkgs, nil
}

func (rm *rpmManager) probeRPMStatus(ctx context.Context, toolImage string) error {
	imageStateCurrent := rm.config.ImageState
	if rm.config.PatchedConfigData != nil {
		imageStateCurrent = rm.config.PatchedImageState
	}

	imagePlatform, err := rm.config.ImageState.GetPlatform(ctx)
	if err != nil {
		log.Error("unable to get image platform")
		return err
	}

	// Spin up a build tooling container to pull and unpack packages to create patch layer.
	toolingBase := llb.Image(toolImage,
		llb.Platform(*imagePlatform),
		llb.ResolveModeDefault,
	)

	// List all packages installed in the tooling image
	toolsListed := toolingBase.Run(llb.Shlex(`sh -c 'ls /usr/bin > applications.txt'`)).Root()
	installToolsCmd, err := rm.generateToolInstallCmd(ctx, &toolsListed)
	if err != nil {
		return err
	}

	packageManagers := []string{"tdnf", "dnf", "microdnf", "yum", "rpm"}

	toolsInstalled := toolingBase.Run(llb.Shlex(installToolsCmd), llb.WithProxy(utils.GetProxy())).Root()
	toolsApplied := imageStateCurrent.File(llb.Copy(toolsInstalled, "/usr/sbin/busybox", "/usr/sbin/busybox"))
	mkFolders := toolsApplied.
		File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true))).
		File(llb.Mkdir(inputPath, 0o744, llb.WithParents(true)))

	rpmDBList := []string{
		filepath.Join(rpmLibPath, rpmBDB),
		filepath.Join(rpmLibPath, rpmNDB),
		filepath.Join(rpmLibPath, rpmSQLLiteDB),
		filepath.Join(rpmManifestPath, rpmManifest1),
		filepath.Join(rpmManifestPath, rpmManifest2),
	}

	toolListPath := filepath.Join(inputPath, "tool_list")
	dbListPath := filepath.Join(inputPath, "rpm_db_list")

	probed := buildkit.WithArrayFile(&mkFolders, toolListPath, packageManagers)
	probed = buildkit.WithArrayFile(&probed, dbListPath, rpmDBList)
	outState := probed.Run(
		llb.AddEnv("TOOL_LIST_PATH", toolListPath),
		llb.AddEnv("DB_LIST_PATH", dbListPath),
		llb.AddEnv("RESULTS_PATH", resultsPath),
		llb.AddEnv("RPM_TOOLS_OUTPUT_FILENAME", rpmToolsFile),
		llb.AddEnv("RPM_DB_LIST_OUTPUT_FILENAME", rpmDBFile),
		llb.AddEnv("BUSYBOX", "/usr/sbin/busybox"),
		llb.Args([]string{
			`/usr/sbin/busybox`, `sh`, `-c`, `
                while IFS= read -r tool; do
                    tool_path="$($BUSYBOX which "$tool")"
                    echo "${tool}:${tool_path:-notfound}" >> "${RESULTS_PATH}/${RPM_TOOLS_OUTPUT_FILENAME}"
                done < "$TOOL_LIST_PATH"

                while IFS= read -r db; do
                    echo "$db"
                    if [ -f "$db" ]; then
                        $BUSYBOX cp "$db" "$RESULTS_PATH"
                        echo "$db" >> "${RESULTS_PATH}/${RPM_DB_LIST_OUTPUT_FILENAME}"
                    fi
                done < "$DB_LIST_PATH"
            `,
		})).AddMount(resultsPath, llb.Scratch())

	rpmDBListOutputBytes, err := buildkit.ExtractFileFromState(ctx, rm.config.Client, &outState, rpmDBFile)
	if err != nil {
		return err
	}

	// Check type of RPM DB on image to infer Mariner Distroless
	rpmDB := getRPMDBType(rpmDBListOutputBytes)
	log.Debugf("RPM DB Type in image is: %s", rpmDB)
	switch rpmDB {
	case RPMDBManifests:
		rm.isDistroless = true
		rpmManifest2File, err := buildkit.ExtractFileFromState(ctx, rm.config.Client, &outState, rpmManifest2)
		if err != nil {
			return err
		}
		// parse container-manifest-2 to get installed package names and versions
		pkgInfo, err := parseManifestFile(string(rpmManifest2File))
		if err != nil {
			return err
		}
		rm.packageInfo = pkgInfo
	case RPMDBNone, RPMDBMixed:
		err := fmt.Errorf("could not find determine RPM DB type of target image: %v", rpmDB)
		log.Error(err)
		return err
	}

	// Parse rpmTools File if not distroless
	if !rm.isDistroless {
		log.Info("Checking for available RPM tools in non-distroless image ...")

		toolsFileBytes, err := buildkit.ExtractFileFromState(ctx, rm.config.Client, &outState, rpmToolsFile)
		if err != nil {
			return err
		}

		rpmTools, err := parseRPMTools(toolsFileBytes)
		if err != nil {
			return err
		}

		var allErrors *multierror.Error
		if rpmTools["tdnf"] == "" && rpmTools["dnf"] == "" && rpmTools["yum"] == "" && rpmTools["microdnf"] == "" {
			err = errors.New("image contains no RPM package managers needed for patching")
			log.Error(err)
			allErrors = multierror.Append(allErrors, err)
		}
		if rpmTools["rpm"] == "" {
			err = errors.New("image does not have the rpm tool needed for patch verification")
			log.Error(err)
			allErrors = multierror.Append(allErrors, err)
		}
		if allErrors != nil {
			return allErrors.ErrorOrNil()
		}

		rm.rpmTools = rpmTools
	}
	return nil
}

func (rm *rpmManager) generateToolInstallCmd(ctx context.Context, toolsListed *llb.State) (string, error) {
	applicationsList, err := buildkit.ExtractFileFromState(ctx, rm.config.Client, toolsListed, "/applications.txt")
	if err != nil {
		return "", err
	}

	// packageManagersInstalled is the package manager(s) available within the tooling image
	// RPM must be excluded from this list as it cannot connect to RPM repos
	var packageManagersInstalled []string
	packageManagerList := []string{"tdnf", "dnf", "microdnf", "yum"}

	for _, packageManager := range packageManagerList {
		if strings.Contains(string(applicationsList), packageManager) {
			packageManagersInstalled = append(packageManagersInstalled, packageManager)
		}
	}

	// missingTools indicates which tools, if any, need to be installed within the tooling image
	var missingTools []string
	requiredToolingList := []string{"busybox", "dnf-utils", "cpio"}

	for _, tool := range requiredToolingList {
		isMissingTool := !strings.Contains(string(applicationsList), tool)
		if isMissingTool {
			missingTools = append(missingTools, tool)
		}

		if tool == "cpio" && !isMissingTool && strings.Contains(string(applicationsList), "rpm2cpio") {
			missingTools = append(missingTools, "cpio")
		}
	}

	// A tooling image could contain multiple package managers
	// Choose the first one detected to use in the installation command
	installCmd := fmt.Sprintf("%s install %s -y", packageManagersInstalled[0], strings.Join(missingTools, " "))

	return installCmd, nil
}

func parseManifestFile(file string) (map[string]string, error) {
	// split into lines
	file = strings.TrimSuffix(file, "\n")
	lines := strings.Split(file, "\n")

	resultMap := make(map[string]string)

	// iterate over lines
	for _, line := range lines {
		// split line into columns
		columns := strings.Split(line, "\t")

		if len(columns) >= 2 {
			// get package name and version
			name := columns[0]
			version := columns[1]
			resultMap[name] = version
		} else {
			return nil, errors.New("unexpected format when parsing rpm manifest file")
		}
	}
	return resultMap, nil
}

// Patch a regular RPM-based image with:
//   - sh and an appropriate tool installed on the image (yum, dnf, microdnf)
//   - valid rpm database on the image
func (rm *rpmManager) installUpdates(ctx context.Context, updates unversioned.UpdatePackages, ignoreErrors bool) (*llb.State, []byte, error) {
	pkgs := ""

	imageStateCurrent := rm.config.ImageState
	if rm.config.PatchedConfigData != nil {
		imageStateCurrent = rm.config.PatchedImageState
	}

	// If specific updates, provided, parse into pkg names, else will update all
	if updates != nil {
		// Format the requested updates into a space-separated string
		pkgStrings := []string{}
		for _, u := range updates {
			pkgStrings = append(pkgStrings, u.Name)
		}
		pkgs = strings.Join(pkgStrings, " ")
	}

	// Install patches using available rpm managers in order of preference
	var installCmd string
	switch {
	case rm.rpmTools["tdnf"] != "" || rm.rpmTools["dnf"] != "":
		dnfTooling := rm.rpmTools["tdnf"]
		if dnfTooling == "" {
			dnfTooling = rm.rpmTools["dnf"]
		}
		if !rm.checkForUpgrades(ctx, dnfTooling, "") {
			return nil, nil, fmt.Errorf("no patchable packages found")
		}

		// Use --releasever=latest for DNFAdd commentMore actions
		var dnfInstallTemplate string
		if strings.Contains(dnfTooling, "dnf") {
			dnfInstallTemplate = `sh -c '%[1]s clean all && %[1]s --releasever=latest makecache --refresh -y && %[1]s --releasever=latest upgrade --best --refresh %[2]s -y && %[1]s clean all'`
		} else {
			dnfInstallTemplate = `sh -c '%[1]s clean all && %[1]s makecache --refresh -y && %[1]s upgrade --best --refresh %[2]s -y && %[1]s clean all'`
		}
		installCmd = fmt.Sprintf(dnfInstallTemplate, dnfTooling, pkgs)
	case rm.rpmTools["yum"] != "":
		if !rm.checkForUpgrades(ctx, rm.rpmTools["yum"], "") {
			return nil, nil, fmt.Errorf("no patchable packages found")
		}

		const yumInstallTemplate = `sh -c '%[1]s clean all && %[1]s makecache --refresh -y && %[1]s upgrade --best %[2]s -y && %[1]s clean all'`
		installCmd = fmt.Sprintf(yumInstallTemplate, rm.rpmTools["yum"], pkgs)
	case rm.rpmTools["microdnf"] != "":
		if !rm.checkForUpgrades(ctx, rm.rpmTools["microdnf"], "") {
			return nil, nil, fmt.Errorf("no patchable packages found")
		}

		// Use --releasever=latest for microdnf as well since it's DNF-basedAdd commentMore actions
		const microdnfInstallTemplate = `sh -c '%[1]s clean all && %[1]s --releasever=latest makecache --refresh -y && %[1]s --releasever=latest update --best %[2]s -y && %[1]s clean all'`
		installCmd = fmt.Sprintf(microdnfInstallTemplate, rm.rpmTools["microdnf"], pkgs)
	default:
		err := errors.New("unexpected: no package manager tools were found for patching")
		return nil, nil, err
	}
	installed := imageStateCurrent.Run(llb.Shlex(installCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Validate no errors were encountered if updating all
	if updates == nil && !ignoreErrors {
		installed = installed.Run(buildkit.Sh("if [ -s error_log.txt ]; then cat error_log.txt; exit 1; fi")).Root()
	}

	// Write results.manifest to host for post-patch validation
	var resultBytes []byte
	if updates != nil {
		const rpmResultsTemplate = `sh -c 'rpm -qa --queryformat "%s" %s > "%s"'`
		outputResultsCmd := fmt.Sprintf(rpmResultsTemplate, resultQueryFormat, pkgs, resultManifest)
		resultsWritten := installed.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).AddMount(resultsPath, llb.Scratch())

		var err error
		resultBytes, err = buildkit.ExtractFileFromState(ctx, rm.config.Client, &resultsWritten, resultManifest)
		if err != nil {
			return nil, nil, err
		}
	}

	// If the image has been patched before, diff the base image and patched image to retain previous patches
	if rm.config.PatchedConfigData != nil {
		// Diff the base image and pat[]ched image to get previous patches
		prevPatchDiff := llb.Diff(rm.config.ImageState, rm.config.PatchedImageState)

		// Diff the base image and new patches
		newPatchDiff := llb.Diff(rm.config.ImageState, installed)

		// Merging these two diffs will discard everything in the filesystem that hasn't changed
		// Doing llb.Scratch ensures we can keep everything in the filesystem that has not changed
		combinedPatch := llb.Merge([]llb.State{prevPatchDiff, newPatchDiff})
		squashedPatch := llb.Scratch().File(llb.Copy(combinedPatch, "/", "/"))

		// Merge previous and new patches into the base image
		completePatchMerge := llb.Merge([]llb.State{rm.config.ImageState, squashedPatch})

		return &completePatchMerge, resultBytes, nil
	}

	// Diff the installed updates and merge that into the target image
	patchDiff := llb.Diff(rm.config.ImageState, installed)
	patchMerge := llb.Merge([]llb.State{rm.config.ImageState, patchDiff})

	return &patchMerge, resultBytes, nil
}

func (rm *rpmManager) checkForUpgrades(ctx context.Context, toolPath, checkUpdateTemplate string) bool {
	imageStateCurrent := rm.config.ImageState
	if rm.config.PatchedConfigData != nil {
		imageStateCurrent = rm.config.PatchedImageState
	}

	// For DNF, use --releasever=latest to ensure we check against the latest releaseAdd commentMore actions
	var refreshCmd string
	if strings.Contains(toolPath, "dnf") {
		refreshCmd = fmt.Sprintf(`sh -c '%[1]s clean all && %[1]s --releasever=latest makecache --refresh -y && %[1]s --releasever=latest check-update --refresh -y; if [ $? -eq 100 ]; then echo >> /updates.txt; fi'`, toolPath)
	} else {
		refreshCmd = fmt.Sprintf(`sh -c '%[1]s clean all && %[1]s makecache --refresh -y && %[1]s check-update --refresh -y; if [ $? -eq 100 ]; then echo >> /updates.txt; fi'`, toolPath)
	}
	stateWithCheck := imageStateCurrent.Run(llb.Shlex(refreshCmd)).Root()

	// if error in extracting file, that means updates.txt does not exist and there are no updates.
	_, err := buildkit.ExtractFileFromState(ctx, rm.config.Client, &stateWithCheck, "/updates.txt")

	return err == nil
}

func (rm *rpmManager) unpackAndMergeUpdates(ctx context.Context, updates unversioned.UpdatePackages, toolImage string, ignoreErrors bool) (*llb.State, []byte, error) {
	// Spin up a build tooling container to fetch and unpack packages to create patch layer.
	// Pull family:version -> need to create version to base image map
	toolingBase := llb.Image(toolImage,
		llb.ResolveModeDefault,
	)

	// List all packages installed in the tooling image
	toolsListed := toolingBase.Run(llb.Shlex(`sh -c 'ls /usr/bin > applications.txt'`)).Root()
	installToolsCmd, err := rm.generateToolInstallCmd(ctx, &toolsListed)
	if err != nil {
		return nil, nil, err
	}

	// Install busybox. This should reuse the layer cached from probeRPMStatus.
	toolsInstalled := toolingBase.Run(llb.Shlex(installToolsCmd), llb.WithProxy(utils.GetProxy())).Root()
	busyboxCopied := toolsInstalled.Dir(downloadPath).Run(llb.Shlex("cp /usr/sbin/busybox .")).Root()

	// Retrieve all package info from image to be patched.
	jsonPackageData, err := getJSONPackageData(rm.packageInfo)
	if err != nil {
		return nil, nil, err
	}

	// In the case of update all packages, only update packages that are not latest version. Store these packages in packages.txt.
	if updates == nil {
		busyboxCopied = busyboxCopied.Run(
			llb.AddEnv("PACKAGES_PRESENT", string(jsonPackageData)),
			llb.Args([]string{
				`bash`, `-c`, `
								json_str=$PACKAGES_PRESENT
								update_packages=""

								while IFS=':' read -r package version; do
									pkg_name=$(echo "$package" | sed 's/^"\(.*\)"$/\1/')

									pkg_version=$(echo "$version" | sed 's/^"\(.*\)"$/\1/')
									latest_version=$(yum list available $pkg_name 2>/dev/null | grep $pkg_name | tail -n 1 | tr -s ' ' | cut -d ' ' -f 2)

									if [ "$latest_version" != "$pkg_version" ]; then
										update_packages="$update_packages $pkg_name"
									fi
								done <<< "$(echo "$json_str" | tr -d '{}\n' | tr ',' '\n')"

								if [ -z "$update_packages" ]; then
									echo "No packages to update"
									exit 1
								fi

								echo "$update_packages" > packages.txt
						`,
			})).Root()
	}

	// Create a new state for tooling image with all the packages from the image we are trying to patch
	// this will ensure the rpm database is generate for us to use
	rpmdb := busyboxCopied.Run(
		llb.AddEnv("PACKAGES_PRESENT_ALL", string(jsonPackageData)),
		llb.AddEnv("OS_VERSION", rm.osVersion),
		llb.Args([]string{
			`bash`, `-xec`, `
								json_str=$PACKAGES_PRESENT_ALL
								packages_formatted=""

								while IFS=':' read -r package version; do
									pkg_name=$(echo "$package" | sed 's/^"\(.*\)"$/\1/')
									pkg_version=$(echo "$version" | sed 's/^"\(.*\)"$/\1/')

									packages_formatted="$packages_formatted $pkg_name-$pkg_version"

								done <<< "$(echo "$json_str" | tr -d '{}\n' | tr ',' '\n')"

								tdnf makecache
								tdnf install -y --releasever=$OS_VERSION --installroot=/tmp/rootfs $packages_formatted

								ls /tmp/rootfs/var/lib/rpm
						`,
		})).AddMount("/tmp/rootfs/var/lib/rpm", llb.Scratch())

	// Download all requested update packages without specifying the version. This works around:
	//  - Reports being slightly out of date, where a newer security revision has displaced the one specified leading to not found errors.
	//  - Reports not specifying version epochs correct (e.g. bsdutils=2.36.1-8+deb11u1 instead of with epoch as 1:2.36.1-8+dev11u1)
	//  - Reports specifying remediation packages for cbl-mariner v1 instead of v2 (e.g. *.cm1.aarch64 instead of *.cm2.aarch64)
	var downloadCmd string

	if updates != nil {
		rpmDownloadTemplate := `
		set -x
		packages="%s"
		echo "$packages"

		mkdir -p /tmp/rootfs/var/lib
		ln -s /tmp/rpmdb /tmp/rootfs/var/lib/rpm

		rpm --dbpath=/tmp/rootfs/var/lib/rpm -qa

		for package in $packages; do
			package="${package%%.*}" # trim anything after the first "."
			output=$(tdnf install -y --releasever=$OS_VERSION --installroot=/tmp/rootfs ${package} 2>&1)

			if [ "$IGNORE_ERRORS" = "false" ] && [ $? -ne 0 ]; then
				exit $?
			fi
		done

		mkdir /tmp/rootfs/var/lib/rpmmanifest

		rpm --dbpath=/tmp/rootfs/var/lib/rpm --erase --allmatches gpg-pubkey-*
		rpm --dbpath=/tmp/rootfs/var/lib/rpm -qa | tee /tmp/rootfs/var/lib/rpmmanifest/container-manifest-1
		rpm --dbpath=/tmp/rootfs/var/lib/rpm -qa --qf "%%{NAME}\t%%{VERSION}-%%{RELEASE}\t%%{INSTALLTIME}\t%%{BUILDTIME}\t%%{VENDOR}\t%%{EPOCH}\t%%{SIZE}\t%%{ARCH}\t%%{EPOCHNUM}\t%%{SOURCERPM}\n" \
		| tee /tmp/rootfs/var/lib/rpmmanifest/container-manifest-2

		rpm --dbpath=/tmp/rootfs/var/lib/rpm -qa
		rm /tmp/rootfs/var/lib/rpm
		rm -rf /tmp/rootfs/var/cache/tdnf

		rpm --dbpath /tmp/rpmdb -qa --qf="%%{NAME}\t%%{VERSION}-%%{RELEASE}\t%%{ARCH}\n" %s > /tmp/rootfs/manifest`

		pkgStrings := []string{}
		for _, u := range updates {
			pkgStrings = append(pkgStrings, u.Name)
		}

		downloadCmd = fmt.Sprintf(rpmDownloadTemplate, strings.Join(pkgStrings, " "), strings.Join(pkgStrings, " "))
	} else {
		// only updated the outdated packages from packages.txt
		downloadCmd = `
		set -x

		packages=$(<packages.txt)
		echo "$packages"
		mkdir -p /tmp/rootfs/var/lib
		ln -s /tmp/rpmdb /tmp/rootfs/var/lib/rpm

		rpm --dbpath=/tmp/rootfs/var/lib/rpm -qa
		for package in $packages; do
			package="${package%%.*}" # trim anything after the first "."
			output=$(tdnf install -y --releasever=$OS_VERSION --installroot=/tmp/rootfs ${package} 2>&1)

			if [ "$IGNORE_ERRORS" = "false" ] && [ $? -ne 0 ]; then
				exit $?
			fi
		done

		mkdir /tmp/rootfs/var/lib/rpmmanifest

		rpm --dbpath=/tmp/rootfs/var/lib/rpm --erase --allmatches gpg-pubkey-*
		rpm --dbpath=/tmp/rootfs/var/lib/rpm -qa | tee /tmp/rootfs/var/lib/rpmmanifest/container-manifest-1
		rpm --dbpath=/tmp/rootfs/var/lib/rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t%{EPOCH}\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}\n' \
		| tee /tmp/rootfs/var/lib/rpmmanifest/container-manifest-2
		 

		rpm --dbpath=/tmp/rootfs/var/lib/rpm -qa
		rm /tmp/rootfs/var/lib/rpm
		rm -rf /tmp/rootfs/var/cache/tdnf

		rpm --dbpath /tmp/rpmdb -qa --qf="%%{NAME}\t%%{VERSION}-%%{RELEASE}\t%%{ARCH}\n" %s > /tmp/rootfs/manifest`
	}

	errorValidation := falseConst
	if ignoreErrors {
		errorValidation = trueConst
	}

	downloaded := busyboxCopied.Run(
		llb.AddEnv("OS_VERSION", rm.osVersion),
		llb.AddEnv("IGNORE_ERRORS", errorValidation),
		buildkit.Sh(downloadCmd),
		llb.WithProxy(utils.GetProxy()),
		llb.AddMount("/tmp/rpmdb", rpmdb),
	).AddMount("/tmp/rootfs", rm.config.ImageState)

	resultBytes, err := buildkit.ExtractFileFromState(ctx, rm.config.Client, &downloaded, "/manifest")
	if err != nil {
		return nil, nil, err
	}

	withoutManifest := downloaded.File(llb.Rm("/manifest"))
	diffBase := llb.Diff(rm.config.ImageState, withoutManifest)
	downloaded = llb.Merge([]llb.State{diffBase, withoutManifest})

	// If the image has been patched before, diff the base image and patched image to retain previous patches
	if rm.config.PatchedConfigData != nil {
		// Diff the base image and patched image to get previous patches
		prevPatchDiff := llb.Diff(rm.config.ImageState, rm.config.PatchedImageState)

		// Merging these two diffs will discard everything in the filesystem that hasn't changed
		// Doing llb.Scratch ensures we can keep everything in the filesystem that has not changed
		combinedPatch := llb.Merge([]llb.State{prevPatchDiff, downloaded})
		squashedPatch := llb.Scratch().File(llb.Copy(combinedPatch, "/", "/"))

		// Merge previous and new patches into the base image
		completePatchMerge := llb.Merge([]llb.State{rm.config.ImageState, squashedPatch})

		return &completePatchMerge, resultBytes, nil
	}

	// Diff unpacked packages layers from previous and merge with target
	diff := llb.Diff(rm.config.ImageState, downloaded)
	merged := llb.Merge([]llb.State{llb.Scratch(), rm.config.ImageState, diff})

	return &merged, resultBytes, nil
}

func (rm *rpmManager) GetPackageType() string {
	return "rpm"
}

func rpmReadResultsManifest(b []byte) ([]string, error) {
	if b == nil {
		return nil, fmt.Errorf("nil result manifest buffer")
	}

	buf := bytes.NewBuffer(b)

	var lines []string
	fs := bufio.NewScanner(buf)
	for fs.Scan() {
		lines = append(lines, fs.Text())
	}

	return lines, nil
}

func getJSONPackageData(packageInfo map[string]string) ([]byte, error) {
	data, err := json.Marshal(packageInfo)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal rm.packageInfo %w", err)
	}

	return data, nil
}

func validateRPMPackageVersions(updates unversioned.UpdatePackages, cmp VersionComparer, resultsBytes []byte, ignoreErrors bool) ([]string, error) {
	lines, err := rpmReadResultsManifest(resultsBytes)
	if err != nil {
		return nil, err
	}

	// Not strictly necessary, but sort the two lists to not take a dependency on the
	// ordering behavior of rpm -qa output
	sort.SliceStable(updates, func(i, j int) bool {
		return updates[i].Name < updates[j].Name
	})
	log.Debugf("Required updates: %s", updates)

	sort.SliceStable(lines, func(i, j int) bool {
		return lines[i] < lines[j]
	})
	log.Debugf("Resulting updates: %s", lines)

	// Assert rpm info list doesn't contain more entries than expected
	if len(lines) > len(updates) {
		err = fmt.Errorf("expected %d updates, installed %d", len(updates), len(lines))
		log.Error(err)
		return nil, err
	}

	// Walk files and check update name is prefix for file name
	// results.manifest file is expected to the `rpm -qa <packages ...>`
	// using the resultQueryFormat with tab delimiters.
	var allErrors *multierror.Error
	var errorPkgs []string
	lineIndex := 0
	for _, update := range updates {
		expectedPrefix := update.Name + "\t"
		if lineIndex >= len(lines) || !strings.HasPrefix(lines[lineIndex], expectedPrefix) {
			log.Warnf("Package %s is not installed, may have been uninstalled during upgrade", update.Name)
			continue
		}

		// Found a match, trim prefix- and drop the .arch suffix to get version string
		archIndex := strings.LastIndex(lines[lineIndex], "\t")
		version := strings.TrimPrefix(lines[lineIndex][:archIndex], expectedPrefix)
		lineIndex++

		if !cmp.IsValid(version) {
			err := fmt.Errorf("invalid version %s found for package %s", version, update.Name)
			log.Error(err)
			errorPkgs = append(errorPkgs, update.Name)
			allErrors = multierror.Append(allErrors, err)
			continue
		}
		// Strip epoch from update.Version; report may specify it, but RPM naming scheme does not support epochs
		expectedVersion := update.FixedVersion[strings.Index(update.FixedVersion, ":")+1:]
		if cmp.LessThan(version, expectedVersion) {
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
