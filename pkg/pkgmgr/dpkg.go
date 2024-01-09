package pkgmgr

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	debVer "github.com/knqyf263/go-deb-version"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const (
	dpkgLibPath      = "/var/lib/dpkg"
	dpkgStatusPath   = dpkgLibPath + "/status"
	dpkgStatusFolder = dpkgLibPath + "/status.d"

	statusdOutputFilename = "statusd_type"
)

type dpkgManager struct {
	config        *buildkit.Config
	workingFolder string
	isDistroless  bool
	statusdNames  string
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
func getAPTImageName(manifest *unversioned.UpdateManifest) string {
	version := manifest.Metadata.OS.Version
	if manifest.Metadata.OS.Type == "debian" {
		version = strings.Split(manifest.Metadata.OS.Version, ".")[0] + "-slim"
	}

	// TODO: support qualifying image name with designated repository
	log.Debugf("Using %s:%s as basis for tooling image", manifest.Metadata.OS.Type, version)
	return fmt.Sprintf("%s:%s", manifest.Metadata.OS.Type, version)
}

func getDPKGStatusType(b []byte) dpkgStatusType {
	if len(b) == 0 {
		return DPKGStatusNone
	}

	st, err := strconv.Atoi(string(b))
	if err != nil {
		st = int(DPKGStatusNone)
	}

	// convert ascii digit to byte
	statusType := dpkgStatusType(st)
	if statusType >= DPKGStatusInvalid {
		return DPKGStatusInvalid
	}

	return statusType
}

func (dm *dpkgManager) InstallUpdates(ctx context.Context, manifest *unversioned.UpdateManifest, ignoreErrors bool) (*llb.State, []string, error) {
	// Validate and extract unique updates listed in input manifest
	debComparer := VersionComparer{isValidDebianVersion, isLessThanDebianVersion}
	updates, err := GetUniqueLatestUpdates(manifest.Updates, debComparer, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}
	if len(updates) == 0 {
		log.Warn("No update packages were specified to apply")
		return &dm.config.ImageState, nil, nil
	}

	// Probe for additional information to execute the appropriate update install graphs
	toolImageName := getAPTImageName(manifest)
	if err := dm.probeDPKGStatus(ctx, toolImageName); err != nil {
		return nil, nil, err
	}

	var updatedImageState *llb.State
	var resultManifestBytes []byte
	if dm.isDistroless {
		updatedImageState, resultManifestBytes, err = dm.unpackAndMergeUpdates(ctx, updates, toolImageName)
		if err != nil {
			return nil, nil, err
		}
	} else {
		updatedImageState, resultManifestBytes, err = dm.installUpdates(ctx, updates)
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
func (dm *dpkgManager) probeDPKGStatus(ctx context.Context, toolImage string) error {
	// Spin up a build tooling container to pull and unpack packages to create patch layer.
	toolingBase := llb.Image(toolImage,
		llb.Platform(dm.config.Platform),
		llb.ResolveModeDefault,
	)
	updated := toolingBase.Run(
		llb.Shlex("apt update"),
		llb.WithProxy(utils.GetProxy()),
		llb.IgnoreCache,
	).Root()

	const installBusyBoxCmd = "apt install busybox-static"
	busyBoxInstalled := updated.Run(llb.Shlex(installBusyBoxCmd), llb.WithProxy(utils.GetProxy())).Root()
	busyBoxApplied := dm.config.ImageState.File(llb.Copy(busyBoxInstalled, "/bin/busybox", "/bin/busybox"))
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
		log.Infof("Processed status.d: %s", dm.statusdNames)
		dm.isDistroless = true
		return nil
	default:
		err := fmt.Errorf("could not infer DPKG status of target image: %v", dpkgStatus)
		log.Error(err)
		return err
	}
}

// Patch a regular debian image with:
//   - sh and apt installed on the image
//   - valid dpkg status on the image
//
// Images Images with neither (i.e. Google Debian Distroless) should be patched with unpackAndMergeUpdates
//
// TODO: Support Debian images with valid dpkg status but missing tools. No current examples exist in test set
// i.e. extra RunOption to mount a copy of busybox-static or full apt install into the image and invoking that.
func (dm *dpkgManager) installUpdates(ctx context.Context, updates unversioned.UpdatePackages) (*llb.State, []byte, error) {
	// TODO: Add support for custom APT config and gpg key injection
	// Since this takes place in the target container, it can interfere with install actions
	// such as the installation of the updated debian-archive-keyring package, so it's probably best
	// to separate it out to an explicit container edit command or opt-in before patching.
	aptUpdated := dm.config.ImageState.Run(
		llb.Shlex("apt update"),
		llb.WithProxy(utils.GetProxy()),
		llb.IgnoreCache,
	).Root()

	// Install all requested update packages without specifying the version. This works around:
	//  - Reports being slightly out of date, where a newer security revision has displaced the one specified leading to not found errors.
	//  - Reports not specifying version epochs correct (e.g. bsdutils=2.36.1-8+deb11u1 instead of with epoch as 1:2.36.1-8+dev11u1)
	// Note that this keeps the log files from the operation, which we can consider removing as a size optimization in the future.
	const aptInstallTemplate = `sh -c "apt install --no-install-recommends -y %s && apt clean -y"`
	pkgStrings := []string{}
	for _, u := range updates {
		pkgStrings = append(pkgStrings, u.Name)
	}
	installCmd := fmt.Sprintf(aptInstallTemplate, strings.Join(pkgStrings, " "))
	aptInstalled := aptUpdated.Run(llb.Shlex(installCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Write results.manifest to host for post-patch validation
	const outputResultsTemplate = `sh -c 'grep "^Package:\|^Version:" "%s" >> "%s"'`
	outputResultsCmd := fmt.Sprintf(outputResultsTemplate, dpkgStatusPath, resultManifest)
	resultsWritten := aptInstalled.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).Root()
	resultsDiff := llb.Diff(aptInstalled, resultsWritten)

	resultsBytes, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, &resultsDiff, filepath.Join(resultsPath, resultManifest))
	if err != nil {
		return nil, nil, err
	}

	// Diff the installed updates and merge that into the target image
	patchDiff := llb.Diff(aptUpdated, aptInstalled)
	patchMerge := llb.Merge([]llb.State{dm.config.ImageState, patchDiff})
	return &patchMerge, resultsBytes, nil
}

func (dm *dpkgManager) unpackAndMergeUpdates(ctx context.Context, updates unversioned.UpdatePackages, toolImage string) (*llb.State, []byte, error) {
	// Spin up a build tooling container to fetch and unpack packages to create patch layer.
	// Pull family:version -> need to create version to base image map
	toolingBase := llb.Image(toolImage,
		llb.Platform(dm.config.Platform),
		llb.ResolveModeDefault,
	)

	// Run apt update && apt download list of updates to target folder
	updated := toolingBase.Run(
		llb.Shlex("apt update"),
		llb.WithProxy(utils.GetProxy()),
		llb.IgnoreCache,
	).Root()

	// Download all requested update packages without specifying the version. This works around:
	//  - Reports being slightly out of date, where a newer security revision has displaced the one specified leading to not found errors.
	//  - Reports not specifying version epochs correct (e.g. bsdutils=2.36.1-8+deb11u1 instead of with epoch as 1:2.36.1-8+dev11u1)
	const aptDownloadTemplate = "apt download --no-install-recommends %s"
	pkgStrings := []string{}
	for _, u := range updates {
		pkgStrings = append(pkgStrings, u.Name)
	}
	downloadCmd := fmt.Sprintf(aptDownloadTemplate, strings.Join(pkgStrings, " "))
	downloaded := updated.Dir(downloadPath).Run(llb.Shlex(downloadCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Scripted enumeration and dpkg unpack of all downloaded packages [layer to merge with target]
	const extractTemplate = `find %s -name '*.deb' -exec dpkg-deb -x '{}' %s \;`
	extractCmd := fmt.Sprintf(extractTemplate, downloadPath, unpackPath)
	unpacked := downloaded.Run(llb.Shlex(extractCmd)).Root()
	unpackedToRoot := llb.Scratch().File(llb.Copy(unpacked, unpackPath, "/", &llb.CopyInfo{CopyDirContentsOnly: true}))

	// Scripted extraction of all debinfo for version checking to separate layer into local mount
	// Note that target dirs of shell commands need to be created before use
	mkFolders := downloaded.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true))).File(llb.Mkdir(dpkgStatusFolder, 0o744, llb.WithParents(true)))
	const writeFieldsTemplate = `find . -name '*.deb' -exec sh -c "dpkg-deb -f {} > %s" \;`
	writeFieldsCmd := fmt.Sprintf(writeFieldsTemplate, filepath.Join(resultsPath, "{}.fields"))
	fieldsWritten := mkFolders.Dir(downloadPath).Run(llb.Shlex(writeFieldsCmd)).Root()

	// Write the name and version of the packages applied to the results.manifest file for the host
	const outputResultsTemplate = `find . -name '*.fields' -exec sh -c 'grep "^Package:\|^Version:" {} >> %s' \;`
	outputResultsCmd := fmt.Sprintf(outputResultsTemplate, resultManifest)
	resultsWritten := fieldsWritten.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).Root()
	resultsDiff := llb.Diff(fieldsWritten, resultsWritten)

	resultsBytes, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, &resultsDiff, filepath.Join(resultsPath, resultManifest))
	if err != nil {
		return nil, nil, err
	}

	// Update the status.d folder with the package info from the applied update packages
	// Each .fields file contains the control information for the package updated in the status.d folder.
	// The package name is used as the file name but has to deal with two possible idiosyncrasies:
	// - Older distroless images had a bug where the file names were base64 encoded. If the base64 versions
	//   of the names were found in the folder previously, then we use those names.
	copyStatusTemplate := `find . -name '*.fields' -exec sh -c
		"awk -v statusDir=%s -v statusdNames=\"%s\"
			'BEGIN{split(statusdNames,names); for (n in names) b64names[names[n]]=\"\"} {a[\$1]=\$2}
			 END{cmd = \"printf \" a[\"Package:\"] \" | base64\" ;
			  cmd | getline b64name ;
			  close(cmd) ;
			  textname = a[\"Package:\"] ;`

	// older distroless/base digests appear to be truncated to use the name up to the first period (e.g. 'libssl1' instead of 'libssl1.1')
	if !strings.Contains(dm.statusdNames, ".") {
		copyStatusTemplate += `
			  gsub(\"\\\\.[^.]*$\", \"\", textname);`
	}

	copyStatusTemplate += `
			  outname = b64name in b64names ? b64name : textname;
			  outpath = statusDir \"/\" outname ;
			  printf \"cp \\\"%%s\\\" \\\"%%s\\\"\\\n\",FILENAME,outpath }'
		{} | sh" \;`

	copyStatusCmd := fmt.Sprintf(strings.ReplaceAll(copyStatusTemplate, "\n", ""), dpkgStatusFolder, dm.statusdNames)
	statusUpdated := fieldsWritten.Dir(resultsPath).Run(llb.Shlex(copyStatusCmd)).Root()

	// Diff unpacked packages layers from previous and merge with target
	statusDiff := llb.Diff(fieldsWritten, statusUpdated)
	merged := llb.Merge([]llb.State{dm.config.ImageState, unpackedToRoot, statusDiff})
	return &merged, resultsBytes, nil
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
