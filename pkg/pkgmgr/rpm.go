// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package pkgmgr

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	rpmVer "github.com/knqyf263/go-rpm-version"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const (
	rpmToolsFile        = "rpmTools"
	rpmLibPath          = "/var/lib/rpm"
	rpmSQLLiteDB        = "rpmdb.sqlite"
	rpmNDB              = "Packages.db"
	rpmBDB              = "Packages"
	rpmManifestPath     = "/var/lib/rpmmanifest"
	rpmManifest1        = "container-manifest-1"
	rpmManifest2        = "container-manifest-2"
	rpmManifestWildcard = "container-manifest-*"

	installToolsCmd   = "yum install busybox -y"
	resultQueryFormat = "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"
)

type rpmToolPaths map[string]string

type rpmManager struct {
	config        *buildkit.Config
	workingFolder string
	rpmTools      rpmToolPaths
	isDistroless  bool
}

type rpmDBType uint

const (
	RPMDBNone rpmDBType = iota
	RPMDBBerkley
	RPMDBNative
	RPMDBSqlLite
	RPMDBManifests
	RPMDBMixed
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
	// TODO: Verify if there are format correctness check that need to be added given lack of support in rpmVer lib
	return true
}

func isLessThanRPMVersion(v1, v2 string) bool {
	rpmV1 := rpmVer.NewVersion(v1)
	rpmV2 := rpmVer.NewVersion(v2)
	return rpmV1.LessThan(rpmV2)
}

// Map the target image OSType & OSVersion to an appropriate tooling image.
func getRPMImageName(manifest *types.UpdateManifest) string {
	// Standardize on mariner as tooling image base as redhat/ubi does not provide
	// static busybox binary
	image := "mcr.microsoft.com/cbl-mariner/base/core"
	version := "2.0"
	if manifest.OSType == "cbl-mariner" {
		// Use appropriate version of cbl-mariner image if available
		vers := strings.Split(manifest.OSVersion, ".")
		if len(vers) < 2 {
			vers = append(vers, "0")
		}
		version = fmt.Sprintf("%s.%s", vers[0], vers[1])
	}
	log.Debugf("Using %s:%s as basis for tooling image", image, version)
	return fmt.Sprintf("%s:%s", image, version)
}

func parseRPMTools(path string) (rpmToolPaths, error) {
	// Open result file
	f, err := os.Open(path)
	if err != nil {
		log.Errorf("%s could not be opened", path)
		return nil, err
	}
	defer f.Close()

	// rpmTools file is expected contain a string map in the format of:
	// <tool name>:<tool path | `notfound`>
	// ...
	rpmTools := rpmToolPaths{}
	fs := bufio.NewScanner(f)
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

// Check the RPM DB type given image probe output path.
func getRPMDBType(dir string) rpmDBType {
	out := RPMDBNone
	rpmDBs := []rpmDBType{}
	if utils.IsNonEmptyFile(dir, rpmBDB) {
		rpmDBs = append(rpmDBs, RPMDBBerkley)
	}
	if utils.IsNonEmptyFile(dir, rpmNDB) {
		rpmDBs = append(rpmDBs, RPMDBNative)
	}
	if utils.IsNonEmptyFile(dir, rpmSQLLiteDB) {
		rpmDBs = append(rpmDBs, RPMDBSqlLite)
	}
	if utils.IsNonEmptyFile(dir, rpmManifest1) && utils.IsNonEmptyFile(dir, rpmManifest2) {
		rpmDBs = append(rpmDBs, RPMDBManifests)
	}
	if len(rpmDBs) == 1 {
		out = rpmDBs[0]
	} else if len(rpmDBs) > 1 {
		out = RPMDBMixed
	}
	return out
}

func (rm *rpmManager) InstallUpdates(ctx context.Context, manifest *types.UpdateManifest, ignoreErrors bool) (*llb.State, error) {
	// Resolve set of unique packages to update
	rpmComparer := VersionComparer{isValidRPMVersion, isLessThanRPMVersion}
	updates, err := GetUniqueLatestUpdates(manifest.Updates, rpmComparer, ignoreErrors)
	if err != nil {
		return nil, err
	}
	if len(updates) == 0 {
		log.Warn("No update packages were specified to apply")
		return &rm.config.ImageState, nil
	}
	log.Debugf("latest unique RPMs: %v", updates)

	// Probe RPM status for available tooling on the target image
	toolImageName := getRPMImageName(manifest)
	if err := rm.probeRPMStatus(ctx, toolImageName); err != nil {
		return nil, err
	}

	var updatedImageState *llb.State
	if rm.isDistroless {
		updatedImageState, err = rm.unpackAndMergeUpdates(ctx, updates, toolImageName)
		if err != nil {
			return nil, err
		}
	} else {
		updatedImageState, err = rm.installUpdates(ctx, updates)
		if err != nil {
			return nil, err
		}
	}

	// Validate that the deployed packages are of the requested version or better
	resultManifestPath := filepath.Join(rm.workingFolder, resultsPath, resultManifest)
	if err := validateRPMPackageVersions(updates, rpmComparer, resultManifestPath, ignoreErrors); err != nil {
		return nil, err
	}

	return updatedImageState, nil
}

func (rm *rpmManager) probeRPMStatus(ctx context.Context, toolImage string) error {
	// Spin up a build tooling container to pull and unpack packages to create patch layer.
	toolingBase := llb.Image(toolImage,
		llb.Platform(rm.config.Platform),
		llb.ResolveModeDefault,
	)

	toolsInstalled := toolingBase.Run(llb.Shlex(installToolsCmd), llb.WithProxy(utils.GetProxy())).Root()
	toolsApplied := rm.config.ImageState.File(llb.Copy(toolsInstalled, "/usr/sbin/busybox", "/usr/sbin/busybox"))
	mkFolders := toolsApplied.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true)))

	toolList := []string{"dnf", "microdnf", "rpm", "yum"}
	toolStr := strings.Join(toolList, " ")
	const probeToolsTemplate = `/usr/sbin/busybox sh -c '
		TOOL_LIST="%s";	n=1;
		while [ $n -le %d ];
		do TOOL=$(echo "$TOOL_LIST" | /usr/sbin/busybox cut -d " " -f $n);
			TOOL_PATH=$(/usr/sbin/busybox which $TOOL);
			if [ -n "$TOOL_PATH" ];
			then echo "$TOOL:$TOOL_PATH";
			else echo "$TOOL:notfound";
			fi;
			n=$(($n+1));
		done> %s'`
	probeToolsCmd := fmt.Sprintf(probeToolsTemplate, toolStr, len(toolList), filepath.Join(resultsPath, rpmToolsFile))

	rpmDBList := []string{
		filepath.Join(rpmLibPath, rpmBDB),
		filepath.Join(rpmLibPath, rpmNDB),
		filepath.Join(rpmLibPath, rpmSQLLiteDB),
		filepath.Join(rpmManifestPath, rpmManifest1),
		filepath.Join(rpmManifestPath, rpmManifest2),
	}
	rpmDBStr := strings.Join(rpmDBList, " ")
	const probeDBTemplate = `/usr/sbin/busybox sh -c '
		DB_LIST="%s"; n=1;
		while [ $n -le %d ];
		do DB=$(echo "$DB_LIST" | /usr/sbin/busybox cut -d " " -f $n);
			echo $DB;
			if [ -f $DB ];
			then /usr/sbin/busybox cp $DB %s;
			fi;
			n=$(($n+1));
		done'`
	probeDBCmd := fmt.Sprintf(probeDBTemplate, rpmDBStr, len(rpmDBList), resultsPath)

	probed := mkFolders.Run(llb.Shlex(probeToolsCmd)).Run(llb.Shlex(probeDBCmd)).Root()
	outState := llb.Diff(toolsApplied, probed)
	if err := buildkit.SolveToLocal(ctx, rm.config.Client, &outState, rm.workingFolder); err != nil {
		return err
	}

	// Check type of RPM DB on image to infer Mariner Distroless
	outStatePath := filepath.Join(rm.workingFolder, resultsPath)
	rpmDB := getRPMDBType(outStatePath)
	log.Debugf("RPM DB Type in image is: %s", rpmDB)
	switch rpmDB {
	case RPMDBManifests:
		rm.isDistroless = true
	case RPMDBNone, RPMDBMixed:
		err := fmt.Errorf("could not find determine RPM DB type of target image: %v", rpmDB)
		log.Error(err)
		return err
	}

	// Parse rpmTools File if not distroless
	if !rm.isDistroless {
		log.Info("Checking for available RPM tools in non-distroless image ...")
		toolsFilePath := filepath.Join(outStatePath, rpmToolsFile)
		rpmTools, err := parseRPMTools(toolsFilePath)
		if err != nil {
			return err
		}
		log.Debugf("RPM tools probe results: %v", rpmTools)

		var allErrors *multierror.Error
		if rpmTools["dnf"] == "" && rpmTools["yum"] == "" && rpmTools["microdnf"] == "" {
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

// Patch a regular RPM-based image with:
//   - sh and an appropriate tool installed on the image (yum, dnf, microdnf)
//   - valid rpm database on the image
//
// TODO: Support RPM-based images with valid rpm status but missing tools. (e.g. calico images > v3.21.0)
// i.e. extra RunOption to mount a copy of rpm tools installed into the image and invoking that.
func (rm *rpmManager) installUpdates(ctx context.Context, updates types.UpdatePackages) (*llb.State, error) {
	// Format the requested updates into a space-separated string
	pkgStrings := []string{}
	for _, u := range updates {
		pkgStrings = append(pkgStrings, u.Name)
	}
	pkgs := strings.Join(pkgStrings, " ")

	// Install patches using available rpm managers in order of preference
	var installCmd string
	switch {
	case rm.rpmTools["dnf"] != "":
		const dnfInstallTemplate = `sh -c '%[1]s upgrade %[2]s -y && %[1]s clean all'`
		installCmd = fmt.Sprintf(dnfInstallTemplate, rm.rpmTools["dnf"], pkgs)
	case rm.rpmTools["yum"] != "":
		const yumInstallTemplate = `sh -c '%[1]s upgrade %[2]s -y && %[1]s clean all'`
		installCmd = fmt.Sprintf(yumInstallTemplate, rm.rpmTools["yum"], pkgs)
	case rm.rpmTools["microdnf"] != "":
		const microdnfInstallTemplate = `sh -c '%[1]s update %[2]s && %[1]s clean all'`
		installCmd = fmt.Sprintf(microdnfInstallTemplate, rm.rpmTools["microdnf"], pkgs)
	default:
		err := errors.New("unexpected: no package manager tools were found for patching")
		return nil, err
	}
	installed := rm.config.ImageState.Run(llb.Shlex(installCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Write results.manifest to host for post-patch validation
	const rpmResultsTemplate = `sh -c 'rpm -qa --queryformat "%s" %s > "%s"'`
	outputResultsCmd := fmt.Sprintf(rpmResultsTemplate, resultQueryFormat, pkgs, resultManifest)
	resultsWritten := installed.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).Root()
	resultsDiff := llb.Diff(installed, resultsWritten)

	if err := buildkit.SolveToLocal(ctx, rm.config.Client, &resultsDiff, rm.workingFolder); err != nil {
		return nil, err
	}

	// Diff the installed updates and merge that into the target image
	patchDiff := llb.Diff(rm.config.ImageState, installed)
	patchMerge := llb.Merge([]llb.State{rm.config.ImageState, patchDiff})
	return &patchMerge, nil
}

func (rm *rpmManager) unpackAndMergeUpdates(ctx context.Context, updates types.UpdatePackages, toolImage string) (*llb.State, error) {
	// Spin up a build tooling container to fetch and unpack packages to create patch layer.
	// Pull family:version -> need to create version to base image map
	toolingBase := llb.Image(toolImage,
		llb.Platform(rm.config.Platform),
		llb.ResolveModeDefault,
	)

	// Install busybox. This should reuse the layer cached from probeRPMStatus.
	toolsInstalled := toolingBase.Run(llb.Shlex(installToolsCmd), llb.WithProxy(utils.GetProxy())).Root()
	busyboxCopied := toolsInstalled.Dir(downloadPath).Run(llb.Shlex("cp /usr/sbin/busybox .")).Root()

	// Download all requested update packages without specifying the version. This works around:
	//  - Reports being slightly out of date, where a newer security revision has displaced the one specified leading to not found errors.
	//  - Reports not specifying version epochs correct (e.g. bsdutils=2.36.1-8+deb11u1 instead of with epoch as 1:2.36.1-8+dev11u1)
	//  - Reports specifying remediation packages for cbl-mariner v1 instead of v2 (e.g. *.cm1.aarch64 instead of *.cm2.aarch64)
	const aptDownloadTemplate = "yum reinstall --downloadonly --downloaddir=. --best -y %s"
	pkgStrings := []string{}
	for _, u := range updates {
		pkgStrings = append(pkgStrings, u.Name)
	}
	downloadCmd := fmt.Sprintf(aptDownloadTemplate, strings.Join(pkgStrings, " "))
	downloaded := busyboxCopied.Run(llb.Shlex(downloadCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Scripted enumeration and rpm install of all downloaded packages under the download folder as root
	// `rpm -i` doesn't support installing to a target directory, so chroot into the download folder to install the packages.
	const extractTemplate = `chroot %s ./busybox find . -name '*.rpm' -exec ./busybox rpm -i '{}' \;`
	extractCmd := fmt.Sprintf(extractTemplate, downloadPath)
	unpacked := downloaded.Run(llb.Shlex(extractCmd)).Root()

	// Diff out busybox and downloaded rpm packages from the installed files under the download folder as root
	// then move the results to normal root for the layer to merge with target image.
	patchDiff := llb.Diff(downloaded, unpacked)
	patchedRoot := llb.Scratch().File(llb.Copy(patchDiff, downloadPath, "/", &llb.CopyInfo{CopyDirContentsOnly: true}))

	// Scripted extraction of all rpm manifest fields for version checking to separate layer into local mount
	// Note that target dirs of shell commands need to be created before use
	mkFolders := downloaded.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true))).File(llb.Mkdir(rpmManifestPath, 0o744, llb.WithParents(true)))
	const rpmManifestFormat = `%{NAME}\\t%{VERSION}-%{RELEASE}\\t$installTime\\t%{BUILDTIME}\\t%{VENDOR}\\t%{EPOCH}\\t%{SIZE}\\t%{ARCH}\\t%{EPOCHNUM}\\t%{SOURCERPM}\\n`
	const writeFieldsTemplate = `find . -name '*.rpm' -exec sh -c "installTime=$(date +%%s); rpm -q {} --queryformat \"%s\" > %s" \;`
	writeFieldsCmd := fmt.Sprintf(writeFieldsTemplate, rpmManifestFormat, filepath.Join(resultsPath, "{}.manifest2"))
	fieldsWritten := mkFolders.Dir(downloadPath).Run(llb.Shlex(writeFieldsCmd)).Root()

	// Update the rpm manifests for Mariner distroless
	manifestsPath := filepath.Join(rpmManifestPath, rpmManifestWildcard)
	manifests := fieldsWritten.File(llb.Copy(rm.config.ImageState, manifestsPath, resultsPath, &llb.CopyInfo{AllowWildcard: true}))
	const updateManifest2Template = `find . -name '*.manifest2' -exec sh -c '
		found={};
		t=$(printf "\t");
		while IFS=$t read -r -a fields;
		do update1="${fields[0]}-${fields[1]}.${fields[7]}";
			update2="$(cat $found)";
			installed=$(grep -P "${fields[0]}\t" container-manifest-2);
			if [[ -n $installed ]];
			then IFS=$t read -a oldInfo <<< $installed;
				old1="${oldInfo[0]}-${oldInfo[1]}.${oldInfo[7]}";
				sed -i "s/$old1/$update1/g" container-manifest-1;
				sed -i "s/$installed/$update2/g" container-manifest-2;
			else echo "$update1" >> container-manifest-1;
				echo "$update2" >> container-manifest-2;
			fi;
		done < $found' \;`
	manifestsUpdated := manifests.Dir(resultsPath).Run(llb.Shlex(updateManifest2Template)).Root()
	manifestsPlaced := manifestsUpdated.File(llb.Copy(manifestsUpdated, filepath.Join(resultsPath, rpmManifestWildcard), rpmManifestPath, &llb.CopyInfo{AllowWildcard: true}))

	// Write results.manifest to host for post-patch validation
	const writeResultsTemplate = `find . -name '*.manifest2' -exec sh -c 't=$(printf "\t"); while IFS=$t read -r -a fields; do echo "${fields[0]}$t${fields[1]}$t${fields[7]}" >> %s; done < {}' \;`
	writeResultsCmd := fmt.Sprintf(writeResultsTemplate, filepath.Join(resultsPath, resultManifest))
	resultsWritten := fieldsWritten.Dir(resultsPath).Run(llb.Shlex(writeResultsCmd)).Root()

	resultsDiff := llb.Diff(fieldsWritten, resultsWritten)
	if err := buildkit.SolveToLocal(ctx, rm.config.Client, &resultsDiff, rm.workingFolder); err != nil {
		return nil, err
	}
	// Diff unpacked packages layers from previous and merge with target
	manifestsDiff := llb.Diff(manifestsUpdated, manifestsPlaced)
	merged := llb.Merge([]llb.State{rm.config.ImageState, patchedRoot, manifestsDiff})
	return &merged, nil
}

func rpmReadResultsManifest(path string) ([]string, error) {
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

func validateRPMPackageVersions(updates types.UpdatePackages, cmp VersionComparer, resultsPath string, ignoreErrors bool) error {
	lines, err := rpmReadResultsManifest(resultsPath)
	if err != nil {
		return err
	}

	// Assert rpm info list doesn't contain more entries than expected
	if len(lines) > len(updates) {
		err = fmt.Errorf("expected %d updates, installed %d", len(updates), len(lines))
		log.Error(err)
		return err
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

	// Walk files and check update name is prefix for file name
	// results.manifest file is expected to the `rpm -qa <packages ...>`
	// using the resultQueryFormat with tab delimiters.
	var allErrors *multierror.Error
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
			allErrors = multierror.Append(allErrors, err)
			continue
		}
		// Strip epoch from update.Version; report may specify it, but RPM naming scheme does not support epochs
		expectedVersion := update.Version[strings.Index(update.Version, ":")+1:]
		if cmp.LessThan(version, expectedVersion) {
			err = fmt.Errorf("downloaded package %s version %s lower than required %s for update", update.Name, version, update.Version)
			log.Error(err)
			allErrors = multierror.Append(allErrors, err)
			continue
		}
		log.Infof("Validated package %s version %s meets requested version %s", update.Name, version, update.Version)
	}

	if ignoreErrors {
		return nil
	}

	return allErrors.ErrorOrNil()
}
