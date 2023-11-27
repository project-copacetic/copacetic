package pkgmgr

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

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

	installToolsCmd   = "tdnf install busybox cpio dnf-utils -y"
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
	// TODO: Verify if there are format correctness check that need to be added given lack of support in rpmVer lib
	return true
}

func isLessThanRPMVersion(v1, v2 string) bool {
	rpmV1 := rpmVer.NewVersion(v1)
	rpmV2 := rpmVer.NewVersion(v2)
	return rpmV1.LessThan(rpmV2)
}

// Map the target image OSType & OSVersion to an appropriate tooling image.
func getRPMImageName(manifest *unversioned.UpdateManifest) string {
	// Standardize on mariner as tooling image base as redhat/ubi does not provide
	// static busybox binary
	image := "mcr.microsoft.com/cbl-mariner/base/core"
	version := "2.0"
	if manifest.Metadata.OS.Type == "cbl-mariner" {
		// Use appropriate version of cbl-mariner image if available
		vers := strings.Split(manifest.Metadata.OS.Version, ".")
		if len(vers) < 2 {
			vers = append(vers, "0")
		}
		version = fmt.Sprintf("%s.%s", vers[0], vers[1])
	}
	log.Debugf("Using %s:%s as basis for tooling image", image, version)
	return fmt.Sprintf("%s:%s", image, version)
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
	// Resolve set of unique packages to update
	rpmComparer := VersionComparer{isValidRPMVersion, isLessThanRPMVersion}
	updates, err := GetUniqueLatestUpdates(manifest.Updates, rpmComparer, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}
	if len(updates) == 0 {
		log.Warn("No update packages were specified to apply")
		return &rm.config.ImageState, nil, nil
	}
	log.Debugf("latest unique RPMs: %v", updates)

	// Probe RPM status for available tooling on the target image
	toolImageName := getRPMImageName(manifest)
	if err := rm.probeRPMStatus(ctx, toolImageName); err != nil {
		return nil, nil, err
	}

	var updatedImageState *llb.State
	var resultManifestBytes []byte
	if rm.isDistroless {
		updatedImageState, resultManifestBytes, err = rm.unpackAndMergeUpdates(ctx, updates, toolImageName)
		if err != nil {
			return nil, nil, err
		}
	} else {
		updatedImageState, resultManifestBytes, err = rm.installUpdates(ctx, updates)
		if err != nil {
			return nil, nil, err
		}
	}

	// Validate that the deployed packages are of the requested version or better
	errPkgs, err := validateRPMPackageVersions(updates, rpmComparer, resultManifestBytes, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}

	return updatedImageState, errPkgs, nil
}

func (rm *rpmManager) probeRPMStatus(ctx context.Context, toolImage string) error {
	// Spin up a build tooling container to pull and unpack packages to create patch layer.
	toolingBase := llb.Image(toolImage,
		llb.Platform(rm.config.Platform),
		llb.ResolveModeDefault,
	)

	toolsInstalled := toolingBase.Run(llb.Shlex(installToolsCmd), llb.WithProxy(utils.GetProxy())).Root()
	toolsApplied := rm.config.ImageState.File(llb.Copy(toolsInstalled, "/usr/sbin/busybox", "/usr/sbin/busybox"))
	mkFolders := toolsApplied.
		File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true))).
		File(llb.Mkdir(inputPath, 0o744, llb.WithParents(true)))

	toolList := []string{"dnf", "microdnf", "rpm", "yum"}

	rpmDBList := []string{
		filepath.Join(rpmLibPath, rpmBDB),
		filepath.Join(rpmLibPath, rpmNDB),
		filepath.Join(rpmLibPath, rpmSQLLiteDB),
		filepath.Join(rpmManifestPath, rpmManifest1),
		filepath.Join(rpmManifestPath, rpmManifest2),
	}

	toolListPath := filepath.Join(inputPath, "tool_list")
	dbListPath := filepath.Join(inputPath, "rpm_db_list")

	probed := buildkit.WithArrayFile(&mkFolders, toolListPath, toolList)
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
		return nil
	}

	// Check type of RPM DB on image to infer Mariner Distroless
	rpmDB := getRPMDBType(rpmDBListOutputBytes)
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

		toolsFileBytes, err := buildkit.ExtractFileFromState(ctx, rm.config.Client, &outState, rpmToolsFile)
		if err != nil {
			return err
		}

		rpmTools, err := parseRPMTools(toolsFileBytes)
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
func (rm *rpmManager) installUpdates(ctx context.Context, updates unversioned.UpdatePackages) (*llb.State, []byte, error) {
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
		return nil, nil, err
	}
	installed := rm.config.ImageState.Run(llb.Shlex(installCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Write results.manifest to host for post-patch validation
	const rpmResultsTemplate = `sh -c 'rpm -qa --queryformat "%s" %s > "%s"'`
	outputResultsCmd := fmt.Sprintf(rpmResultsTemplate, resultQueryFormat, pkgs, resultManifest)
	resultsWritten := installed.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).AddMount(resultsPath, llb.Scratch())

	resultBytes, err := buildkit.ExtractFileFromState(ctx, rm.config.Client, &resultsWritten, resultManifest)
	if err != nil {
		return nil, nil, err
	}

	// Diff the installed updates and merge that into the target image
	patchDiff := llb.Diff(rm.config.ImageState, installed)
	patchMerge := llb.Merge([]llb.State{rm.config.ImageState, patchDiff})
	return &patchMerge, resultBytes, nil
}

func (rm *rpmManager) unpackAndMergeUpdates(ctx context.Context, updates unversioned.UpdatePackages, toolImage string) (*llb.State, []byte, error) {
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
	const rpmDownloadTemplate = `yumdownloader --downloadonly --downloaddir=. --best -y %s`
	pkgStrings := []string{}
	for _, u := range updates {
		pkgStrings = append(pkgStrings, u.Name)
	}
	downloadCmd := fmt.Sprintf(rpmDownloadTemplate, strings.Join(pkgStrings, " "))
	downloaded := busyboxCopied.Run(llb.Shlex(downloadCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Scripted enumeration and rpm install of all downloaded packages under the download folder as root
	const extractTemplate = `sh -c 'for f in %[1]s/*.rpm ; do rpm2cpio "$f" | cpio -idmv -D %[1]s ; done'`
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

	resultBytes, err := buildkit.ExtractFileFromState(ctx, rm.config.Client, &resultsWritten, filepath.Join(resultsPath, resultManifest))
	if err != nil {
		return nil, nil, err
	}

	// Diff unpacked packages layers from previous and merge with target
	manifestsDiff := llb.Diff(manifestsUpdated, manifestsPlaced)
	merged := llb.Merge([]llb.State{rm.config.ImageState, patchedRoot, manifestsDiff})
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

func validateRPMPackageVersions(updates unversioned.UpdatePackages, cmp VersionComparer, resultsBytes []byte, ignoreErrors bool) ([]string, error) {
	lines, err := rpmReadResultsManifest(resultsBytes)
	if err != nil {
		return nil, err
	}

	// Assert rpm info list doesn't contain more entries than expected
	if len(lines) > len(updates) {
		err = fmt.Errorf("expected %d updates, installed %d", len(updates), len(lines))
		log.Error(err)
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
