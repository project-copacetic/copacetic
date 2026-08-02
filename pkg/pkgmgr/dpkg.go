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
	"sort"
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
var aptGetDownloadScript []byte

//go:embed scripts/select_dpkg_updates.sh
var selectDPKGUpdatesScript []byte

//go:embed scripts/probe_dpkg.sh
var probeDPKGScript []byte

//go:embed scripts/finalize_dpkg_status.sh
var finalizeDPKGStatusScript []byte

const (
	dpkgLibPath        = "/var/lib/dpkg"
	dpkgStatusPath     = dpkgLibPath + "/status"
	dpkgStatusFolder   = dpkgLibPath + "/status.d"
	chiselManifestPath = "/var/lib/chisel/manifest.wall"
	dpkgDownloadPath   = "/copa-dpkg-downloads"

	dpkgProbeBusyBoxPath     = "/copa-dpkg-probe/busybox"
	dpkgProbeScriptPath      = "/copa-dpkg-probe/probe.sh"
	dpkgProbeOutputFilename  = "dpkg-probe"
	dpkgStatusOutputFilename = "status"
	dpkgStatusdListFilename  = "status.d-list"
	dpkgStatusdFilesFolder   = "status.d-files"

	dpkgInstalledPackagesPath   = "/copa-dpkg-installed-packages"
	dpkgVersionFloorsPath       = "/copa-dpkg-version-floors"
	dpkgSelectUpdatesScriptPath = "/select_dpkg_updates.sh"
	dpkgUpdatePackagesPath      = dpkgDownloadPath + "/packages.txt"
	dpkgUpdatesMarkerPath       = "/updates.txt"
)

var requiredDPKGTools = []string{"apt-get", "apt-mark", "dpkg", "sh", "grep", "tee"}

type dpkgManager struct {
	config            *buildkit.Config
	workingFolder     string
	installationMode  dpkgInstallationMode
	statusdNames      string
	packageInfo       map[string]string
	heldPackages      map[string]struct{}
	statusdFileMap    map[string]string // Maps package names to their status.d filenames
	osVersion         string
	osType            string
	tempStatusFile    []byte
	chiselRelease     string
	chiselAnnotations map[string]string
}

type dpkgInstallationMode uint

const (
	dpkgInstallationModeUnknown dpkgInstallationMode = iota
	dpkgInstallationModeTargetTools
	dpkgInstallationModeExternalFullStatus
	dpkgInstallationModeExternalStatusDirectory
	dpkgInstallationModeNativeChisel
)

func (mode dpkgInstallationMode) String() string {
	switch mode {
	case dpkgInstallationModeTargetTools:
		return "target-dpkg-tools"
	case dpkgInstallationModeExternalFullStatus:
		return "external-full-status"
	case dpkgInstallationModeExternalStatusDirectory:
		return "external-status-directory"
	case dpkgInstallationModeNativeChisel:
		return "native-chisel"
	default:
		return "unknown"
	}
}

func (mode dpkgInstallationMode) usesExternalTools() bool {
	return mode == dpkgInstallationModeExternalFullStatus || mode == dpkgInstallationModeExternalStatusDirectory
}

type dpkgProbeResult struct {
	hasManifest        bool
	hasStatus          bool
	hasStatusDirectory bool
	missingTools       []string
}

type parsedDPKGStatus struct {
	contents         []byte
	databaseContents []byte
	packages         map[string]string
	heldPackages     map[string]struct{}
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

// Map the manager-detected target image OS type and version to an appropriate tooling image.
func getAPTImageName(osType, osVersion string, useCachePrefix bool) string {
	version := osVersion
	osType = utils.CanonicalOSType(osType)
	if osType == "" {
		osType = utils.OSTypeDebian
	}

	if osType == utils.OSTypeDebian {
		majorVersion := strings.Split(version, ".")[0]
		major, err := strconv.Atoi(majorVersion)
		if err == nil && major > 12 {
			version = "stable-slim"
		} else {
			version = majorVersion + "-slim"
		}
	}

	log.Debugf("Using %s:%s as basis for tooling image", osType, version)
	if !useCachePrefix {
		return fmt.Sprintf("%s:%s", osType, version)
	}
	return fmt.Sprintf("%s/%s:%s", imageCachePrefix, osType, version)
}

func (dm *dpkgManager) currentImageState() llb.State {
	if dm.config.PatchedConfigData != nil {
		return dm.config.PatchedImageState
	}
	return dm.config.ImageState
}

func (dm *dpkgManager) InstallUpdates(ctx context.Context, manifest *unversioned.UpdateManifest, ignoreErrors bool) (*llb.State, []string, error) {
	// Native Chisel metadata has highest precedence. Detect it directly before
	// resolving an apt tooling image so native images never depend on target
	// binaries or on the availability of a matching apt container.
	currentState := dm.currentImageState()
	if _, readErr := buildkit.TryExtractFileFromState(ctx, dm.config.Client, &currentState, chiselManifestPath); readErr == nil {
		dm.installationMode = dpkgInstallationModeNativeChisel
		log.Infof("Detected Debian installation mode: %s", dm.installationMode)
		return dm.installNativeChiselUpdates(ctx, manifest)
	} else if !isMarkerMissingErr(readErr, chiselManifestPath) {
		return nil, nil, fmt.Errorf("probing for native Chisel manifest %s: %w", chiselManifestPath, readErr)
	}

	imagePlatform, err := currentState.GetPlatform(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get image platform %w", err)
	}

	// Probe with manager-detected OS metadata so no-report Ubuntu images use
	// Ubuntu tooling rather than the Debian fallback.
	toolImageName := getAPTImageName(dm.osType, dm.osVersion, true)
	if _, err := tryImage(ctx, toolImageName, dm.config.Client, imagePlatform); err != nil {
		toolImageName = getAPTImageName(dm.osType, dm.osVersion, false)
	}
	if err := dm.probeDPKGStatus(ctx, toolImageName, imagePlatform); err != nil {
		return nil, nil, err
	}

	log.Infof("Detected Debian installation mode: %s", dm.installationMode)
	if dm.installationMode == dpkgInstallationModeNativeChisel {
		return dm.installNativeChiselUpdates(ctx, manifest)
	}
	if dm.installationMode == dpkgInstallationModeUnknown {
		return nil, nil, fmt.Errorf("could not determine Debian installation mode")
	}

	useExternalTools := dm.installationMode.usesExternalTools()

	// If manifest nil, update all packages.
	if manifest == nil {
		if useExternalTools {
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

	// Else update according to specified updates.
	debComparer := VersionComparer{isValidDebianVersion, isLessThanDebianVersion}
	updates, err := GetUniqueLatestUpdates(manifest.OSUpdates, debComparer, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}
	if len(updates) == 0 {
		log.Warn("No update packages were specified to apply")
		state := dm.currentImageState()
		return &state, nil, nil
	}

	var updatedImageState *llb.State
	var resultManifestBytes []byte
	if useExternalTools {
		updatedImageState, resultManifestBytes, err = dm.unpackAndMergeUpdates(ctx, updates, toolImageName, ignoreErrors)
	} else {
		updatedImageState, resultManifestBytes, err = dm.installUpdates(ctx, updates, ignoreErrors)
	}
	if err != nil {
		return nil, nil, err
	}

	// Validate that deployed packages did not regress below either the target's
	// currently installed version or the requested fixed version.
	errPkgs, err := validateDebianPackageVersions(updates, dm.packageInfo, debComparer, resultManifestBytes, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}

	return updatedImageState, errPkgs, nil
}

func classifyDPKGInstallationMode(result dpkgProbeResult) (dpkgInstallationMode, error) {
	switch {
	case result.hasManifest:
		return dpkgInstallationModeNativeChisel, nil
	case result.hasStatus && len(result.missingTools) == 0:
		return dpkgInstallationModeTargetTools, nil
	case result.hasStatus:
		return dpkgInstallationModeExternalFullStatus, nil
	case result.hasStatusDirectory:
		return dpkgInstallationModeExternalStatusDirectory, nil
	default:
		return dpkgInstallationModeUnknown, fmt.Errorf(
			"unsupported Debian package metadata: checked %s, %s, and %s; no supported metadata was found",
			chiselManifestPath,
			dpkgStatusPath,
			dpkgStatusFolder,
		)
	}
}

func parseDPKGProbeResult(b []byte) (dpkgProbeResult, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			return dpkgProbeResult{}, fmt.Errorf("unexpected probe output line %q", scanner.Text())
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return dpkgProbeResult{}, fmt.Errorf("reading probe output: %w", err)
	}

	parseFlag := func(key string) (bool, error) {
		value, ok := values[key]
		if !ok {
			return false, fmt.Errorf("probe output is missing %q", key)
		}
		switch value {
		case "0":
			return false, nil
		case "1":
			return true, nil
		default:
			return false, fmt.Errorf("probe output %q has invalid value %q", key, value)
		}
	}

	hasManifest, err := parseFlag("manifest")
	if err != nil {
		return dpkgProbeResult{}, err
	}
	hasStatus, err := parseFlag("status")
	if err != nil {
		return dpkgProbeResult{}, err
	}
	hasStatusDirectory, err := parseFlag("status_directory")
	if err != nil {
		return dpkgProbeResult{}, err
	}
	missingTools, ok := values["missing_tools"]
	if !ok {
		return dpkgProbeResult{}, fmt.Errorf("probe output is missing %q", "missing_tools")
	}

	return dpkgProbeResult{
		hasManifest:        hasManifest,
		hasStatus:          hasStatus,
		hasStatusDirectory: hasStatusDirectory,
		missingTools:       strings.Fields(missingTools),
	}, nil
}

// Probe the target without invoking its shell or any of its binaries. A
// temporary BusyBox from the tooling image executes the probe and only checks
// target tool paths for executability.
func (dm *dpkgManager) probeDPKGStatus(ctx context.Context, toolImage string, platform *ocispecs.Platform) error {
	imageStateCurrent := dm.currentImageState()

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

	const installBusyBoxCmd = "apt-get -o Acquire::Retries=3 install -y busybox-static"
	busyBoxInstalled := updated.Run(
		llb.Shlex(installBusyBoxCmd),
		llb.WithProxy(utils.GetProxy()),
		llb.WithCustomName("Installing BusyBox for Debian metadata probe"),
	).Root()

	probeState := imageStateCurrent.
		File(llb.Mkdir(filepath.Dir(dpkgProbeBusyBoxPath), 0o755, llb.WithParents(true))).
		File(llb.Copy(busyBoxInstalled, "/bin/busybox", dpkgProbeBusyBoxPath)).
		File(llb.Mkfile(dpkgProbeScriptPath, 0o555, probeDPKGScript))

	resultsState := probeState.Run(
		llb.AddEnv("BUSYBOX", dpkgProbeBusyBoxPath),
		llb.AddEnv("CHISEL_MANIFEST_PATH", chiselManifestPath),
		llb.AddEnv("DPKG_STATUS_PATH", dpkgStatusPath),
		llb.AddEnv("DPKG_STATUS_FOLDER", dpkgStatusFolder),
		llb.AddEnv("REQUIRED_DPKG_TOOLS", strings.Join(requiredDPKGTools, " ")),
		llb.AddEnv("RESULTS_PATH", resultsPath),
		llb.AddEnv("RESULT_STATUS_PATH", filepath.Join(resultsPath, dpkgStatusOutputFilename)),
		llb.AddEnv("RESULT_STATUSD_LIST_PATH", filepath.Join(resultsPath, dpkgStatusdListFilename)),
		llb.AddEnv("RESULT_STATUSD_FILES_PATH", filepath.Join(resultsPath, dpkgStatusdFilesFolder)),
		llb.AddEnv("PROBE_OUTPUT_PATH", filepath.Join(resultsPath, dpkgProbeOutputFilename)),
		llb.Args([]string{dpkgProbeBusyBoxPath, "sh", dpkgProbeScriptPath}),
		llb.WithCustomName("Classifying Debian package metadata"),
	).AddMount(resultsPath, llb.Scratch())

	probeBytes, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, &resultsState, dpkgProbeOutputFilename)
	if err != nil {
		return fmt.Errorf("extracting Debian metadata probe results: %w", err)
	}
	probeResult, err := parseDPKGProbeResult(probeBytes)
	if err != nil {
		return fmt.Errorf("parsing Debian metadata probe results: %w", err)
	}

	mode, err := classifyDPKGInstallationMode(probeResult)
	if err != nil {
		return err
	}
	dm.installationMode = mode

	switch mode {
	case dpkgInstallationModeNativeChisel:
		return nil
	case dpkgInstallationModeTargetTools, dpkgInstallationModeExternalFullStatus:
		status, err := dm.loadFullStatus(ctx, &resultsState)
		if err != nil {
			return err
		}
		dm.packageInfo = status.packages
		dm.heldPackages = status.heldPackages
		if mode == dpkgInstallationModeTargetTools {
			return nil
		}

		dm.tempStatusFile = status.databaseContents
		dm.statusdFileMap = nil

		log.Warnf(
			"Target has %s but is missing required tools (%s); using external tooling. Installing complete .deb archives may add files not present in the original image",
			dpkgStatusPath,
			strings.Join(probeResult.missingTools, ", "),
		)
		return nil
	case dpkgInstallationModeExternalStatusDirectory:
		return dm.loadStatusDirectory(ctx, &resultsState)
	default:
		return fmt.Errorf("unsupported Debian installation mode %s", mode)
	}
}

func (dm *dpkgManager) loadFullStatus(ctx context.Context, resultsState *llb.State) (parsedDPKGStatus, error) {
	statusBytes, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, resultsState, dpkgStatusOutputFilename)
	if err != nil {
		return parsedDPKGStatus{}, fmt.Errorf("extracting %s: %w", dpkgStatusPath, err)
	}
	status, err := parseDPKGStatus(statusBytes)
	if err != nil {
		return parsedDPKGStatus{}, fmt.Errorf("parsing %s: %w", dpkgStatusPath, err)
	}
	return status, nil
}

func (dm *dpkgManager) loadStatusDirectory(ctx context.Context, resultsState *llb.State) error {
	statusdNamesBytes, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, resultsState, dpkgStatusdListFilename)
	if err != nil {
		return fmt.Errorf("extracting package list from %s: %w", dpkgStatusFolder, err)
	}

	dm.statusdNames = strings.Join(strings.Fields(string(statusdNamesBytes)), " ")
	packageInfo := make(map[string]string)
	statusdFileMap := make(map[string]string)
	var statusBuffer bytes.Buffer

	scanner := bufio.NewScanner(bytes.NewReader(statusdNamesBytes))
	for scanner.Scan() {
		name := scanner.Text()
		if name == "" {
			continue
		}
		fileBytes, err := buildkit.ExtractFileFromState(
			ctx,
			dm.config.Client,
			resultsState,
			filepath.Join(dpkgStatusdFilesFolder, name),
		)
		if err != nil {
			return fmt.Errorf("extracting %s: %w", filepath.Join(dpkgStatusFolder, name), err)
		}

		if strings.HasSuffix(name, ".md5sums") {
			continue
		}
		pkgName, pkgVersion, err := GetPackageInfo(string(fileBytes))
		if err != nil {
			return fmt.Errorf("parsing %s: %w", filepath.Join(dpkgStatusFolder, name), err)
		}

		statusBuffer.Write(fileBytes)
		statusBuffer.WriteByte('\n')
		packageInfo[pkgName] = pkgVersion
		statusdFileMap[pkgName] = name
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading package list from %s: %w", dpkgStatusFolder, err)
	}

	dm.tempStatusFile = bytes.Clone(statusBuffer.Bytes())
	dm.packageInfo = packageInfo
	dm.statusdFileMap = statusdFileMap

	log.Infof("Processed status.d: %s", dm.statusdNames)
	return nil
}

func parseDPKGStatus(contents []byte) (parsedDPKGStatus, error) {
	status := parsedDPKGStatus{
		contents:     bytes.Clone(contents),
		packages:     make(map[string]string),
		heldPackages: make(map[string]struct{}),
	}

	paragraphNumber := 0
	paragraphHasData := false
	packageName := ""
	packageVersion := ""
	packageStatus := ""

	flushParagraph := func() error {
		if !paragraphHasData {
			return nil
		}
		paragraphNumber++
		if packageName == "" {
			return fmt.Errorf("paragraph %d has no Package field", paragraphNumber)
		}
		if !isValidDebianPackageName(packageName) {
			return fmt.Errorf("paragraph %d has invalid package name %q", paragraphNumber, packageName)
		}
		// Microsoft-style apt-less Chiseled images retain complete package
		// control paragraphs but omit dpkg's Status field. Presence in that
		// inventory means installed. When Status is present, retain normal dpkg
		// semantics so removed/not-installed entries stay excluded. Those dpkg
		// bookkeeping entries may legitimately omit Version.
		installed := packageStatus == ""
		held := false
		if packageStatus != "" {
			statusFields := strings.Fields(packageStatus)
			if len(statusFields) != 3 {
				return fmt.Errorf("paragraph %d for package %q has invalid status %q", paragraphNumber, packageName, packageStatus)
			}
			installed = statusFields[2] == "installed"
			held = installed && statusFields[0] == "hold"
		}

		if packageVersion == "" {
			if installed {
				return fmt.Errorf("paragraph %d for package %q has no Version field", paragraphNumber, packageName)
			}
		} else if !isValidDebianVersion(packageVersion) {
			return fmt.Errorf("paragraph %d for package %q has invalid version %q", paragraphNumber, packageName, packageVersion)
		}
		if installed {
			status.packages[packageName] = packageVersion
			if held {
				status.heldPackages[packageName] = struct{}{}
			}
		}
		paragraphHasData = false
		packageName = ""
		packageVersion = ""
		packageStatus = ""
		return nil
	}

	for _, rawLine := range bytes.Split(contents, []byte{'\n'}) {
		line := strings.TrimSuffix(string(rawLine), "\r")
		if strings.TrimSpace(line) == "" {
			if err := flushParagraph(); err != nil {
				return parsedDPKGStatus{}, err
			}
			continue
		}

		paragraphHasData = true
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			return parsedDPKGStatus{}, fmt.Errorf("paragraph %d contains malformed field %q", paragraphNumber+1, line)
		}
		switch field {
		case "Package":
			packageName = strings.TrimSpace(value)
		case "Version":
			packageVersion = strings.TrimSpace(value)
		case "Status":
			packageStatus = strings.TrimSpace(value)
		}
	}
	if err := flushParagraph(); err != nil {
		return parsedDPKGStatus{}, err
	}
	if len(status.packages) == 0 {
		return parsedDPKGStatus{}, fmt.Errorf("status file contains no package paragraphs")
	}
	status.databaseContents = normalizeDPKGStatusForDatabase(contents)

	return status, nil
}

// normalizeDPKGStatusForDatabase adds dpkg's installed Status field to inventory
// paragraphs that omit it (as used by Microsoft Chiseled images). The original
// bytes remain separately retained for representation and diagnostics.
func normalizeDPKGStatusForDatabase(contents []byte) []byte {
	var output bytes.Buffer
	var paragraph []string

	flush := func() {
		if len(paragraph) == 0 {
			return
		}
		hasStatus := false
		for _, line := range paragraph {
			if strings.HasPrefix(line, "Status:") {
				hasStatus = true
				break
			}
		}
		for _, line := range paragraph {
			output.WriteString(line)
			output.WriteByte('\n')
			if !hasStatus && strings.HasPrefix(line, "Package:") {
				output.WriteString("Status: install ok installed\n")
			}
		}
		output.WriteByte('\n')
		paragraph = paragraph[:0]
	}

	for _, rawLine := range bytes.Split(contents, []byte{'\n'}) {
		line := strings.TrimSuffix(string(rawLine), "\r")
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		paragraph = append(paragraph, line)
	}
	flush()
	return output.Bytes()
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
	if !isValidDebianPackageName(packageName) {
		return "", "", fmt.Errorf("invalid package name %q", packageName)
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

// debPkgNameRE matches valid Debian package names: lowercase, digits, plus, hyphen, period.
var debPkgNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)

func isValidDebianPackageName(name string) bool {
	return debPkgNameRE.MatchString(name)
}

// marshalDPKGPackageVersions serializes validated package/version pairs for
// shell scripts without interpolating package metadata into shell source. The
// pipe delimiter is excluded by both Debian package-name and version syntax.
func marshalDPKGPackageVersions(packageInfo map[string]string, heldPackages map[string]struct{}) ([]byte, error) {
	packageNames := make([]string, 0, len(packageInfo))
	for packageName := range packageInfo {
		packageNames = append(packageNames, packageName)
	}
	sort.Strings(packageNames)

	var data strings.Builder
	for _, packageName := range packageNames {
		if !isValidDebianPackageName(packageName) {
			return nil, fmt.Errorf("invalid package name %q in installed package metadata", packageName)
		}
		version := packageInfo[packageName]
		if !isValidDebianVersion(version) {
			return nil, fmt.Errorf("invalid installed version %q for package %s", version, packageName)
		}
		selection := "install"
		if _, held := heldPackages[packageName]; held {
			selection = "hold"
		}
		fmt.Fprintf(&data, "%s|%s|%s\n", packageName, version, selection)
	}

	return []byte(data.String()), nil
}

func marshalDPKGUpdatePackageNames(updates unversioned.UpdatePackages) ([]byte, error) {
	if err := ValidateOSPackageNames(updates); err != nil {
		return nil, err
	}

	packageNames := make([]string, 0, len(updates))
	for _, update := range updates {
		packageNames = append(packageNames, update.Name)
	}
	sort.Strings(packageNames)

	return []byte(strings.Join(packageNames, "\n") + "\n"), nil
}

func marshalDPKGVersionFloors(updates unversioned.UpdatePackages, installedVersions map[string]string) ([]byte, error) {
	type versionFloor struct {
		installed string
		fixed     string
	}

	floors := make(map[string]versionFloor)
	if updates == nil {
		for packageName, installedVersion := range installedVersions {
			floors[packageName] = versionFloor{installed: installedVersion}
		}
	} else {
		if err := ValidateOSPackageNames(updates); err != nil {
			return nil, err
		}
		for packageName, installedVersion := range installedVersions {
			floors[packageName] = versionFloor{installed: installedVersion}
		}
		for _, update := range updates {
			floor := floors[update.Name]
			floor.fixed = update.FixedVersion
			floors[update.Name] = floor
		}
	}

	packageNames := make([]string, 0, len(floors))
	for packageName := range floors {
		packageNames = append(packageNames, packageName)
	}
	sort.Strings(packageNames)

	var data strings.Builder
	for _, packageName := range packageNames {
		if !isValidDebianPackageName(packageName) {
			return nil, fmt.Errorf("invalid package name %q in package version floor", packageName)
		}
		floor := floors[packageName]
		if floor.installed != "" && !isValidDebianVersion(floor.installed) {
			return nil, fmt.Errorf("invalid installed version %q for package %s", floor.installed, packageName)
		}
		if floor.fixed != "" && !isValidDebianVersion(floor.fixed) {
			return nil, fmt.Errorf("invalid fixed version %q for package %s", floor.fixed, packageName)
		}
		fmt.Fprintf(&data, "%s|%s|%s\n", packageName, floor.installed, floor.fixed)
	}

	return []byte(data.String()), nil
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

		_, err := buildkit.TryExtractFileFromState(ctx, dm.config.Client, &aptGetUpdated, updatesAvailableMarker)
		if err != nil {
			if !isMarkerMissingErr(err, updatesAvailableMarker) {
				return nil, nil, fmt.Errorf("failed while checking for available apt updates: %w", err)
			}
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
		if err := ValidateOSPackageNames(updates); err != nil {
			return nil, nil, fmt.Errorf("package name validation failed: %w", err)
		}
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
	if !dm.installationMode.usesExternalTools() {
		return nil, nil, fmt.Errorf("installation mode %s does not use external dpkg tooling", dm.installationMode)
	}
	if updates != nil {
		if err := ValidateOSPackageNames(updates); err != nil {
			return nil, nil, fmt.Errorf("package name validation failed: %w", err)
		}
	}

	imageStateCurrent := dm.currentImageState()
	imagePlatform, err := imageStateCurrent.GetPlatform(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get image platform %w", err)
	}

	// First try with the target platform, then fall back to the host platform.
	toolingBase, err := tryImage(ctx, toolImage, dm.config.Client, imagePlatform)
	if err != nil {
		log.Debugf("Failed to resolve tooling image %s with platform %v, falling back to host platform: %v", toolImage, imagePlatform, err)
		toolingBase, err = tryImage(ctx, toolImage, dm.config.Client, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve tooling image %s even with host platform fallback: %w", toolImage, err)
		}
		log.Debugf("Successfully resolved tooling image %s using host platform", toolImage)
	}

	updated := toolingBase.Run(
		llb.Shlex("apt-get -o Acquire::Retries=3 update"),
		llb.WithProxy(utils.GetProxy()),
		llb.IgnoreCache,
		llb.WithCustomName("Updating package database in tooling container"),
	).Root()

	installedPackageData, err := marshalDPKGPackageVersions(dm.packageInfo, dm.heldPackages)
	if err != nil {
		return nil, nil, err
	}
	versionFloorData, err := marshalDPKGVersionFloors(updates, dm.packageInfo)
	if err != nil {
		return nil, nil, err
	}

	updated = updated.
		File(llb.Mkfile(dpkgInstalledPackagesPath, 0o444, installedPackageData)).
		File(llb.Mkfile(dpkgVersionFloorsPath, 0o444, versionFloorData)).
		File(llb.Mkfile(dpkgSelectUpdatesScriptPath, 0o555, selectDPKGUpdatesScript))

	// For comprehensive updates, select only repository candidates that are
	// strictly newer under Debian version ordering. Equal or older candidates
	// are intentionally ignored to prevent public repositories from
	// downgrading packages sourced from a PPA, private archive, or newer image.
	if updates == nil {
		updated = updated.Run(
			buildkit.Sh(dpkgSelectUpdatesScriptPath),
			llb.WithCustomName("Analyzing packages for updates"),
		).Root()
		if _, err := buildkit.TryExtractFileFromState(ctx, dm.config.Client, &updated, dpkgUpdatesMarkerPath); err != nil {
			if !isMarkerMissingErr(err, dpkgUpdatesMarkerPath) {
				return nil, nil, fmt.Errorf("failed while checking for available apt updates with external tooling: %w", err)
			}
			log.Info("No upgradable packages found for this image (external dpkg path).")
			return nil, nil, types.ErrNoUpdatesFound
		}
	} else {
		packageNames, err := marshalDPKGUpdatePackageNames(updates)
		if err != nil {
			return nil, nil, fmt.Errorf("serializing requested package names: %w", err)
		}
		updated = updated.
			File(llb.Mkdir(dpkgDownloadPath, 0o755, llb.WithParents(true))).
			File(llb.Mkfile(dpkgUpdatePackagesPath, 0o444, packageNames))
	}

	// Rebuild enough of the temporary dpkg administrative database to run
	// maintainer scripts. Full-status images already provide complete control
	// paragraphs, so a minimal administrative tree is sufficient and avoids
	// reinstalling every package into the tooling image. Preserve the established
	// status.d reconstruction path unchanged.
	var dpkgdb llb.State
	if dm.installationMode == dpkgInstallationModeExternalFullStatus {
		dpkgdb = llb.Scratch().
			File(llb.Mkdir(filepath.Join(dpkgLibPath, "info"), 0o755, llb.WithParents(true))).
			File(llb.Mkdir(filepath.Join(dpkgLibPath, "updates"), 0o755, llb.WithParents(true))).
			File(llb.Mkdir(filepath.Join(dpkgLibPath, "triggers"), 0o755, llb.WithParents(true))).
			File(llb.Mkfile(dpkgStatusPath, 0o644, dm.tempStatusFile)).
			File(llb.Mkfile(filepath.Join(dpkgLibPath, "available"), 0o644, nil))
	} else {
		dpkgdb = updated.Run(
			llb.Args([]string{
				`bash`, `-xec`, `
                            rm -rf /var/lib/dpkg/info
                            mkdir -p /var/lib/dpkg/info

                            apt-get -o Acquire::Retries=3 update

                            while IFS='|' read -r pkg_name installed_version selection extra || [ -n "${pkg_name}${installed_version}${selection}${extra}" ]; do
                                if [ -z "$pkg_name" ] || [ -z "$installed_version" ] || [ -z "$selection" ] || [ -n "$extra" ]; then
                                    echo "invalid installed package record" >&2
                                    exit 1
                                fi
                                case "$selection" in
                                    hold) continue ;;
                                    install) ;;
                                    *) echo "invalid package selection: $selection" >&2; exit 1 ;;
                                esac
                                apt-get -o Acquire::Retries=3 install --reinstall -y -- "$pkg_name"
                            done < /copa-dpkg-installed-packages

                            apt --fix-broken install -y
                            dpkg --configure -a
                            apt-get check
                        `,
			}),
			llb.WithCustomName("Setting up package database in tooling container"),
		).Root().File(llb.Mkfile(dpkgStatusPath, 0o644, dm.tempStatusFile))
	}

	updateAll := falseConst
	if updates == nil {
		updateAll = trueConst
	}

	errorValidation := falseConst
	if ignoreErrors {
		errorValidation = trueConst
	}

	jsonStatusdFileMap, err := getJSONStatusdFileMap(dm.statusdFileMap)
	if err != nil {
		return nil, nil, err
	}

	updated = updated.
		File(llb.Mkfile("/download.sh", 0o555, aptGetDownloadScript)).
		File(llb.Mkfile("/finalize_dpkg_status.sh", 0o555, finalizeDPKGStatusScript))

	// Always base the temporary target root on the currently supplied image. In
	// particular, a second Copa run must use the already-patched dpkg status and
	// filesystem rather than reconstructing from the original base image.
	withDPkgStatus := imageStateCurrent.
		File(llb.Rm(dpkgLibPath)).
		File(llb.Copy(dpkgdb, dpkgLibPath, dpkgLibPath))

	var downloadCustomName string
	if updates != nil {
		downloadCustomName = fmt.Sprintf("Downloading and installing %d security updates", len(updates))
	} else {
		downloadCustomName = "Downloading and installing all package updates"
	}
	downloaded := updated.Run(
		llb.AddEnv("IGNORE_ERRORS", errorValidation),
		llb.AddEnv("UPDATE_ALL", updateAll),
		llb.AddEnv("DOWNLOAD_DIR", dpkgDownloadPath),
		llb.AddEnv("PACKAGES_FILE", dpkgUpdatePackagesPath),
		llb.AddEnv("DEBIAN_FRONTEND", "noninteractive"),
		llb.AddEnv("DPKG_INSTALLATION_MODE", dm.installationMode.String()),
		llb.AddEnv("STATUSD_FILE_MAP", string(jsonStatusdFileMap)),
		buildkit.Sh(`/download.sh`),
		llb.WithProxy(utils.GetProxy()),
		llb.WithCustomName(downloadCustomName),
	).AddMount("/tmp/debian-rootfs", withDPkgStatus)

	resultBytes, err := buildkit.ExtractFileFromState(ctx, dm.config.Client, &downloaded, "/manifest")
	if err != nil {
		return nil, nil, err
	}

	withoutManifest := downloaded.File(llb.Rm("/manifest"))
	patchedState := externalDPKGPatchedState(&withoutManifest)

	return patchedState, resultBytes, nil
}

func externalDPKGPatchedState(updated *llb.State) *llb.State {
	// AddMount returns the complete updated target filesystem. Returning that
	// state directly keeps the exported layer graph linear and repatchable.
	// Wrapping it in Diff+Merge produces nested merge graphs that Docker can run
	// after import but BuildKit cannot reliably consume as a later image source.
	return updated
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

func validateDebianPackageVersions(
	updates unversioned.UpdatePackages,
	installedVersions map[string]string,
	cmp VersionComparer,
	results []byte,
	ignoreErrors bool,
) ([]string, error) {
	// Load file into map[string]string for package:version lookup
	updateMap, err := dpkgParseResultsManifest(results)
	if err != nil {
		return nil, err
	}

	// For each target package, validate the resulting version is at least both
	// the current installed version and the requested fixed version.
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
		installedVersion, hasInstalledVersion := installedVersions[update.Name]
		if hasInstalledVersion {
			if !cmp.IsValid(installedVersion) {
				err := fmt.Errorf("invalid installed version %s found for package %s", installedVersion, update.Name)
				log.Error(err)
				errorPkgs = append(errorPkgs, update.Name)
				allErrors = multierror.Append(allErrors, err)
				continue
			}
			if cmp.LessThan(version, installedVersion) {
				err = fmt.Errorf("downloaded package %s version %s lower than currently installed version %s", update.Name, version, installedVersion)
				log.Error(err)
				errorPkgs = append(errorPkgs, update.Name)
				allErrors = multierror.Append(allErrors, err)
				continue
			}
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
