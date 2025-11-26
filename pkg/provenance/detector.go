package provenance

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/containerd/platforms"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// Detector extracts build information from Go binaries using go version -m.
type Detector struct{}

// NewDetector creates a new binary detector.
func NewDetector() *Detector {
	return &Detector{}
}

// DetectBinaryInfo extracts build information from a Go binary file.
// This uses "go version -m <binary>" to read embedded build info.
func (d *Detector) DetectBinaryInfo(binaryPath string) (*BinaryInfo, error) {
	log.Debugf("Detecting build info from binary: %s", binaryPath)

	// Run go version -m on the binary
	cmd := exec.Command("go", "version", "-m", binaryPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run go version -m: %w", err)
	}

	return d.parseBuildInfo(string(output), binaryPath)
}

// parseBuildInfo parses the output of go version -m.
func (d *Detector) parseBuildInfo(output, binaryPath string) (*BinaryInfo, error) {
	info := &BinaryInfo{
		Path:          binaryPath,
		Dependencies:  make(map[string]string),
		BuildSettings: make(map[string]string),
	}

	scanner := bufio.NewScanner(strings.NewReader(output))

	// First line contains binary path and Go version
	// Format: /path/to/binary: go1.21.0
	if scanner.Scan() {
		firstLine := scanner.Text()
		if matches := regexp.MustCompile(`go(\d+\.\d+(?:\.\d+)?)`).FindStringSubmatch(firstLine); len(matches) > 1 {
			info.GoVersion = matches[1]
			log.Debugf("Detected Go version: %s", info.GoVersion)
		}
	}

	// Parse the rest of the output
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := parts[0]
		value := strings.Join(parts[1:], " ")

		switch key {
		case "path":
			// Module path (e.g., github.com/fluxcd/source-controller)
			info.ModulePath = value
			log.Debugf("Module path: %s", value)

		case "mod":
			// Main module info: mod <module> <version> <hash>
			if len(parts) >= 3 {
				info.MainModule = parts[1]
				info.MainModuleVersion = parts[2]
				log.Debugf("Main module: %s@%s", info.MainModule, info.MainModuleVersion)
			}

		case "dep":
			// Dependency: dep <module> <version> <hash>
			if len(parts) >= 3 {
				module := parts[1]
				version := parts[2]
				info.Dependencies[module] = version
			}

		case "build":
			// Build setting: build <key>=<value>
			if strings.Contains(value, "=") {
				settingParts := strings.SplitN(value, "=", 2)
				if len(settingParts) == 2 {
					settingKey := settingParts[0]
					settingValue := settingParts[1]
					info.BuildSettings[settingKey] = settingValue

					// Extract specific known settings
					switch settingKey {
					case "GOOS":
						info.GOOS = settingValue
					case "GOARCH":
						info.GOARCH = settingValue
					case "CGO_ENABLED":
						info.CGOEnabled = settingValue == "1"
					case "vcs.revision":
						info.VCSRevision = settingValue
					case "vcs.time":
						info.VCSTime = settingValue
					case "vcs":
						info.VCS = settingValue
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error parsing go version output: %w", err)
	}

	// Validate that we got at least minimal information
	if info.GoVersion == "" {
		return nil, fmt.Errorf("could not extract Go version from binary")
	}

	return info, nil
}

// FindBinariesInImage searches for Go binaries in common locations within a container image.
// This returns a list of potential binary paths to check.
func (d *Detector) FindBinariesInImage(imageRoot string) ([]string, error) {
	// Common locations for binaries in container images
	searchPaths := []string{
		"/usr/local/bin",
		"/usr/bin",
		"/bin",
		"/app",
		"/",
	}

	var binaries []string

	for _, searchPath := range searchPaths {
		fullPath := filepath.Join(imageRoot, searchPath)

		// Use find to locate executable files
		cmd := exec.Command("find", fullPath, "-type", "f", "-executable", "-o", "-type", "f", "-name", "*.bin")
		output, err := cmd.Output()
		if err != nil {
			log.Debugf("Could not search %s: %v", fullPath, err)
			continue
		}

		// Parse find output
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			binaryPath := strings.TrimSpace(scanner.Text())
			if binaryPath != "" {
				binaries = append(binaries, binaryPath)
			}
		}
	}

	log.Debugf("Found %d potential binary files", len(binaries))
	return binaries, nil
}

// IsGoBinary checks if a file is a Go binary by attempting to read build info.
func (d *Detector) IsGoBinary(binaryPath string) bool {
	cmd := exec.Command("go", "version", "-m", binaryPath)
	err := cmd.Run()
	return err == nil
}

// FilterGoBinaries filters a list of paths to only include Go binaries.
func (d *Detector) FilterGoBinaries(paths []string) []string {
	var goBinaries []string

	for _, path := range paths {
		if d.IsGoBinary(path) {
			goBinaries = append(goBinaries, path)
			log.Debugf("Identified Go binary: %s", path)
		}
	}

	return goBinaries
}

// ConvertBinaryInfoToBuildInfo converts BinaryInfo to BuildInfo format for consistency.
func (d *Detector) ConvertBinaryInfoToBuildInfo(binaryInfo *BinaryInfo) *BuildInfo {
	buildInfo := &BuildInfo{
		GoVersion:    binaryInfo.GoVersion,
		CGOEnabled:   binaryInfo.CGOEnabled,
		ModulePath:   binaryInfo.ModulePath,
		BuildArgs:    make(map[string]string),
		BuildFlags:   []string{},
		Dependencies: binaryInfo.Dependencies,
	}

	// Copy build settings as build args
	for k, v := range binaryInfo.BuildSettings {
		buildInfo.BuildArgs[k] = v
	}

	// Add OS/Arch info
	if binaryInfo.GOOS != "" {
		buildInfo.BuildArgs["GOOS"] = binaryInfo.GOOS
	}
	if binaryInfo.GOARCH != "" {
		buildInfo.BuildArgs["GOARCH"] = binaryInfo.GOARCH
	}

	// Add VCS info if available
	if binaryInfo.VCSRevision != "" {
		buildInfo.BuildArgs["vcs.revision"] = binaryInfo.VCSRevision
	}

	return buildInfo
}

// Constants for BuildKit-based detection.
const (
	goBuildInfoOutputFile = "/copa-go-buildinfo-output"
	goFindBinariesFile    = "/copa-go-find-binaries"
)

// DetectBinaryInfoInBuildKit extracts build information from a Go binary using BuildKit.
// This runs "go version -m" inside the container to read embedded build info,
// which is necessary for distroless images where we can't access the filesystem directly.
func (d *Detector) DetectBinaryInfoInBuildKit(
	ctx context.Context,
	client gwclient.Client,
	state *llb.State,
	binaryPath string,
) (*BinaryInfo, error) {
	log.Debugf("Detecting build info from binary in BuildKit: %s", binaryPath)

	// We need a Go tooling image to run "go version -m"
	// Use alpine-based Go image for smallest footprint
	toolingImage := llb.Image("docker.io/library/golang:1.23-alpine")

	// Create a command that:
	// 1. Copies the binary from the target image to the tooling container
	// 2. Runs "go version -m" on it
	// 3. Outputs to a file we can extract
	extractCmd := fmt.Sprintf(
		`cp /target%s /tmp/binary && go version -m /tmp/binary > %s 2>&1 || echo "FAILED" > %s`,
		binaryPath, goBuildInfoOutputFile, goBuildInfoOutputFile,
	)

	// Mount target image filesystem and run extraction
	execState := toolingImage.Run(
		llb.Shlex(fmt.Sprintf("sh -c '%s'", extractCmd)),
		llb.AddMount("/target", *state, llb.Readonly),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Extract the output file
	output, err := d.extractFileFromState(ctx, client, &execState, goBuildInfoOutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to extract go version output: %w", err)
	}

	outputStr := string(output)
	if strings.Contains(outputStr, "FAILED") || outputStr == "" {
		return nil, fmt.Errorf("go version -m failed for %s", binaryPath)
	}

	// Parse the output using our existing parser
	return d.parseBuildInfo(outputStr, binaryPath)
}

// FindBinariesInBuildKit searches for Go binaries in an image using BuildKit.
// This is necessary for distroless images where we can't access the filesystem directly.
func (d *Detector) FindBinariesInBuildKit(
	ctx context.Context,
	client gwclient.Client,
	state *llb.State,
) ([]string, error) {
	log.Debug("Finding binaries in image via BuildKit")

	// Common locations for binaries in container images
	searchPaths := []string{
		"/usr/local/bin",
		"/usr/bin",
		"/bin",
		"/app",
		"/",
	}

	// Build a find command that searches common locations
	searchPathsStr := strings.Join(searchPaths, " ")
	findCmd := fmt.Sprintf(
		`find %s -maxdepth 3 -type f -executable 2>/dev/null | head -50 > %s || true`,
		searchPathsStr, goFindBinariesFile,
	)

	// Run find command in the target image
	execState := state.Run(
		llb.Shlex(fmt.Sprintf("sh -c '%s'", findCmd)),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Extract the output file
	output, err := d.extractFileFromState(ctx, client, &execState, goFindBinariesFile)
	if err != nil {
		// Image might not have shell, try alternative approach
		log.Debugf("find command failed: %v, image may be distroless", err)
		return d.findBinariesInDistroless(ctx, client, state)
	}

	// Parse output
	var binaries []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		path := strings.TrimSpace(scanner.Text())
		if path != "" {
			binaries = append(binaries, path)
		}
	}

	log.Debugf("Found %d potential binaries via BuildKit", len(binaries))
	return binaries, nil
}

// findBinariesInDistroless handles distroless images that don't have shell.
// We use a tooling container to inspect the target filesystem.
func (d *Detector) findBinariesInDistroless(
	ctx context.Context,
	client gwclient.Client,
	state *llb.State,
) ([]string, error) {
	log.Debug("Using tooling container to find binaries in distroless image")

	// Use busybox for minimal find utility
	toolingImage := llb.Image("docker.io/library/busybox:latest")

	// Search common binary locations in the mounted target
	findCmd := fmt.Sprintf(
		`find /target/usr/local/bin /target/usr/bin /target/bin /target/app /target -maxdepth 3 -type f -executable 2>/dev/null | sed 's|^/target||' | head -50 > %s || true`,
		goFindBinariesFile,
	)

	execState := toolingImage.Run(
		llb.Shlex(fmt.Sprintf("sh -c '%s'", findCmd)),
		llb.AddMount("/target", *state, llb.Readonly),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	output, err := d.extractFileFromState(ctx, client, &execState, goFindBinariesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to find binaries in distroless image: %w", err)
	}

	var binaries []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		path := strings.TrimSpace(scanner.Text())
		if path != "" {
			binaries = append(binaries, path)
		}
	}

	log.Debugf("Found %d potential binaries in distroless image", len(binaries))
	return binaries, nil
}

// FilterGoBinariesInBuildKit filters a list of paths to only include Go binaries using BuildKit.
// This checks each binary using "go version -m" via a tooling container.
func (d *Detector) FilterGoBinariesInBuildKit(
	ctx context.Context,
	client gwclient.Client,
	state *llb.State,
	paths []string,
) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	log.Debugf("Filtering %d paths for Go binaries via BuildKit", len(paths))

	var goBinaries []string

	// Check each binary (limit to first 10 to avoid excessive API calls)
	maxToCheck := 10
	if len(paths) < maxToCheck {
		maxToCheck = len(paths)
	}

	for i := 0; i < maxToCheck; i++ {
		path := paths[i]
		_, err := d.DetectBinaryInfoInBuildKit(ctx, client, state, path)
		if err == nil {
			goBinaries = append(goBinaries, path)
			log.Debugf("Identified Go binary: %s", path)
		}
	}

	log.Debugf("Found %d Go binaries out of %d checked", len(goBinaries), maxToCheck)
	return goBinaries, nil
}

// DetectAllGoBinariesInBuildKit finds and analyzes all Go binaries in an image.
// This combines FindBinariesInBuildKit, filtering, and detection.
func (d *Detector) DetectAllGoBinariesInBuildKit(
	ctx context.Context,
	client gwclient.Client,
	state *llb.State,
) ([]*BinaryInfo, error) {
	// Find all potential binaries
	candidates, err := d.FindBinariesInBuildKit(ctx, client, state)
	if err != nil {
		return nil, fmt.Errorf("failed to find binaries: %w", err)
	}

	if len(candidates) == 0 {
		log.Debug("No executable files found in image")
		return nil, nil
	}

	// Filter to Go binaries and collect their info
	var binaryInfos []*BinaryInfo

	// Limit to first 10 candidates to avoid performance issues
	maxCandidates := 10
	if len(candidates) < maxCandidates {
		maxCandidates = len(candidates)
	}

	for i := 0; i < maxCandidates; i++ {
		path := candidates[i]
		info, err := d.DetectBinaryInfoInBuildKit(ctx, client, state, path)
		if err != nil {
			log.Debugf("Not a Go binary or failed to detect: %s (%v)", path, err)
			continue
		}
		binaryInfos = append(binaryInfos, info)
		log.Infof("Detected Go binary: %s (Go %s, module: %s)", path, info.GoVersion, info.ModulePath)
	}

	log.Infof("Found %d Go binaries in image", len(binaryInfos))
	return binaryInfos, nil
}

// extractFileFromState extracts a file from an LLB state using BuildKit.
// This is a helper that duplicates logic from pkg/buildkit for use in this package.
func (d *Detector) extractFileFromState(ctx context.Context, c gwclient.Client, st *llb.State, path string) ([]byte, error) {
	// Normalize platform to Linux (BuildKit requirement)
	platform := platforms.Normalize(platforms.DefaultSpec())
	if platform.OS != "linux" {
		platform.OS = "linux"
	}

	def, err := st.Marshal(ctx, llb.Platform(platform))
	if err != nil {
		return nil, err
	}

	resp, err := c.Solve(ctx, gwclient.SolveRequest{
		Evaluate:   true,
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, err
	}

	ref, err := resp.SingleRef()
	if err != nil {
		return nil, err
	}

	return ref.ReadFile(ctx, gwclient.ReadRequest{
		Filename: path,
	})
}
