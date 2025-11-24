package provenance

import (
	"bufio"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

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
