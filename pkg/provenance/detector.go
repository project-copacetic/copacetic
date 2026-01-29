package provenance

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
)

const (
	// golangToolingImage is the image used for running go version -m.
	golangToolingImage = "golang:1.23-alpine"
	// outputDir is where the detection results are written.
	outputDir = "/copa-detect"
	// outputFile is the file containing go version -m output.
	outputFile = "/copa-detect/binaries.txt"
)

// Detector detects Go binaries in container images using `go version -m`.
type Detector struct{}

// NewDetector creates a new binary detector.
func NewDetector() *Detector {
	return &Detector{}
}

// DetectGoBinaries detects all Go binaries in an image using a single BuildKit operation.
// It mounts the target image and runs `go version -m` on all executable files.
func (d *Detector) DetectGoBinaries(
	ctx context.Context,
	gwClient client.Client,
	targetState *llb.State,
	platform *specs.Platform,
) ([]*BinaryInfo, error) {
	if gwClient == nil {
		return nil, fmt.Errorf("gateway client is nil")
	}
	if targetState == nil {
		return nil, fmt.Errorf("target state is nil")
	}

	log.Info("Detecting Go binaries in image using go version -m")
	if platform != nil {
		log.Debugf("Target platform: %s/%s", platform.OS, platform.Architecture)
	}

	// Create tooling image with Go installed, using the target platform
	var tooling llb.State
	if platform != nil {
		tooling = llb.Image(golangToolingImage, llb.Platform(*platform))
	} else {
		tooling = llb.Image(golangToolingImage)
	}

	// Create output directory
	tooling = tooling.File(llb.Mkdir(outputDir, 0o755))

	// Script that finds executables and runs go version -m on all of them
	// This runs as a single operation - very fast
	script := fmt.Sprintf(`
bins=""

# Check root directory first (common for distroless single-binary containers)
for f in /target/*; do
    if [ -f "$f" ]; then
        bins="$bins $f"
    fi
done

# Find executables in common binary locations (if they exist)
for dir in /target/usr/local/bin /target/usr/bin /target/bin /target/sbin /target/usr/sbin /target/app /target/opt /target/go/bin /target/usr/share; do
    if [ -d "$dir" ]; then
        found=$(find "$dir" -type f -perm /0111 2>/dev/null)
        bins="$bins $found"
    fi
done

# Run go version -m on all found binaries, output to file
GO_BIN=/usr/local/go/bin/go
for bin in $bins; do
    if [ -n "$bin" ] && [ -f "$bin" ]; then
        realpath=$(echo "$bin" | sed 's|^/target||')
        echo "=== BINARY: $realpath ===" >> %s
        # Capture file permissions and ownership for preservation during rebuild
        filemode=$(stat -c '%%a' "$bin" 2>/dev/null || stat -f '%%Lp' "$bin" 2>/dev/null || echo "755")
        fileowner=$(stat -c '%%u:%%g' "$bin" 2>/dev/null || echo "0:0")
        echo "=== FILEMODE: $filemode ===" >> %s
        echo "=== FILEOWNER: $fileowner ===" >> %s
        $GO_BIN version -m "$bin" >> %s 2>&1 || echo "NOT_GO_BINARY" >> %s
        echo "" >> %s
    fi
done

# Ensure file exists even if no binaries found
touch %s
`, outputFile, outputFile, outputFile, outputFile, outputFile, outputFile, outputFile)

	// Run the detection script with target image mounted at /target
	execState := tooling.Run(
		llb.Shlex("sh -c '"+strings.ReplaceAll(script, "'", "'\"'\"'")+"'"),
		llb.AddMount("/target", *targetState, llb.Readonly),
	).Root()

	// Solve to get the result
	log.Debug("Marshaling detection state...")
	def, err := execState.Marshal(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal detector state: %w", err)
	}

	log.Debug("Running binary detection in BuildKit...")
	res, err := gwClient.Solve(ctx, client.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to run binary detection (go version -m): %w. This may indicate the tooling image %s is not available for the target platform", err, golangToolingImage)
	}

	// Read the output file
	ref, err := res.SingleRef()
	if err != nil {
		return nil, fmt.Errorf("failed to get result reference from BuildKit: %w", err)
	}

	log.Debugf("Reading detection output from %s...", outputFile)
	outputBytes, err := ref.ReadFile(ctx, client.ReadRequest{
		Filename: outputFile,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read detector output file %s: %w", outputFile, err)
	}

	// Debug: log the raw output
	log.Debugf("Binary detection raw output (%d bytes):\n%s", len(outputBytes), string(outputBytes))

	// Parse the output
	binaries := d.parseGoVersionOutput(string(outputBytes))

	if len(binaries) == 0 {
		log.Debug("No Go binaries detected in the image")
	} else {
		log.Infof("Detected %d Go binaries in image", len(binaries))
		for _, bi := range binaries {
			log.Debugf("  Binary: %s (Go %s, module: %s)", bi.Path, bi.GoVersion, bi.ModulePath)
		}
	}
	return binaries, nil
}

// parseGoVersionOutput parses the output of `go version -m` for multiple binaries.
func (d *Detector) parseGoVersionOutput(output string) []*BinaryInfo {
	var binaries []*BinaryInfo
	var current *BinaryInfo

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		// New binary section
		if strings.HasPrefix(line, "=== BINARY: ") {
			// Save previous binary if it was valid
			if current != nil && current.GoVersion != "" {
				binaries = append(binaries, current)
			}
			// Start new binary
			path := strings.TrimPrefix(line, "=== BINARY: ")
			path = strings.TrimSuffix(path, " ===")
			current = &BinaryInfo{
				Path:          path,
				Dependencies:  make(map[string]string),
				BuildSettings: make(map[string]string),
				VCS:           make(map[string]string),
			}
			continue
		}

		// File mode (e.g., "=== FILEMODE: 755 ===")
		if strings.HasPrefix(line, "=== FILEMODE: ") && current != nil {
			current.FileMode = strings.TrimSuffix(strings.TrimPrefix(line, "=== FILEMODE: "), " ===")
			continue
		}

		// File ownership (e.g., "=== FILEOWNER: 0:0 ===")
		if strings.HasPrefix(line, "=== FILEOWNER: ") && current != nil {
			current.FileOwner = strings.TrimSuffix(strings.TrimPrefix(line, "=== FILEOWNER: "), " ===")
			continue
		}

		// Skip if not currently parsing a binary
		if current == nil {
			continue
		}

		// Not a Go binary
		if line == "NOT_GO_BINARY" {
			current = nil
			continue
		}

		// Parse go version line (e.g., "/path/to/bin: go1.21.5")
		if strings.Contains(line, ": go1.") || strings.Contains(line, ": go2.") {
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) == 2 {
				current.GoVersion = parts[1]
			}
			continue
		}

		// Parse indented lines (path, mod, dep, build)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "path":
			current.ModulePath = fields[1]
		case "mod":
			if len(fields) >= 2 {
				current.Main = fields[1]
				if len(fields) >= 3 {
					current.Main += "@" + fields[2]
				}
			}
		case "dep":
			if len(fields) >= 3 {
				current.Dependencies[fields[1]] = fields[2]
			}
		case "build":
			// Build settings come as key=value pairs
			if len(fields) >= 2 {
				kv := strings.SplitN(fields[1], "=", 2)
				if len(kv) == 2 {
					key := kv[0]
					value := kv[1]
					// Handle multi-word values (like ldflags)
					if len(fields) > 2 {
						value = strings.Join(fields[1:], " ")
						value = strings.TrimPrefix(value, key+"=")
					}
					// Separate VCS info
					if strings.HasPrefix(key, "vcs") {
						current.VCS[key] = value
					} else {
						current.BuildSettings[key] = value
					}
				} else {
					// Single value like "-buildmode=exe" -> key="-buildmode", value="exe"
					current.BuildSettings[fields[1]] = ""
				}
			}
		}
	}

	// Don't forget the last binary
	if current != nil && current.GoVersion != "" {
		binaries = append(binaries, current)
	}

	return binaries
}

// ConvertBinaryInfoToBuildInfo converts detected binary info to BuildInfo for rebuilding.
func (d *Detector) ConvertBinaryInfoToBuildInfo(bi *BinaryInfo) *BuildInfo {
	if bi == nil {
		return nil
	}

	// Extract the module root from the Main field (e.g., "github.com/prometheus/alertmanager@v0.26.0"
	// or "github.com/prometheus/alertmanager@(devel)"). The ModulePath from go version -m's "path" line
	// is the main package import path, which may be a subdirectory of the module (e.g., .../cmd/amtool).
	modulePath := bi.ModulePath
	if bi.Main != "" {
		moduleRoot := strings.Split(bi.Main, "@")[0]
		if moduleRoot != "" {
			modulePath = moduleRoot
		}
	}

	buildInfo := &BuildInfo{
		GoVersion:    strings.TrimPrefix(bi.GoVersion, "go"),
		ModulePath:   modulePath,
		Dependencies: bi.Dependencies,
		BuildArgs:    make(map[string]string),
	}

	// Derive MainPackage if the binary's import path differs from the module root.
	// e.g., import path "github.com/prometheus/alertmanager/cmd/amtool" with module root
	// "github.com/prometheus/alertmanager" → MainPackage = "./cmd/amtool"
	if bi.ModulePath != "" && modulePath != "" && bi.ModulePath != modulePath &&
		strings.HasPrefix(bi.ModulePath, modulePath+"/") {
		buildInfo.MainPackage = "./" + strings.TrimPrefix(bi.ModulePath, modulePath+"/")
	}

	// Extract CGO setting
	if cgo, ok := bi.BuildSettings["CGO_ENABLED"]; ok {
		buildInfo.CGOEnabled = cgo == "1"
	}

	// Extract GOOS/GOARCH
	if goos, ok := bi.BuildSettings["GOOS"]; ok {
		buildInfo.BuildArgs["GOOS"] = goos
	}
	if goarch, ok := bi.BuildSettings["GOARCH"]; ok {
		buildInfo.BuildArgs["GOARCH"] = goarch
	}

	// Extract ldflags if present
	if ldflags, ok := bi.BuildSettings["-ldflags"]; ok {
		buildInfo.BuildFlags = append(buildInfo.BuildFlags, "-ldflags="+ldflags)
	}

	// Extract VCS info for source identification
	if rev, ok := bi.VCS["vcs.revision"]; ok {
		buildInfo.BuildArgs["_sourceCommit"] = rev
	}

	// Derive source repository from module path
	if buildInfo.ModulePath != "" {
		repoURL, _ := deriveRepoFromModulePath(buildInfo.ModulePath)
		if repoURL != "" {
			buildInfo.BuildArgs["_sourceRepo"] = repoURL
		}
	}

	log.Debugf("Converted binary info: Go %s, module %s, mainPkg=%s, CGO=%v, commit=%s",
		buildInfo.GoVersion, buildInfo.ModulePath, buildInfo.MainPackage, buildInfo.CGOEnabled,
		buildInfo.BuildArgs["_sourceCommit"])

	return buildInfo
}
