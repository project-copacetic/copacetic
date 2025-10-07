package buildkit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/project-copacetic/copacetic/pkg/buildkit/connhelpers"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
)

type Config struct {
	ImageName         string
	Client            gwclient.Client
	ConfigData        []byte
	PatchedConfigData []byte
	Platform          *specs.Platform
	ImageState        llb.State
	PatchedImageState llb.State
}

type Opts struct {
	Addr       string
	CACertPath string
	CertPath   string
	KeyPath    string
}

const (
	linux = "linux"
	arm64 = "arm64"
)

// for testing.
var (
	readDir  = os.ReadDir
	readFile = os.ReadFile
	lookPath = exec.LookPath
)

func InitializeBuildkitConfig(
	ctx context.Context,
	c gwclient.Client,
	userImage string,
	platform *specs.Platform,
) (*Config, error) {
	// Initialize buildkit config for the target image
	config := Config{
		ImageName: userImage,
		Platform:  platform,
	}

	// Resolve and pull the config for the target image
	resolveOpt := sourceresolver.Opt{
		ImageOpt: &sourceresolver.ResolveImageOpt{
			ResolveMode: llb.ResolveModePreferLocal.String(),
		},
	}
	if platform != nil {
		resolveOpt.Platform = platform
	}
	_, _, configData, err := c.ResolveImageConfig(ctx, userImage, resolveOpt)
	if err != nil {
		return nil, err
	}

	var baseImage string
	config.ConfigData, config.PatchedConfigData, baseImage, err = updateImageConfigData(ctx, c, configData, userImage)
	if err != nil {
		return nil, err
	}

	// Load the target image state with the resolved image config in case environment variable settings
	// are necessary for running apps in the target image for updates
	imageOpts := []llb.ImageOption{
		llb.ResolveModePreferLocal,
		llb.WithMetaResolver(c),
	}
	if platform != nil {
		imageOpts = append(imageOpts, llb.Platform(*platform))
	}
	config.ImageState, err = llb.Image(baseImage, imageOpts...).WithImageConfig(config.ConfigData)
	if err != nil {
		return nil, err
	}

	// Only set PatchedImageState if the user supplied a patched image
	// An image is deemed to be a patched image if it contains one of two metadata values
	// BaseImage or specs.AnnotationBaseImageName
	if config.PatchedConfigData != nil {
		patchedImageOpts := []llb.ImageOption{
			llb.ResolveModePreferLocal,
			llb.WithMetaResolver(c),
		}
		if platform != nil {
			patchedImageOpts = append(patchedImageOpts, llb.Platform(*platform))
		}
		config.PatchedImageState, err = llb.Image(userImage, patchedImageOpts...).WithImageConfig(config.PatchedConfigData)
		if err != nil {
			return nil, err
		}
	}

	config.Client = c

	return &config, nil
}

func DiscoverPlatformsFromReport(reportDir, scanner string) ([]types.PatchPlatform, error) {
	var platforms []types.PatchPlatform

	reportNames, err := os.ReadDir(reportDir)
	if err != nil {
		return nil, err
	}

	for _, file := range reportNames {
		filePath := reportDir + "/" + file.Name()
		if file.IsDir() {
			continue
		}
		report, err := report.TryParseScanReport(filePath, scanner, utils.PkgTypeOS, utils.PatchTypePatch)
		if err != nil {
			return nil, fmt.Errorf("error parsing report %w", err)
		}

		// use this to confirm that os type (ex/Debian) is linux based and supported since report.Metadata.OS.Type gives specific like "debian" rather than "linux"
		if !isSupportedOsType(report.Metadata.OS.Type) {
			continue
		}

		platform := types.PatchPlatform{
			Platform: specs.Platform{
				OS:           linux,
				Architecture: report.Metadata.Config.Arch,
				Variant:      report.Metadata.Config.Variant,
			},
			ReportFile:     filePath,
			ShouldPreserve: false, // This platform has a report, so it should be patched
		}

		if platform.Architecture == arm64 && platform.Variant == "v8" {
			// removing this to maintain consistency since we do
			// the same for the platforms discovered from reports
			platform.Variant = ""
		}
		platforms = append(platforms, platform)
	}

	return platforms, nil
}

func isSupportedOsType(osType string) bool {
	switch osType {
	case utils.OSTypeAlpine,
		utils.OSTypeDebian,
		utils.OSTypeUbuntu,
		utils.OSTypeCBLMariner,
		utils.OSTypeAzureLinux,
		utils.OSTypeCentOS,
		utils.OSTypeOracle,
		utils.OSTypeRedHat,
		utils.OSTypeRocky,
		utils.OSTypeAmazon,
		utils.OSTypeAlma,
		utils.OSTypeAlmaLinux:
		return true
	default:
		return false
	}
}

// TryGetManifestFromLocal attempts to get manifest data from the local Docker daemon.
// It returns a remote.Descriptor if successful, or an error if the manifest cannot be retrieved locally.
// This is exported to support patching images that exist locally but not in a remote registry.
func TryGetManifestFromLocal(ref name.Reference) (*remote.Descriptor, error) {
	imageName := ref.String()
	log.Debugf("Attempting to get manifest from local daemon for %s", imageName)

	// Try to get the image from the local daemon using go-containerregistry
	// First, try to get it as an image index (multi-platform)
	ctx := context.Background()

	// Attempt to read raw manifest from daemon
	// The daemon package doesn't directly expose manifest inspection, so we use a workaround:
	// Try to get the image and then extract its raw manifest
	img, err := daemon.Image(ref, daemon.WithContext(ctx))
	if err != nil {
		log.Debugf("Failed to get image from daemon for %s: %v", imageName, err)
		return nil, fmt.Errorf("failed to get image from local daemon: %v", err)
	}

	// Get the raw manifest
	rawManifest, err := img.RawManifest()
	if err != nil {
		log.Debugf("Failed to get raw manifest for %s: %v", imageName, err)
		return nil, fmt.Errorf("failed to get raw manifest: %v", err)
	}

	// Parse the manifest to determine if it's a manifest list
	var manifestData map[string]interface{}
	if err := json.Unmarshal(rawManifest, &manifestData); err != nil {
		log.Debugf("Failed to parse manifest JSON for %s: %v", imageName, err)
		return nil, fmt.Errorf("failed to parse manifest JSON: %v", err)
	}

	// Check if this is a manifest list (has "manifests" field)
	if manifests, ok := manifestData["manifests"]; ok {
		if manifestSlice, ok := manifests.([]interface{}); ok && len(manifestSlice) > 0 {
			log.Debugf("Found multi-platform manifest from daemon with %d platforms", len(manifestSlice))

			// Parse the manifest list to extract individual platform image references
			var enhancedManifestData struct {
				MediaType string `json:"mediaType"`
				Manifests []struct {
					Digest    string `json:"digest"`
					MediaType string `json:"mediaType"`
					Size      int64  `json:"size"`
					Platform  struct {
						Architecture string `json:"architecture"`
						OS           string `json:"os"`
						Variant      string `json:"variant,omitempty"`
					} `json:"platform"`
				} `json:"manifests"`
			}

			if err := json.Unmarshal(rawManifest, &enhancedManifestData); err != nil {
				log.Debugf("Failed to parse enhanced manifest JSON for %s: %v", imageName, err)
				return nil, fmt.Errorf("failed to parse enhanced manifest JSON: %v", err)
			}

			// Log platform information for debugging
			log.Debugf("Manifest list contains the following platforms:")
			for i, manifest := range enhancedManifestData.Manifests {
				log.Debugf("  Platform %d: %s/%s (digest: %s)", i+1,
					manifest.Platform.OS, manifest.Platform.Architecture,
					manifest.Digest[:12]+"...")
			}

			// Determine media type
			mediaType := "application/vnd.docker.distribution.manifest.list.v2+json"
			if enhancedManifestData.MediaType != "" {
				mediaType = enhancedManifestData.MediaType
			}

			// Calculate digest from the manifest content
			digest := fmt.Sprintf("%x", sha256.Sum256(rawManifest))

			return &remote.Descriptor{
				Descriptor: v1.Descriptor{
					MediaType: v1types.MediaType(mediaType),
					Size:      int64(len(rawManifest)),
					Digest:    v1.Hash{Algorithm: "sha256", Hex: digest},
				},
				Manifest: rawManifest,
			}, nil
		}
	}

	return nil, fmt.Errorf("single-platform image")
}

// DiscoverPlatformsFromReference discovers platforms from both local and remote manifests.
// It first attempts to inspect the manifest locally using Docker API
// to get raw manifest data and determine if it's multi-platform.
// If local inspection fails, it falls back to remote registry inspection.
// This allows Copa to patch multi-platform manifests that exist locally but not in the registry.
func DiscoverPlatformsFromReference(manifestRef string) ([]types.PatchPlatform, error) {
	var platforms []types.PatchPlatform

	ref, err := name.ParseReference(manifestRef)
	if err != nil {
		return nil, fmt.Errorf("error parsing reference %q: %w", manifestRef, err)
	}

	// Try local daemon first, then fall back to remote
	desc, err := TryGetManifestFromLocal(ref)
	if err != nil {
		log.Debugf("Failed to get descriptor from local daemon: %v, trying remote registry", err)
		desc, err = remote.Get(ref)
		if err != nil {
			return nil, fmt.Errorf("error fetching descriptor for %q from both local daemon and remote registry: %w", manifestRef, err)
		}
		log.Debugf("Successfully fetched descriptor from remote registry for %s", manifestRef)
	} else {
		log.Debugf("Successfully fetched descriptor from local daemon for %s", manifestRef)
	}

	if desc.MediaType.IsIndex() {
		index, err := desc.ImageIndex()
		if err != nil {
			return nil, fmt.Errorf("error getting image index %w", err)
		}

		manifest, err := index.IndexManifest()
		if err != nil {
			return nil, fmt.Errorf("error getting manifest: %w", err)
		}

		for i := range manifest.Manifests {
			m := &manifest.Manifests[i]

			// Skip manifests with unknown platforms
			if m.Platform == nil || m.Platform.OS == "unknown" || m.Platform.Architecture == "unknown" {
				log.Debugf("Skipping manifest with unknown platform: %s/%s", m.Platform.OS, m.Platform.Architecture)
				continue
			}

			patchPlatform := types.PatchPlatform{
				Platform: specs.Platform{
					OS:           m.Platform.OS,
					Architecture: m.Platform.Architecture,
					Variant:      m.Platform.Variant,
					OSVersion:    m.Platform.OSVersion,
					OSFeatures:   m.Platform.OSFeatures,
				},
				ReportFile:     "",    // No report file for platforms discovered from reference
				ShouldPreserve: false, // Default to false, will be set appropriately later
			}
			if m.Platform.Architecture == arm64 && m.Platform.Variant == "v8" {
				// some scanners may not add v8 to arm64 reports, so we
				// need to remove it here to maintain consistency
				patchPlatform.Variant = ""
			}
			platforms = append(platforms, patchPlatform)
		}
		return platforms, nil
	}

	// For single-platform images, try to get the image config to extract platform information
	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("error getting image %w", err)
	}

	config, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("error getting image config %w", err)
	}

	// Extract platform from image config
	if config.Architecture != "" && config.OS != "" {
		platform := types.PatchPlatform{
			Platform: specs.Platform{
				OS:           config.OS,
				Architecture: config.Architecture,
				Variant:      config.Variant,
			},
			ReportFile:     "",
			ShouldPreserve: false,
		}
		if platform.Architecture == arm64 && platform.Variant == "v8" {
			platform.Variant = ""
		}
		return []types.PatchPlatform{platform}, nil
	}

	// return nil if platform information is not available
	return nil, nil
}

//nolint:gocritic
func PlatformKey(pl specs.Platform) string {
	// if platform is present in list from reference and report, then we should patch that platform
	key := pl.OS + "/" + pl.Architecture
	if pl.Variant != "" {
		key += "/" + pl.Variant
	}
	// Include OS version for platforms like Windows that have multiple versions
	if pl.OSVersion != "" {
		key += "@" + pl.OSVersion
	}
	return key
}

func DiscoverPlatforms(manifestRef, reportDir, scanner string) ([]types.PatchPlatform, error) {
	var platforms []types.PatchPlatform

	p, err := DiscoverPlatformsFromReference(manifestRef)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errors.New("image is not multi platform")
	}
	log.WithField("platforms", p).Debug("Discovered platforms from manifest")

	if reportDir != "" {
		p2, err := DiscoverPlatformsFromReport(reportDir, scanner)
		if err != nil {
			return nil, err
		}
		log.WithField("platforms", p2).Debug("Discovered platforms from report")

		// include all platforms from original manifest, patching only those with reports
		reportSet := make(map[string]string, len(p2))
		for _, pl := range p2 {
			reportSet[PlatformKey(pl.Platform)] = pl.ReportFile
		}

		for _, pl := range p {
			if rp, ok := reportSet[PlatformKey(pl.Platform)]; ok {
				// Platform has a report - will be patched
				pl.ReportFile = rp
				pl.ShouldPreserve = false
				platforms = append(platforms, pl)
			} else {
				// Platform has no report - preserve original without patching
				log.Debugf("No report found for platform %s, preserving original", PlatformKey(pl.Platform))
				pl.ReportFile = ""
				pl.ShouldPreserve = true
				platforms = append(platforms, pl)
			}
		}

		return platforms, nil
	}

	return p, nil
}

// GetPlatformImageReference resolves a platform-specific image reference from a local manifest.
// For multi-platform images that exist locally but not in the registry, this function extracts
// the platform-specific digest and constructs a reference that BuildKit can resolve.
func GetPlatformImageReference(manifestRef string, targetPlatform *specs.Platform) (string, error) {
	ref, err := name.ParseReference(manifestRef)
	if err != nil {
		return "", fmt.Errorf("error parsing reference %q: %w", manifestRef, err)
	}

	// Try to get the local manifest first
	desc, err := TryGetManifestFromLocal(ref)
	if err != nil {
		// Not a local manifest, return original reference
		return manifestRef, nil
	}

	if !desc.MediaType.IsIndex() {
		// Single platform image, return original reference
		return manifestRef, nil
	}

	// Parse the manifest to extract platform-specific information
	var manifestData struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Variant      string `json:"variant,omitempty"`
			} `json:"platform"`
		} `json:"manifests"`
	}

	if err := json.Unmarshal(desc.Manifest, &manifestData); err != nil {
		return "", fmt.Errorf("failed to parse manifest JSON: %w", err)
	}

	// Find the matching platform
	for _, manifest := range manifestData.Manifests {
		manifestPlatform := manifest.Platform

		// Normalize arm64 variant for comparison
		if manifestPlatform.Architecture == arm64 && manifestPlatform.Variant == "v8" {
			manifestPlatform.Variant = ""
		}
		targetVariant := targetPlatform.Variant
		if targetPlatform.Architecture == arm64 && targetVariant == "v8" {
			targetVariant = ""
		}

		// Check if platforms match
		if manifestPlatform.OS == targetPlatform.OS &&
			manifestPlatform.Architecture == targetPlatform.Architecture &&
			manifestPlatform.Variant == targetVariant {
			// For local manifests, we need to construct a reference to the platform-specific image
			// Extract the base repository name (without tag/digest)
			baseRepo := ref.Context().Name()

			// Construct platform-specific image reference with digest
			platformImageRef := baseRepo + "@" + manifest.Digest

			log.Debugf("Found platform %s/%s in local manifest, using image reference: %s",
				manifestPlatform.OS, manifestPlatform.Architecture, platformImageRef)
			return platformImageRef, nil
		}
	}

	return "", fmt.Errorf("platform %s/%s not found in manifest", targetPlatform.OS, targetPlatform.Architecture)
}

func updateImageConfigData(ctx context.Context, c gwclient.Client, configData []byte, image string) ([]byte, []byte, string, error) {
	baseImage, userImageConfig, err := setupLabels(image, configData)
	if err != nil {
		return nil, nil, "", err
	}

	if baseImage == "" {
		configData = userImageConfig
	} else {
		patchedImageConfig := userImageConfig
		_, _, baseImageConfig, err := c.ResolveImageConfig(ctx, baseImage, sourceresolver.Opt{
			ImageOpt: &sourceresolver.ResolveImageOpt{
				ResolveMode: llb.ResolveModePreferLocal.String(),
			},
		})
		if err != nil {
			log.Warnf("Failed to resolve BaseImage %s: %v. Falling back to using current image %s as base", baseImage, err, image)
			// Fallback: Create a new config with the BaseImage label set to current image
			imageConfig := make(map[string]interface{})
			if err := json.Unmarshal(configData, &imageConfig); err != nil {
				log.Warnf("Failed to unmarshal image config: %v", err)
				return configData, nil, image, nil
			}
			configMap, ok := imageConfig["config"].(map[string]interface{})
			if !ok {
				log.Warnf("Invalid config structure in image config")
				return configData, nil, image, nil
			}
			if configMap["labels"] == nil {
				configMap["labels"] = make(map[string]interface{})
			}
			labelsMap, ok := configMap["labels"].(map[string]interface{})
			if !ok {
				log.Warnf("Invalid labels structure in image config")
				return configData, nil, image, nil
			}
			labelsMap["BaseImage"] = image
			updatedConfigData, err := json.Marshal(imageConfig)
			if err != nil {
				log.Warnf("Failed to marshal updated image config: %v", err)
				return configData, nil, image, nil
			}
			return updatedConfigData, nil, image, nil
		}

		_, baseImageWithLabels, _ := setupLabels(baseImage, baseImageConfig)
		configData = baseImageWithLabels

		return configData, patchedImageConfig, baseImage, nil
	}

	return configData, nil, image, nil
}

func setupLabels(image string, configData []byte) (string, []byte, error) {
	imageConfig := make(map[string]interface{})
	err := json.Unmarshal(configData, &imageConfig)
	if err != nil {
		return "", nil, err
	}

	configMap, ok := imageConfig["config"].(map[string]interface{})
	if !ok {
		err := fmt.Errorf("type assertion to map[string]interface{} failed")
		return "", nil, err
	}

	var baseImage string
	labels := configMap["labels"]
	if labels == nil {
		configMap["labels"] = make(map[string]interface{})
	}
	labelsMap, ok := configMap["labels"].(map[string]interface{})
	if !ok {
		err := fmt.Errorf("type assertion to map[string]interface{} failed")
		return "", nil, err
	}
	if baseImageValue := labelsMap["BaseImage"]; baseImageValue != nil {
		baseImage, ok = baseImageValue.(string)
		if !ok {
			err := fmt.Errorf("type assertion to string failed")
			return "", nil, err
		}
	} else {
		labelsMap["BaseImage"] = image
	}

	imageWithLabels, _ := json.Marshal(imageConfig)

	return baseImage, imageWithLabels, nil
}

// Extracts the bytes of the file denoted by `path` from the state `st`.
func ExtractFileFromState(ctx context.Context, c gwclient.Client, st *llb.State, path string) ([]byte, error) {
	// since platform is obtained from host, override it in the case of Darwin
	platform := platforms.Normalize(platforms.DefaultSpec())
	if platform.OS != linux {
		platform.OS = linux
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

func Sh(cmd string) llb.RunOption {
	return llb.Args([]string{"/bin/sh", "-c", cmd})
}

func ArrayFile(input []string) []byte {
	var b bytes.Buffer
	for _, s := range input {
		b.WriteString(s)
		b.WriteRune('\n') // newline
	}
	return b.Bytes()
}

func WithArrayFile(s *llb.State, path string, contents []string) llb.State {
	af := ArrayFile(contents)
	return WithFileBytes(s, path, af)
}

func WithFileString(s *llb.State, path, contents string) llb.State {
	return WithFileBytes(s, path, []byte(contents))
}

func WithFileBytes(s *llb.State, path string, contents []byte) llb.State {
	return s.File(llb.Mkfile(path, 0o600, contents))
}

func QemuAvailable(p *types.PatchPlatform) bool {
	if p == nil {
		return false
	}

	// check if were on macos or windows
	switch runtime.GOOS {
	case "darwin":
		// on macos, we cant directly check binfmt_misc on the host
		// we assume docker desktop handles emulation
		log.Warn("Running on macOS, assuming Docker Desktop handles emulation.")
		return true
	case "windows":
		log.Warn("Running on Windows, assuming Docker Desktop handles emulation.")
		return true
	}

	archKey := mapGoArch(p.Architecture, p.Variant)

	// walk binfmt_misc entries
	entries, err := readDir("/proc/sys/fs/binfmt_misc")
	if err != nil {
		return false
	}

	for _, e := range entries {
		if e.IsDir() || e.Name() == "register" || e.Name() == "status" {
			continue
		}
		data, _ := readFile("/proc/sys/fs/binfmt_misc/" + e.Name())
		if bytes.Contains(data, []byte("interpreter")) &&
			bytes.Contains(data, []byte("qemu-"+archKey)) {
			return true
		}
	}
	// fallback to interpreter binary on PATH (for rootless case)
	if _, err := lookPath("qemu-" + archKey + "-static"); err == nil {
		return true
	}
	return false
}

func mapGoArch(arch, variant string) string {
	switch arch {
	case "amd64", "amd64p32":
		return "x86_64"

	case "386":
		return "i386"

	case "arm64", "arm64be":
		return "aarch64"

	case "arm":
		// GOARM=5/6/7 -> qemu-arm
		// big-endian -> qemu-armeb
		if strings.HasSuffix(variant, "eb") || strings.HasSuffix(arch, "be") {
			return "armeb"
		}
		return "arm"

	case "mips":
		if strings.HasSuffix(arch, "le") {
			return "mipsel"
		}
		return "mips"

	case "mips64":
		if strings.HasSuffix(variant, "n32") {
			return "mipsn32"
		}
		if strings.HasSuffix(arch, "le") {
			return "mips64el"
		}
		return "mips64"

	case "mips64le":
		if strings.HasSuffix(variant, "n32") {
			return "mipsn32el"
		}
		return "mips64el"

	case "ppc64":
		if strings.HasSuffix(variant, "le") {
			return "ppc64le"
		}
		return "ppc64"

	case "loong64":
		return "loongarch64"

	case "sh4":
		if strings.HasSuffix(variant, "eb") {
			return "sh4eb"
		}
		return "sh4"

	case "xtensa":
		if strings.HasSuffix(variant, "eb") {
			return "xtensaeb"
		}
		return "xtensa"

	case "microblaze":
		if strings.HasSuffix(variant, "el") {
			return "microblazeel"
		}
		return "microblaze"
	}

	// fallback: hope QEMU name == GOARCH
	return arch
}

// CreateOCILayoutFromResults creates an OCI layout directory from patch results using BuildKit's OCI exporter.
func CreateOCILayoutFromResults(outputDir string, results []types.PatchResult, platforms []types.PatchPlatform) error {
	log.Infof("Creating multi-platform OCI layout in directory: %s with %d platforms", outputDir, len(platforms))

	// Create output directory
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Check if we have BuildKit states available
	hasStates := false

	for _, result := range results {
		if result.PatchedState != nil {
			hasStates = true
			break
		}
	}

	if hasStates {
		log.Info("Using BuildKit states directly for OCI export")
		return createOCILayoutFromStates(outputDir, results, platforms)
	}

	return fmt.Errorf("no BuildKit states available for OCI export, cannot proceed")
}

// createOCILayoutFromStates creates OCI layout directly from BuildKit states.
func createOCILayoutFromStates(outputDir string, results []types.PatchResult, platforms []types.PatchPlatform) error {
	log.Info("Creating OCI layout from preserved BuildKit states and preserved platforms")

	// Separate patched and preserved platforms
	var patchedPlatforms []types.PatchPlatform
	var preservedPlatforms []types.PatchPlatform

	for _, platform := range platforms {
		if platform.ShouldPreserve {
			preservedPlatforms = append(preservedPlatforms, platform)
		} else {
			patchedPlatforms = append(patchedPlatforms, platform)
		}
	}

	log.Infof("Found %d patched platforms and %d preserved platforms", len(patchedPlatforms), len(preservedPlatforms))

	// Build platform states from results for patched platforms only
	var platformStates []llb.State
	var platformSpecs []specs.Platform

	// Map results by platform for easy lookup
	resultMap := make(map[string]*types.PatchResult)
	for i, result := range results {
		// Find the platform for this result
		for _, platform := range patchedPlatforms {
			platformKey := PlatformKey(platform.Platform)
			// Match by patched reference suffix or exact match
			if result.PatchedState != nil {
				expectedSuffix := getPlatformSuffix(&platform.Platform)
				if strings.HasSuffix(result.PatchedRef.String(), expectedSuffix) {
					resultMap[platformKey] = &results[i]
					break
				}
			}
		}
	}

	// Create states for each patched platform
	for _, platform := range patchedPlatforms {
		platformKey := PlatformKey(platform.Platform)
		if result, exists := resultMap[platformKey]; exists && result.PatchedState != nil {
			platformStates = append(platformStates, *result.PatchedState)
			platformSpecs = append(platformSpecs, platform.Platform)
		}
	}

	if len(platformStates) == 0 && len(preservedPlatforms) == 0 {
		return fmt.Errorf("no BuildKit states or preserved platforms found")
	}

	// Handle different layout creation scenarios
	hasPatchedPlatforms := len(platformStates) > 0
	hasPreservedPlatforms := len(preservedPlatforms) > 0

	switch {
	case hasPreservedPlatforms && hasPatchedPlatforms:
		log.Infof("Creating mixed OCI layout with %d patched and %d preserved platforms", len(platformStates), len(preservedPlatforms))
		return createMixedOCILayout(outputDir, results, platformStates, platformSpecs, preservedPlatforms)
	case hasPatchedPlatforms:
		log.Infof("Creating OCI layout from %d patched platforms only", len(platformStates))
	case hasPreservedPlatforms:
		log.Infof("Creating OCI layout from %d preserved platforms only", len(preservedPlatforms))
		return createPreservedOnlyOCILayout(outputDir, results, preservedPlatforms)
	}

	log.Infof("Creating OCI layout from %d BuildKit states", len(platformStates))

	// Use BuildKit Go client to create OCI layout
	ctx := context.Background()

	// Try buildx driver first
	h, err := connhelpers.Buildx(&url.URL{})
	if err != nil {
		log.WithError(err).Debug("Could not get buildx helper")
	} else {
		c, err := client.New(ctx, "", client.WithContextDialer(h.ContextDialer))
		if err == nil {
			err = ValidateClient(ctx, c)
			if err == nil {
				log.Debug("Using buildx driver for OCI layout export")
				defer c.Close()

				return solveMultiPlatformOCI(ctx, c, outputDir, platformStates, platformSpecs)
			}
			c.Close()
		}
		log.WithError(err).Debug("Buildx driver validation failed")
	}

	// Fall back to auto-detection
	log.Debug("Falling back to auto-detection for BuildKit client")
	bkOpts := Opts{}
	c, err := NewClient(ctx, bkOpts)
	if err != nil {
		return fmt.Errorf("failed to create BuildKit client: %w", err)
	}
	defer c.Close()

	return solveMultiPlatformOCI(ctx, c, outputDir, platformStates, platformSpecs)
}

// solveMultiPlatformOCI uses BuildKit client to solve multi-platform states and export to OCI layout.
func solveMultiPlatformOCI(ctx context.Context, c *client.Client, outputDir string, platformStates []llb.State, platformSpecs []specs.Platform) error {
	if len(platformStates) == 0 {
		return fmt.Errorf("no platform states provided")
	}

	if len(platformStates) != len(platformSpecs) {
		return fmt.Errorf("mismatch between states (%d) and platform specs (%d)", len(platformStates), len(platformSpecs))
	}

	// Remove output directory if it exists
	os.RemoveAll(outputDir)

	// Create output directory
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if len(platformStates) == 1 {
		// Single platform case - use output function to avoid diffcopy issues
		return solveSinglePlatformOCI(ctx, c, outputDir, &platformStates[0], &platformSpecs[0])
	}

	// Multi-platform case - solve each platform and combine
	return solveAndCombineAllPlatforms(ctx, c, outputDir, platformStates, platformSpecs)
}

// solveSinglePlatformOCI handles single platform OCI export using output function.
func solveSinglePlatformOCI(ctx context.Context, c *client.Client, outputDir string, state *llb.State, platformSpec *specs.Platform) error {
	// Create solve options with output function to avoid diffcopy issues
	solveOpt := client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type: client.ExporterOCI,
			Attrs: map[string]string{
				"oci-mediatypes": "true",
				"buildinfo":      "false",
			},
			Output: func(_ map[string]string) (io.WriteCloser, error) {
				tarPath := filepath.Join(outputDir, "image.tar")
				return os.Create(tarPath)
			},
		}},
	}

	// Marshal the state with platform constraint
	def, err := state.Marshal(ctx, llb.Platform(*platformSpec))
	if err != nil {
		return fmt.Errorf("failed to marshal LLB state: %w", err)
	}

	// Solve to tar
	_, err = c.Solve(ctx, def, solveOpt, nil)
	if err != nil {
		return fmt.Errorf("BuildKit solve failed: %w", err)
	}

	// Extract tar to OCI layout
	tarPath := filepath.Join(outputDir, "image.tar")
	if err := extractTarToDirectory(tarPath, outputDir); err != nil {
		return fmt.Errorf("failed to extract OCI layout: %w", err)
	}

	// Clean up tar file
	os.Remove(tarPath)

	// Fix platform information in the extracted OCI layout
	if err := fixSinglePlatformInfo(outputDir, platformSpec); err != nil {
		return fmt.Errorf("failed to fix platform information: %w", err)
	}

	return nil
}

// fixSinglePlatformInfo corrects the platform information in a single-platform OCI layout.
func fixSinglePlatformInfo(outputDir string, platformSpec *specs.Platform) error {
	indexPath := filepath.Join(outputDir, "index.json")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return fmt.Errorf("failed to read index.json: %w", err)
	}

	var index map[string]interface{}
	if err := json.Unmarshal(indexData, &index); err != nil {
		return fmt.Errorf("failed to parse index.json: %w", err)
	}

	// Create correct platform info
	targetPlatform := map[string]interface{}{
		"os":           platformSpec.OS,
		"architecture": platformSpec.Architecture,
	}

	if platformSpec.Variant != "" {
		targetPlatform["variant"] = platformSpec.Variant
	}

	// Update platform information in all manifests
	if manifests, ok := index["manifests"].([]interface{}); ok {
		for _, manifest := range manifests {
			if manifestMap, ok := manifest.(map[string]interface{}); ok {
				manifestMap["platform"] = targetPlatform
			}
		}
	}

	// Write back the corrected index
	indexJSON, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal corrected index: %w", err)
	}

	if err := os.WriteFile(indexPath, indexJSON, 0o600); err != nil {
		return fmt.Errorf("failed to write corrected index.json: %w", err)
	}

	return nil
}

// solveAndCombineAllPlatforms solves each platform and combines them into one OCI layout.
func solveAndCombineAllPlatforms(ctx context.Context, c *client.Client, outputDir string, platformStates []llb.State, platformSpecs []specs.Platform) error {
	// Create temporary directory for platform tars
	tempDir, err := os.MkdirTemp("", "copa-platforms-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	var platformTars []string

	// Solve each platform to its own tar file using output function
	for i := range platformSpecs {
		platformTarPath := filepath.Join(tempDir, fmt.Sprintf("platform-%d.tar", i))
		platformTars = append(platformTars, platformTarPath)

		// Create solve options with output function
		platformSolveOpt := client.SolveOpt{
			Exports: []client.ExportEntry{{
				Type: client.ExporterOCI,
				Attrs: map[string]string{
					"oci-mediatypes": "true",
					"buildinfo":      "false",
				},
				Output: func(_ map[string]string) (io.WriteCloser, error) {
					return os.Create(platformTarPath)
				},
			}},
		}

		// Marshal and solve this platform's definition
		def, err := platformStates[i].Marshal(ctx, llb.Platform(platformSpecs[i]))
		if err != nil {
			return fmt.Errorf("failed to marshal platform: %w", err)
		}

		_, err = c.Solve(ctx, def, platformSolveOpt, nil)
		if err != nil {
			return fmt.Errorf("failed to solve platform: %w", err)
		}
	}

	// Extract and combine all platform tars into multi-platform OCI layout
	return extractAndCombinePlatformTars(outputDir, platformTars, platformSpecs)
}

// extractAndCombinePlatformTars extracts platform tars and combines them into multi-platform OCI layout.
func extractAndCombinePlatformTars(outputDir string, platformTars []string, platformSpecs []specs.Platform) error {
	// Create output directory structure
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	blobsDir := filepath.Join(outputDir, "blobs")
	if err := os.MkdirAll(blobsDir, 0o755); err != nil {
		return fmt.Errorf("failed to create blobs directory: %w", err)
	}

	// Create oci-layout file
	ociLayoutContent := `{"imageLayoutVersion":"1.0.0"}`
	if err := os.WriteFile(filepath.Join(outputDir, "oci-layout"), []byte(ociLayoutContent), 0o600); err != nil {
		return fmt.Errorf("failed to write oci-layout: %w", err)
	}

	// Collect all platform manifests and copy blobs
	var platformManifests []map[string]interface{}
	blobsSet := make(map[string]bool) // Track blobs to avoid duplicates

	for i, platformTar := range platformTars {
		platformSpec := platformSpecs[i]

		// Extract platform tar to temporary directory
		platformTempDir, err := os.MkdirTemp("", "copa-platform-extract-*")
		if err != nil {
			return fmt.Errorf("failed to create temp directory for platform: %w", err)
		}
		defer os.RemoveAll(platformTempDir)

		// Extract tar file
		if err := extractTarToDirectory(platformTar, platformTempDir); err != nil {
			return fmt.Errorf("failed to extract tar for platform: %w", err)
		}

		// Read the platform's index.json
		indexPath := filepath.Join(platformTempDir, "index.json")
		indexData, err := os.ReadFile(indexPath)
		if err != nil {
			return fmt.Errorf("failed to read index.json from platform: %w", err)
		}

		var index map[string]interface{}
		if err := json.Unmarshal(indexData, &index); err != nil {
			return fmt.Errorf("failed to parse index.json from platform: %w", err)
		}

		// Create platform info from platformSpec
		targetPlatform := map[string]interface{}{
			"os":           platformSpec.OS,
			"architecture": platformSpec.Architecture,
		}

		// Add variant if present
		if platformSpec.Variant != "" {
			targetPlatform["variant"] = platformSpec.Variant
		}

		// Extract manifests from this platform's index and set correct platform
		if manifests, ok := index["manifests"].([]interface{}); ok {
			for _, manifest := range manifests {
				if manifestMap, ok := manifest.(map[string]interface{}); ok {
					// Override the platform information with our correct target platform
					manifestMap["platform"] = targetPlatform
					platformManifests = append(platformManifests, manifestMap)
				}
			}
		}

		// Copy blobs from this platform to the combined layout
		platformBlobsDir := filepath.Join(platformTempDir, "blobs")
		if err := copyBlobs(platformBlobsDir, blobsDir, blobsSet); err != nil {
			return fmt.Errorf("failed to copy blobs from platform: %w", err)
		}
	}

	// Create the combined index.json with all platform manifests
	combinedIndex := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests":     platformManifests,
	}

	indexJSON, err := json.MarshalIndent(combinedIndex, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal combined index: %w", err)
	}

	if err := os.WriteFile(filepath.Join(outputDir, "index.json"), indexJSON, 0o600); err != nil {
		return fmt.Errorf("failed to write combined index.json: %w", err)
	}

	return nil
}

// copyBlobs copies blob files from source to destination, avoiding duplicates.
func copyBlobs(srcBlobsDir, dstBlobsDir string, blobsSet map[string]bool) error {
	// Check if source blobs directory exists
	if _, err := os.Stat(srcBlobsDir); os.IsNotExist(err) {
		log.Debugf("Source blobs directory does not exist: %s", srcBlobsDir)
		return nil // Not an error, platform might not have blobs
	}

	// Walk through the blobs directory structure (sha256/*)
	return filepath.Walk(srcBlobsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Get relative path from blobs directory
		relPath, err := filepath.Rel(srcBlobsDir, path)
		if err != nil {
			return err
		}

		// Skip if blob already exists
		if blobsSet[relPath] {
			log.Debugf("Skipping duplicate blob: %s", relPath)
			return nil
		}

		// Create destination directory structure
		dstPath := filepath.Join(dstBlobsDir, relPath)
		dstDir := filepath.Dir(dstPath)
		if err := os.MkdirAll(dstDir, 0o755); err != nil {
			return fmt.Errorf("failed to create destination directory %s: %w", dstDir, err)
		}

		// Copy the blob file
		srcFile, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open source blob %s: %w", path, err)
		}
		defer srcFile.Close()

		dstFile, err := os.Create(dstPath)
		if err != nil {
			return fmt.Errorf("failed to create destination blob %s: %w", dstPath, err)
		}
		defer dstFile.Close()

		if _, err := io.Copy(dstFile, srcFile); err != nil {
			return fmt.Errorf("failed to copy blob %s: %w", relPath, err)
		}

		// Mark blob as copied
		blobsSet[relPath] = true
		log.Debugf("Copied blob: %s", relPath)

		return nil
	})
}

// extractTarToDirectory extracts a tar file to a directory.
func extractTarToDirectory(tarPath, destDir string) error {
	// Validate and clean paths to prevent path traversal attacks
	cleanTarPath := filepath.Clean(tarPath)
	cleanDestDir := filepath.Clean(destDir)

	// Ensure destination directory doesn't contain path traversal sequences
	if strings.Contains(cleanDestDir, "..") {
		return fmt.Errorf("destination directory contains invalid path traversal sequence: %s", destDir)
	}

	// Verify tar file exists and is a regular file
	tarInfo, err := os.Stat(cleanTarPath)
	if err != nil {
		return fmt.Errorf("failed to stat tar file %s: %w", cleanTarPath, err)
	}
	if !tarInfo.Mode().IsRegular() {
		return fmt.Errorf("tar path %s is not a regular file", cleanTarPath)
	}

	// Ensure destination directory exists
	if err := os.MkdirAll(cleanDestDir, 0o755); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", cleanDestDir, err)
	}

	// Extract tar file using tar command with validated paths
	cmd := exec.Command("tar", "-xf", cleanTarPath, "-C", cleanDestDir)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to extract tar %s: %v, output: %s", cleanTarPath, err, string(output))
	}

	log.Debugf("Successfully extracted tar %s to directory %s", cleanTarPath, cleanDestDir)
	return nil
}

// getPlatformSuffix returns the expected image tag suffix for a platform.
func getPlatformSuffix(platform *specs.Platform) string {
	suffix := "-" + platform.Architecture
	if platform.Variant != "" {
		suffix += "-" + platform.Variant
	}
	return suffix
}

// createMixedOCILayout creates an OCI layout combining patched and preserved platforms.
func createMixedOCILayout(
	outputDir string,
	results []types.PatchResult,
	platformStates []llb.State,
	platformSpecs []specs.Platform,
	preservedPlatforms []types.PatchPlatform,
) error {
	log.Infof("Creating mixed OCI layout with %d patched platforms and %d preserved platforms", len(platformStates), len(preservedPlatforms))

	ctx := context.Background()

	// Step 1: Create OCI layouts for patched platforms
	var patchedManifests []map[string]interface{}
	allBlobs := make(map[string]bool) // Track all blobs to avoid duplicates

	if len(platformStates) > 0 {
		// Create temporary directory for patched platforms
		patchedTempDir, err := os.MkdirTemp("", "copa-patched-platforms-*")
		if err != nil {
			return fmt.Errorf("failed to create temp directory for patched platforms: %w", err)
		}
		defer os.RemoveAll(patchedTempDir)

		// Export patched platforms using BuildKit
		bkOpts := Opts{}
		c, err := NewClient(ctx, bkOpts)
		if err != nil {
			return fmt.Errorf("failed to create BuildKit client for mixed layout: %w", err)
		}
		defer c.Close()

		patchedManifests, err = exportPatchedPlatformsToTemp(ctx, c, patchedTempDir, platformStates, platformSpecs)
		if err != nil {
			return fmt.Errorf("failed to export patched platforms: %w", err)
		}

		// Copy patched platform blobs to final output directory
		if err := copyBlobsToOutput(outputDir, patchedTempDir, allBlobs); err != nil {
			return fmt.Errorf("failed to copy patched platform blobs: %w", err)
		}
	}

	// Step 2: Export preserved platforms from original image
	var preservedManifests []map[string]interface{}
	if len(preservedPlatforms) > 0 {
		// Find original image reference from results
		var originalRef reference.Named
		for _, result := range results {
			if result.OriginalRef != nil {
				originalRef = result.OriginalRef
				break
			}
		}

		if originalRef == nil {
			log.Warn("Could not determine original image reference for preserved platforms, skipping preserved platforms export")
		} else {
			var err error
			preservedManifests, err = exportPreservedPlatformsToOutput(outputDir, originalRef, preservedPlatforms, allBlobs)
			if err != nil {
				return fmt.Errorf("failed to export preserved platforms: %w", err)
			}
		}
	}

	// Step 3: Combine all manifests into final OCI layout
	patchedManifests = append(patchedManifests, preservedManifests...)

	if len(patchedManifests) == 0 {
		return fmt.Errorf("no manifests to include in mixed OCI layout")
	}

	return createFinalOCILayout(outputDir, patchedManifests)
}

// exportPatchedPlatformsToTemp exports patched platforms using BuildKit to a temporary directory.
func exportPatchedPlatformsToTemp(ctx context.Context, c *client.Client, tempDir string, platformStates []llb.State, platformSpecs []specs.Platform) ([]map[string]interface{}, error) {
	var manifests []map[string]interface{}

	// Export each platform to its own tar file
	for i, platformState := range platformStates {
		platformSpec := platformSpecs[i]
		platformTarPath := filepath.Join(tempDir, fmt.Sprintf("platform-%d.tar", i))

		// Create solve options with output function
		solveOpt := client.SolveOpt{
			Exports: []client.ExportEntry{{
				Type: client.ExporterOCI,
				Attrs: map[string]string{
					"oci-mediatypes": "true",
					"buildinfo":      "false",
				},
				Output: func(_ map[string]string) (io.WriteCloser, error) {
					return os.Create(platformTarPath)
				},
			}},
		}

		// Marshal and solve this platform's definition
		def, err := platformState.Marshal(ctx, llb.Platform(platformSpec))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal platform: %w", err)
		}

		_, err = c.Solve(ctx, def, solveOpt, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to solve platform: %w", err)
		}

		// Extract tar and read manifest
		platformExtractDir := filepath.Join(tempDir, fmt.Sprintf("extract-%d", i))
		if err := os.MkdirAll(platformExtractDir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create extraction directory: %w", err)
		}

		if err := extractTarToDirectory(platformTarPath, platformExtractDir); err != nil {
			return nil, fmt.Errorf("failed to extract platform tar: %w", err)
		}

		// Read the platform's index.json and extract manifest
		manifest, err := extractManifestFromOCI(platformExtractDir, &platformSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to extract manifest: %w", err)
		}

		manifests = append(manifests, manifest)
	}

	return manifests, nil
}

// copyBlobsToOutput copies all blobs from temporary directory to output directory.
func copyBlobsToOutput(outputDir, tempDir string, blobsSet map[string]bool) error {
	// Create output blobs directory
	outputBlobsDir := filepath.Join(outputDir, "blobs")
	if err := os.MkdirAll(outputBlobsDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output blobs directory: %w", err)
	}

	// Walk through temp directory to find all blobs directories
	return filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Look for blobs directories
		if info.IsDir() && info.Name() == "blobs" {
			return copyBlobs(path, outputBlobsDir, blobsSet)
		}

		return nil
	})
}

// exportPreservedPlatformsToOutput exports preserved platforms from original image to output directory.
func exportPreservedPlatformsToOutput(outputDir string, originalRef reference.Named, preservedPlatforms []types.PatchPlatform, blobsSet map[string]bool) ([]map[string]interface{}, error) {
	// Convert reference.Named to name.Reference for go-containerregistry
	ref, err := name.ParseReference(originalRef.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}

	// Try local daemon first, then fall back to remote
	desc, err := TryGetManifestFromLocal(ref)
	isLocal := (err == nil)
	if err != nil {
		log.Debugf("Failed to get descriptor from local daemon: %v, trying remote registry", err)
		desc, err = remote.Get(ref)
		if err != nil {
			return nil, fmt.Errorf("failed to get remote descriptor: %w", err)
		}
		log.Debugf("Successfully fetched descriptor from remote registry for preserved platforms")
	} else {
		log.Debugf("Successfully fetched descriptor from local daemon for preserved platforms")
	}

	var manifests []map[string]interface{}

	// Ensure blobs directory exists so we can materialize preserved platform content
	blobsDir := filepath.Join(outputDir, "blobs", "sha256")
	if err := os.MkdirAll(blobsDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create blobs directory for preserved platforms: %w", err)
	}

	// Helper to write a blob if we have not already written it (dedupe across platforms)
	writeBlobIfAbsent := func(hash v1.Hash, data []byte) error {
		relPath := filepath.Join("sha256", hash.Hex)
		if blobsSet[relPath] { // already written
			return nil
		}
		outPath := filepath.Join(outputDir, "blobs", relPath)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return fmt.Errorf("failed to create blob dir: %w", err)
		}
		if err := os.WriteFile(outPath, data, 0o600); err != nil {
			return fmt.Errorf("failed to write blob %s: %w", hash.String(), err)
		}
		blobsSet[relPath] = true
		log.Debugf("Wrote preserved blob %s", hash.String())
		return nil
	}

	// Helper to stream-copy a (potentially large) layer blob
	writeLayerIfAbsent := func(layer v1.Layer) error {
		ld, err := layer.Digest()
		if err != nil {
			return fmt.Errorf("failed to get layer digest: %w", err)
		}
		relPath := filepath.Join("sha256", ld.Hex)
		if blobsSet[relPath] { // already written
			return nil
		}
		rc, err := layer.Compressed()
		if err != nil {
			return fmt.Errorf("failed to read compressed layer %s: %w", ld.String(), err)
		}
		defer rc.Close()
		outPath := filepath.Join(outputDir, "blobs", relPath)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return fmt.Errorf("failed to create layer blob dir: %w", err)
		}
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("failed to create layer blob file %s: %w", outPath, err)
		}
		if _, err := io.Copy(f, rc); err != nil {
			f.Close()
			return fmt.Errorf("failed to copy layer blob %s: %w", ld.String(), err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to close layer blob file %s: %w", outPath, err)
		}
		blobsSet[relPath] = true
		log.Debugf("Wrote preserved layer %s", ld.String())
		return nil
	}

	// Check if it's a manifest list (multi-platform)
	if desc.MediaType == v1types.OCIImageIndex || desc.MediaType == v1types.DockerManifestList {
		// Parse the index
		idx, err := desc.ImageIndex()
		if err != nil {
			return nil, fmt.Errorf("failed to parse image index: %w", err)
		}

		// Get the index manifest
		manifest, err := idx.IndexManifest()
		if err != nil {
			return nil, fmt.Errorf("failed to get index manifest: %w", err)
		}

		// Filter manifests for the preserved platforms we want and materialize their blobs
		for _, platformSpec := range preservedPlatforms {
			for i := range manifest.Manifests {
				mdesc := &manifest.Manifests[i]
				if mdesc.Platform != nil &&
					mdesc.Platform.OS == platformSpec.OS &&
					mdesc.Platform.Architecture == platformSpec.Architecture {
					var img v1.Image

					// For local images, we need to fetch by digest using the daemon
					// For remote images, we can use idx.Image() which has proper remote context
					if isLocal {
						// Construct digest reference for this platform
						digestRef := fmt.Sprintf("%s@%s", originalRef.Name(), mdesc.Digest.String())
						platformRef, err := name.ParseReference(digestRef)
						if err != nil {
							return nil, fmt.Errorf("failed to parse platform digest reference: %w", err)
						}

						// Try to get from local daemon first
						platformDesc, err := TryGetManifestFromLocal(platformRef)
						if err != nil {
							// Fall back to remote if local fails
							img, err = remote.Image(platformRef)
							if err != nil {
								return nil, fmt.Errorf("failed to get image for preserved platform %s/%s: %w", platformSpec.OS, platformSpec.Architecture, err)
							}
						} else {
							img, err = platformDesc.Image()
							if err != nil {
								return nil, fmt.Errorf("failed to get image from local descriptor for preserved platform %s/%s: %w", platformSpec.OS, platformSpec.Architecture, err)
							}
						}
					} else {
						// Remote image - can use idx.Image() directly
						img, err = idx.Image(mdesc.Digest)
						if err != nil {
							return nil, fmt.Errorf("failed to get image for preserved platform %s/%s: %w", platformSpec.OS, platformSpec.Architecture, err)
						}
					}

					// Write manifest blob (raw bytes) so index reference is resolvable offline
					rawManifest, err := img.RawManifest()
					if err != nil {
						return nil, fmt.Errorf("failed to get raw manifest: %w", err)
					}
					if err := writeBlobIfAbsent(mdesc.Digest, rawManifest); err != nil {
						return nil, err
					}

					// Write config blob
					cfgHash, err := img.ConfigName()
					if err != nil {
						return nil, fmt.Errorf("failed to get config digest: %w", err)
					}
					rawConfig, err := img.RawConfigFile()
					if err != nil {
						return nil, fmt.Errorf("failed to get raw config: %w", err)
					}
					if err := writeBlobIfAbsent(cfgHash, rawConfig); err != nil {
						return nil, err
					}

					// Write layer blobs
					layers, err := img.Layers()
					if err != nil {
						return nil, fmt.Errorf("failed to get layers: %w", err)
					}
					for _, layer := range layers {
						if err := writeLayerIfAbsent(layer); err != nil {
							return nil, err
						}
					}

					// Create manifest entry for this preserved platform (index level descriptor)
					manifestEntry := map[string]interface{}{
						"mediaType": string(mdesc.MediaType),
						"digest":    mdesc.Digest.String(),
						"size":      mdesc.Size,
						"platform": map[string]interface{}{
							"os":           mdesc.Platform.OS,
							"architecture": mdesc.Platform.Architecture,
						},
					}
					if mdesc.Platform.Variant != "" {
						if platform, ok := manifestEntry["platform"].(map[string]interface{}); ok {
							platform["variant"] = mdesc.Platform.Variant
						}
					}
					manifests = append(manifests, manifestEntry)
					break
				}
			}
		}
	} else {
		// Single platform image
		// Materialize single-platform image blobs
		img, err := desc.Image()
		if err != nil {
			return nil, fmt.Errorf("failed to get single-platform image: %w", err)
		}

		// Write manifest
		rawManifest, err := img.RawManifest()
		if err != nil {
			return nil, fmt.Errorf("failed to get raw manifest: %w", err)
		}
		if err := writeBlobIfAbsent(desc.Digest, rawManifest); err != nil {
			return nil, err
		}

		// Write config
		cfgHash, err := img.ConfigName()
		if err != nil {
			return nil, fmt.Errorf("failed to get config digest: %w", err)
		}
		rawConfig, err := img.RawConfigFile()
		if err != nil {
			return nil, fmt.Errorf("failed to get raw config: %w", err)
		}
		if err := writeBlobIfAbsent(cfgHash, rawConfig); err != nil {
			return nil, err
		}

		// Write layers
		layers, err := img.Layers()
		if err != nil {
			return nil, fmt.Errorf("failed to get layers: %w", err)
		}
		for _, layer := range layers {
			if err := writeLayerIfAbsent(layer); err != nil {
				return nil, err
			}
		}

		platformEntry := map[string]interface{}{
			"mediaType": string(desc.MediaType),
			"digest":    desc.Digest.String(),
			"size":      desc.Size,
		}
		if len(preservedPlatforms) > 0 {
			platform := preservedPlatforms[0].Platform
			platformEntry["platform"] = map[string]interface{}{
				"os":           platform.OS,
				"architecture": platform.Architecture,
			}
			if platform.Variant != "" {
				if platformMap, ok := platformEntry["platform"].(map[string]interface{}); ok {
					platformMap["variant"] = platform.Variant
				}
			}
		}
		manifests = append(manifests, platformEntry)
	}

	log.Infof("Materialized %d preserved platform manifest(s) with blobs", len(manifests))

	return manifests, nil
}

// extractManifestFromOCI extracts manifest information from an OCI layout directory.
func extractManifestFromOCI(ociDir string, platformSpec *specs.Platform) (map[string]interface{}, error) {
	indexPath := filepath.Join(ociDir, "index.json")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read index.json: %w", err)
	}

	var index map[string]interface{}
	if err := json.Unmarshal(indexData, &index); err != nil {
		return nil, fmt.Errorf("failed to parse index.json: %w", err)
	}

	// Extract the first manifest and fix its platform information
	if manifests, ok := index["manifests"].([]interface{}); ok && len(manifests) > 0 {
		if manifestMap, ok := manifests[0].(map[string]interface{}); ok {
			// Set the correct platform information
			targetPlatform := map[string]interface{}{
				"os":           platformSpec.OS,
				"architecture": platformSpec.Architecture,
			}

			if platformSpec.Variant != "" {
				targetPlatform["variant"] = platformSpec.Variant
			}

			manifestMap["platform"] = targetPlatform
			return manifestMap, nil
		}
	}

	return nil, fmt.Errorf("no valid manifest found in OCI layout")
}

// createFinalOCILayout creates the final OCI layout with combined manifests.
func createFinalOCILayout(outputDir string, allManifests []map[string]interface{}) error {
	// Create output directory structure
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create oci-layout file
	ociLayoutContent := `{"imageLayoutVersion":"1.0.0"}`
	if err := os.WriteFile(filepath.Join(outputDir, "oci-layout"), []byte(ociLayoutContent), 0o600); err != nil {
		return fmt.Errorf("failed to write oci-layout: %w", err)
	}

	// Create the combined index.json with all manifests
	combinedIndex := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests":     allManifests,
	}

	indexJSON, err := json.MarshalIndent(combinedIndex, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal combined index: %w", err)
	}

	if err := os.WriteFile(filepath.Join(outputDir, "index.json"), indexJSON, 0o600); err != nil {
		return fmt.Errorf("failed to write combined index.json: %w", err)
	}

	log.Infof("Successfully created mixed OCI layout with %d platform manifests", len(allManifests))
	return nil
}

// createPreservedOnlyOCILayout creates an OCI layout from preserved platforms only.
func createPreservedOnlyOCILayout(outputDir string, results []types.PatchResult, preservedPlatforms []types.PatchPlatform) error {
	log.Infof("Creating OCI layout from %d preserved platforms only", len(preservedPlatforms))

	// Find the original image reference from results
	var originalRef reference.Named
	for _, result := range results {
		if result.OriginalRef != nil {
			originalRef = result.OriginalRef
			break
		}
	}

	if originalRef == nil {
		return fmt.Errorf("no original reference found for preserved-only layout")
	}

	// Use go-containerregistry to get the original manifest and export only needed platforms
	return exportOriginalImagePlatformsAsOCI(outputDir, originalRef, preservedPlatforms)
}

// exportOriginalImagePlatformsAsOCI uses go-containerregistry to export specific platforms.
func exportOriginalImagePlatformsAsOCI(outputDir string, originalRef reference.Named, platforms []types.PatchPlatform) error {
	log.Infof("Exporting %d platforms from original image %s using go-containerregistry", len(platforms), originalRef.String())

	// Convert reference.Named to name.Reference for go-containerregistry
	ref, err := name.ParseReference(originalRef.String())
	if err != nil {
		return fmt.Errorf("failed to parse reference: %w", err)
	}

	// Get the remote descriptor
	desc, err := remote.Get(ref)
	if err != nil {
		return fmt.Errorf("failed to get remote descriptor: %w", err)
	}

	// Check if it's a manifest list (multi-platform)
	if desc.MediaType == v1types.OCIImageIndex || desc.MediaType == v1types.DockerManifestList {
		// Parse the index
		idx, err := desc.ImageIndex()
		if err != nil {
			return fmt.Errorf("failed to parse image index: %w", err)
		}

		// Get the index manifest
		manifest, err := idx.IndexManifest()
		if err != nil {
			return fmt.Errorf("failed to get index manifest: %w", err)
		}

		// Create OCI layout structure
		if err := os.MkdirAll(filepath.Join(outputDir, "blobs", "sha256"), 0o755); err != nil {
			return fmt.Errorf("failed to create blobs directory: %w", err)
		}

		// Create oci-layout file
		ociLayoutContent := `{"imageLayoutVersion": "1.0.0"}`
		if err := os.WriteFile(filepath.Join(outputDir, "oci-layout"), []byte(ociLayoutContent), 0o600); err != nil {
			return fmt.Errorf("failed to write oci-layout file: %w", err)
		}

		// Filter manifests for the preserved platforms we want
		var preservedManifests []v1.Descriptor
		for _, platformSpec := range platforms {
			for i := range manifest.Manifests {
				desc := &manifest.Manifests[i]
				if desc.Platform != nil &&
					desc.Platform.OS == platformSpec.OS &&
					desc.Platform.Architecture == platformSpec.Architecture {
					preservedManifests = append(preservedManifests, *desc)
					log.Debugf("Including preserved platform %s/%s", desc.Platform.OS, desc.Platform.Architecture)
					break
				}
			}
		}

		// Create new index with only preserved platforms
		newIndex := &v1.IndexManifest{
			SchemaVersion: 2,
			Manifests:     preservedManifests,
		}

		// Write the index
		indexBytes, err := json.MarshalIndent(newIndex, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal index: %w", err)
		}

		if err := os.WriteFile(filepath.Join(outputDir, "index.json"), indexBytes, 0o600); err != nil {
			return fmt.Errorf("failed to write index.json: %w", err)
		}

		log.Infof("Successfully created OCI layout with %d preserved platforms", len(preservedManifests))
		return nil
	}

	// Single platform image - just create a simple index
	log.Info("Single platform image - creating simple index")
	singleIndex := &v1.IndexManifest{
		SchemaVersion: 2,
		Manifests: []v1.Descriptor{{
			MediaType: desc.MediaType,
			Digest:    desc.Digest,
			Size:      desc.Size,
		}},
	}

	// Create directory structure
	if err := os.MkdirAll(filepath.Join(outputDir, "blobs", "sha256"), 0o755); err != nil {
		return fmt.Errorf("failed to create blobs directory: %w", err)
	}

	// Write files
	ociLayoutContent := `{"imageLayoutVersion": "1.0.0"}`
	if err := os.WriteFile(filepath.Join(outputDir, "oci-layout"), []byte(ociLayoutContent), 0o600); err != nil {
		return fmt.Errorf("failed to write oci-layout file: %w", err)
	}

	indexBytes, err := json.MarshalIndent(singleIndex, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal single index: %w", err)
	}

	if err := os.WriteFile(filepath.Join(outputDir, "index.json"), indexBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write index.json: %w", err)
	}

	return nil
}
