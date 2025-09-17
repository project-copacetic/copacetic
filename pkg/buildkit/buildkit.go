package buildkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/containerd/platforms"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type Config struct {
	ImageName         string
	Client            gwclient.Client
	ConfigData        []byte
	PatchedConfigData []byte
	Platform          *ispec.Platform
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
	platform *ispec.Platform,
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
	// BaseImage or ispec.AnnotationBaseImageName
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
			Platform: ispec.Platform{
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

// This approach will not work for local images, add future support for this.
func DiscoverPlatformsFromReference(manifestRef string) ([]types.PatchPlatform, error) {
	var platforms []types.PatchPlatform

	ref, err := name.ParseReference(manifestRef)
	if err != nil {
		return nil, fmt.Errorf("error parsing reference %q: %w", manifestRef, err)
	}

	desc, err := remote.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("error fetching descriptor for %q: %w", manifestRef, err)
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
				Platform: ispec.Platform{
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
			Platform: ispec.Platform{
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
func PlatformKey(pl ispec.Platform) string {
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
			return nil, nil, "", err
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
