package buildkit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/docker/cli/cli/config"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	sourcepolicy "github.com/moby/buildkit/sourcepolicy/pb"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"

	"github.com/google/go-containerregistry/pkg/authn"
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
	SourceLineage     *types.SourceLineage
	// SourceLineageValidated is true when a supplied patched image carried a
	// patch origin tuple whose digest matches the original BuildKit actually selected.
	// Multi-platform callers use this to avoid treating an index digest as a
	// child-manifest digest when re-patching older Copa images.
	SourceLineageValidated bool
	Platform               *specs.Platform
	ImageState             llb.State
	PatchedImageState      llb.State
	// ImageLabels contains OCI labels from the image config (e.g. org.opencontainers.image.*).
	ImageLabels map[string]string
}

type Opts struct {
	Addr       string
	CACertPath string
	CertPath   string
	KeyPath    string
}

// OCILayoutExportOptions controls BuildKit OCI exporter behavior when writing
// patched platforms into an OCI image layout. Preserved platforms are copied
// from the original image as-is to keep their descriptors and layer blobs unchanged.
type OCILayoutExportOptions struct {
	Compression      string
	ForceCompression bool
	BuildkitOpts     *Opts
	Atomic           bool
	OutputReference  string
	IndexAnnotations map[string]string
	// PreservedSourceRef identifies the immutable current index whose
	// descriptors and blobs must be copied for untouched platforms.
	PreservedSourceRef reference.Canonical
	// SourcePolicy is the policy applied to the patch solve. Export re-solves
	// the patched states, so it must resolve their sources the same way.
	SourcePolicy *sourcepolicy.Policy
	state        *ociLayoutExportState
}

type ociLayoutExportState struct {
	sources []*ocilayout.Source
	context context.Context
}

// WithContext makes OCI export and source copying observe cancellation and
// timeouts from the patch operation.
func (opts OCILayoutExportOptions) WithContext(ctx context.Context) OCILayoutExportOptions {
	if ctx == nil {
		ctx = context.Background()
	}
	opts.state = &ociLayoutExportState{context: ctx}
	return opts
}

type platformExportMetadata struct {
	Config                []byte
	Annotations           map[string]string
	DescriptorAnnotations map[string]string
}

const (
	linux                       = "linux"
	arm64                       = "arm64"
	maxGatewayReadFileChunkSize = int64(8 << 20)
)

// for testing.
var (
	readDir                       = os.ReadDir
	readFile                      = os.ReadFile
	lookPath                      = exec.LookPath
	localImagePlatforms           = utils.LocalImagePlatforms
	localImageIndex               = utils.LocalImageIndex
	localImageStoreKeepsManifests = utils.LocalImageStoreKeepsManifests
	getRemoteImageDescriptor      = remote.Get
	getImageFromDaemon            = daemon.Image
	tryGetManifestFromLocal       = getManifestFromLocal
)

// ImageSource captures the immutable identity and, for indexes, the platform
// descriptors of one locally or remotely resolved image reference. A local
// mutable tag in an image store that keeps manifests is authoritative and is
// never replaced with same-named remote content.
type ImageSource struct {
	Name       string
	Descriptor specs.Descriptor
	Index      *specs.Index
	// Registry is true when the identity was read from a registry: the image
	// is not local, or the local store cannot provide its original manifests.
	Registry bool
}

// PlatformDescriptor returns the one image manifest matching platform.
func (source *ImageSource) PlatformDescriptor(platform *specs.Platform) (*specs.Descriptor, error) {
	if source == nil || source.Index == nil {
		return nil, errors.New("image source is not an index")
	}
	if platform == nil {
		return nil, errors.New("platform is nil")
	}

	target := platforms.Normalize(*platform)
	var matched *specs.Descriptor
	for i := range source.Index.Manifests {
		descriptor := &source.Index.Manifests[i]
		if descriptor.Platform == nil || !platformIdentityEqual(descriptor.Platform, &target) {
			continue
		}
		if matched != nil {
			return nil, fmt.Errorf("image index contains multiple descriptors for platform %s", platforms.Format(target))
		}
		copy := *descriptor
		matched = &copy
	}
	if matched == nil {
		return nil, fmt.Errorf("image index contains no descriptor for platform %s", platforms.Format(target))
	}
	return matched, nil
}

// ResolveImageSource resolves top-level and platform descriptor identity using
// the same local-first policy as Copa's platform discovery. The returned top
// digest is the daemon's source descriptor digest, not a digest recomputed from
// a possibly incomplete locally reconstructed index. A classic Docker image
// store keeps no manifests, so its images are identified from the registry
// content that a supported builder actually reads.
func ResolveImageSource(ctx context.Context, imageRef string) (*ImageSource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	named, err := reference.ParseNormalizedNamed(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parse image reference %q: %w", imageRef, err)
	}
	if reference.IsNameOnly(named) {
		named = reference.TagNameOnly(named)
	}
	ref, err := name.ParseReference(named.String())
	if err != nil {
		return nil, fmt.Errorf("parse normalized image reference %q: %w", named.String(), err)
	}

	descriptor, sourceDigest, complete, localErr := tryGetManifestFromLocal(ctx, ref)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if localErr == nil && descriptor != nil && complete && sourceDigest.Algorithm == "" && sourceDigest.Hex == "" {
		// A classic Docker image store found the image but can only
		// reconstruct its manifest. Supported builders cannot read that store
		// and patch the registry content, so capture the registry identity.
		log.Debugf("Local daemon cannot provide the original manifest of %s; resolving its identity from the registry", named.String())
		localErr = errLocalManifestUnavailable
	}
	if localErr == nil {
		if descriptor == nil {
			return nil, fmt.Errorf("local daemon returned no descriptor for %q", named.String())
		}
		if sourceDigest.Algorithm == "" || sourceDigest.Hex == "" {
			return nil, fmt.Errorf("local source descriptor digest is unavailable for %q", named.String())
		}
		immutable, isImmutable := ref.(name.Digest)
		if isImmutable {
			if sourceDigest.String() != immutable.DigestStr() {
				return nil, fmt.Errorf("local source descriptor digest %s does not match immutable reference %s", sourceDigest.String(), immutable.DigestStr())
			}
		}
		if !complete {
			sourceRef := ref.Context().Digest(sourceDigest.String())
			descriptor, err = GetVerifiedRemoteIndexWithContext(ctx, sourceRef)
			if err != nil {
				return nil, fmt.Errorf("reconcile incomplete local image index %q: %w", named.String(), err)
			}
			return imageSourceFromRemoteDescriptor(named.String(), descriptor)
		}
		if isImmutable {
			if descriptor.MediaType.IsIndex() {
				descriptor.Digest = sourceDigest
				return imageSourceFromRemoteDescriptor(named.String(), descriptor)
			}
			// Docker save can reconstruct different manifest bytes, and a daemon
			// can expose a child of an immutable index. Verify the exact source
			// descriptor without assuming that either mismatch denotes an index.
			if descriptor.Digest.String() != sourceDigest.String() {
				descriptor, err = getVerifiedRemoteDescriptor(ctx, immutable)
				if err != nil {
					return nil, fmt.Errorf("resolve immutable source descriptor %q: %w", named.String(), err)
				}
				return imageSourceFromRemoteDescriptor(named.String(), descriptor)
			}
		}

		descriptor.Digest = sourceDigest
		return imageSourceFromRemoteDescriptor(named.String(), descriptor)
	}
	var archiveErr *localArchiveError
	if errors.As(localErr, &archiveErr) {
		return nil, archiveErr
	}
	log.Debugf("Failed to resolve image source %s from local daemon: %v", named.String(), localErr)

	descriptor, err = getRemoteImageDescriptor(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("resolve image source %q remotely: %w", named.String(), err)
	}
	if descriptor == nil {
		return nil, fmt.Errorf("registry returned no descriptor for %q", named.String())
	}
	source, err := imageSourceFromRemoteDescriptor(named.String(), descriptor)
	if err != nil {
		return nil, err
	}
	source.Registry = true
	return source, nil
}

func imageSourceFromRemoteDescriptor(sourceName string, descriptor *remote.Descriptor) (*ImageSource, error) {
	if descriptor == nil || descriptor.Digest.Algorithm == "" || descriptor.Digest.Hex == "" {
		return nil, fmt.Errorf("source descriptor digest is unavailable for %q", sourceName)
	}
	source := &ImageSource{
		Name: sourceName,
		Descriptor: specs.Descriptor{
			MediaType:   string(descriptor.MediaType),
			Digest:      digest.Digest(descriptor.Digest.String()),
			Size:        descriptor.Size,
			URLs:        slices.Clone(descriptor.URLs),
			Annotations: maps.Clone(descriptor.Annotations),
		},
	}
	if !descriptor.MediaType.IsIndex() {
		return source, nil
	}

	var index specs.Index
	if err := json.Unmarshal(descriptor.Manifest, &index); err != nil {
		return nil, fmt.Errorf("parse source image index %q: %w", sourceName, err)
	}
	source.Index = &index
	return source, nil
}

// GetVerifiedRemoteIndex fetches an image index through an immutable digest
// reference and verifies that the registry returned that exact index. Callers
// must not use this helper with mutable tags when reconciling local images with
// remote metadata.
func GetVerifiedRemoteIndex(ref name.Digest) (*remote.Descriptor, error) {
	return GetVerifiedRemoteIndexWithContext(context.Background(), ref)
}

// GetVerifiedRemoteIndexWithContext fetches and verifies an immutable index while honoring cancellation.
func GetVerifiedRemoteIndexWithContext(ctx context.Context, ref name.Digest) (*remote.Descriptor, error) {
	desc, err := getVerifiedRemoteDescriptor(ctx, ref)
	if err != nil {
		return nil, err
	}
	if !desc.MediaType.IsIndex() {
		return nil, fmt.Errorf("remote descriptor for %q is not an image index", ref.String())
	}
	return desc, nil
}

func getVerifiedRemoteDescriptor(ctx context.Context, ref name.Digest) (*remote.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	desc, err := getRemoteImageDescriptor(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("fetch remote descriptor for %q: %w", ref.String(), err)
	}
	if desc == nil {
		return nil, fmt.Errorf("registry returned no descriptor for %q", ref.String())
	}
	if !desc.MediaType.IsIndex() && !desc.MediaType.IsImage() {
		return nil, fmt.Errorf("remote descriptor for %q is not an image or index", ref.String())
	}
	if desc.Digest.String() != ref.DigestStr() {
		return nil, fmt.Errorf(
			"remote descriptor digest %s does not match immutable reference %s",
			desc.Digest.String(), ref.DigestStr(),
		)
	}
	return desc, nil
}

func InitializeBuildkitConfig(
	ctx context.Context,
	c gwclient.Client,
	userImage string,
	platform *specs.Platform,
) (*Config, error) {
	return InitializeBuildkitConfigWithBaseImage(ctx, c, userImage, userImage, platform)
}

// InitializeBuildkitConfigWithBaseImage reads the image through userImage,
// which may be a digest-pinned child. The first-patch BaseImage label keeps
// baseImageLocator unless a source policy selects a different image. Older
// Copa versions use that label to find the image to rebuild from.
func InitializeBuildkitConfigWithBaseImage(
	ctx context.Context,
	c gwclient.Client,
	userImage string,
	baseImageLocator string,
	platform *specs.Platform,
) (*Config, error) {
	return InitializeBuildkitConfigWithSource(ctx, c, userImage, baseImageLocator, platform, nil)
}

// InitializeBuildkitConfigWithSource initializes the patch state from either
// the existing named-image path or an explicitly selected OCI layout source.
func InitializeBuildkitConfigWithSource(
	ctx context.Context,
	c gwclient.Client,
	userImage string,
	baseImageLocator string,
	platform *specs.Platform,
	source *ocilayout.Source,
) (*Config, error) {
	if source != nil {
		return initializeOCISourceConfig(ctx, c, userImage, platform, source)
	}
	if baseImageLocator == "" {
		baseImageLocator = userImage
	}
	// Initialize buildkit config for the target image
	config := Config{
		ImageName: userImage,
		Platform:  platform,
	}

	// Use the source metadata API so resolve mode survives gateway transport.
	// BuildKit's legacy ResolveImageConfig adapter can drop prefer-local mode.
	resolver := &gatewayImageResolver{ImageMetaResolver: sourceresolver.NewImageMetaResolver(c), client: c}
	// Resolve and pull the config for the target image
	resolveOpt := sourceresolver.Opt{
		ImageOpt: &sourceresolver.ResolveImageOpt{
			ResolveMode: llb.ResolveModePreferLocal.String(),
		},
	}
	if platform != nil {
		resolveOpt.ImageOpt.Platform = platform
	}
	resolvedUserImage, userImageDigest, configData, err := resolver.ResolveImageConfig(ctx, userImage, resolveOpt)
	if err != nil {
		return nil, err
	}
	requested, err := reference.ParseNormalizedNamed(userImage)
	if err != nil {
		return nil, err
	}
	selected, err := reference.ParseNormalizedNamed(resolvedUserImage)
	if err != nil {
		return nil, fmt.Errorf("parse resolved image reference: %w", err)
	}
	// A source policy may select another repository or tag. Use that source
	// for content and lineage, without mistaking ordinary name normalization
	// for a conversion that replaces the caller's BaseImage locator.
	if reference.TagNameOnly(requested).String() != reference.TagNameOnly(selected).String() {
		baseImageLocator = selected.String()
	}

	var baseImage string
	config.ConfigData, config.PatchedConfigData, baseImage, config.SourceLineage, config.SourceLineageValidated, err = updateImageConfigData(
		ctx,
		resolver,
		configData,
		selected.String(),
		baseImageLocator,
		userImageDigest,
		platform,
	)
	if err != nil {
		return nil, err
	}

	// Load the target image state with the resolved image config in case environment variable settings
	// are necessary for running apps in the target image for updates
	imageOpts := []llb.ImageOption{
		llb.ResolveModePreferLocal,
		llb.WithMetaResolver(resolver),
	}
	if platform != nil {
		imageOpts = append(imageOpts, llb.Platform(*platform))
	}
	baseSource := baseImage
	if config.SourceLineage.Valid() {
		baseSource, err = resolvedImageReference(baseImage, config.SourceLineage.Digest)
		if err != nil {
			return nil, err
		}
	}
	config.ImageState, err = llb.Image(baseSource, imageOpts...).WithImageConfig(config.ConfigData)
	if err != nil {
		return nil, err
	}

	// Only set PatchedImageState if the user supplied a patched image
	// BaseImage identifies a Copa patch. Application-owned OCI base annotations
	// do not identify Copa patches.
	if config.PatchedConfigData != nil {
		patchedImageOpts := []llb.ImageOption{
			llb.ResolveModePreferLocal,
			llb.WithMetaResolver(resolver),
		}
		if platform != nil {
			patchedImageOpts = append(patchedImageOpts, llb.Platform(*platform))
		}
		patchedSource, err := resolvedImageReference(selected.String(), userImageDigest)
		if err != nil {
			return nil, err
		}
		config.PatchedImageState, err = llb.Image(patchedSource, patchedImageOpts...).WithImageConfig(config.PatchedConfigData)
		if err != nil {
			return nil, err
		}
	}

	config.Client = c

	// Extract OCI labels from image config for use by language managers
	// (e.g. org.opencontainers.image.revision for Go binary source cloning).
	config.ImageLabels = extractLabelsFromConfig(configData)

	return &config, nil
}

// initializeOCISourceConfig reads the image from an OCI layout source. The
// layout is the complete source of truth, including any layers from a previous
// Copa patch. Treat that complete local state as the new base so a recorded
// BaseImage label cannot trigger a registry lookup.
func initializeOCISourceConfig(
	ctx context.Context,
	c gwclient.Client,
	userImage string,
	platform *specs.Platform,
	source *ocilayout.Source,
) (*Config, error) {
	config := Config{
		ImageName: userImage,
		Platform:  platform,
	}
	configData, err := source.ResolveImageConfig(ctx, c, platform)
	if err != nil {
		return nil, err
	}
	if _, config.ConfigData, err = setupLabels(userImage, configData); err != nil {
		return nil, err
	}
	config.ImageState, err = source.State(ctx, platform, config.ConfigData)
	if err != nil {
		return nil, err
	}
	config.Client = c
	config.ImageLabels = extractLabelsFromConfig(configData)
	return &config, nil
}

// Config resolution does not pin llb.Image's source operation. Keep the
// original locator in labels, but read content through its verified digest so
// a later tag move cannot change the image being patched.
func resolvedImageReference(image string, resolved digest.Digest) (string, error) {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return "", err
	}
	pinned, err := reference.WithDigest(reference.TrimNamed(named), resolved)
	if err != nil {
		return "", fmt.Errorf("pin resolved image %s: %w", image, err)
	}
	return pinned.String(), nil
}

// extractLabelsFromConfig parses OCI image config JSON and returns the labels map.
func extractLabelsFromConfig(configData []byte) map[string]string {
	var parsed struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(configData, &parsed); err != nil {
		return nil
	}
	return parsed.Config.Labels
}

func DiscoverPlatformsFromReport(reportDir, scanner string) ([]types.PatchPlatform, error) {
	return discoverPlatformsFromReport(reportDir, scanner, false)
}

// DiscoverPlatformsFromReportStrict rejects reports that ordinary named-image
// discovery skips. OCI input must not silently preserve a requested target.
func DiscoverPlatformsFromReportStrict(reportDir, scanner string) ([]types.PatchPlatform, error) {
	return discoverPlatformsFromReport(reportDir, scanner, true)
}

func discoverPlatformsFromReport(reportDir, scanner string, strict bool) ([]types.PatchPlatform, error) {
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
		supported := isSupportedOsType(report.Metadata.OS.Type)
		if strict {
			supported = IsSupportedOSType(report.Metadata.OS.Type)
		}
		if !supported {
			if strict {
				return nil, fmt.Errorf("unsupported scan report OS %q in report %s", report.Metadata.OS.Type, filePath)
			}
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

// IsSupportedOSType reports whether a scan report's OS family is one a Copa
// package manager can patch. Strict report discovery and single OCI reports
// use it. Non-strict discovery keeps its narrower isSupportedOsType list,
// which omits Arch Linux.
func IsSupportedOSType(osType string) bool {
	return isSupportedOsType(osType) || utils.CanonicalOSType(osType) == utils.OSTypeArchLinux
}

func isSupportedOsType(osType string) bool {
	switch utils.CanonicalOSType(osType) {
	case utils.OSTypeAlpine,
		utils.OSTypeDebian,
		utils.OSTypeUbuntu,
		utils.OSTypeCBLMariner,
		utils.OSTypeAzureLinux,
		utils.OSTypeCentOS,
		utils.OSTypeOracle,
		utils.OSTypeRedHat,
		utils.OSTypeRocky,
		utils.OSTypeFedora,
		utils.OSTypeAmazon,
		utils.OSTypeAlma,
		utils.OSTypeAlmaLinux,
		utils.OSTypeSLES,
		utils.OSTypeOpenSUSELeap,
		utils.OSTypeOpenSUSETW:
		return true
	default:
		return false
	}
}

// TryGetManifestFromLocal attempts to get manifest data from the local Docker daemon.
// It returns a remote.Descriptor if successful, or an error if the manifest cannot be retrieved locally.
// This is exported to support patching images that exist locally but not in a remote registry.
func TryGetManifestFromLocal(ref name.Reference) (*remote.Descriptor, error) {
	return TryGetManifestFromLocalWithContext(context.Background(), ref)
}

// TryGetManifestFromLocalWithContext reads local manifest metadata while honoring cancellation.
func TryGetManifestFromLocalWithContext(ctx context.Context, ref name.Reference) (*remote.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	descriptor, _, _, err := getManifestFromLocal(ctx, ref)
	return descriptor, err
}

func getManifestFromLocal(ctx context.Context, ref name.Reference) (*remote.Descriptor, v1.Hash, bool, error) {
	imageName := ref.String()
	log.Debugf("Attempting to get manifest from local daemon for %s", imageName)

	index, localDescriptor, complete, found, err := localImageIndex(ctx, imageName)
	if err != nil {
		return nil, v1.Hash{}, false, fmt.Errorf("failed to inspect image in local daemon: %w", err)
	}
	if !found {
		return nil, v1.Hash{}, false, fmt.Errorf("image %q was not found in the local daemon", imageName)
	}
	if index != nil {
		rawManifest, err := json.Marshal(index)
		if err != nil {
			return nil, v1.Hash{}, false, fmt.Errorf("marshal local image index: %w", err)
		}
		manifestSum := sha256.Sum256(rawManifest)
		manifestDigest := v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", manifestSum)}
		sourceDigest := manifestDigest
		if !complete {
			sourceDigest = v1.Hash{}
		}
		if localDescriptor != nil && localDescriptor.Digest != "" {
			sourceDigest, err = v1.NewHash(localDescriptor.Digest.String())
			if err != nil {
				return nil, v1.Hash{}, false, fmt.Errorf("parse local image index digest: %w", err)
			}
		}
		descriptor := v1.Descriptor{
			MediaType:   v1types.MediaType(index.MediaType),
			Size:        int64(len(rawManifest)),
			Digest:      manifestDigest,
			Annotations: index.Annotations,
		}
		return &remote.Descriptor{Descriptor: descriptor, Manifest: rawManifest}, sourceDigest, complete, nil
	}

	// Docker's classic graph-driver store has no descriptor and keeps no
	// manifests. Its `docker save` index and go-containerregistry's daemon
	// image both describe reconstructed manifests that no registry has served,
	// so they can describe local content but cannot identify a source.
	keepsManifests := localDescriptor != nil
	if localDescriptor == nil {
		keepsManifests, err = localImageStoreKeepsManifests(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, v1.Hash{}, false, ctxErr
			}
			log.Debugf("Could not determine whether the local image store keeps manifests: %v", err)
			keepsManifests = false
		}
	}

	if localDescriptor == nil && keepsManifests {
		descriptor, err := localArchiveDescriptor(ctx, imageName)
		if err != nil {
			return nil, v1.Hash{}, false, &localArchiveError{fmt.Errorf("read original local source manifest: %w", err)}
		}
		if descriptor != nil {
			// Unlike inspection's partial reconstruction, a containerd-store
			// archive contains the full original index metadata even when some
			// blobs are absent.
			return descriptor, descriptor.Digest, true, nil
		}
	}

	img, err := getImageFromDaemon(ref, daemon.WithContext(ctx))
	if err != nil {
		return nil, v1.Hash{}, false, fmt.Errorf("failed to get image from local daemon: %w", err)
	}
	rawManifest, err := img.RawManifest()
	if err != nil {
		return nil, v1.Hash{}, false, fmt.Errorf("failed to get raw local manifest: %w", err)
	}
	mediaType, err := img.MediaType()
	if err != nil {
		return nil, v1.Hash{}, false, fmt.Errorf("failed to get local manifest media type: %w", err)
	}
	digest, err := img.Digest()
	if err != nil {
		return nil, v1.Hash{}, false, fmt.Errorf("failed to get local manifest digest: %w", err)
	}
	sourceDigest := digest
	if localDescriptor != nil && localDescriptor.Digest != "" {
		sourceDigest, err = v1.NewHash(localDescriptor.Digest.String())
		if err != nil {
			return nil, v1.Hash{}, false, fmt.Errorf("parse local source descriptor digest: %w", err)
		}
	} else if !keepsManifests {
		// A complete result with no source digest tells ResolveImageSource
		// that this local manifest is a reconstruction, not an identity.
		sourceDigest = v1.Hash{}
	}
	return &remote.Descriptor{
		Descriptor: v1.Descriptor{MediaType: mediaType, Size: int64(len(rawManifest)), Digest: digest},
		Manifest:   rawManifest,
	}, sourceDigest, complete, nil
}

// platformsFromIndexManifest converts the entries of a multi-platform image
// index into the platforms copa can patch. Entries without a platform (for
// example attestation or provenance entries) or with an unknown platform are
// skipped, since an image index can legitimately contain them.
func platformsFromIndexManifest(manifest *v1.IndexManifest) []types.PatchPlatform {
	var platforms []types.PatchPlatform
	for i := range manifest.Manifests {
		m := &manifest.Manifests[i]

		// Skip manifests with no platform (e.g. attestation or provenance
		// entries). Reading m.Platform below would otherwise panic.
		if m.Platform == nil {
			log.Debugf("Skipping manifest with no platform")
			continue
		}
		if m.Platform.OS == "unknown" || m.Platform.Architecture == "unknown" {
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
	return platforms
}

// DiscoverPlatformsFromReference discovers platforms from both local and remote manifests.
// It first attempts to inspect the manifest locally using Docker API
// to get raw manifest data and determine if it's multi-platform.
// If local inspection fails, it falls back to remote registry inspection.
// This allows Copa to patch multi-platform manifests that exist locally but not in the registry.
func DiscoverPlatformsFromReference(manifestRef string) ([]types.PatchPlatform, error) {
	return DiscoverPlatformsFromReferenceWithContext(context.Background(), manifestRef)
}

// DiscoverPlatformsFromReferenceWithContext discovers platforms while honoring cancellation of local and remote lookups.
func DiscoverPlatformsFromReferenceWithContext(ctx context.Context, manifestRef string) ([]types.PatchPlatform, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var platforms []types.PatchPlatform

	ref, err := name.ParseReference(manifestRef)
	if err != nil {
		return nil, fmt.Errorf("error parsing reference %q: %w", manifestRef, err)
	}

	// Prefer the local image store. Mutable tags and local references may name a
	// different image remotely, so a successful local lookup is authoritative.
	// For immutable digest references only, a daemon may expose just the host
	// child of the referenced remote index; reconcile that single local platform
	// with a remote index only after confirming the descriptor digest matches.
	var desc *remote.Descriptor
	if locals, ok, localErr := localImagePlatforms(ctx, manifestRef); ok {
		if len(locals) == 0 {
			return nil, fmt.Errorf("image %q found in local daemon but no usable platforms could be discovered", manifestRef)
		}
		log.Debugf("Discovered %d platform(s) from local daemon for %s", len(locals), manifestRef)
		for _, p := range locals {
			patchPlatform := types.PatchPlatform{
				Platform: specs.Platform{
					OS:           p.OS,
					Architecture: p.Architecture,
					Variant:      p.Variant,
					OSVersion:    p.OSVersion,
					OSFeatures:   p.OSFeatures,
				},
			}
			if patchPlatform.Architecture == arm64 && patchPlatform.Variant == "v8" {
				patchPlatform.Variant = ""
			}
			platforms = append(platforms, patchPlatform)
		}
		if len(platforms) > 1 {
			return platforms, nil
		}

		digestRef, immutable := ref.(name.Digest)
		if !immutable {
			return platforms, nil
		}

		remoteDesc, remoteErr := GetVerifiedRemoteIndexWithContext(ctx, digestRef)
		if remoteErr != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			log.Debugf("Remote platform discovery failed for locally cached %s: %v", manifestRef, remoteErr)
			return platforms, nil
		}
		log.Debugf("Locally cached child masks the matching remote index for %s; using remote platform list", manifestRef)
		desc = remoteDesc
	} else {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if localErr != nil {
			log.Debugf("Local platform discovery failed for %s: %v", manifestRef, localErr)
		}

		// Try the legacy local daemon manifest path, then fall back to the remote registry.
		var err error
		desc, _, _, err = tryGetManifestFromLocal(ctx, ref)
		if err != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			log.Debugf("Failed to get manifest list from local daemon: %v", err)
			log.Debugf("Falling back to remote registry for %s", manifestRef)
			desc, err = getRemoteImageDescriptor(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
			if err != nil {
				return nil, fmt.Errorf("error fetching descriptor for %q from both local daemon and remote registry: %w", manifestRef, err)
			}
			log.Debugf("Successfully fetched descriptor from remote registry for %s", manifestRef)
		} else {
			log.Debugf("Successfully fetched descriptor from local daemon for %s", manifestRef)
		}
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

		return platformsFromIndexManifest(manifest), nil
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

// PlatformKey encodes the complete normalized identity for map lookups.
// Display labels must use FormatPlatform instead.
//
//nolint:gocritic
func PlatformKey(pl specs.Platform) string {
	encoded, _ := json.Marshal(platforms.Normalize(pl))
	return string(encoded)
}

// FormatPlatform returns a readable platform label for logs and summaries.
//
//nolint:gocritic
func FormatPlatform(pl specs.Platform) string {
	pl = platforms.Normalize(pl)
	key := pl.OS + "/" + pl.Architecture
	if pl.Variant != "" {
		key += "/" + pl.Variant
	}
	// Include OS version for platforms like Windows that have multiple versions
	if pl.OSVersion != "" {
		key += "@" + pl.OSVersion
	}
	if len(pl.OSFeatures) > 0 {
		features, _ := json.Marshal(pl.OSFeatures)
		key += "+" + string(features)
	}
	return key
}

// reportPlatformKey uses the fields supplied by scanner reports. Complete
// platform keys remain necessary for result and descriptor association.
func reportPlatformKey(pl *specs.Platform) string {
	return PlatformKey(specs.Platform{OS: pl.OS, Architecture: pl.Architecture, Variant: pl.Variant})
}

func DiscoverPlatforms(manifestRef, reportDir, scanner string) ([]types.PatchPlatform, error) {
	return DiscoverPlatformsWithContext(context.Background(), manifestRef, reportDir, scanner)
}

// DiscoverPlatformsWithContext discovers source platforms with cancellation and associates scanner reports.
func DiscoverPlatformsWithContext(ctx context.Context, manifestRef, reportDir, scanner string) ([]types.PatchPlatform, error) {
	var platforms []types.PatchPlatform

	p, err := DiscoverPlatformsFromReferenceWithContext(ctx, manifestRef)
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
			key := reportPlatformKey(&pl.Platform)
			if _, exists := reportSet[key]; exists {
				return nil, fmt.Errorf("multiple reports target platform %s", FormatPlatform(specs.Platform{OS: pl.OS, Architecture: pl.Architecture, Variant: pl.Variant}))
			}
			reportSet[key] = pl.ReportFile
		}

		matchCounts := make(map[string]int, len(p))
		for _, pl := range p {
			matchCounts[reportPlatformKey(&pl.Platform)]++
		}

		for _, pl := range p {
			key := reportPlatformKey(&pl.Platform)
			if rp, ok := reportSet[key]; ok {
				if matchCounts[key] != 1 {
					return nil, fmt.Errorf("report %s matches %d image platforms for %s", rp, matchCounts[key], FormatPlatform(specs.Platform{OS: pl.OS, Architecture: pl.Architecture, Variant: pl.Variant}))
				}
				// Platform has a report - will be patched
				pl.ReportFile = rp
				pl.ShouldPreserve = false
				platforms = append(platforms, pl)
			} else {
				// Platform has no report - preserve original without patching
				log.Debugf("No report found for platform %s, preserving original", FormatPlatform(pl.Platform))
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
	return GetPlatformImageReferenceWithContext(context.Background(), manifestRef, targetPlatform)
}

// GetPlatformImageReferenceWithContext resolves a local platform reference while honoring cancellation.
func GetPlatformImageReferenceWithContext(ctx context.Context, manifestRef string, targetPlatform *specs.Platform) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	ref, err := name.ParseReference(manifestRef)
	if err != nil {
		return "", fmt.Errorf("error parsing reference %q: %w", manifestRef, err)
	}

	// Try to get the local manifest first
	desc, _, _, err := tryGetManifestFromLocal(ctx, ref)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		// Not a local manifest, return original reference
		return manifestRef, nil
	}

	if !desc.MediaType.IsIndex() {
		// Single platform image, return original reference
		return manifestRef, nil
	}

	return platformImageReferenceFromManifest(ref, desc.Manifest, targetPlatform)
}

func platformImageReferenceFromManifest(ref name.Reference, manifestBytes []byte, targetPlatform *specs.Platform) (string, error) {
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

	if err := json.Unmarshal(manifestBytes, &manifestData); err != nil {
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

func updateImageConfigData(
	ctx context.Context,
	c sourceresolver.ImageMetaResolver,
	configData []byte,
	image string,
	locator string,
	imageDigest digest.Digest,
	platform *specs.Platform,
) ([]byte, []byte, string, *types.SourceLineage, bool, error) {
	document, err := parseImageConfigLabels(configData)
	if err != nil {
		return nil, nil, "", nil, false, err
	}
	// BaseImage records the supplied locator; content reads use image.
	baseImage, userImageConfig, err := setupLabels(locator, configData)
	if err != nil {
		return nil, nil, "", nil, false, err
	}
	_, hasKind := document.labels[types.AnnotationPatchOriginKind]
	_, hasName := document.labels[types.AnnotationPatchOriginName]
	_, hasDigest := document.labels[types.AnnotationPatchOriginDigest]
	hasOrigin := hasKind || hasName || hasDigest
	recorded := sourceLineageFromConfig(configData)
	if hasOrigin && (!recorded.Valid() || baseImage == "") {
		return nil, nil, "", nil, false, fmt.Errorf("%w: invalid patch origin metadata: a complete origin and BaseImage locator are required", ErrOriginIntegrity)
	}
	if baseImage == "" {
		return userImageConfig, nil, image, newSourceLineage(image, imageDigest), false, nil
	}
	resolveOpt := sourceresolver.Opt{ImageOpt: &sourceresolver.ResolveImageOpt{
		ResolveMode: llb.ResolveModePreferLocal.String(), Platform: platform,
	}}
	var baseConfig []byte
	if hasOrigin {
		// Keep the recorded BaseImage locator for the output label. Reads of the
		// recovered original are pinned to its recorded digest by the caller.
		_, _, baseConfig, err = resolveRecordedOrigin(ctx, c, baseImage, recorded, resolveOpt)
		if err != nil {
			// A sibling failure may cancel recovery without invalidating the origin.
			if contextErr := ctx.Err(); contextErr != nil {
				return nil, nil, "", nil, false, contextErr
			}
			return nil, nil, "", nil, false, fmt.Errorf("%w: cannot recover recorded patch origin; restore the original image before re-patching: %w", ErrOriginIntegrity, err)
		}
		baseDocument, parseErr := parseImageConfigLabels(baseConfig)
		if parseErr != nil {
			return nil, nil, "", nil, false, fmt.Errorf("%w: parse recorded patch origin config: %w", ErrOriginIntegrity, parseErr)
		}
		if baseDocument.labels["BaseImage"] != "" {
			return nil, nil, "", nil, false, fmt.Errorf("%w: recorded patch origin is itself a Copa-patched image", ErrOriginIntegrity)
		}
		if err := verifyRecoveredOriginPlatform(configData, baseConfig, platform); err != nil {
			return nil, nil, "", nil, false, fmt.Errorf("%w: %w", ErrOriginIntegrity, err)
		}
	} else {
		// Legacy images have only a mutable BaseImage locator. Preserve their
		// existing best-effort behavior without asserting verified original identity.
		_, _, baseConfig, err = c.ResolveImageConfig(ctx, baseImage, resolveOpt)
		if err != nil {
			log.Warnf("Failed to resolve legacy BaseImage %s: %v. Falling back to current image %s without verified patch origin", baseImage, err, image)
			document.labels["BaseImage"] = locator
			fallback, marshalErr := document.marshal()
			return fallback, nil, image, nil, false, marshalErr
		}
		log.Warn("Re-patching a legacy BaseImage-only image without verified patch origin")
	}
	_, baseWithLabels, err := setupLabels(baseImage, baseConfig)
	if err != nil {
		return nil, nil, "", nil, false, err
	}
	return baseWithLabels, userImageConfig, baseImage, recorded, hasOrigin, nil
}

// verifyRecoveredOriginPlatform rejects a recovered origin built for a different
// platform than the image being re-patched. The recorded digest establishes
// content identity only: a single-platform manifest resolves regardless of the
// requested platform, so metadata naming another platform's manifest would
// otherwise rebuild the patch on a foreign root filesystem. An origin that
// cannot be compared with any platform is rejected rather than trusted.
func verifyRecoveredOriginPlatform(inputConfig, originConfig []byte, requested *specs.Platform) error {
	var input, origin specs.Platform
	if err := json.Unmarshal(inputConfig, &input); err != nil {
		return fmt.Errorf("parse patched image platform: %w", err)
	}
	inputDeclared := input.OS != "" && input.Architecture != ""
	if !inputDeclared && requested == nil {
		return errors.New("cannot verify recorded patch origin platform: the patched image config does not declare its platform and no target platform was requested")
	}
	if err := json.Unmarshal(originConfig, &origin); err != nil {
		return fmt.Errorf("parse recorded patch origin platform: %w", err)
	}
	if origin.OS == "" || origin.Architecture == "" {
		return errors.New("recorded patch origin config does not declare its platform")
	}
	if inputDeclared && !platformIdentityEqual(&origin, &input) {
		return fmt.Errorf("recorded patch origin platform %s does not match patched image platform %s",
			platforms.FormatAll(origin), platforms.FormatAll(input))
	}
	// A requested platform may omit identity details such as a Windows
	// os.version, so compare only the fields that select a root filesystem.
	if requested != nil {
		want, got := platforms.Normalize(*requested), platforms.Normalize(origin)
		if want.OS != got.OS || want.Architecture != got.Architecture || want.Variant != got.Variant {
			return fmt.Errorf("recorded patch origin platform %s does not match requested platform %s",
				platforms.FormatAll(origin), platforms.FormatAll(*requested))
		}
	}
	return nil
}

// resolveRecordedOrigin preserves a matching local locator, but recovers a
// moved/missing tag through its recorded immutable identity. Metadata may not
// redirect recovery into a different repository than the BaseImage locator.
func resolveRecordedOrigin(ctx context.Context, c sourceresolver.ImageMetaResolver, baseImage string, recorded *types.SourceLineage, opt sourceresolver.Opt) (string, digest.Digest, []byte, error) {
	if !recorded.Valid() || recorded.Kind != types.PatchOriginImage {
		return "", "", nil, errors.New("recorded patch origin cannot be resolved as an image reference")
	}
	base, err := reference.ParseNormalizedNamed(baseImage)
	if err != nil {
		return "", "", nil, fmt.Errorf("parse BaseImage: %w", err)
	}
	origin, err := reference.ParseNormalizedNamed(recorded.Name)
	if err != nil || base.Name() != origin.Name() {
		return "", "", nil, errors.New("recorded patch origin repository does not match BaseImage")
	}
	// An immutable locator may name an index whose selected platform is the
	// recorded origin. Validate that selection before comparing locator digests.
	_, selected, config, err := c.ResolveImageConfig(ctx, baseImage, opt)
	if err == nil && selected == recorded.Digest {
		return baseImage, selected, config, nil
	}
	if pinned, ok := base.(reference.Digested); ok && pinned.Digest() != recorded.Digest {
		if err != nil {
			return "", "", nil, fmt.Errorf("resolve immutable BaseImage %s: %w", baseImage, err)
		}
		if selected != pinned.Digest() {
			return "", "", nil, errors.New("recorded patch origin digest does not match immutable BaseImage")
		}
		return resolveRecordedIndexOrigin(ctx, c, baseImage, selected, config, recorded, opt)
	}
	pinned, err := reference.WithDigest(reference.TrimNamed(base), recorded.Digest)
	if err != nil {
		return "", "", nil, err
	}
	_, selected, config, err = c.ResolveImageConfig(ctx, pinned.String(), opt)
	if err != nil {
		return "", "", nil, fmt.Errorf("recover patch origin %s: %w", pinned, err)
	}
	if selected != recorded.Digest {
		return "", "", nil, fmt.Errorf("recovered patch origin %s resolved to unexpected digest %s", pinned, selected)
	}
	return pinned.String(), selected, config, nil
}

// BuildKit may return the index digest along with the selected child's config.
// Verify the immutable index's platform descriptor and resolve that exact child
// before retaining the index locator. Config equality also checks that the
// index and child resolutions selected the same image configuration.
func resolveRecordedIndexOrigin(
	ctx context.Context,
	c sourceresolver.ImageMetaResolver,
	baseImage string,
	indexDigest digest.Digest,
	config []byte,
	recorded *types.SourceLineage,
	opt sourceresolver.Opt,
) (string, digest.Digest, []byte, error) {
	if opt.ImageOpt == nil || opt.ImageOpt.Platform == nil {
		// The frontend may use BuildKit's default platform. Recover that exact
		// selection from the already-resolved original config, not the host.
		var platform specs.Platform
		if err := json.Unmarshal(config, &platform); err != nil {
			return "", "", nil, fmt.Errorf("infer immutable BaseImage platform from image config: %w", err)
		}
		if platform.OS == "" || platform.Architecture == "" {
			return "", "", nil, errors.New("cannot verify immutable BaseImage index platform: image config must specify OS and architecture")
		}
		platform = platforms.Normalize(platform)
		// Opt is passed by value, but ImageOpt belongs to the caller.
		imageOpt := sourceresolver.ResolveImageOpt{}
		if opt.ImageOpt != nil {
			imageOpt = *opt.ImageOpt
		}
		imageOpt.Platform = &platform
		opt.ImageOpt = &imageOpt
	}
	source, err := resolveOriginIndex(ctx, c, baseImage)
	if err != nil {
		return "", "", nil, fmt.Errorf("resolve immutable BaseImage index: %w", err)
	}
	if source.Descriptor.Digest != indexDigest {
		return "", "", nil, errors.New("resolved immutable BaseImage index has an unexpected digest")
	}
	child, err := source.PlatformDescriptor(opt.ImageOpt.Platform)
	if err != nil {
		return "", "", nil, fmt.Errorf("select immutable BaseImage platform: %w", err)
	}
	if child.Digest != recorded.Digest || !v1types.MediaType(child.MediaType).IsImage() {
		return "", "", nil, errors.New("recorded patch origin does not match immutable BaseImage platform manifest")
	}
	base, err := reference.ParseNormalizedNamed(baseImage)
	if err != nil {
		return "", "", nil, err
	}
	pinned, err := reference.WithDigest(reference.TrimNamed(base), recorded.Digest)
	if err != nil {
		return "", "", nil, err
	}
	_, selected, childConfig, err := c.ResolveImageConfig(ctx, pinned.String(), opt)
	if err != nil {
		return "", "", nil, fmt.Errorf("resolve immutable BaseImage child: %w", err)
	}
	if selected != recorded.Digest || !bytes.Equal(config, childConfig) {
		return "", "", nil, errors.New("immutable BaseImage child resolution does not match the recorded patch origin")
	}
	return baseImage, selected, childConfig, nil
}

func newSourceLineage(image string, imageDigest digest.Digest) *types.SourceLineage {
	if imageDigest.Validate() != nil {
		return nil
	}
	imageName, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return nil
	}
	if reference.IsNameOnly(imageName) {
		imageName = reference.TagNameOnly(imageName)
	}
	if pinned, ok := imageName.(reference.Digested); ok && pinned.Digest() != imageDigest {
		imageName, err = reference.WithDigest(reference.TrimNamed(imageName), imageDigest)
		if err != nil {
			return nil
		}
	}
	return &types.SourceLineage{Kind: types.PatchOriginImage, Name: imageName.String(), Digest: imageDigest}
}

func sourceLineageFromConfig(configData []byte) *types.SourceLineage {
	document, err := parseImageConfigLabels(configData)
	if err != nil {
		return nil
	}
	return types.SourceLineageFromAnnotations(document.labels)
}

type imageConfigLabelsDocument struct {
	image     map[string]json.RawMessage
	config    map[string]json.RawMessage
	labelsKey string
	labels    map[string]string
}

func parseImageConfigLabels(imageConfig []byte) (*imageConfigLabelsDocument, error) {
	var image map[string]json.RawMessage
	if err := json.Unmarshal(imageConfig, &image); err != nil {
		return nil, fmt.Errorf("parse image config: %w", err)
	}
	configData, ok := image["config"]
	if !ok {
		return nil, fmt.Errorf("image config does not contain a config field")
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("image config does not contain an object-valued config field: %w", err)
	}
	if config == nil {
		return nil, fmt.Errorf("image config does not contain an object-valued config field")
	}

	labelsKey := "Labels"
	labelsData, upperExists := config[labelsKey]
	if lowerLabels, lowerExists := config["labels"]; !upperExists && lowerExists {
		labelsKey = "labels"
		labelsData = lowerLabels
	} else if !upperExists && !lowerExists {
		for key, data := range config {
			if !strings.EqualFold(key, "labels") {
				continue
			}
			if labelsData != nil {
				return nil, fmt.Errorf("image config contains multiple case-insensitive labels fields")
			}
			labelsKey = key
			labelsData = data
		}
	}

	labels := make(map[string]string)
	if len(labelsData) > 0 && string(labelsData) != "null" {
		if err := json.Unmarshal(labelsData, &labels); err != nil {
			return nil, fmt.Errorf("image config labels field is not a string-valued object: %w", err)
		}
	}

	return &imageConfigLabelsDocument{
		image:     image,
		config:    config,
		labelsKey: labelsKey,
		labels:    labels,
	}, nil
}

func (document *imageConfigLabelsDocument) marshal() ([]byte, error) {
	// JSON field matching is case-insensitive. Remove every spelling except the
	// selected source so stale variants cannot shadow the updated labels.
	for key := range document.config {
		if strings.EqualFold(key, "labels") {
			delete(document.config, key)
		}
	}

	labelsData, err := json.Marshal(document.labels)
	if err != nil {
		return nil, fmt.Errorf("marshal image config labels: %w", err)
	}
	document.config[document.labelsKey] = labelsData
	configData, err := json.Marshal(document.config)
	if err != nil {
		return nil, fmt.Errorf("marshal image config object: %w", err)
	}
	document.image["config"] = configData
	updated, err := json.Marshal(document.image)
	if err != nil {
		return nil, fmt.Errorf("marshal image config: %w", err)
	}
	return updated, nil
}

// AddImageConfigLabels returns imageConfig with labels merged into its OCI
// config. The input is left unchanged, and supplied values take precedence.
func AddImageConfigLabels(imageConfig []byte, labels map[string]string) ([]byte, error) {
	if len(labels) == 0 {
		return imageConfig, nil
	}
	document, err := parseImageConfigLabels(imageConfig)
	if err != nil {
		return nil, err
	}
	for key, value := range labels {
		document.labels[key] = value
	}
	return document.marshal()
}

// RemoveImageConfigLabels returns imageConfig without the named labels. This
// keeps an unverified origin tuple from surviving a re-patch through copied
// runtime configuration.
func RemoveImageConfigLabels(imageConfig []byte, labels ...string) ([]byte, error) {
	if len(labels) == 0 {
		return imageConfig, nil
	}
	document, err := parseImageConfigLabels(imageConfig)
	if err != nil {
		return nil, err
	}
	for _, label := range labels {
		delete(document.labels, label)
	}
	return document.marshal()
}

func setupLabels(image string, configData []byte) (string, []byte, error) {
	document, err := parseImageConfigLabels(configData)
	if err != nil {
		return "", nil, err
	}

	baseImage := document.labels["BaseImage"]
	if baseImage == "" && image != "" {
		document.labels["BaseImage"] = image
	}
	imageWithLabels, err := document.marshal()
	if err != nil {
		return "", nil, err
	}
	return baseImage, imageWithLabels, nil
}

func solveStateReference(ctx context.Context, c gwclient.Client, st *llb.State) (gwclient.Reference, error) {
	// Since the platform is obtained from the host, override it for non-Linux hosts.
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

	return resp.SingleRef()
}

// ExtractFileFromState extracts the bytes of the file denoted by path from st.
func ExtractFileFromState(ctx context.Context, c gwclient.Client, st *llb.State, path string) ([]byte, error) {
	ref, err := solveStateReference(ctx, c, st)
	if err != nil {
		return nil, err
	}

	return ref.ReadFile(ctx, gwclient.ReadRequest{Filename: path})
}

// ExtractFileFromStateWithLimit extracts path after verifying its size without
// issuing an unbounded BuildKit read. The stat check happens before converting
// the file size to int or asking BuildKit to allocate the response buffer.
func ExtractFileFromStateWithLimit(
	ctx context.Context,
	c gwclient.Client,
	st *llb.State,
	path string,
	maxSize int64,
) ([]byte, error) {
	ref, err := solveStateReference(ctx, c, st)
	if err != nil {
		return nil, err
	}
	return ReadFileWithLimit(ctx, ref, path, maxSize)
}

// ReadFileWithLimit reads path from a BuildKit reference after enforcing a
// maximum file size. It uses bounded range requests so each unary gateway
// response remains safely below BuildKit's 16 MiB gRPC message limit. Reads
// continue through EOF because StatFile reports lstat metadata while ReadFile
// follows symlinks, so the stat size is not necessarily the resolved file size.
func ReadFileWithLimit(ctx context.Context, ref gwclient.Reference, path string, maxSize int64) ([]byte, error) {
	if maxSize < 0 {
		return nil, fmt.Errorf("maximum size for %q must not be negative", path)
	}

	stat, err := ref.StatFile(ctx, gwclient.StatRequest{Path: path})
	if err != nil {
		return nil, fmt.Errorf("unable to stat %q: %w", path, err)
	}
	if stat == nil {
		return nil, fmt.Errorf("unable to stat %q: BuildKit returned no file metadata", path)
	}
	if stat.Size < 0 {
		return nil, fmt.Errorf("unable to read %q: BuildKit reported a negative size of %d bytes", path, stat.Size)
	}
	if os.FileMode(stat.Mode)&os.ModeSymlink == 0 && stat.Size > maxSize {
		return nil, fmt.Errorf("file %q is %d bytes, exceeding the maximum allowed size of %d bytes", path, stat.Size, maxSize)
	}

	maxInt := int64(^uint(0) >> 1)
	capacity := min(stat.Size, maxSize)
	if capacity > maxInt {
		capacity = 0
	}
	data := make([]byte, 0, int(capacity))
	for offset := int64(0); ; {
		if offset > maxInt {
			return nil, fmt.Errorf("unable to read %q: offset %d exceeds the platform read limit", path, offset)
		}

		remaining := maxSize - offset
		chunkSize := maxGatewayReadFileChunkSize
		if remaining < chunkSize {
			// Read one byte past the limit so an exact-boundary file can be
			// distinguished from an oversized resolved symlink target.
			chunkSize = remaining + 1
		}
		chunk, err := ref.ReadFile(ctx, gwclient.ReadRequest{
			Filename: path,
			Range: &gwclient.FileRange{
				Offset: int(offset),
				Length: int(chunkSize),
			},
		})
		if err != nil {
			return nil, fmt.Errorf("unable to read %q at offset %d: %w", path, offset, err)
		}
		if int64(len(chunk)) > remaining {
			return nil, fmt.Errorf("file %q exceeds the maximum allowed size of %d bytes", path, maxSize)
		}
		data = append(data, chunk...)
		offset += int64(len(chunk))
		if int64(len(chunk)) < chunkSize {
			return data, nil
		}
	}
}

// platformIdentityEqual reports whether a descriptor's platform is the target.
// Windows OS versions and features identify distinct images, so they must match
// exactly. Other operating systems can record an informational os.version, such
// as Azure Linux's "azurelinux-3.0"; there the strict containerd match applies,
// as for a target taken from a scanner report or --platform.
func platformIdentityEqual(descriptor, target *specs.Platform) bool {
	normalizedDescriptor := platforms.Normalize(*descriptor)
	normalizedTarget := platforms.Normalize(*target)
	if normalizedTarget.OS != "windows" {
		return platforms.OnlyStrict(normalizedTarget).Match(normalizedDescriptor)
	}
	return normalizedDescriptor.OS == normalizedTarget.OS &&
		normalizedDescriptor.Architecture == normalizedTarget.Architecture &&
		normalizedDescriptor.Variant == normalizedTarget.Variant &&
		normalizedDescriptor.OSVersion == normalizedTarget.OSVersion &&
		slices.Equal(normalizedDescriptor.OSFeatures, normalizedTarget.OSFeatures)
}

func imagePlatformSpec(platform *v1.Platform) specs.Platform {
	return specs.Platform{
		OS:           platform.OS,
		Architecture: platform.Architecture,
		Variant:      platform.Variant,
		OSVersion:    platform.OSVersion,
		OSFeatures:   platform.OSFeatures,
	}
}

func matchingPlatformDescriptor(manifest *v1.IndexManifest, target *specs.Platform) (*v1.Descriptor, error) {
	var match *v1.Descriptor
	for i := range manifest.Manifests {
		descriptor := &manifest.Manifests[i]
		if descriptor.Platform == nil {
			continue
		}
		descriptorPlatform := imagePlatformSpec(descriptor.Platform)
		if !platformIdentityEqual(&descriptorPlatform, target) {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("image index contains multiple descriptors matching platform %+v", platforms.Normalize(*target))
		}
		match = descriptor
	}
	if match == nil {
		return nil, fmt.Errorf("image index contains no descriptor matching platform %+v", platforms.Normalize(*target))
	}
	return match, nil
}

// ReadFileErr distinguishes the cause of a file extraction failure so callers
// can tell a missing file apart from a solve-time failure of the underlying
// build graph (which may have included the path in its error text).
type ReadFileErr struct {
	// Err is the underlying buildkit error.
	Err error
	// SolveFailed is true when c.Solve(...) itself failed. When true the
	// target file was never actually read, and the failure belongs to the
	// graph that was supposed to produce it. Err may contain shell command
	// text and must not be used for path-based heuristics.
	SolveFailed bool
	// ReadFailed is true when Solve succeeded but ref.ReadFile for the
	// requested path failed. This is the only case where path-based
	// classification (e.g. "missing marker file") is safe.
	ReadFailed bool
}

func (e *ReadFileErr) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ReadFileErr) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// TryExtractFileFromState is like ExtractFileFromState but tags the returned
// error with which phase failed. Prefer this when callers need to treat a
// missing file differently from a real failure of the build graph.
func TryExtractFileFromState(ctx context.Context, c gwclient.Client, st *llb.State, path string) ([]byte, *ReadFileErr) {
	ref, err := solveStateReference(ctx, c, st)
	if err != nil {
		return nil, &ReadFileErr{Err: err, SolveFailed: true}
	}

	data, err := ref.ReadFile(ctx, gwclient.ReadRequest{
		Filename: path,
	})
	if err != nil {
		return nil, &ReadFileErr{Err: err, ReadFailed: true}
	}
	return data, nil
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
	return CreateOCILayoutFromResultsWithOptions(outputDir, results, platforms, OCILayoutExportOptions{})
}

// CreateOCILayoutFromResultsWithOptions creates an OCI layout directory from patch results using
// BuildKit's OCI exporter with the provided export options. It observes the
// context set by OCILayoutExportOptions.WithContext, if any.
func CreateOCILayoutFromResultsWithOptions(outputDir string, results []types.PatchResult, platforms []types.PatchPlatform, exportOpts OCILayoutExportOptions) error {
	ctx := context.Background()
	if exportOpts.state != nil && exportOpts.state.context != nil {
		ctx = exportOpts.state.context
	}
	return CreateOCILayoutFromResultsWithContext(ctx, outputDir, results, platforms, exportOpts)
}

// CreateOCILayoutFromResultsWithContext exports an OCI layout with options and cancellation of BuildKit and source reads.
func CreateOCILayoutFromResultsWithContext(ctx context.Context, outputDir string, results []types.PatchResult, platforms []types.PatchPlatform, exportOpts OCILayoutExportOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	log.Infof("Creating multi-platform OCI layout in directory: %s with %d platforms", outputDir, len(platforms))

	exportOpts.state = &ociLayoutExportState{context: ctx}
	seenSources := make(map[string]struct{})
	for i := range results {
		source := results[i].OCISource
		if source == nil {
			continue
		}
		if _, ok := seenSources[source.StoreID]; !ok {
			exportOpts.state.sources = append(exportOpts.state.sources, source)
			seenSources[source.StoreID] = struct{}{}
		}
		if exportOpts.OutputReference == "" && results[i].PatchedRef != nil {
			exportOpts.OutputReference = results[i].PatchedRef.String()
		}
	}
	if len(exportOpts.state.sources) > 0 {
		annotations, err := exportOpts.state.sources[0].IndexAnnotations(ctx)
		if err != nil {
			return fmt.Errorf("read OCI source index annotations: %w", err)
		}
		if annotations == nil {
			annotations = make(map[string]string)
		}
		// Copa records no patch origin for OCI layout input, so an origin
		// carried by the source index must not describe the output.
		delete(annotations, types.AnnotationPatchOriginKind)
		delete(annotations, types.AnnotationPatchOriginName)
		delete(annotations, types.AnnotationPatchOriginDigest)
		now := time.Now().UTC().Format(time.RFC3339)
		annotations["org.opencontainers.image.created"] = now
		annotations["sh.copa.patched"] = now
		if exportOpts.OutputReference != "" {
			outputRef, err := reference.ParseNormalizedNamed(exportOpts.OutputReference)
			if err != nil {
				return fmt.Errorf("parse OCI layout output reference %q: %w", exportOpts.OutputReference, err)
			}
			if tagged, ok := outputRef.(reference.Tagged); ok {
				if version, exists := annotations["org.opencontainers.image.version"]; exists {
					annotations["org.opencontainers.image.version"] = rewriteOCIExportVersionAnnotation(version, tagged.Tag())
				}
			}
		}
		maps.Copy(annotations, exportOpts.IndexAnnotations)
		exportOpts.IndexAnnotations = annotations
	}

	if exportOpts.Atomic {
		return createAtomicOCILayout(ctx, outputDir, func(tempDir string) error {
			if err := createOCILayoutFromResultsAt(ctx, tempDir, results, platforms, exportOpts); err != nil {
				return err
			}
			if len(exportOpts.state.sources) > 0 {
				return wrapOCIOutputIndex(tempDir, exportOpts.OutputReference, exportOpts.state.sources[0].Descriptor.Annotations)
			}
			return nil
		})
	}

	if err := createOCILayoutFromResultsAt(ctx, outputDir, results, platforms, exportOpts); err != nil {
		return err
	}
	if len(exportOpts.state.sources) > 0 {
		return wrapOCIOutputIndex(outputDir, exportOpts.OutputReference, exportOpts.state.sources[0].Descriptor.Annotations)
	}
	return nil
}

// createAtomicOCILayout owns the staging directory and publishes it only after
// the writer completes successfully and the caller still permits publication.
// Staging uses the resolved parent of outputDir, so a link/.. component cannot
// place it in a different directory, such as the protected input layout.
func createAtomicOCILayout(ctx context.Context, outputDir string, write func(string) error) error {
	destination, err := ocilayout.CanonicalNewPath(outputDir)
	if err != nil {
		return fmt.Errorf("resolve OCI layout output directory: %w", err)
	}
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("OCI layout output directory %q already exists; choose a new path", outputDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat OCI layout output directory: %w", err)
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create OCI layout output parent: %w", err)
	}
	tempDir, err := os.MkdirTemp(parent, ".copa-oci-output-*")
	if err != nil {
		return fmt.Errorf("create temporary OCI layout output: %w", err)
	}
	defer os.RemoveAll(tempDir)
	if err := write(tempDir); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("OCI layout export canceled before publication: %w", err)
	}
	if err := renameDirectoryNoReplace(tempDir, destination); err != nil {
		return fmt.Errorf("publish OCI layout output atomically without replacing an existing path: %w", err)
	}
	return nil
}

func wrapOCIOutputIndex(outputDir, outputReference string, sourceAnnotations map[string]string) error {
	if outputReference == "" {
		return fmt.Errorf("OCI layout output reference is required for OCI layout input")
	}
	named, err := reference.ParseNormalizedNamed(outputReference)
	if err != nil {
		return fmt.Errorf("parse OCI layout output reference %q: %w", outputReference, err)
	}

	indexPath := filepath.Join(outputDir, specs.ImageIndexFile)
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return fmt.Errorf("read generated OCI image index: %w", err)
	}
	var imageIndex specs.Index
	if err := json.Unmarshal(indexData, &imageIndex); err != nil {
		return fmt.Errorf("parse generated OCI image index: %w", err)
	}
	if imageIndex.SchemaVersion != 2 || (imageIndex.MediaType != "" && imageIndex.MediaType != specs.MediaTypeImageIndex) {
		return fmt.Errorf("generated OCI image index has invalid schemaVersion or mediaType")
	}

	indexDigest := digest.FromBytes(indexData)
	blobPath := filepath.Join(outputDir, "blobs", indexDigest.Algorithm().String(), indexDigest.Encoded())
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		return fmt.Errorf("create generated OCI index blob directory: %w", err)
	}
	if err := os.WriteFile(blobPath, indexData, 0o600); err != nil {
		return fmt.Errorf("write generated OCI index blob: %w", err)
	}

	annotations := maps.Clone(sourceAnnotations)
	if annotations == nil {
		annotations = make(map[string]string)
	}
	delete(annotations, specs.AnnotationRefName)
	annotations["io.containerd.image.name"] = named.String()
	if tagged, ok := named.(reference.Tagged); ok {
		annotations[specs.AnnotationRefName] = tagged.Tag()
	}
	rootIndex := specs.Index{
		Versioned: imageIndex.Versioned,
		MediaType: specs.MediaTypeImageIndex,
		Manifests: []specs.Descriptor{{
			MediaType:   specs.MediaTypeImageIndex,
			Digest:      indexDigest,
			Size:        int64(len(indexData)),
			Annotations: annotations,
		}},
	}
	rootData, err := json.MarshalIndent(rootIndex, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal OCI layout root index: %w", err)
	}
	if err := os.WriteFile(indexPath, rootData, 0o600); err != nil {
		return fmt.Errorf("write OCI layout root index: %w", err)
	}
	return nil
}

func createOCILayoutFromResultsAt(ctx context.Context, outputDir string, results []types.PatchResult, platforms []types.PatchPlatform, exportOpts OCILayoutExportOptions) error {
	// Create output directory
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if hasOCILayoutInputs(results, platforms) {
		log.Info("Using patched states and/or preserved platforms for OCI export")
		return createOCILayoutFromStates(ctx, outputDir, results, platforms, exportOpts)
	}

	return fmt.Errorf("no BuildKit states or preserved platforms available for OCI export, cannot proceed")
}

// prepareExportSolveOpt gives an export solve the same source bindings and
// source policy as the patch solve that validated its state.
func prepareExportSolveOpt(solveOpt *client.SolveOpt, exportOpts OCILayoutExportOptions) { //nolint:gocritic
	addOCIStores(solveOpt, exportOpts)
	solveOpt.SourcePolicy = exportOpts.SourcePolicy
}

func addOCIStores(solveOpt *client.SolveOpt, exportOpts OCILayoutExportOptions) {
	if exportOpts.state == nil {
		return
	}
	for _, source := range exportOpts.state.sources {
		source.AddToSolveOpt(solveOpt)
	}
}

func hasOCILayoutInputs(results []types.PatchResult, platforms []types.PatchPlatform) bool {
	for _, result := range results {
		if result.PatchedState != nil {
			return true
		}
	}
	for _, platform := range platforms {
		if platform.ShouldPreserve {
			return true
		}
	}
	return false
}

// createOCILayoutFromStates creates OCI layout directly from BuildKit states.
func createOCILayoutFromStates(ctx context.Context, outputDir string, results []types.PatchResult, platforms []types.PatchPlatform, exportOpts OCILayoutExportOptions) error {
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
	var platformMetadata []platformExportMetadata
	outputTag := ""
	if outputRef, err := reference.ParseNormalizedNamed(exportOpts.OutputReference); err == nil {
		if tagged, ok := outputRef.(reference.Tagged); ok {
			outputTag = tagged.Tag()
		}
	}

	// Map results by platform for easy lookup
	resultMap := make(map[string]*types.PatchResult)
	for i, result := range results {
		if result.OCISource != nil {
			if result.PatchedState == nil {
				continue
			}
			if result.PatchedDesc == nil || result.PatchedDesc.Platform == nil {
				return fmt.Errorf("OCI patch result is missing its source platform")
			}
			key := PlatformKey(*result.PatchedDesc.Platform)
			if _, exists := resultMap[key]; exists {
				return fmt.Errorf("multiple OCI patch results for platform %s", FormatPlatform(*result.PatchedDesc.Platform))
			}
			resultMap[key] = &results[i]
			continue
		}
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
	if len(patchedPlatforms) == 1 {
		platformKey := PlatformKey(patchedPlatforms[0].Platform)
		if _, exists := resultMap[platformKey]; !exists {
			for i := range results {
				if results[i].OCISource == nil && results[i].PatchedState != nil {
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
			platformMetadata = append(platformMetadata, ociPlatformExportMetadata(result, outputTag))
		} else if len(exportOpts.state.sources) > 0 {
			return fmt.Errorf("missing OCI patch result for platform %s", FormatPlatform(platform.Platform))
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
		return createMixedOCILayout(ctx, outputDir, results, platformStates, platformSpecs, platformMetadata, preservedPlatforms, exportOpts)
	case hasPatchedPlatforms:
		log.Infof("Creating OCI layout from %d patched platforms only", len(platformStates))
	case hasPreservedPlatforms:
		log.Infof("Creating OCI layout from %d preserved platforms only", len(preservedPlatforms))
		return createPreservedOnlyOCILayout(ctx, outputDir, results, preservedPlatforms, exportOpts)
	}

	log.Infof("Creating OCI layout from %d BuildKit states", len(platformStates))

	// Use BuildKit Go client to create OCI layout

	c, err := newOCIExportClient(ctx, exportOpts.BuildkitOpts)
	if err != nil {
		return fmt.Errorf("failed to create BuildKit client: %w", err)
	}
	defer c.Close()

	return solveMultiPlatformOCI(ctx, c, outputDir, platformStates, platformSpecs, platformMetadata, exportOpts)
}

// OCI export uses the same client selection as patching so the validated state
// is not re-solved on a different default worker.
func newOCIExportClient(ctx context.Context, opts *Opts) (*client.Client, error) {
	if opts == nil {
		opts = &Opts{}
	}
	return NewClient(ctx, *opts)
}

// solveMultiPlatformOCI uses BuildKit client to solve multi-platform states and export to OCI layout.
func solveMultiPlatformOCI(
	ctx context.Context,
	c *client.Client,
	outputDir string,
	platformStates []llb.State,
	platformSpecs []specs.Platform,
	platformMetadata []platformExportMetadata,
	exportOpts OCILayoutExportOptions,
) error {
	if len(platformStates) == 0 {
		return fmt.Errorf("no platform states provided")
	}

	if len(platformStates) != len(platformSpecs) {
		return fmt.Errorf("mismatch between states (%d) and platform specs (%d)", len(platformStates), len(platformSpecs))
	}
	if len(platformStates) != len(platformMetadata) {
		return fmt.Errorf("mismatch between states (%d) and platform metadata (%d)", len(platformStates), len(platformMetadata))
	}

	// An atomic export passes in a new staging directory that only this process
	// can use. Removing and recreating it would let another local user claim the
	// path in between, and the publishing rename would then move their directory
	// or link into place. A named export writes to --oci-dir itself and replaces
	// any earlier layout there.
	if !exportOpts.Atomic {
		os.RemoveAll(outputDir)
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	if len(platformStates) == 1 {
		// Single platform case - use output function to avoid diffcopy issues
		return solveSinglePlatformOCI(ctx, c, outputDir, &platformStates[0], &platformSpecs[0], platformMetadata[0], exportOpts)
	}

	// Multi-platform case - solve each platform and combine
	return solveAndCombineAllPlatforms(ctx, c, outputDir, platformStates, platformSpecs, platformMetadata, exportOpts)
}

func ociPlatformExportMetadata(result *types.PatchResult, outputTags ...string) platformExportMetadata {
	metadata := platformExportMetadata{Config: result.ConfigData}
	if result.OCISource != nil {
		metadata.Annotations = maps.Clone(result.ManifestAnnotations)
		if result.PatchedDesc != nil {
			metadata.DescriptorAnnotations = maps.Clone(result.PatchedDesc.Annotations)
		}
	} else if result.PatchedDesc != nil {
		metadata.Annotations = maps.Clone(result.PatchedDesc.Annotations)
	}

	const versionAnnotation = "org.opencontainers.image.version"
	originalVersion, ok := metadata.Annotations[versionAnnotation]
	if !ok || result.PatchedRef == nil {
		return metadata
	}
	patchedTag := ""
	if len(outputTags) > 0 {
		patchedTag = outputTags[0]
	}
	if patchedTag == "" {
		patchedRef, ok := result.PatchedRef.(reference.Tagged)
		if !ok {
			return metadata
		}
		patchedTag = patchedRef.Tag()
	}
	if patchedTag == "" {
		return metadata
	}
	metadata.Annotations[versionAnnotation] = rewriteOCIExportVersionAnnotation(originalVersion, patchedTag)
	return metadata
}

func rewriteOCIExportVersionAnnotation(originalVersion, patchedTag string) string {
	if originalVersion == "" || patchedTag == "" {
		return originalVersion
	}
	if ociTagContainsVersionComponent(patchedTag, originalVersion) {
		return patchedTag
	}
	return originalVersion + "-" + patchedTag
}

func ociTagContainsVersionComponent(tag, version string) bool {
	for searchFrom := 0; searchFrom <= len(tag)-len(version); {
		relative := strings.Index(tag[searchFrom:], version)
		if relative < 0 {
			return false
		}
		start := searchFrom + relative
		end := start + len(version)
		beforeBoundary := start == 0 || isOCIVersionTagSeparator(tag[start-1])
		if !beforeBoundary && (tag[start-1] == 'v' || tag[start-1] == 'V') {
			versionPrefix := start - 1
			beforeBoundary = versionPrefix == 0 || isOCIVersionTagSeparator(tag[versionPrefix-1])
		}
		afterBoundary := end == len(tag) || isOCIVersionTagSeparator(tag[end])
		if beforeBoundary && afterBoundary {
			return true
		}
		searchFrom = start + 1
	}
	return false
}

func isOCIVersionTagSeparator(character byte) bool {
	return character == '-' || character == '_' || character == '.' || character == '+'
}

func ociExporterAttrs(exportOpts OCILayoutExportOptions) map[string]string {
	attrs := map[string]string{
		"oci-mediatypes": "true",
		"buildinfo":      "false",
	}
	if exportOpts.Compression != "" {
		attrs["compression"] = exportOpts.Compression
	}
	if exportOpts.ForceCompression {
		attrs["force-compression"] = "true"
	}

	return attrs
}

func addOCIExportMetadata(result *gwclient.Result, metadata platformExportMetadata) error {
	if len(metadata.Config) == 0 {
		return fmt.Errorf("patched platform is missing image config metadata")
	}
	result.AddMeta(exptypes.ExporterImageConfigKey, metadata.Config)
	for key, value := range metadata.Annotations {
		result.AddMeta(exptypes.AnnotationManifestKey(nil, key), []byte(value))
	}
	for key, value := range metadata.DescriptorAnnotations {
		result.AddMeta(exptypes.AnnotationManifestDescriptorKey(nil, key), []byte(value))
	}
	return nil
}

// ensureAuthSession attaches the local Docker credentials to an OCI export solve when the
// caller has not supplied a session of its own.
//
// The patched states still reference the source image, so BuildKit resolves the
// `docker-image://` source again while solving the export. With no auth session attached it
// does so anonymously, which succeeds for a public source but fails on a private registry
// with "failed to authorize: failed to fetch anonymous token" — even though patching itself
// has already succeeded using these same credentials, because the patch solve attaches them
// (see pkg/patch.authenticatedSolveOpt).
func ensureAuthSession(solveOpt *client.SolveOpt) {
	if solveOpt == nil || len(solveOpt.Session) > 0 {
		return
	}
	dockerConfig := config.LoadDefaultConfigFile(os.Stderr)
	authConfig := authprovider.DockerAuthProviderConfig{
		AuthConfigProvider: authprovider.LoadAuthConfig(dockerConfig),
	}
	solveOpt.Session = []session.Attachable{authprovider.NewDockerAuthProvider(authConfig)}
}

func solvePlatformOCI(
	ctx context.Context,
	c *client.Client,
	state *llb.State,
	platformSpec *specs.Platform,
	metadata platformExportMetadata,
	solveOpt *client.SolveOpt,
) error {
	ensureAuthSession(solveOpt)

	_, err := c.Build(ctx, *solveOpt, "copa-oci-export", func(ctx context.Context, gateway gwclient.Client) (*gwclient.Result, error) {
		def, err := state.Marshal(ctx, llb.Platform(*platformSpec))
		if err != nil {
			return nil, fmt.Errorf("marshal platform state: %w", err)
		}
		result, err := gateway.Solve(ctx, gwclient.SolveRequest{Definition: def.ToPB(), Evaluate: true})
		if err != nil {
			return nil, fmt.Errorf("solve platform state: %w", err)
		}
		if err := addOCIExportMetadata(result, metadata); err != nil {
			return nil, err
		}
		return result, nil
	}, nil)
	return err
}

// solveSinglePlatformOCI handles single platform OCI export using output function.
func solveSinglePlatformOCI(
	ctx context.Context,
	c *client.Client,
	outputDir string,
	state *llb.State,
	platformSpec *specs.Platform,
	metadata platformExportMetadata,
	exportOpts OCILayoutExportOptions,
) error {
	// Create solve options with output function to avoid diffcopy issues
	solveOpt := client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:  client.ExporterOCI,
			Attrs: ociExporterAttrs(exportOpts),
			Output: func(_ map[string]string) (io.WriteCloser, error) {
				tarPath := filepath.Join(outputDir, "image.tar")
				return os.Create(tarPath)
			},
		}},
	}
	prepareExportSolveOpt(&solveOpt, exportOpts)

	if err := solvePlatformOCI(ctx, c, state, platformSpec, metadata, &solveOpt); err != nil {
		return fmt.Errorf("BuildKit solve failed: %w", err)
	}

	// Extract tar to OCI layout
	tarPath := filepath.Join(outputDir, "image.tar")
	if err := extractTarToDirectory(ctx, tarPath, outputDir); err != nil {
		return fmt.Errorf("failed to extract OCI layout: %w", err)
	}

	// Clean up tar file
	os.Remove(tarPath)

	// Fix platform information in the extracted OCI layout
	if err := fixSinglePlatformInfo(outputDir, platformSpec, exportOpts.IndexAnnotations); err != nil {
		return fmt.Errorf("failed to fix platform information: %w", err)
	}

	return nil
}

// fixSinglePlatformInfo corrects the platform information in a single-platform OCI layout.
func fixSinglePlatformInfo(outputDir string, platformSpec *specs.Platform, indexAnnotations map[string]string) error {
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
	if platformSpec.OSVersion != "" {
		targetPlatform["os.version"] = platformSpec.OSVersion
	}
	if len(platformSpec.OSFeatures) > 0 {
		targetPlatform["os.features"] = platformSpec.OSFeatures
	}

	// Update platform information in all manifests
	if manifests, ok := index["manifests"].([]interface{}); ok {
		for _, manifest := range manifests {
			if manifestMap, ok := manifest.(map[string]interface{}); ok {
				manifestMap["platform"] = targetPlatform
			}
		}
	}
	addIndexAnnotations(index, indexAnnotations)

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
func solveAndCombineAllPlatforms(
	ctx context.Context,
	c *client.Client,
	outputDir string,
	platformStates []llb.State,
	platformSpecs []specs.Platform,
	platformMetadata []platformExportMetadata,
	exportOpts OCILayoutExportOptions,
) error {
	// Create temporary directory for platform tars
	tempDir, err := utils.MkdirTemp("copa-platforms-*")
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
				Type:  client.ExporterOCI,
				Attrs: ociExporterAttrs(exportOpts),
				Output: func(_ map[string]string) (io.WriteCloser, error) {
					return os.Create(platformTarPath)
				},
			}},
		}
		prepareExportSolveOpt(&platformSolveOpt, exportOpts)

		if err := solvePlatformOCI(ctx, c, &platformStates[i], &platformSpecs[i], platformMetadata[i], &platformSolveOpt); err != nil {
			return fmt.Errorf("failed to solve platform: %w", err)
		}
	}

	// Extract and combine all platform tars into multi-platform OCI layout
	return extractAndCombinePlatformTars(ctx, outputDir, platformTars, platformSpecs, exportOpts.IndexAnnotations)
}

// extractAndCombinePlatformTars extracts platform tars and combines them into multi-platform OCI layout.
func extractAndCombinePlatformTars(ctx context.Context, outputDir string, platformTars []string, platformSpecs []specs.Platform, indexAnnotations map[string]string) error {
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
		platformTempDir, err := utils.MkdirTemp("copa-platform-extract-*")
		if err != nil {
			return fmt.Errorf("failed to create temp directory for platform: %w", err)
		}
		defer os.RemoveAll(platformTempDir)

		// Extract tar file
		if err := extractTarToDirectory(ctx, platformTar, platformTempDir); err != nil {
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
		if platformSpec.OSVersion != "" {
			targetPlatform["os.version"] = platformSpec.OSVersion
		}
		if len(platformSpec.OSFeatures) > 0 {
			targetPlatform["os.features"] = platformSpec.OSFeatures
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
		if err := copyBlobs(ctx, platformBlobsDir, blobsDir, blobsSet); err != nil {
			return fmt.Errorf("failed to copy blobs from platform: %w", err)
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	// Create the combined index.json with all platform manifests
	combinedIndex := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests":     platformManifests,
	}
	addIndexAnnotations(combinedIndex, indexAnnotations)

	indexJSON, err := json.MarshalIndent(combinedIndex, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal combined index: %w", err)
	}

	if err := os.WriteFile(filepath.Join(outputDir, "index.json"), indexJSON, 0o600); err != nil {
		return fmt.Errorf("failed to write combined index.json: %w", err)
	}

	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// copyBlobs copies blob files from source to destination, avoiding duplicates.
func copyBlobs(ctx context.Context, srcBlobsDir, dstBlobsDir string, blobsSet map[string]bool) error {
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
		if err := ctx.Err(); err != nil {
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

		if _, err := io.Copy(dstFile, &contextReader{ctx: ctx, reader: srcFile}); err != nil {
			return fmt.Errorf("failed to copy blob %s: %w", relPath, err)
		}

		// Mark blob as copied
		blobsSet[relPath] = true
		log.Debugf("Copied blob: %s", relPath)

		return nil
	})
}

// extractTarToDirectory extracts a tar file to a directory. Cancellation stops
// the tar process.
func extractTarToDirectory(ctx context.Context, tarPath, destDir string) error {
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
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "tar", "-xf", cleanTarPath, "-C", cleanDestDir)

	if output, err := cmd.CombinedOutput(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("extract tar %s: %w", cleanTarPath, ctxErr)
		}
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
	ctx context.Context,
	outputDir string,
	results []types.PatchResult,
	platformStates []llb.State,
	platformSpecs []specs.Platform,
	platformMetadata []platformExportMetadata,
	preservedPlatforms []types.PatchPlatform,
	exportOpts OCILayoutExportOptions,
) error {
	log.Infof("Creating mixed OCI layout with %d patched platforms and %d preserved platforms", len(platformStates), len(preservedPlatforms))

	// Step 1: Create OCI layouts for patched platforms
	var patchedManifests []map[string]interface{}
	allBlobs := make(map[string]bool) // Track all blobs to avoid duplicates

	if len(platformStates) > 0 {
		// Create temporary directory for patched platforms
		patchedTempDir, err := utils.MkdirTemp("copa-patched-platforms-*")
		if err != nil {
			return fmt.Errorf("failed to create temp directory for patched platforms: %w", err)
		}
		defer os.RemoveAll(patchedTempDir)

		c, err := newOCIExportClient(ctx, exportOpts.BuildkitOpts)
		if err != nil {
			return fmt.Errorf("failed to create BuildKit client for mixed layout: %w", err)
		}
		defer c.Close()

		patchedManifests, err = exportPatchedPlatformsToTemp(ctx, c, patchedTempDir, platformStates, platformSpecs, platformMetadata, exportOpts)
		if err != nil {
			return fmt.Errorf("failed to export patched platforms: %w", err)
		}

		// Copy patched platform blobs to final output directory
		if err := copyBlobsToOutput(ctx, outputDir, patchedTempDir, allBlobs); err != nil {
			return fmt.Errorf("failed to copy patched platform blobs: %w", err)
		}
	}

	// Step 2: Export preserved platforms from original image
	var preservedManifests []map[string]interface{}
	if len(preservedPlatforms) > 0 {
		preservedSourceRef := preservedPlatformsSourceRef(results, exportOpts)
		switch {
		case len(exportOpts.state.sources) > 0:
			for _, platform := range preservedPlatforms {
				desc, err := exportOpts.state.sources[0].CopyPlatform(ctx, outputDir, &platform.Platform, allBlobs)
				if err != nil {
					return fmt.Errorf("copy preserved OCI platform %s: %w", FormatPlatform(platform.Platform), err)
				}
				entry, err := descriptorMap(desc)
				if err != nil {
					return err
				}
				preservedManifests = append(preservedManifests, entry)
			}
		case preservedSourceRef == nil:
			log.Warn("Could not determine original image reference for preserved platforms, skipping preserved platforms export")
		default:
			// Preserved platforms intentionally keep their original descriptors and
			// layer blobs, even when compression options are set for patched platforms.
			exportedManifests, err := exportPreservedPlatformsToOutput(ctx, outputDir, preservedSourceRef, preservedPlatforms, allBlobs)
			if err != nil {
				return fmt.Errorf("failed to export preserved platforms: %w", err)
			}
			preservedManifests = exportedManifests
		}
	}

	// Step 3: Combine all manifests into final OCI layout
	patchedManifests = append(patchedManifests, preservedManifests...)

	if len(patchedManifests) == 0 {
		return fmt.Errorf("no manifests to include in mixed OCI layout")
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	return createFinalOCILayout(outputDir, patchedManifests, exportOpts.IndexAnnotations)
}

// exportPatchedPlatformsToTemp exports patched platforms using BuildKit to a temporary directory.
func exportPatchedPlatformsToTemp(
	ctx context.Context,
	c *client.Client,
	tempDir string,
	platformStates []llb.State,
	platformSpecs []specs.Platform,
	platformMetadata []platformExportMetadata,
	exportOpts OCILayoutExportOptions,
) ([]map[string]interface{}, error) {
	var manifests []map[string]interface{}

	// Export each platform to its own tar file
	for i, platformState := range platformStates {
		platformSpec := platformSpecs[i]
		platformTarPath := filepath.Join(tempDir, fmt.Sprintf("platform-%d.tar", i))

		// Create solve options with output function
		solveOpt := client.SolveOpt{
			Exports: []client.ExportEntry{{
				Type:  client.ExporterOCI,
				Attrs: ociExporterAttrs(exportOpts),
				Output: func(_ map[string]string) (io.WriteCloser, error) {
					return os.Create(platformTarPath)
				},
			}},
		}
		prepareExportSolveOpt(&solveOpt, exportOpts)

		if err := solvePlatformOCI(ctx, c, &platformState, &platformSpec, platformMetadata[i], &solveOpt); err != nil {
			return nil, fmt.Errorf("failed to solve platform: %w", err)
		}

		// Extract tar and read manifest
		platformExtractDir := filepath.Join(tempDir, fmt.Sprintf("extract-%d", i))
		if err := os.MkdirAll(platformExtractDir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create extraction directory: %w", err)
		}

		if err := extractTarToDirectory(ctx, platformTarPath, platformExtractDir); err != nil {
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
func copyBlobsToOutput(ctx context.Context, outputDir, tempDir string, blobsSet map[string]bool) error {
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
			return copyBlobs(ctx, path, outputBlobsDir, blobsSet)
		}

		return nil
	})
}

func resolvePreservedPlatformsDescriptor(ctx context.Context, ref name.Reference) (*remote.Descriptor, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	desc, sourceDigest, complete, err := tryGetManifestFromLocal(ctx, ref)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		log.Debugf("Failed to get descriptor from local daemon: %v, trying remote registry", err)
		desc, err = getRemoteImageDescriptor(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
		if err != nil {
			return nil, false, fmt.Errorf("failed to get remote descriptor: %w", err)
		}
		if desc == nil {
			return nil, false, fmt.Errorf("remote registry returned no descriptor for %q", ref.String())
		}
		log.Debugf("Successfully fetched descriptor from remote registry for preserved platforms")
		return desc, false, nil
	}
	if desc == nil {
		return nil, false, fmt.Errorf("local daemon returned no descriptor for %q", ref.String())
	}
	if !complete {
		if sourceDigest.Algorithm == "" || sourceDigest.Hex == "" {
			return nil, false, fmt.Errorf("cannot reconcile incomplete local image index %q: source descriptor digest is unavailable", ref.String())
		}
		if digestRef, immutable := ref.(name.Digest); immutable && sourceDigest.String() != digestRef.DigestStr() {
			return nil, false, fmt.Errorf(
				"local source descriptor digest %s does not match immutable reference %s",
				sourceDigest.String(), digestRef.DigestStr(),
			)
		}

		sourceRef := ref.Context().Digest(sourceDigest.String())
		remoteDesc, remoteErr := GetVerifiedRemoteIndexWithContext(ctx, sourceRef)
		if remoteErr != nil {
			return nil, false, fmt.Errorf("reconcile incomplete local image index %q: %w", ref.String(), remoteErr)
		}

		log.Debugf("Reconciled incomplete local image index for %s from verified remote descriptor %s", ref.String(), sourceDigest.String())
		return remoteDesc, false, nil
	}

	// A local daemon may cache an immutable index digest as only the selected
	// child image. Resolve the immutable reference remotely to distinguish a
	// genuine single-image digest from a masked index. Fail closed when the
	// remote descriptor cannot be verified so preserved platforms are never
	// silently dropped. Mutable tags continue to use the local descriptor.
	if digestRef, immutable := ref.(name.Digest); immutable {
		if desc.MediaType.IsIndex() {
			if sourceDigest.String() != digestRef.DigestStr() {
				return nil, false, fmt.Errorf(
					"local source descriptor digest %s does not match immutable reference %s",
					sourceDigest.String(), digestRef.DigestStr(),
				)
			}
			log.Debugf("Successfully fetched immutable image index from local daemon for preserved platforms")
			return desc, true, nil
		}
		remoteDesc, remoteErr := getRemoteImageDescriptor(digestRef, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
		if remoteErr != nil {
			return nil, false, fmt.Errorf("verify immutable descriptor %q for preserved platforms: %w", ref.String(), remoteErr)
		}
		if remoteDesc == nil {
			return nil, false, fmt.Errorf("verify immutable descriptor %q for preserved platforms: registry returned no descriptor", ref.String())
		}
		if remoteDesc.Digest.String() != digestRef.DigestStr() {
			return nil, false, fmt.Errorf(
				"remote descriptor digest %s does not match immutable reference %s",
				remoteDesc.Digest.String(), digestRef.DigestStr(),
			)
		}
		if remoteDesc.MediaType.IsIndex() {
			log.Debugf("Locally cached child masks the matching remote index for %s; using remote index for preserved platforms", ref.String())
			return remoteDesc, false, nil
		}
		if sourceDigest.String() != digestRef.DigestStr() {
			return nil, false, fmt.Errorf(
				"local source descriptor digest %s does not match verified immutable image %s",
				sourceDigest.String(), digestRef.DigestStr(),
			)
		}

		log.Debugf("Verified %s as a genuine single-image digest; using the local descriptor", ref.String())
		return desc, true, nil
	}

	log.Debugf("Successfully fetched descriptor from local daemon for preserved platforms")
	return desc, true, nil
}

// exportPreservedPlatformsToOutput exports preserved platforms from original image to output directory.
func exportPreservedPlatformsToOutput(
	ctx context.Context,
	outputDir string,
	originalRef reference.Named,
	preservedPlatforms []types.PatchPlatform,
	blobsSet map[string]bool,
) ([]map[string]interface{}, error) {
	// Convert reference.Named to name.Reference for go-containerregistry
	ref, err := name.ParseReference(originalRef.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}

	desc, isLocal, err := resolvePreservedPlatformsDescriptor(ctx, ref)
	if err != nil {
		return nil, err
	}

	var manifests []map[string]interface{}

	// Ensure blobs directory exists so we can materialize preserved platform content
	blobsDir := filepath.Join(outputDir, "blobs", "sha256")
	if err := os.MkdirAll(blobsDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create blobs directory for preserved platforms: %w", err)
	}

	// Helper to write a blob if we have not already written it (dedupe across platforms)
	writeBlobIfAbsent := func(hash v1.Hash, data []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
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
		if _, err := io.Copy(f, &contextReader{ctx: ctx, reader: rc}); err != nil {
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

		// Resolve and materialize any image-manifest descriptor from the source
		// index. Attestation manifests use the same OCI image-manifest shape, so
		// this also copies their config and in-toto layer blobs.
		materializeDescriptor := func(mdesc *v1.Descriptor) (map[string]interface{}, error) {
			var img v1.Image
			if isLocal {
				digestRef := fmt.Sprintf("%s@%s", originalRef.Name(), mdesc.Digest.String())
				platformRef, err := name.ParseReference(digestRef)
				if err != nil {
					return nil, fmt.Errorf("failed to parse preserved descriptor reference: %w", err)
				}
				img, err = getImageFromDaemon(platformRef, daemon.WithContext(ctx))
				if err != nil {
					return nil, fmt.Errorf("failed to get preserved descriptor %s from local daemon: %w", mdesc.Digest, err)
				}
			} else {
				var err error
				img, err = idx.Image(mdesc.Digest)
				if err != nil {
					return nil, fmt.Errorf("failed to get preserved descriptor %s: %w", mdesc.Digest, err)
				}
			}

			rawManifest, err := img.RawManifest()
			if err != nil {
				return nil, fmt.Errorf("failed to get raw preserved manifest %s: %w", mdesc.Digest, err)
			}
			if err := writeBlobIfAbsent(mdesc.Digest, rawManifest); err != nil {
				return nil, err
			}

			cfgHash, err := img.ConfigName()
			if err != nil {
				return nil, fmt.Errorf("failed to get preserved config digest for %s: %w", mdesc.Digest, err)
			}
			rawConfig, err := img.RawConfigFile()
			if err != nil {
				return nil, fmt.Errorf("failed to get raw preserved config for %s: %w", mdesc.Digest, err)
			}
			if err := writeBlobIfAbsent(cfgHash, rawConfig); err != nil {
				return nil, err
			}

			layers, err := img.Layers()
			if err != nil {
				return nil, fmt.Errorf("failed to get preserved layers for %s: %w", mdesc.Digest, err)
			}
			for _, layer := range layers {
				if err := writeLayerIfAbsent(layer); err != nil {
					return nil, err
				}
			}

			descriptorJSON, err := json.Marshal(mdesc)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal preserved descriptor %s: %w", mdesc.Digest, err)
			}
			var entry map[string]interface{}
			if err := json.Unmarshal(descriptorJSON, &entry); err != nil {
				return nil, fmt.Errorf("failed to decode preserved descriptor %s: %w", mdesc.Digest, err)
			}
			return entry, nil
		}

		// Filter image manifests for the preserved platforms, then preserve any
		// source attestations whose subject points to those unchanged children.
		for _, platformSpec := range preservedPlatforms {
			mdesc, err := matchingPlatformDescriptor(manifest, &platformSpec.Platform)
			if err != nil {
				return nil, err
			}

			entry, err := materializeDescriptor(mdesc)
			if err != nil {
				return nil, fmt.Errorf("failed to preserve platform %s/%s: %w", platformSpec.OS, platformSpec.Architecture, err)
			}
			manifests = append(manifests, entry)

			subject := mdesc.Digest.String()
			for j := range manifest.Manifests {
				attestation := &manifest.Manifests[j]
				if attestation.Annotations["vnd.docker.reference.type"] != "attestation-manifest" ||
					attestation.Annotations["vnd.docker.reference.digest"] != subject {
					continue
				}
				attestationEntry, err := materializeDescriptor(attestation)
				if err != nil {
					return nil, fmt.Errorf("failed to preserve attestation for %s: %w", subject, err)
				}
				manifests = append(manifests, attestationEntry)
			}
		}
	} else {
		// Single platform image
		// Materialize single-platform image blobs
		var img v1.Image
		if isLocal {
			img, err = getImageFromDaemon(ref, daemon.WithContext(ctx))
		} else {
			img, err = desc.Image()
		}
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
			if platformSpec.OSVersion != "" {
				targetPlatform["os.version"] = platformSpec.OSVersion
			}
			if len(platformSpec.OSFeatures) > 0 {
				targetPlatform["os.features"] = platformSpec.OSFeatures
			}

			manifestMap["platform"] = targetPlatform
			return manifestMap, nil
		}
	}

	return nil, fmt.Errorf("no valid manifest found in OCI layout")
}

// createFinalOCILayout creates the final OCI layout with combined manifests.
func createFinalOCILayout(outputDir string, allManifests []map[string]interface{}, indexAnnotations map[string]string) error {
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
	addIndexAnnotations(combinedIndex, indexAnnotations)

	indexJSON, err := json.MarshalIndent(combinedIndex, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal combined index: %w", err)
	}

	if err := os.WriteFile(filepath.Join(outputDir, "index.json"), indexJSON, 0o600); err != nil {
		return fmt.Errorf("failed to write combined index.json: %w", err)
	}

	log.Infof("Successfully created OCI layout with %d platform manifests", len(allManifests))
	return nil
}

func descriptorMap(desc *specs.Descriptor) (map[string]interface{}, error) {
	data, err := json.Marshal(desc)
	if err != nil {
		return nil, fmt.Errorf("marshal OCI descriptor %s: %w", desc.Digest, err)
	}
	var entry map[string]interface{}
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("decode OCI descriptor %s: %w", desc.Digest, err)
	}
	return entry, nil
}

func addIndexAnnotations(index map[string]interface{}, annotations map[string]string) {
	if len(annotations) == 0 {
		return
	}
	index["annotations"] = maps.Clone(annotations)
}

// createPreservedOnlyOCILayout creates an OCI layout from preserved platforms only.
func createPreservedOnlyOCILayout(
	ctx context.Context,
	outputDir string,
	results []types.PatchResult,
	preservedPlatforms []types.PatchPlatform,
	exportOpts OCILayoutExportOptions,
) error {
	log.Infof("Creating OCI layout from %d preserved platforms only", len(preservedPlatforms))
	if exportOpts.state == nil {
		exportOpts.state = &ociLayoutExportState{context: context.Background()}
	}

	preservedSourceRef := preservedPlatformsSourceRef(results, exportOpts)
	if preservedSourceRef == nil && len(exportOpts.state.sources) == 0 {
		return fmt.Errorf("no original reference found for preserved-only layout")
	}

	var preservedManifests []map[string]interface{}
	var err error
	if len(exportOpts.state.sources) > 0 {
		copied := make(map[string]bool)
		for _, platform := range preservedPlatforms {
			desc, copyErr := exportOpts.state.sources[0].CopyPlatform(ctx, outputDir, &platform.Platform, copied)
			if copyErr != nil {
				return fmt.Errorf("copy preserved OCI platform %s: %w", FormatPlatform(platform.Platform), copyErr)
			}
			entry, mapErr := descriptorMap(desc)
			if mapErr != nil {
				return mapErr
			}
			preservedManifests = append(preservedManifests, entry)
		}
	} else {
		preservedManifests, err = exportPreservedPlatformsToOutput(ctx,
			outputDir,
			preservedSourceRef,
			preservedPlatforms,
			make(map[string]bool),
		)
	}
	if err != nil {
		return fmt.Errorf("failed to export preserved platforms: %w", err)
	}
	if len(preservedManifests) == 0 {
		return fmt.Errorf("no manifests to include in preserved-only OCI layout")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return createFinalOCILayout(outputDir, preservedManifests, exportOpts.IndexAnnotations)
}

func preservedPlatformsSourceRef(results []types.PatchResult, exportOpts OCILayoutExportOptions) reference.Named {
	if exportOpts.PreservedSourceRef != nil {
		return exportOpts.PreservedSourceRef
	}

	for _, result := range results {
		if result.OriginalRef != nil {
			return result.OriginalRef
		}
	}
	return nil
}
