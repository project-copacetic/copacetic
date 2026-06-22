package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client/llb"
	mobyimage "github.com/moby/moby/api/types/image"
	dockerClient "github.com/moby/moby/client"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	log "github.com/sirupsen/logrus"
)

const (
	PkgTypeLibrary = "library"
	PkgTypeOS      = "os"

	PatchTypeMajor = "major"
	PatchTypeMinor = "minor"
	PatchTypePatch = "patch"

	// Package types for language managers.
	LangPackages   = "lang-pkgs"
	PythonPackages = "python-pkg"
	NodePackages   = "node-pkg"
	GoModules      = "gomod"
	GoBinary       = "gobinary"
	DotNetPackages = "dotnet-core"

	DefaultTempWorkingFolder = "/tmp"
)

// CanonicalPkgManagerType maps various OS family/type identifiers that may
// appear in scanner outputs (e.g. Trivy) to the canonical package manager
// type strings used by Copacetic and expected in purl identifiers within
// generated VEX documents. If the provided value is already canonical or an
// unknown value, it is returned unchanged.
//
// Examples:
//
//	alpine              -> apk
//	debian              -> deb
//	ubuntu              -> deb
//	centos              -> rpm
//	almalinux           -> rpm
//	rocky               -> rpm
//	redhat              -> rpm
//	amazon              -> rpm
//	oracle              -> rpm
//	cbl-mariner         -> rpm
//	sles                -> rpm
//	opensuse-leap       -> rpm
//	opensuse-tumbleweed -> rpm
func CanonicalPkgManagerType(raw string) string {
	// Normalize once for matching; we still return the original raw when already canonical
	lowered := strings.ToLower(raw)
	switch lowered { // normalize case defensively
	case OSTypeAlpine:
		return "apk"
	case OSTypeDebian, OSTypeUbuntu:
		return "deb"
	case OSTypeCBLMariner, OSTypeAzureLinux, OSTypeCentOS, OSTypeOracle, OSTypeRedHat, OSTypeRocky, OSTypeAmazon, OSTypeAlma, OSTypeAlmaLinux:
		return "rpm"
	case OSTypeSLES, OSTypeOpenSUSELeap, OSTypeOpenSUSETW:
		return "rpm"
	default:
		return raw
	}
}

// DeduplicateStringSlice removes duplicate strings from a slice while preserving order.
func DeduplicateStringSlice(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func EnsurePath(path string, perm fs.FileMode) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(path, perm)
			return err == nil, err
		}
		return false, err
	}

	if !st.IsDir() {
		return false, fs.ErrExist
	}
	if st.Mode().Perm() != perm {
		return false, fs.ErrPermission
	}
	return false, nil
}

func IsNonEmptyFile(dir, file string) bool {
	p := filepath.Join(dir, file)
	info, err := os.Stat(p)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir() && info.Size() > 0
}

func IsSUSEImage(osType string) bool {
	if osType == OSTypeSLES || osType == OSTypeOpenSUSELeap || osType == OSTypeOpenSUSETW {
		return true
	}

	return false
}

func getEnvAny(names ...string) string {
	for _, n := range names {
		if val := os.Getenv(n); val != "" {
			return val
		}
	}
	return ""
}

func GetProxy() llb.ProxyEnv {
	proxy := llb.ProxyEnv{
		HTTPProxy:  getEnvAny("HTTP_PROXY"),
		HTTPSProxy: getEnvAny("HTTPS_PROXY"),
		NoProxy:    getEnvAny("NO_PROXY"),
		AllProxy:   getEnvAny("HTTP_PROXY"),
	}
	return proxy
}

// localImageDescriptor tries to get the OCI image descriptor using the local Docker client.
func localImageDescriptor(ctx context.Context, imageRef string) (*ocispec.Descriptor, error) {
	cli, err := newClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	distInspect, err := cli.ImageInspect(ctx, imageRef)
	if err != nil {
		return nil, err
	}

	return distInspect.Descriptor, nil
}

// podmanImageDescriptor tries to get the OCI image descriptor using podman CLI.
func podmanImageDescriptor(ctx context.Context, imageRef string) (*ocispec.Descriptor, error) {
	// Check if podman is available
	if _, err := exec.LookPath("podman"); err != nil {
		return nil, fmt.Errorf("podman not found in PATH: %w", err)
	}

	// Run podman inspect to get image metadata
	cmd := exec.CommandContext(ctx, "podman", "inspect", "--type", "image", imageRef)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Check if it's a "not found" error
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "no such image") || strings.Contains(stderr, "not found") {
				return nil, errdefs.ErrNotFound
			}
		}
		return nil, fmt.Errorf("podman inspect failed: %w", err)
	}

	// Parse the JSON output
	var inspectResults []map[string]interface{}
	if err := json.Unmarshal(output, &inspectResults); err != nil {
		return nil, fmt.Errorf("failed to parse podman inspect output: %w", err)
	}

	if len(inspectResults) == 0 {
		return nil, errdefs.ErrNotFound
	}

	result := inspectResults[0]

	// Extract relevant fields to construct the descriptor
	digestStr, _ := result["Digest"].(string)
	if digestStr == "" {
		digestStr, _ = result["Id"].(string)
		if digestStr != "" && !strings.HasPrefix(digestStr, "sha256:") {
			digestStr = "sha256:" + digestStr
		}
	}

	size := int64(0)
	if sizeVal, ok := result["Size"].(float64); ok {
		size = int64(sizeVal)
	}

	// Get architecture and OS
	architecture := "amd64"
	os := "linux"
	if archVal, ok := result["Architecture"].(string); ok {
		architecture = archVal
	}
	if osVal, ok := result["Os"].(string); ok {
		os = osVal
	}

	// Construct the descriptor
	desc := &ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.Digest(digestStr),
		Size:      size,
		Platform: &ocispec.Platform{
			Architecture: architecture,
			OS:           os,
		},
	}

	return desc, nil
}

// remoteImageDescriptor tries to get the OCI image descriptor from a remote registry.
func remoteImageDescriptor(imageRef string) (*ocispec.Descriptor, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference '%s': %w", imageRef, err)
	}

	ggcrDesc, err := remoteGet(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		log.Debugf("failed to get remote descriptor for %s: %v", imageRef, err)
		return nil, fmt.Errorf("failed to get remote descriptor for '%s': %w", imageRef, err)
	}

	ociDesc := &ocispec.Descriptor{
		MediaType:    string(ggcrDesc.MediaType),
		Size:         ggcrDesc.Size,
		Digest:       digest.Digest(ggcrDesc.Digest.String()),
		URLs:         ggcrDesc.URLs,
		Annotations:  ggcrDesc.Annotations,
		Data:         ggcrDesc.Data,
		ArtifactType: ggcrDesc.ArtifactType,
	}

	if ggcrDesc.Platform != nil {
		ociDesc.Platform = &ocispec.Platform{
			Architecture: ggcrDesc.Platform.Architecture,
			OS:           ggcrDesc.Platform.OS,
			OSVersion:    ggcrDesc.Platform.OSVersion,
			OSFeatures:   ggcrDesc.Platform.OSFeatures,
			Variant:      ggcrDesc.Platform.Variant,
		}
	}
	return ociDesc, nil
}

// GetImageDescriptor retrieves the image descriptor for a given image reference using the specified runtime.
// It first tries to inspect the image using the specified runtime client (local).
// If the image is not found locally or a local error occurs, it tries to get the image descriptor from the remote registry.
// runtime should be imageloader.Docker or imageloader.Podman.
func GetImageDescriptor(ctx context.Context, imageRef, runtime string) (*ocispec.Descriptor, error) {
	log.Debugf("Attempting to get local image descriptor for %s using runtime %s", imageRef, runtime)

	var localDesc *ocispec.Descriptor
	var localErr error

	switch runtime {
	case imageloader.Podman:
		localDesc, localErr = podmanImageDescriptor(ctx, imageRef)
	default:
		// Default to Docker
		localDesc, localErr = localImageDescriptor(ctx, imageRef)
	}

	if localErr == nil {
		log.Debugf("found local image descriptor for %s via %s", imageRef, runtime)
		return localDesc, nil
	}

	isNotFoundError := errdefs.IsNotFound(localErr)
	if isNotFoundError {
		log.Debugf("image %s not found locally in %s (error: %v), trying remote.", imageRef, runtime, localErr)
	} else {
		log.Warnf("local descriptor lookup for %s failed in %s (error: %v), trying remote.", imageRef, runtime, localErr)
	}

	log.Debugf("attempting to get remote image descriptor for %s", imageRef)
	remoteDesc, remoteErr := remoteImageDescriptor(imageRef)
	if remoteErr != nil {
		log.Errorf("failed to get remote image descriptor for %s: %v", imageRef, remoteErr)
		if isNotFoundError {
			return nil, fmt.Errorf("image '%s' not found locally and remote lookup failed: %w", imageRef, remoteErr)
		}
		return nil, fmt.Errorf("local lookup for '%s' failed (error: %v) and remote lookup also failed (error: %v)", imageRef, localErr, remoteErr)
	}

	log.Infof("found remote image descriptor for %s", imageRef)
	return remoteDesc, nil
}

// GetIndexManifestAnnotations retrieves annotations from an image index manifest.
// This is specifically for multi-platform images to get the index-level annotations.
// For single-platform manifests, it returns the annotations from the manifest body
// (NOT desc.Annotations, which is empty for top-level lookups since there is no
// parent index entry to inherit annotations from).
//
// The local image store is checked first via the Docker daemon; if the image is
// present locally, its index-level annotations are returned from there and the
// remote registry is not contacted. Only when the image is not available locally
// does this function fall back to a remote registry lookup.
func GetIndexManifestAnnotations(ctx context.Context, imageRef string) (map[string]string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference '%s': %w", imageRef, err)
	}

	// Prefer the local image store: if the image is present locally, read its
	// index-level annotations from there and skip the remote registry entirely.
	local, ok, err := localIndexManifestAnnotations(ctx, imageRef)
	if err != nil {
		log.Debugf("local index annotation lookup for '%s' returned error: %v", imageRef, err)
	}
	if ok {
		log.Debugf("Using local index annotations for '%s'", imageRef)
		return local, nil
	}

	// Fall back to the remote registry
	desc, err := remoteGet(
		ref,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get descriptor for '%s': %w", imageRef, err)
	}

	// Check if this is an index manifest
	if desc.MediaType != types.OCIImageIndex && desc.MediaType != types.DockerManifestList {
		log.Debugf("Image %s is not a multi-platform image (media type: %s)", imageRef, desc.MediaType)
		// For single-platform images, parse the manifest body to extract its
		// annotations. desc.Annotations is empty here because the descriptor
		// returned by remote.Get for a top-level reference has no parent index
		// entry to inherit annotations from.
		return parseManifestBodyAnnotations(desc.Manifest)
	}

	// Fetch the actual index
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("failed to get image index for '%s': %w", imageRef, err)
	}

	// Get the index manifest
	indexManifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get index manifest for '%s': %w", imageRef, err)
	}

	return indexManifest.Annotations, nil
}

// GetPlatformManifestAnnotations retrieves manifest-level annotations for a specific platform
// from an image index manifest. For single-platform images (no index), it parses the manifest
// body to extract its annotations rather than returning nil — annotations on a single-platform
// manifest live in the manifest body, not in the descriptor returned by a top-level fetch.
//
// The local image store is checked first via the Docker daemon; if the image is
// present locally, the matching platform's manifest-level annotations are returned
// from there and the remote registry is not contacted. Only when the image is not
// available locally does this function fall back to a remote registry lookup.
func GetPlatformManifestAnnotations(ctx context.Context, imageRef string, targetPlatform *ocispec.Platform) (map[string]string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference '%s': %w", imageRef, err)
	}

	// Prefer the local image store: if the image is present locally, extract
	// the platform-specific manifest-level annotations from there and skip the
	// remote registry entirely.
	local, ok, err := localPlatformManifestAnnotations(ctx, imageRef, targetPlatform)
	if err != nil {
		log.Debugf("local platform annotation lookup for '%s' returned error: %v", imageRef, err)
	}
	if ok {
		log.Debugf("Using local manifest annotations for '%s'", imageRef)
		return local, nil
	}

	// Fall back to the remote registry
	desc, err := remoteGet(
		ref,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get descriptor for '%s': %w", imageRef, err)
	}

	// Check if this is an index manifest
	if desc.MediaType != types.OCIImageIndex && desc.MediaType != types.DockerManifestList {
		log.Debugf("Image %s is not a multi-platform image (media type: %s)", imageRef, desc.MediaType)
		// For single-platform images, parse the manifest body to extract its
		// annotations. desc.Annotations is empty here because the descriptor
		// returned by remote.Get for a top-level reference has no parent index
		// entry to inherit annotations from.
		return parseManifestBodyAnnotations(desc.Manifest)
	}

	// Fetch the actual index
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("failed to get image index for '%s': %w", imageRef, err)
	}

	// Get the index manifest
	indexManifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get index manifest for '%s': %w", imageRef, err)
	}

	// Find the matching platform in the manifest list
	for i := range indexManifest.Manifests {
		manifest := &indexManifest.Manifests[i]
		if manifest.Platform == nil {
			continue
		}

		// Compare platforms (normalize variants for comparison)
		manifestPlatform := ocispec.Platform{
			OS:           manifest.Platform.OS,
			Architecture: manifest.Platform.Architecture,
			Variant:      manifest.Platform.Variant,
		}

		// Use containerd's OnlyStrict matcher which handles variant normalization
		// including arm64/v8 matching arm64 (empty variant)
		matcher := platforms.OnlyStrict(*targetPlatform)
		if matcher.Match(manifestPlatform) {
			// Return the manifest-level annotations for this platform
			if manifest.Annotations != nil {
				return manifest.Annotations, nil
			}
			return map[string]string{}, nil
		}
	}

	return nil, fmt.Errorf("platform %s/%s/%s not found in image index", targetPlatform.OS, targetPlatform.Architecture, targetPlatform.Variant)
}

// parseManifestBodyAnnotations extracts the top-level "annotations" field from a raw
// OCI/Docker image manifest body. The remote registry returns the manifest body in
// remote.Descriptor.Manifest; this avoids a second registry round-trip vs calling
// desc.Image() then img.Manifest().
func parseManifestBodyAnnotations(manifestBody []byte) (map[string]string, error) {
	if len(manifestBody) == 0 {
		return map[string]string{}, nil
	}
	var m struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(manifestBody, &m); err != nil {
		return nil, fmt.Errorf("failed to parse manifest body annotations: %w", err)
	}
	if m.Annotations == nil {
		return map[string]string{}, nil
	}
	return m.Annotations, nil
}

// inspectLocalImage runs ImageInspect with ImageInspectWithManifests(true) to
// get the richest possible response (including per-platform manifest entries
// when the daemon uses a multi-platform image store). If the daemon rejects
// that option (e.g. Docker API < 1.48), it transparently retries with a plain
// inspect so callers can still detect that the image is present locally.
func inspectLocalImage(ctx context.Context, imageRef string) (*mobyimage.InspectResponse, error) {
	cli, err := newClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	inspect, err := cli.ImageInspect(ctx, imageRef, dockerClient.ImageInspectWithManifests(true))
	if err == nil {
		return &inspect.InspectResponse, nil
	}
	log.Debugf("ImageInspect with manifests failed for %s (%v); retrying without manifests option", imageRef, err)

	plain, err := cli.ImageInspect(ctx, imageRef)
	if err != nil {
		return nil, err
	}
	return &plain.InspectResponse, nil
}

// localPlatformManifestAnnotations attempts to read the manifest-level annotations
// for a specific platform from the local Docker image store. Returns (annotations,
// true, nil) when the image was found locally (even if no annotations are present,
// in which case an empty map is returned). The second return value indicates that
// the local lookup succeeded; callers should not fall back to a remote registry in
// that case. Returns (nil, false, err) when the image is not available locally via
// the Docker daemon.
func localPlatformManifestAnnotations(ctx context.Context, imageRef string, targetPlatform *ocispec.Platform) (map[string]string, bool, error) {
	inspect, err := inspectLocalImage(ctx, imageRef)
	if err != nil {
		return nil, false, err
	}

	// Multi-platform image: search the per-platform manifest list.
	if len(inspect.Manifests) > 0 && targetPlatform != nil {
		matcher := platforms.OnlyStrict(*targetPlatform)
		for i := range inspect.Manifests {
			m := &inspect.Manifests[i]
			if m.Kind != mobyimage.ManifestKindImage || m.ImageData == nil {
				continue
			}
			if !m.Available {
				continue
			}
			if matcher.Match(m.ImageData.Platform) {
				if m.Descriptor.Annotations != nil {
					return m.Descriptor.Annotations, true, nil
				}
				return map[string]string{}, true, nil
			}
		}
	}

	// Single-platform image (or daemon without multi-platform store): fall back
	// to the top-level descriptor when available.
	if inspect.Descriptor != nil && inspect.Descriptor.Annotations != nil {
		return inspect.Descriptor.Annotations, true, nil
	}
	return map[string]string{}, true, nil
}

// localIndexManifestAnnotations attempts to read the index-level annotations
// for a multi-platform image from the local Docker image store. Returns
// (annotations, true, nil) when the image was found locally. The second return
// value indicates that the local lookup succeeded; callers should not fall back
// to a remote registry in that case.
func localIndexManifestAnnotations(ctx context.Context, imageRef string) (map[string]string, bool, error) {
	inspect, err := inspectLocalImage(ctx, imageRef)
	if err != nil {
		return nil, false, err
	}

	if inspect.Descriptor != nil && inspect.Descriptor.Annotations != nil {
		return inspect.Descriptor.Annotations, true, nil
	}
	return map[string]string{}, true, nil
}

// LocalImagePlatforms returns the list of platforms present in the local Docker
// image store for the given image reference. The second return value indicates
// whether the image was found locally; callers should not fall back to a remote
// registry when ok is true. For single-platform local images, a one-element
// slice is returned. For multi-platform images (only available when the daemon
// uses a multi-platform image store), one entry per image manifest is returned.
func LocalImagePlatforms(ctx context.Context, imageRef string) ([]ocispec.Platform, bool, error) {
	inspect, err := inspectLocalImage(ctx, imageRef)
	if err != nil {
		return nil, false, err
	}

	// Multi-platform image store: collect each image manifest's platform.
	if len(inspect.Manifests) > 0 {
		var out []ocispec.Platform
		for i := range inspect.Manifests {
			m := &inspect.Manifests[i]
			if m.Kind != mobyimage.ManifestKindImage || m.ImageData == nil {
				continue
			}
			if !m.Available {
				continue
			}
			p := m.ImageData.Platform
			if p.OS == "" || p.OS == "unknown" || p.Architecture == "" || p.Architecture == "unknown" {
				continue
			}
			out = append(out, p)
		}
		if len(out) > 0 {
			return out, true, nil
		}
	}

	// Single-platform image: fall back to the top-level inspect fields.
	if inspect.Architecture != "" && inspect.Os != "" {
		return []ocispec.Platform{{
			OS:           inspect.Os,
			Architecture: inspect.Architecture,
			Variant:      inspect.Variant,
			OSVersion:    inspect.OsVersion,
		}}, true, nil
	}
	return nil, false, nil
}

// LocalPlatformDescriptor returns the OCI descriptor for a specific platform
// from a multi-platform image present in the local Docker image store. The
// second return value indicates whether the image was found locally; callers
// should not fall back to a remote registry when ok is true.
//
// When ok is true but the returned descriptor is nil, the image is present
// locally but does not contain a matching platform (either because the daemon
// does not expose per-platform manifest entries — e.g. legacy snapshotter —
// or because the requested platform is not represented in the image).
func LocalPlatformDescriptor(ctx context.Context, imageRef string, targetPlatform *ocispec.Platform) (*ocispec.Descriptor, bool, error) {
	inspect, err := inspectLocalImage(ctx, imageRef)
	if err != nil {
		return nil, false, err
	}

	if len(inspect.Manifests) > 0 && targetPlatform != nil {
		matcher := platforms.OnlyStrict(*targetPlatform)
		for i := range inspect.Manifests {
			m := &inspect.Manifests[i]
			if m.Kind != mobyimage.ManifestKindImage || m.ImageData == nil {
				continue
			}
			if !m.Available {
				continue
			}
			if matcher.Match(m.ImageData.Platform) {
				d := m.Descriptor
				return &d, true, nil
			}
		}
	}

	// Image is local but per-platform manifest summaries aren't available.
	return nil, true, nil
}
