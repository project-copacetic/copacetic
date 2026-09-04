package ocilayout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	contentlocal "github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	annotationImageName      = "io.containerd.image.name"
	architectureARM64        = "arm64"
	dockerMediaTypeIndex     = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerMediaTypeManifest  = "application/vnd.docker.distribution.manifest.v2+json"
	dockerMediaTypeConfig    = "application/vnd.docker.container.image.v1+json"
	dockerMediaTypeLayer     = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	dockerMediaTypeLayerRaw  = "application/vnd.docker.image.rootfs.diff.tar"
	dockerMediaTypeForeign   = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
	dockerMediaTypeForeignZs = "application/vnd.docker.image.rootfs.foreign.diff.tar.zstd"
	ociMediaTypeForeign      = "application/vnd.oci.image.layer.nondistributable.v1.tar"
	ociMediaTypeForeignGzip  = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
	ociMediaTypeForeignZstd  = "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd"
	unknownPlatformField     = "unknown"
)

// Source is one validated, immutable image selected from an OCI Image Layout.
// Store is intentionally exposed only through methods that attach it to a
// BuildKit session; callers should use the metadata helpers for local reads.
type Source struct {
	Path       string
	StoreID    string
	Reference  reference.Named
	Descriptor ocispec.Descriptor

	store content.Store
}

// Open validates an OCI Image Layout, resolves the logical image selector, and
// opens its blobs as a client-side BuildKit content store.
func Open(ctx context.Context, inputPath, outputPath, selector string) (*Source, error) {
	input, err := canonicalExistingDirectory(inputPath)
	if err != nil {
		return nil, fmt.Errorf("invalid OCI layout input %q: %w", inputPath, err)
	}
	if outputPath != "" {
		output, err := canonicalTargetPath(outputPath)
		if err != nil {
			return nil, fmt.Errorf("resolve OCI layout output %q: %w", outputPath, err)
		}
		if pathsOverlap(input, output) {
			return nil, fmt.Errorf("OCI layout input %q and output %q must be distinct, non-overlapping directories", input, output)
		}
	}

	layoutData, err := readLayoutMetadata(input, ocispec.ImageLayoutFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", ocispec.ImageLayoutFile, err)
	}
	var layout ocispec.ImageLayout
	if err := json.Unmarshal(layoutData, &layout); err != nil {
		return nil, fmt.Errorf("parse %s: %w", ocispec.ImageLayoutFile, err)
	}
	if layout.Version != ocispec.ImageLayoutVersion {
		return nil, fmt.Errorf("unsupported OCI image layout version %q in %s (expected %q)", layout.Version, ocispec.ImageLayoutFile, ocispec.ImageLayoutVersion)
	}

	indexData, err := readLayoutMetadata(input, ocispec.ImageIndexFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", ocispec.ImageIndexFile, err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(indexData, &index); err != nil {
		return nil, fmt.Errorf("parse %s: %w", ocispec.ImageIndexFile, err)
	}
	if index.SchemaVersion != 2 {
		return nil, fmt.Errorf("invalid %s schemaVersion %d (expected 2)", ocispec.ImageIndexFile, index.SchemaVersion)
	}
	if index.MediaType != "" && index.MediaType != ocispec.MediaTypeImageIndex {
		return nil, fmt.Errorf("invalid %s mediaType %q (expected %q)", ocispec.ImageIndexFile, index.MediaType, ocispec.MediaTypeImageIndex)
	}
	if len(index.Manifests) == 0 {
		return nil, fmt.Errorf("%s contains no image descriptors", ocispec.ImageIndexFile)
	}

	named, err := reference.ParseNormalizedNamed(selector)
	if err != nil {
		return nil, fmt.Errorf("parse OCI layout image selector %q: %w", selector, err)
	}
	desc, err := selectDescriptor(index.Manifests, selector, named)
	if err != nil {
		return nil, err
	}
	if !isImageManifest(desc.MediaType) && !isImageIndex(desc.MediaType) {
		return nil, fmt.Errorf("selected descriptor %s has unsupported image mediaType %q", desc.Digest, desc.MediaType)
	}

	store, err := contentlocal.NewStore(input)
	if err != nil {
		return nil, fmt.Errorf("open OCI layout content store: %w", err)
	}
	pathSum := sha256.Sum256([]byte(input + "\x00" + desc.Digest.String()))
	source := &Source{
		Path:       input,
		StoreID:    "copa-oci-" + hex.EncodeToString(pathSum[:8]),
		Reference:  named,
		Descriptor: desc,
		store:      store,
	}
	if err := source.validateReachableImage(ctx, &desc); err != nil {
		return nil, fmt.Errorf("validate selected OCI image %s: %w", desc.Digest, err)
	}
	return source, nil
}

func readLayoutMetadata(root, name string) ([]byte, error) {
	path := filepath.Join(root, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("must be a regular file")
	}
	return os.ReadFile(path)
}

func canonicalExistingDirectory(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path is not a directory")
	}
	return filepath.Clean(resolved), nil
}

func canonicalTargetPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved), nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	parent := filepath.Dir(abs)
	for {
		resolvedParent, err := filepath.EvalSymlinks(parent)
		if err == nil {
			rel, relErr := filepath.Rel(parent, abs)
			if relErr != nil {
				return "", relErr
			}
			return filepath.Clean(filepath.Join(resolvedParent, rel)), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		next := filepath.Dir(parent)
		if next == parent {
			return "", err
		}
		parent = next
	}
}

func pathsOverlap(left, right string) bool {
	rel, err := filepath.Rel(left, right)
	if err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))) {
		return true
	}
	rel, err = filepath.Rel(right, left)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

func selectDescriptor(descriptors []ocispec.Descriptor, rawSelector string, named reference.Named) (ocispec.Descriptor, error) {
	if digested, ok := named.(reference.Digested); ok {
		matches := descriptorsMatching(descriptors, func(desc ocispec.Descriptor) bool {
			return desc.Digest == digested.Digest()
		})
		return requireUniqueSelection(matches, "digest "+digested.Digest().String(), descriptors)
	}

	normalized := named.String()
	familiar := reference.FamiliarString(named)
	nameMatches := descriptorsMatching(descriptors, func(desc ocispec.Descriptor) bool {
		value := desc.Annotations[annotationImageName]
		return value != "" && (value == rawSelector || value == normalized || value == familiar)
	})
	if len(nameMatches) > 0 {
		return requireUniqueSelection(nameMatches, "name "+normalized, descriptors)
	}

	if tagged, ok := named.(reference.Tagged); ok {
		tag := tagged.Tag()
		tagMatches := descriptorsMatching(descriptors, func(desc ocispec.Descriptor) bool {
			value := desc.Annotations[ocispec.AnnotationRefName]
			return value == tag || value == rawSelector || value == normalized || value == familiar
		})
		if len(tagMatches) > 0 {
			return requireUniqueSelection(tagMatches, "tag "+tag, descriptors)
		}
	}

	if len(descriptors) == 1 {
		return descriptors[0], nil
	}
	return ocispec.Descriptor{}, fmt.Errorf("OCI layout selector %q is ambiguous or unavailable; choose one of: %s", rawSelector, availableDescriptors(descriptors))
}

func descriptorsMatching(descriptors []ocispec.Descriptor, match func(ocispec.Descriptor) bool) []ocispec.Descriptor {
	var matches []ocispec.Descriptor
	for _, desc := range descriptors {
		if match(desc) {
			matches = append(matches, desc)
		}
	}
	return matches
}

func requireUniqueSelection(matches []ocispec.Descriptor, selector string, all []ocispec.Descriptor) (ocispec.Descriptor, error) {
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) == 0 {
		return ocispec.Descriptor{}, fmt.Errorf("OCI layout contains no descriptor matching %s; available descriptors: %s", selector, availableDescriptors(all))
	}
	return ocispec.Descriptor{}, fmt.Errorf("OCI layout contains %d descriptors matching %s; available descriptors: %s", len(matches), selector, availableDescriptors(matches))
}

func availableDescriptors(descriptors []ocispec.Descriptor) string {
	available := make([]string, 0, len(descriptors))
	for _, desc := range descriptors {
		parts := []string{"digest=" + desc.Digest.String()}
		if name := desc.Annotations[annotationImageName]; name != "" {
			parts = append(parts, "name="+name)
		}
		if tag := desc.Annotations[ocispec.AnnotationRefName]; tag != "" {
			parts = append(parts, "tag="+tag)
		}
		available = append(available, strings.Join(parts, ","))
	}
	sort.Strings(available)
	return strings.Join(available, "; ")
}

func isImageIndex(mediaType string) bool {
	return mediaType == ocispec.MediaTypeImageIndex || mediaType == dockerMediaTypeIndex
}

func isImageManifest(mediaType string) bool {
	return mediaType == ocispec.MediaTypeImageManifest || mediaType == dockerMediaTypeManifest
}

func isImageConfig(mediaType string) bool {
	return mediaType == ocispec.MediaTypeImageConfig || mediaType == dockerMediaTypeConfig
}

func isImageLayer(mediaType string) bool {
	switch mediaType {
	case ocispec.MediaTypeImageLayer,
		ocispec.MediaTypeImageLayerGzip,
		ocispec.MediaTypeImageLayerZstd,
		ociMediaTypeForeign,
		ociMediaTypeForeignGzip,
		ociMediaTypeForeignZstd,
		dockerMediaTypeLayer,
		dockerMediaTypeLayerRaw,
		dockerMediaTypeForeign,
		dockerMediaTypeForeignZs:
		return true
	default:
		return false
	}
}

func (s *Source) validateReachableImage(ctx context.Context, desc *ocispec.Descriptor) error {
	switch {
	case isImageIndex(desc.MediaType):
		var index ocispec.Index
		if err := s.readJSONBlob(ctx, desc, &index); err != nil {
			return fmt.Errorf("read image index: %w", err)
		}
		if index.SchemaVersion != 2 {
			return fmt.Errorf("image index %s has schemaVersion %d (expected 2)", desc.Digest, index.SchemaVersion)
		}
		for _, child := range index.Manifests {
			if isImageIndex(child.MediaType) {
				if err := s.validateReachableImage(ctx, &child); err != nil {
					return fmt.Errorf("descriptor %s: %w", child.Digest, err)
				}
				continue
			}
			if !isImageManifest(child.MediaType) || child.ArtifactType != "" || child.Platform == nil ||
				child.Platform.OS == unknownPlatformField || child.Platform.Architecture == unknownPlatformField {
				continue
			}
			if err := s.validateReachableImage(ctx, &child); err != nil {
				return fmt.Errorf("descriptor %s: %w", child.Digest, err)
			}
		}
		return nil
	case isImageManifest(desc.MediaType):
		var manifest ocispec.Manifest
		if err := s.readJSONBlob(ctx, desc, &manifest); err != nil {
			return fmt.Errorf("read image manifest: %w", err)
		}
		if manifest.SchemaVersion != 2 {
			return fmt.Errorf("image manifest %s has schemaVersion %d (expected 2)", desc.Digest, manifest.SchemaVersion)
		}
		if !isImageConfig(manifest.Config.MediaType) {
			return fmt.Errorf("image manifest %s has unsupported config mediaType %q", desc.Digest, manifest.Config.MediaType)
		}
		if err := s.validateBlob(ctx, &manifest.Config); err != nil {
			return fmt.Errorf("config %s: %w", manifest.Config.Digest, err)
		}
		for i := range manifest.Layers {
			layer := &manifest.Layers[i]
			if !isImageLayer(layer.MediaType) {
				return fmt.Errorf("image manifest %s has unsupported layer mediaType %q", desc.Digest, layer.MediaType)
			}
			if err := s.validateBlob(ctx, layer); err != nil {
				return fmt.Errorf("layer %s: %w", layer.Digest, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported image mediaType %q", desc.MediaType)
	}
}

func (s *Source) validateBlob(ctx context.Context, desc *ocispec.Descriptor) error {
	if err := desc.Digest.Validate(); err != nil {
		return fmt.Errorf("invalid digest %q: %w", desc.Digest, err)
	}
	if desc.Size < 0 {
		return fmt.Errorf("invalid negative size %d", desc.Size)
	}
	if err := s.validateBlobPath(desc.Digest); err != nil {
		return err
	}
	ra, err := s.store.ReaderAt(ctx, *desc)
	if err != nil {
		return fmt.Errorf("open blob: %w", err)
	}
	defer ra.Close()
	if ra.Size() != desc.Size {
		return fmt.Errorf("size mismatch: descriptor declares %d bytes, blob contains %d", desc.Size, ra.Size())
	}
	verifier := desc.Digest.Verifier()
	if _, err := io.Copy(verifier, content.NewReader(ra)); err != nil {
		return fmt.Errorf("read blob: %w", err)
	}
	if !verifier.Verified() {
		return fmt.Errorf("digest mismatch: blob content does not match %s", desc.Digest)
	}
	return nil
}

func (s *Source) validateBlobPath(dgst digest.Digest) error {
	blobPath := filepath.Join(s.Path, "blobs", dgst.Algorithm().String(), dgst.Encoded())
	resolved, err := filepath.EvalSymlinks(blobPath)
	if err != nil {
		return fmt.Errorf("resolve blob path %s: %w", dgst, err)
	}
	blobRoot := filepath.Join(s.Path, "blobs")
	rel, err := filepath.Rel(blobRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("blob %s resolves outside OCI layout blob directory", dgst)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("stat blob path %s: %w", dgst, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("blob %s is not a regular file", dgst)
	}
	return nil
}

func (s *Source) readJSONBlob(ctx context.Context, desc *ocispec.Descriptor, target any) error {
	if err := s.validateBlob(ctx, desc); err != nil {
		return err
	}
	data, err := content.ReadBlob(ctx, s.store, *desc)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("parse %s: %w", desc.Digest, err)
	}
	return nil
}

// ResolveReference returns the immutable dummy reference used by BuildKit's
// OCI source resolver. The logical repository name is retained for logs and
// VEX identity while the selected layout digest fixes the source content.
func (s *Source) ResolveReference() (string, error) {
	named := reference.TrimNamed(s.Reference)
	withDigest, err := reference.WithDigest(named, s.Descriptor.Digest)
	if err != nil {
		return "", fmt.Errorf("attach selected OCI digest to logical image name: %w", err)
	}
	return withDigest.String(), nil
}

// ResolveImageConfig resolves an image config through the client-side OCI
// store, including platform selection for a selected image index.
func (s *Source) ResolveImageConfig(ctx context.Context, gateway interface {
	ResolveImageConfig(context.Context, string, sourceresolver.Opt) (string, digest.Digest, []byte, error)
}, platform *ocispec.Platform,
) ([]byte, error) {
	ref, err := s.ResolveReference()
	if err != nil {
		return nil, err
	}
	_, _, config, err := gateway.ResolveImageConfig(ctx, ref, sourceresolver.Opt{
		OCILayoutOpt: &sourceresolver.ResolveOCILayoutOpt{
			Platform: platform,
			Store: sourceresolver.ResolveImageConfigOptStore{
				StoreID: s.StoreID,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("resolve OCI layout image config for %s: %w", ref, err)
	}
	return config, nil
}

// State returns an LLB source state bound to this client-side OCI store.
func (s *Source) State(platform *ocispec.Platform, config []byte) (llb.State, error) {
	ref, err := s.ResolveReference()
	if err != nil {
		return llb.State{}, err
	}
	opts := []llb.OCILayoutOption{llb.OCIStore("", s.StoreID)}
	if platform != nil {
		opts = append(opts, llb.Platform(*platform))
	}
	return llb.OCILayout(ref, opts...).WithImageConfig(config)
}

// AddToSolveOpt exposes the layout content store through the BuildKit session.
// This is what allows a remote BuildKit daemon to consume a client-local path.
func (s *Source) AddToSolveOpt(opt *client.SolveOpt) {
	if s == nil || opt == nil {
		return
	}
	if opt.OCIStores == nil {
		opt.OCIStores = make(map[string]content.Store)
	}
	opt.OCIStores[s.StoreID] = s.store
}

// Platforms discovers patchable platforms without any daemon or registry
// lookup. Non-image and unknown/unknown index entries are ignored.
func (s *Source) Platforms(ctx context.Context) ([]ocispec.Platform, error) {
	if isImageIndex(s.Descriptor.MediaType) {
		index, err := s.selectedIndex(ctx)
		if err != nil {
			return nil, err
		}
		var found []ocispec.Platform
		for _, desc := range index.Manifests {
			if !isImageManifest(desc.MediaType) || desc.Platform == nil {
				continue
			}
			if desc.Platform.OS == unknownPlatformField || desc.Platform.Architecture == unknownPlatformField {
				continue
			}
			platform := platforms.Normalize(*desc.Platform)
			if platform.Architecture == architectureARM64 && platform.Variant == "v8" {
				platform.Variant = ""
			}
			found = append(found, platform)
		}
		if len(found) == 0 {
			return nil, fmt.Errorf("selected OCI image index %s contains no patchable platform manifests", s.Descriptor.Digest)
		}
		return found, nil
	}

	manifest, err := s.selectedManifest(ctx, &s.Descriptor)
	if err != nil {
		return nil, err
	}
	var image ocispec.Image
	if err := s.readJSONBlob(ctx, &manifest.Config, &image); err != nil {
		return nil, fmt.Errorf("read image config platform: %w", err)
	}
	platform := platforms.Normalize(ocispec.Platform{
		OS:           image.OS,
		Architecture: image.Architecture,
		Variant:      image.Variant,
		OSVersion:    image.OSVersion,
		OSFeatures:   image.OSFeatures,
	})
	if platform.OS == "" || platform.Architecture == "" {
		return nil, fmt.Errorf("selected image config %s does not declare os and architecture", manifest.Config.Digest)
	}
	if platform.Architecture == architectureARM64 && platform.Variant == "v8" {
		platform.Variant = ""
	}
	return []ocispec.Platform{platform}, nil
}

func (s *Source) selectedIndex(ctx context.Context) (*ocispec.Index, error) {
	if !isImageIndex(s.Descriptor.MediaType) {
		return nil, fmt.Errorf("selected OCI descriptor %s is not an image index", s.Descriptor.Digest)
	}
	var index ocispec.Index
	if err := s.readJSONBlob(ctx, &s.Descriptor, &index); err != nil {
		return nil, err
	}
	return &index, nil
}

func (s *Source) selectedManifest(ctx context.Context, desc *ocispec.Descriptor) (*ocispec.Manifest, error) {
	if !isImageManifest(desc.MediaType) {
		return nil, fmt.Errorf("descriptor %s is not an image manifest", desc.Digest)
	}
	var manifest ocispec.Manifest
	if err := s.readJSONBlob(ctx, desc, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// PlatformDescriptor returns the exact selected manifest descriptor for a
// platform, preserving its digest, media type, size, annotations, and platform.
func (s *Source) PlatformDescriptor(ctx context.Context, target *ocispec.Platform) (*ocispec.Descriptor, error) {
	if !isImageIndex(s.Descriptor.MediaType) {
		desc := s.Descriptor
		if desc.Platform == nil && target != nil {
			platform := *target
			desc.Platform = &platform
		}
		return &desc, nil
	}
	index, err := s.selectedIndex(ctx)
	if err != nil {
		return nil, err
	}
	var match *ocispec.Descriptor
	for i := range index.Manifests {
		desc := &index.Manifests[i]
		if !isImageManifest(desc.MediaType) || desc.Platform == nil || target == nil {
			continue
		}
		if platformEqual(desc.Platform, target) {
			if match != nil {
				return nil, fmt.Errorf("selected OCI image index contains multiple descriptors for platform %s", platforms.Format(*target))
			}
			copy := *desc
			match = &copy
		}
	}
	if match == nil {
		return nil, fmt.Errorf("selected OCI image index contains no descriptor for platform %s", platforms.Format(*target))
	}
	return match, nil
}

func platformEqual(leftPlatform, rightPlatform *ocispec.Platform) bool {
	left := platforms.Normalize(*leftPlatform)
	right := platforms.Normalize(*rightPlatform)
	if left.Architecture == architectureARM64 && left.Variant == "v8" {
		left.Variant = ""
	}
	if right.Architecture == architectureARM64 && right.Variant == "v8" {
		right.Variant = ""
	}
	return left.OS == right.OS && left.Architecture == right.Architecture && left.Variant == right.Variant && left.OSVersion == right.OSVersion
}

// PlatformAnnotations returns manifest-body and descriptor annotations for the
// selected platform. Descriptor annotations win on duplicate keys.
func (s *Source) PlatformAnnotations(ctx context.Context, target *ocispec.Platform) (map[string]string, error) {
	desc, err := s.PlatformDescriptor(ctx, target)
	if err != nil {
		return nil, err
	}
	manifest, err := s.selectedManifest(ctx, desc)
	if err != nil {
		return nil, err
	}
	annotations := maps.Clone(manifest.Annotations)
	if annotations == nil {
		annotations = make(map[string]string)
	}
	maps.Copy(annotations, desc.Annotations)
	return annotations, nil
}

// IndexAnnotations returns annotations from the selected image-index body.
func (s *Source) IndexAnnotations(ctx context.Context) (map[string]string, error) {
	if !isImageIndex(s.Descriptor.MediaType) {
		return nil, nil
	}
	index, err := s.selectedIndex(ctx)
	if err != nil {
		return nil, err
	}
	return maps.Clone(index.Annotations), nil
}

// CopyPlatform copies one platform manifest and its config/layers byte-for-byte
// into an output layout and returns the unchanged manifest descriptor.
func (s *Source) CopyPlatform(ctx context.Context, outputDir string, target *ocispec.Platform, copied map[string]bool) (*ocispec.Descriptor, error) {
	desc, err := s.PlatformDescriptor(ctx, target)
	if err != nil {
		return nil, err
	}
	manifest, err := s.selectedManifest(ctx, desc)
	if err != nil {
		return nil, err
	}
	for _, blob := range append([]ocispec.Descriptor{*desc, manifest.Config}, manifest.Layers...) {
		if err := s.copyBlob(ctx, outputDir, &blob, copied); err != nil {
			return nil, err
		}
	}
	return desc, nil
}

func (s *Source) copyBlob(ctx context.Context, outputDir string, desc *ocispec.Descriptor, copied map[string]bool) error {
	rel := filepath.Join(desc.Digest.Algorithm().String(), desc.Digest.Encoded())
	if copied[rel] {
		return nil
	}
	if err := s.validateBlob(ctx, desc); err != nil {
		return fmt.Errorf("copy blob %s: %w", desc.Digest, err)
	}
	ra, err := s.store.ReaderAt(ctx, *desc)
	if err != nil {
		return fmt.Errorf("open blob %s for copy: %w", desc.Digest, err)
	}
	defer ra.Close()
	destination := filepath.Join(outputDir, "blobs", rel)
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(destination), ".copa-blob-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if _, err := io.Copy(temp, content.NewReader(ra)); err != nil {
		temp.Close()
		return fmt.Errorf("copy blob %s: %w", desc.Digest, err)
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, destination); err != nil {
		return err
	}
	copied[rel] = true
	return nil
}
