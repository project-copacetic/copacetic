package utils

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	mobyimage "github.com/moby/moby/api/types/image"
	dockerClient "github.com/moby/moby/client"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	log "github.com/sirupsen/logrus"
)

// For testing.
var (
	remoteGet = remote.Get
	newClient = func() (dockerClient.APIClient, error) {
		return dockerClient.New(
			dockerClient.FromEnv,
		)
	}
)

// GetMediaType returns the manifest's media type for an image reference.
// It prefers a local inspection and falls back to a registry lookup only when
// the image is not present in the local image store. When the image is
// confirmed locally but no media type metadata is available, a Docker manifest
// v2 media type is returned to keep daemon-only refs strictly local-first.
func GetMediaType(imageRef, runtime string) (string, error) {
	return GetMediaTypeWithContext(context.Background(), imageRef, runtime)
}

// GetMediaTypeWithContext behaves like GetMediaType but binds media type
// detection to ctx, so the local Docker inspection, Podman CLI execution, and
// remote registry lookup are canceled when the caller's context (e.g. the patch
// timeout) is done. A nil ctx is treated as context.Background() to avoid
// panicking exec.CommandContext.
func GetMediaTypeWithContext(ctx context.Context, imageRef, runtime string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var (
		mt    string
		found bool
		err   error
	)

	switch runtime {
	case imageloader.Podman:
		mt, found, err = podmanMediaType(ctx, imageRef)
	default:
		// Default to Docker
		mt, found, err = localMediaType(ctx, imageRef)
	}

	if found {
		if mt != "" {
			log.Debugf("local media type found for %s using %s: %s", imageRef, runtime, mt)
			return mt, nil
		}
		// Image is in the local store but the descriptor did not expose a
		// media type. Treat it as a Docker manifest and skip the remote
		// registry probe — daemon-only refs (e.g. ones tagged against an
		// unreachable registry hostname) must never trigger network access.
		log.Debugf("image %s found in local %s store without descriptor media type; defaulting to docker manifest v2 and skipping remote probe", imageRef, runtime)
		return string(ggcrtypes.DockerManifestSchema2), nil
	}
	log.Debugf("local media type not found for %s using %s: %v", imageRef, runtime, err)

	// Image is not present locally — consult the remote registry.
	return remoteMediaType(ctx, imageRef)
}

// localMediaType inspects the local docker daemon for imageRef. The second
// return value indicates whether the image is present in the daemon (regardless
// of whether a media type could be read from its descriptor).
//
// Lookup precedence for the manifest media type:
//  1. The top-level Descriptor.MediaType — populated for multi-platform image
//     indexes and for single-platform images on legacy daemons that expose it.
//  2. The first image manifest entry under inspect.Manifests — populated by
//     multi-platform (containerd) image stores, where the top-level descriptor
//     may be empty for single-arch images that were loaded via `docker load`
//     but the per-platform manifest descriptor carries the true type.
//
// Returning (mt="", found=true, nil) means the image is local but the daemon
// exposed no manifest-level media type at all; callers should treat that as
// "docker manifest v2" by default rather than triggering a remote probe.
func localMediaType(ctx context.Context, imageRef string) (string, bool, error) {
	inspect, err := inspectLocalImage(ctx, imageRef)
	if err != nil {
		return "", false, err
	}

	if inspect.Descriptor != nil && inspect.Descriptor.MediaType != "" {
		return inspect.Descriptor.MediaType, true, nil
	}

	for i := range inspect.Manifests {
		m := &inspect.Manifests[i]
		if m.Kind == mobyimage.ManifestKindImage && m.Descriptor.MediaType != "" {
			return m.Descriptor.MediaType, true, nil
		}
	}

	return "", true, nil
}

// podmanMediaType tries to get the manifest's media type using podman CLI.
// The second return value indicates whether the image is present in the local
// podman store.
func podmanMediaType(ctx context.Context, imageRef string) (string, bool, error) {
	// Check if podman is available
	if _, err := exec.LookPath("podman"); err != nil {
		return "", false, err
	}

	// Run podman inspect to get image metadata
	cmd := exec.CommandContext(ctx, "podman", "inspect", "--type", "image", imageRef)
	output, err := cmd.Output()
	if err != nil {
		return "", false, err
	}

	// Parse the JSON output
	var inspectResults []map[string]interface{}
	if err := json.Unmarshal(output, &inspectResults); err != nil {
		return "", false, err
	}

	if len(inspectResults) == 0 {
		return "", false, errors.New("no inspect results")
	}

	result := inspectResults[0]

	// Try to get MediaType from the result
	if mt, ok := result["MediaType"].(string); ok && mt != "" {
		return mt, true, nil
	}

	// Try to get it from ManifestType (some versions of podman use this)
	if mt, ok := result["ManifestType"].(string); ok && mt != "" {
		return mt, true, nil
	}

	return "", true, nil
}

func remoteMediaType(ctx context.Context, imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		log.Debugf("failed to parse reference %s: %v", imageRef, err)
		return "", err
	}
	desc, err := remoteGet(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
	if err != nil {
		log.Debugf("failed to get remote media type for %s: %v", imageRef, err)
		return "", err
	}
	log.Debugf("remote media type found for %s: %s", imageRef, desc.MediaType)
	return string(desc.MediaType), nil
}
