package utils

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
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

// GetMediaType returns the manifest’s media type for an image reference
// It prefers a local inspection and falls back to a registry lookup.
func GetMediaType(imageRef, runtime string) (string, error) {
	return GetMediaTypeWithContext(context.Background(), imageRef, runtime)
}

func GetMediaTypeWithContext(ctx context.Context, imageRef, runtime string) (string, error) {
	// Check if the image is local first using the appropriate runtime
	var mt string
	var err error

	switch runtime {
	case imageloader.Podman:
		mt, err = podmanMediaType(ctx, imageRef)
	default:
		// Default to Docker
		mt, err = localMediaType(ctx, imageRef)
	}

	if err == nil && mt != "" {
		log.Debugf("local media type found for %s using %s: %s", imageRef, runtime, mt)
		return mt, nil
	}
	log.Debugf("local media type not found for %s using %s: %v", imageRef, runtime, err)

	// If the image is not local, use the remote media type
	return remoteMediaType(ctx, imageRef)
}

func localMediaType(ctx context.Context, imageRef string) (string, error) {
	cli, err := newClient()
	if err != nil {
		return "", err
	}
	defer cli.Close()

	distInspect, err := cli.ImageInspect(ctx, imageRef)
	if err != nil {
		return "", err
	}
	if distInspect.Descriptor == nil {
		return "", errors.New("descriptor is nil")
	}
	return distInspect.Descriptor.MediaType, nil
}

// podmanMediaType tries to get the manifest's media type using podman CLI.
func podmanMediaType(ctx context.Context, imageRef string) (string, error) {
	// Check if podman is available
	if _, err := exec.LookPath("podman"); err != nil {
		return "", err
	}

	// Run podman inspect to get image metadata
	cmd := exec.CommandContext(ctx, "podman", "inspect", "--type", "image", imageRef)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse the JSON output
	var inspectResults []map[string]interface{}
	if err := json.Unmarshal(output, &inspectResults); err != nil {
		return "", err
	}

	if len(inspectResults) == 0 {
		return "", errors.New("no inspect results")
	}

	result := inspectResults[0]

	// Try to get MediaType from the result
	if mt, ok := result["MediaType"].(string); ok && mt != "" {
		return mt, nil
	}

	// Try to get it from ManifestType (some versions of podman use this)
	if mt, ok := result["ManifestType"].(string); ok && mt != "" {
		return mt, nil
	}

	return "", nil
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
