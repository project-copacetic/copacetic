package utils

import (
	"context"

	dockerClient "github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// For testing.
var (
	remoteGet = remote.Get
	newClient = func() (dockerClient.APIClient, error) {
		return dockerClient.NewClientWithOpts(
			dockerClient.FromEnv,
			dockerClient.WithAPIVersionNegotiation(),
		)
	}
)

// GetMediaType returns the manifest’s media type for an image reference
// It prefers a local inspection and falls back to a registry lookup.
func GetMediaType(imageRef string) (string, error) {
	// Check if the image is local first
	// If it is, use the local media type
	if mt, err := localMediaType(imageRef); err == nil && mt != "" {
		return mt, nil
	}

	// If the image is not local, use the remote media type
	return remoteMediaType(imageRef)
}

func localMediaType(imageRef string) (string, error) {
	cli, err := newClient()
	if err != nil {
		return "", err
	}
	defer cli.Close()

	distInspect, err := cli.DistributionInspect(context.Background(), imageRef, "")
	if err != nil {
		return "", err
	}
	return distInspect.Descriptor.MediaType, nil
}

func remoteMediaType(imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", err
	}
	desc, err := remoteGet(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", err
	}
	return string(desc.MediaType), nil
}
