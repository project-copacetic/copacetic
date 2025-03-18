package utils

import (
	"context"
	"strings"

	dockerClient "github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/moby/buildkit/client"
)

// For testing.
var (
	remoteGet = remote.Get
	newClient = func() (dockerClient.APIClient, error) {
		return dockerClient.NewClientWithOpts(dockerClient.FromEnv)
	}
)

func GetMediaType(imageRef string) (string, error) {
	mt, err := localMediaType(imageRef)
	if err == nil && mt != "" {
		return mt, nil
	}
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

func ParseMediaType(mt string) string {
	if strings.Contains(mt, "vnd.oci.image") {
		return client.ExporterOCI
	}
	if strings.Contains(mt, "vnd.docker.distribution") || strings.Contains(mt, "vnd.docker.container.image") {
		return client.ExporterDocker
	}
	return ""
}
