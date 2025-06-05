package utils

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/containerd/errdefs"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/moby/buildkit/client/llb"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
)

func EnsurePath(path string, perm fs.FileMode) (bool, error) {
	createdPath := false
	st, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(path, perm)
		createdPath = (err == nil)
	} else {
		if !st.IsDir() {
			return false, fs.ErrExist
		}
		if st.Mode().Perm() != perm {
			return false, fs.ErrPermission
		}
	}
	return createdPath, err
}

func IsNonEmptyFile(dir, file string) bool {
	p := filepath.Join(dir, file)
	info, err := os.Stat(p)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir() && info.Size() > 0
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

// GetImageDescriptor retrieves the image descriptor for a given image reference.
// It first tries to inspect the image using the Docker client (local).
// If the image is not found locally or a local error occurs, it tries to get the image descriptor from the remote registry.
func GetImageDescriptor(ctx context.Context, imageRef string) (*ocispec.Descriptor, error) {
	log.Debugf("Attempting to get local image descriptor for %s", imageRef)
	localDesc, localErr := localImageDescriptor(ctx, imageRef)

	if localErr == nil {
		log.Infof("found local image descriptor for %s via Docker client", imageRef)
		return localDesc, nil
	}

	isNotFoundError := errdefs.IsNotFound(localErr)
	if isNotFoundError {
		log.Debugf("image %s not found locally (error: %v), trying remote.", imageRef, localErr)
	} else {
		log.Warnf("local descriptor lookup for %s failed (error: %v), trying remote.", imageRef, localErr)
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
