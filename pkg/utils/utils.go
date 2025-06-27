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
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/moby/buildkit/client/llb"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
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
		log.Infof("found local image descriptor for %s via %s", imageRef, runtime)
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
