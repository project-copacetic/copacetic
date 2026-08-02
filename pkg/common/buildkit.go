package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	fstypes "github.com/tonistiigi/fsutil/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
)

const (
	LINUX = "linux"

	osReleasePath     = "/etc/os-release"
	maxOSReleaseBytes = int64(1 << 20)
)

// ExtractOSReleaseFromState reads /etc/os-release after enforcing the same
// 1 MiB input limit used by Chisel release inference. The bounded BuildKit
// helper stats before allocating and uses ranged reads for the file contents.
func ExtractOSReleaseFromState(ctx context.Context, c gwclient.Client, state *llb.State) ([]byte, error) {
	return buildkit.ExtractFileFromStateWithLimit(ctx, c, state, osReleasePath, maxOSReleaseBytes)
}

// SetupBuildkitConfigAndManager initializes buildkit config and package manager.
// This combines the common pattern used in both generate and patch commands.
func SetupBuildkitConfigAndManager(
	ctx context.Context,
	c gwclient.Client,
	image string,
	platform *ispec.Platform,
	workingFolder string,
	osInfo *OSInfo, // If nil, will be detected from image
) (*buildkit.Config, pkgmgr.PackageManager, error) {
	return SetupBuildkitConfigAndManagerWithOptions(ctx, c, image, platform, workingFolder, osInfo, pkgmgr.PackageManagerOptions{})
}

// SetupBuildkitConfigAndManagerWithOptions initializes BuildKit config and a
// package manager with optional manager-specific settings.
func SetupBuildkitConfigAndManagerWithOptions(
	ctx context.Context,
	c gwclient.Client,
	image string,
	platform *ispec.Platform,
	workingFolder string,
	osInfo *OSInfo,
	managerOptions pkgmgr.PackageManagerOptions,
) (*buildkit.Config, pkgmgr.PackageManager, error) {
	// Initialize buildkit config
	config, err := buildkit.InitializeBuildkitConfig(ctx, c, image, platform)
	if err != nil {
		return nil, nil, err
	}

	var manager pkgmgr.PackageManager
	if osInfo == nil {
		// Need to determine OS from image
		fileBytes, err := ExtractOSReleaseFromState(ctx, c, &config.ImageState)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to extract %s file from state %w", osReleasePath, err)
		}

		detectedOSInfo, err := GetOSInfo(ctx, fileBytes)
		if err != nil {
			return nil, nil, err
		}
		osInfo = detectedOSInfo
	}

	// Get package manager based on OS type
	manager, err = pkgmgr.GetPackageManagerWithOptions(osInfo.Type, osInfo.Version, config, workingFolder, managerOptions)
	if err != nil {
		return nil, nil, err
	}

	return config, manager, nil
}

// MergeImageRuntimeConfig preserves base layer metadata while replacing the
// runtime config object with the one from the supplied image being repatched.
func MergeImageRuntimeConfig(baseConfig, suppliedConfig []byte) ([]byte, error) {
	var base map[string]json.RawMessage
	if err := json.Unmarshal(baseConfig, &base); err != nil {
		return nil, fmt.Errorf("parse base image config: %w", err)
	}
	if base == nil {
		return nil, fmt.Errorf("base image config is not an object")
	}
	var supplied map[string]json.RawMessage
	if err := json.Unmarshal(suppliedConfig, &supplied); err != nil {
		return nil, fmt.Errorf("parse supplied image config: %w", err)
	}
	if supplied == nil {
		return nil, fmt.Errorf("supplied image config is not an object")
	}
	runtimeConfig, ok := supplied["config"]
	if !ok {
		runtimeConfig = json.RawMessage(`{}`)
	}
	var runtimeObject map[string]json.RawMessage
	if err := json.Unmarshal(runtimeConfig, &runtimeObject); err != nil {
		return nil, fmt.Errorf("supplied image config does not contain an object-valued config field: %w", err)
	}
	if runtimeObject == nil {
		return nil, fmt.Errorf("supplied image config does not contain an object-valued config field")
	}
	base["config"] = runtimeConfig
	merged, err := json.Marshal(base)
	if err != nil {
		return nil, fmt.Errorf("marshal image config with supplied runtime settings: %w", err)
	}
	return merged, nil
}

// AddImageConfigLabels returns imageConfig with labels merged into its OCI
// config. The input is left unchanged, and manager-provided values take
// precedence when a label already exists.
func AddImageConfigLabels(imageConfig []byte, labels map[string]string) ([]byte, error) {
	if len(labels) == 0 {
		return imageConfig, nil
	}

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

	// JSON field matching is case-insensitive. Remove every spelling except the
	// selected source so stale or attacker-controlled variants cannot shadow the
	// updated labels when consumers decode the config.
	for key := range config {
		if strings.EqualFold(key, "labels") {
			delete(config, key)
		}
	}

	configLabels := make(map[string]string)
	if len(labelsData) > 0 && string(labelsData) != "null" {
		if err := json.Unmarshal(labelsData, &configLabels); err != nil {
			return nil, fmt.Errorf("image config labels field is not a string-valued object: %w", err)
		}
	}
	for key, value := range labels {
		configLabels[key] = value
	}

	labelsData, err := json.Marshal(configLabels)
	if err != nil {
		return nil, fmt.Errorf("marshal image config labels: %w", err)
	}
	config[labelsKey] = labelsData
	configData, err = json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("marshal image config object: %w", err)
	}
	image["config"] = configData

	updated, err := json.Marshal(image)
	if err != nil {
		return nil, fmt.Errorf("marshal image config: %w", err)
	}
	return updated, nil
}

// StatePathExists reports whether path exists in state without executing any
// binary from the target image. A missing path is not an error; solve and stat
// failures that are not NotFound are returned to the caller.
func StatePathExists(ctx context.Context, c gwclient.Client, state *llb.State, platform *ispec.Platform, path string) (bool, error) {
	_, exists, err := statePathStat(ctx, c, state, platform, path)
	return exists, err
}

// StateFileExists reports whether path is a regular file in state without
// reading its contents or executing any binary from the target image. A missing
// path is not an error; a path with another type is rejected as malformed.
func StateFileExists(ctx context.Context, c gwclient.Client, state *llb.State, platform *ispec.Platform, path string) (bool, error) {
	stat, exists, err := statePathStat(ctx, c, state, platform, path)
	if err != nil || !exists {
		return exists, err
	}
	if stat == nil {
		return false, fmt.Errorf("stat %s: BuildKit returned no file metadata", path)
	}
	if !fs.FileMode(stat.Mode).IsRegular() {
		return false, fmt.Errorf("%s exists but is not a regular file", path)
	}
	return true, nil
}

func statePathStat(
	ctx context.Context,
	c gwclient.Client,
	state *llb.State,
	platform *ispec.Platform,
	path string,
) (*fstypes.Stat, bool, error) {
	constraints := []llb.ConstraintsOpt{}
	if platform != nil {
		constraints = append(constraints, llb.Platform(*platform))
	}

	definition, err := state.Marshal(ctx, constraints...)
	if err != nil {
		return nil, false, fmt.Errorf("marshal image state: %w", err)
	}

	result, err := c.Solve(ctx, gwclient.SolveRequest{
		Definition: definition.ToPB(),
		Evaluate:   true,
	})
	if err != nil {
		return nil, false, fmt.Errorf("solve image state: %w", err)
	}

	reference, err := result.SingleRef()
	if err != nil {
		return nil, false, fmt.Errorf("get image state reference: %w", err)
	}
	stat, err := reference.StatFile(ctx, gwclient.StatRequest{Path: path})
	if err != nil {
		if statePathNotFound(err, path) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("stat %s: %w", path, err)
	}

	return stat, true, nil
}

func statePathNotFound(err error, path string) bool {
	if errors.Is(err, fs.ErrNotExist) || os.IsNotExist(err) || errdefs.IsNotFound(err) || status.Code(err) == codes.NotFound {
		return true
	}

	// BuildKit gateway errors can lose their typed NotFound status while being
	// serialized across the frontend boundary. Match only the requested path's
	// filesystem-style missing error instead of treating arbitrary text as
	// absence.
	missingPath := strings.ToLower(path + ": no such file or directory")
	return strings.Contains(strings.ToLower(err.Error()), missingPath)
}

// GetDefaultLinuxPlatform returns a normalized Linux platform, defaulting to Linux if not already Linux.
func GetDefaultLinuxPlatform() ispec.Platform {
	platform := platforms.Normalize(platforms.DefaultSpec())
	if platform.OS != LINUX {
		platform.OS = LINUX
	}
	return platform
}
