package common

import (
	"context"
	"fmt"

	"github.com/containerd/platforms"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
)

const (
	LINUX = "linux"
)

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
	// Initialize buildkit config
	config, err := buildkit.InitializeBuildkitConfig(ctx, c, image, platform)
	if err != nil {
		return nil, nil, err
	}

	var manager pkgmgr.PackageManager
	if osInfo == nil {
		// Need to determine OS from image
		fileBytes, err := buildkit.ExtractFileFromState(ctx, c, &config.ImageState, "/etc/os-release")
		if err != nil {
			return nil, nil, fmt.Errorf("unable to extract /etc/os-release file from state %w", err)
		}

		detectedOSInfo, err := GetOSInfo(ctx, fileBytes)
		if err != nil {
			return nil, nil, err
		}
		osInfo = detectedOSInfo
	}

	// Get package manager based on OS type
	manager, err = pkgmgr.GetPackageManager(osInfo.Type, osInfo.Version, config, workingFolder)
	if err != nil {
		return nil, nil, err
	}

	return config, manager, nil
}

// GetDefaultLinuxPlatform returns a normalized Linux platform, defaulting to Linux if not already Linux.
func GetDefaultLinuxPlatform() ispec.Platform {
	platform := platforms.Normalize(platforms.DefaultSpec())
	if platform.OS != LINUX {
		platform.OS = LINUX
	}
	return platform
}
