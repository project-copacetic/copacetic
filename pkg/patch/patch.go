// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package patch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/docker/buildx/util/buildflags"
	log "github.com/sirupsen/logrus"

	ref "github.com/distribution/distribution/reference"
	controllerapi "github.com/docker/buildx/controller/pb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

const (
	defaultPatchedTagSuffix = "patched"
)

type Config struct {
	Image        string
	ReportFile   string
	PatchedTag   string
	WorkDir      string
	BuildkitAddr string
	Timeout      time.Duration
	CacheFrom    []string
	CacheTo      []string
}

// Patch command applies package updates to an OCI image given a vulnerability report.
func Patch(ctx context.Context, cfg *Config) error {
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	imageName, err := ref.ParseNamed(cfg.Image)
	if err != nil {
		return fmt.Errorf("could not parse image name: %w", err)
	}
	if ref.IsNameOnly(imageName) {
		log.Warnf("Image name has no tag or digest, using latest as tag")
		imageName = ref.TagNameOnly(imageName)
	}
	taggedName, ok := imageName.(ref.Tagged)
	if !ok {
		err := errors.New("unexpected: TagNameOnly did create Tagged ref")
		log.Error(err)
		return err
	}
	tag := taggedName.Tag()
	if cfg.PatchedTag == "" {
		if tag == "" {
			log.Warnf("No output tag specified for digest-referenced image, defaulting to `%s`", defaultPatchedTagSuffix)
			cfg.PatchedTag = defaultPatchedTagSuffix
		} else {
			cfg.PatchedTag = fmt.Sprintf("%s-%s", tag, defaultPatchedTagSuffix)
		}
	}
	patchedImageName := fmt.Sprintf("%s:%s", imageName.Name(), cfg.PatchedTag)

	// Ensure working folder exists for call to InstallUpdates
	if cfg.WorkDir == "" {
		var err error
		cfg.WorkDir, err = os.MkdirTemp("", "copa-*")
		if err != nil {
			return err
		}
		defer removeIfNotDebug(cfg.WorkDir)
		if err = os.Chmod(cfg.WorkDir, 0o744); err != nil {
			return err
		}
	} else {
		if isNew, err := utils.EnsurePath(cfg.WorkDir, 0o744); err != nil {
			log.Errorf("failed to create workingFolder %s", cfg.WorkDir)
			return err
		} else if isNew {
			defer removeIfNotDebug(cfg.WorkDir)
		}
	}

	// Parse report for update packages
	updates, err := report.TryParseScanReport(cfg.ReportFile)
	if err != nil {
		return err
	}
	log.Debugf("updates to apply: %v", updates)

	client, err := buildkit.NewClient(ctx, cfg.BuildkitAddr)
	if err != nil {
		return err
	}
	defer client.Close()

	// Configure buildctl/client for use by package manager
	config, err := buildkit.InitializeBuildkitConfig(ctx, client, cfg.Image, updates)
	if err != nil {
		return err
	}

	cacheFromBk, err := buildflags.ParseCacheEntry(cfg.CacheFrom)
	if err != nil {
		return fmt.Errorf("could not parse cache-from: %w", err)
	}
	cacheToBk, err := buildflags.ParseCacheEntry(cfg.CacheTo)
	if err != nil {
		return fmt.Errorf("could not parse cache-to: %w", err)
	}
	cacheFrom := controllerapi.CreateCaches(cacheFromBk)
	cacheTo := controllerapi.CreateCaches(cacheToBk)

	config.CacheFrom = cacheFrom
	config.CacheTo = cacheTo

	// Create package manager helper
	pkgmgr, err := pkgmgr.GetPackageManager(updates.OSType, config, cfg.WorkDir)
	if err != nil {
		return err
	}

	// Export the patched image state to Docker
	// TODO: Add support for other output modes as buildctl does.
	patchedImageState, err := pkgmgr.InstallUpdates(ctx, updates)
	if err != nil {
		return err
	}

	return buildkit.SolveToDocker(ctx, config.Client, patchedImageState, config.ConfigData, patchedImageName, cacheFrom, cacheTo)
}

func removeIfNotDebug(workingFolder string) {
	if log.GetLevel() >= log.DebugLevel {
		// Keep the intermediate outputs for outputs solved to working folder if debugging
		log.Warnf("--debug specified, working folder at %s needs to be manually cleaned up", workingFolder)
	} else {
		os.RemoveAll(workingFolder)
	}
}
