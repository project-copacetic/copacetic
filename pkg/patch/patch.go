package patch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	ref "github.com/distribution/reference"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/project-copacetic/copacetic/pkg/vex"
)

const (
	defaultPatchedTagSuffix = "patched"
)

// Patch command applies package updates to an OCI image given a vulnerability report.
func Patch(ctx context.Context, timeout time.Duration, image, reportFile, patchedTag, workingFolder, scanner, format, output string, ignoreError, push bool, bkOpts buildkit.Opts) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan error)
	go func() {
		ch <- patchWithContext(timeoutCtx, image, reportFile, patchedTag, workingFolder, scanner, format, output, ignoreError, push, bkOpts)
	}()

	select {
	case err := <-ch:
		return err
	case <-timeoutCtx.Done():
		// add a grace period for long running deferred cleanup functions to complete
		<-time.After(1 * time.Second)

		err := fmt.Errorf("patch exceeded timeout %v", timeout)
		log.Error(err)
		return err
	}
}

func removeIfNotDebug(workingFolder string) {
	if log.GetLevel() >= log.DebugLevel {
		// Keep the intermediate outputs for outputs solved to working folder if debugging
		log.Warnf("--debug specified, working folder at %s needs to be manually cleaned up", workingFolder)
	} else {
		os.RemoveAll(workingFolder)
	}
}

func patchWithContext(ctx context.Context, image, reportFile, patchedTag, workingFolder, scanner, format, output string, ignoreError, push bool, bkOpts buildkit.Opts) error {
	patchedImageName, err := patchedImageTarget(image, patchedTag)
	if err != nil {
		return err
	}

	// Ensure working folder exists for call to InstallUpdates
	if workingFolder == "" {
		var err error
		workingFolder, err = os.MkdirTemp("", "copa-*")
		if err != nil {
			return err
		}
		defer removeIfNotDebug(workingFolder)
		if err = os.Chmod(workingFolder, 0o744); err != nil {
			return err
		}
	} else {
		if isNew, err := utils.EnsurePath(workingFolder, 0o744); err != nil {
			log.Errorf("failed to create workingFolder %s", workingFolder)
			return err
		} else if isNew {
			defer removeIfNotDebug(workingFolder)
		}
	}

	// Parse report for update packages
	updates, err := report.TryParseScanReport(reportFile, scanner)
	if err != nil {
		return err
	}
	log.Debugf("updates to apply: %v", updates)

	client, err := buildkit.NewClient(ctx, bkOpts)
	if err != nil {
		return err
	}
	defer client.Close()

	// Configure buildctl/client for use by package manager
	config, err := buildkit.InitializeBuildkitConfig(ctx, client, image, updates)
	if err != nil {
		return err
	}

	// Create package manager helper
	pkgmgr, err := pkgmgr.GetPackageManager(updates.Metadata.OS.Type, config, workingFolder)
	if err != nil {
		return err
	}

	// Export the patched image state to Docker
	// TODO: Add support for other output modes as buildctl does.
	patchedImageState, errPkgs, err := pkgmgr.InstallUpdates(ctx, updates, ignoreError)
	if err != nil {
		return err
	}

	if err = buildkit.Solve(ctx, config.Client, patchedImageState, config.ConfigData, *patchedImageName, push); err != nil {
		return err
	}

	// create a new manifest with the successfully patched packages
	validatedManifest := &unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    updates.Metadata.OS.Type,
				Version: updates.Metadata.OS.Version,
			},
			Config: unversioned.Config{
				Arch: updates.Metadata.Config.Arch,
			},
		},
		Updates: []unversioned.UpdatePackage{},
	}
	for _, update := range updates.Updates {
		if !slices.Contains(errPkgs, update.Name) {
			validatedManifest.Updates = append(validatedManifest.Updates, update)
		}
	}
	// vex document must contain at least one statement
	if output != "" && len(validatedManifest.Updates) > 0 {
		return vex.TryOutputVexDocument(validatedManifest, pkgmgr, *patchedImageName, format, output)
	}
	return nil
}

func patchedImageTarget(image, patchedTag string) (*string, error) {
	imageName, err := ref.ParseNamed(image)
	if err != nil {
		return nil, err
	}
	if ref.IsNameOnly(imageName) {
		log.Warn("Image name has no tag or digest, using latest as tag")
		imageName = ref.TagNameOnly(imageName)
	}
	taggedName, ok := imageName.(ref.Tagged)
	if !ok {
		err := errors.New("unexpected: TagNameOnly did create Tagged ref")
		log.Error(err)
		return nil, err
	}
	tag := taggedName.Tag()
	var patchedImageName string
	if patchedTag == "" {
		if tag == "" {
			log.Warnf("No output tag specified for digest-referenced image, defaulting to `%s`", defaultPatchedTagSuffix)
			patchedTag = defaultPatchedTagSuffix
		} else {
			patchedTag = fmt.Sprintf("%s-%s", tag, defaultPatchedTagSuffix)
		}
	}

	slashCount := strings.Count(patchedTag, "/")
	if slashCount > 0 {
		if slashCount < 2 {
			err := fmt.Errorf("invalid tag %s, must be in the form <registry>/<image>:<tag>", patchedTag)
			return nil, err
		}
		// this implies user has passed a destination image name, not just a tag
		patchedImageName = patchedTag
	} else {
		patchedImageName = fmt.Sprintf("%s:%s", imageName.Name(), patchedTag)
	}

	return &patchedImageName, nil
}
