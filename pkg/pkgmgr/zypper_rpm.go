package pkgmgr

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type rpmZypperManager struct {
	config        *buildkit.Config
	workingFolder string
	osType        string
	osVersion     string
}

func getZypperToolingImageName(osType string, osVersion string) string {
	registry := "registry.opensuse.org"
	version := osVersion
	var image string

	switch osType {
	case "sles":
		registry = "registry.suse.com"
		image = "bci/bci-base"
	case "opensuse-leap":
		image = "opensuse/leap"
	case "opensuse-tumbleweed":
		image = "opensuse/tumbleweed"
	default:
		image = "opensuse/tumbleweed"
	}

	log.Debugf("Using %s/%s:%s as basis for tooling image", registry, image, version)

	return fmt.Sprintf("%s/%s:%s", registry, image, version)
}

func (rm *rpmZypperManager) InstallUpdates(ctx context.Context, manifest *unversioned.UpdateManifest, ignoreErrors bool) (*llb.State, []string, error) {
	if manifest == nil {
		return nil, nil, fmt.Errorf("image manifest is nil")
	}

	rpmComparer := VersionComparer{isValidRPMVersion, isLessThanRPMVersion}
	updates, err := GetUniqueLatestUpdates(manifest.Updates, rpmComparer, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}
	if len(updates) == 0 {
		log.Warn("No update packages were specified to apply")
		return &rm.config.ImageState, nil, nil
	}
	log.Debugf("Latest unique RPMs: %v", updates)

	toolImageName := getZypperToolingImageName(rm.osType, rm.osVersion)

	// We treat all updates as being done on distroless images, like SUSE's
	// bci-busybox or bci-micro, for example, that don't have zypper
	// installed. This could be improved to detect if the image being
	// updated is based on bci-base or OpenSUSE, for example, which could
	// result on a direct update with installed zypper version instead of
	// the chroot option.
	updatedImageState, resultManifestBytes, err := rm.zypperChrootInstallUpdates(ctx, updates, toolImageName)
	if err != nil {
		return nil, nil, err
	}

	// Validate that the deployed packages are of the requested version or
	// greater.
	errPkgs, err := validateRPMPackageVersions(updates, rpmComparer, resultManifestBytes, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}

	return updatedImageState, errPkgs, nil
}

func (rm *rpmZypperManager) zypperChrootInstallUpdates(ctx context.Context, updates unversioned.UpdatePackages, toolImage string) (*llb.State, []byte, error) {
	// Spin up a build tooling container to fetch and install packages
	// inside a chroot directory to create the patch layer.
	toolingBase := llb.Image(toolImage,
		llb.ResolveModeDefault,
	)

	pkgStrings := []string{}
	for _, u := range updates {
		pkgStrings = append(pkgStrings, u.Name)
	}
	pkgsToUpdate := strings.Join(pkgStrings, " ")

	chrootDir := "/tmp/rootfs"
	manifestFile := "/tmp/manifest"
	zypperCmd := `
                if ! [[ -e "${COPA_RPM_DB_FILE}" ]]; then echo "RPM DB not found"; exit 1; fi
                zypper --non-interactive refresh
                zypper --non-interactive --installroot "${COPA_CHROOT_DIR}" up --no-recommends %s
                zypper --installroot "${COPA_CHROOT_DIR}" clean --all
                rm -rf "${COPA_CHROOT_DIR}"/var/cache/zypp/* "${COPA_CHROOT_DIR}"/var/log/zypp/*
                rm -rf "${COPA_CHROOT_DIR}"/var/tmp/* "${COPA_CHROOT_DIR}"/usr/share/doc/packages/*
                rpm --dbpath "${COPA_CHROOT_DIR}"/var/lib/rpm -qa --qf="%%{NAME}\t%%{VERSION}-%%{RELEASE}\t%%{ARCH}\n" %s > "${COPA_MANIFEST_FILE}"
	`
	zypperCmd = fmt.Sprintf(zypperCmd, pkgsToUpdate, pkgsToUpdate)

	downloaded := toolingBase.Run(
		llb.AddEnv("COPA_CHROOT_DIR", chrootDir),
		llb.AddEnv("COPA_RPM_DB_FILE", path.Join(chrootDir, rpmLibPath, rpmNDB)),
		llb.AddEnv("COPA_MANIFEST_FILE", path.Join(chrootDir, manifestFile)),
		buildkit.Sh(zypperCmd),
		llb.WithProxy(utils.GetProxy()),
	).AddMount(chrootDir, rm.config.ImageState)

	resultBytes, err := buildkit.ExtractFileFromState(ctx, rm.config.Client, &downloaded, manifestFile)
	if err != nil {
		return nil, nil, err
	}

	withoutManifest := downloaded.File(llb.Rm(manifestFile))
	diffBase := llb.Diff(rm.config.ImageState, withoutManifest)
	downloaded = llb.Merge([]llb.State{diffBase, withoutManifest})

	// If the image has been patched before, diff the base image and patched image to retain previous patches
	if rm.config.PatchedConfigData != nil {
		// Diff the base image and patched image to get previous patches
		prevPatchDiff := llb.Diff(rm.config.ImageState, rm.config.PatchedImageState)

		// Merging these two diffs will discard everything in the filesystem that hasn't changed
		// Doing llb.Scratch ensures we can keep everything in the filesystem that has not changed
		combinedPatch := llb.Merge([]llb.State{prevPatchDiff, downloaded})
		squashedPatch := llb.Scratch().File(llb.Copy(combinedPatch, "/", "/"))

		// Merge previous and new patches into the base image
		completePatchMerge := llb.Merge([]llb.State{rm.config.ImageState, squashedPatch})

		return &completePatchMerge, resultBytes, nil
	}

	// Diff unpacked packages layers from previous and merge with target
	diff := llb.Diff(rm.config.ImageState, downloaded)
	merged := llb.Merge([]llb.State{llb.Scratch(), rm.config.ImageState, diff})

	return &merged, resultBytes, nil
}

func (rm *rpmZypperManager) GetPackageType() string {
	return "rpm"
}
