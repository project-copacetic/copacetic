package pkgmgr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-multierror"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	log "github.com/sirupsen/logrus"
)

const (
	copaPrefix     = "copa-"
	inputPath      = "/" + copaPrefix + "input"
	resultsPath    = "/" + copaPrefix + "out"
	downloadPath   = "/" + copaPrefix + "downloads"
	unpackPath     = "/" + copaPrefix + "unpacked"
	resultManifest = "results.manifest"
)

type PackageManager interface {
	InstallUpdates(context.Context, *unversioned.UpdateManifest, bool) (*llb.State, []string, error)
	GetPackageType() string
}

func GetPackageManager(osType string, config *buildkit.Config, workingFolder string) (PackageManager, error) {
	switch osType {
	case "alpine":
		return &apkManager{config: config, workingFolder: workingFolder}, nil
	case "debian", "ubuntu":
		return &dpkgManager{config: config, workingFolder: workingFolder}, nil
	case "cbl-mariner", "centos", "redhat", "amazon":
		return &rpmManager{config: config, workingFolder: workingFolder}, nil
	default:
		return nil, fmt.Errorf("unsupported osType %s specified", osType)
	}
}

// Utility functions for package manager implementations to share

type VersionComparer struct {
	IsValid  func(string) bool
	LessThan func(string, string) bool
}

func GetUniqueLatestUpdates(updates unversioned.UpdatePackages, cmp VersionComparer, ignoreErrors bool) (unversioned.UpdatePackages, error) {
	if len(updates) == 0 {
		return nil, fmt.Errorf("no patchable vulnerabilities found")
	}

	dict := make(map[string]string)
	var allErrors *multierror.Error
	for _, u := range updates {
		if cmp.IsValid(u.FixedVersion) {
			ver, ok := dict[u.Name]
			if !ok {
				dict[u.Name] = u.FixedVersion
			} else if cmp.LessThan(ver, u.FixedVersion) {
				dict[u.Name] = u.FixedVersion
			}
		} else {
			err := fmt.Errorf("invalid version %s found for package %s", u.FixedVersion, u.Name)
			log.Error(err)
			allErrors = multierror.Append(allErrors, err)
			continue
		}
	}
	if allErrors != nil && !ignoreErrors {
		return nil, allErrors.ErrorOrNil()
	}

	out := unversioned.UpdatePackages{}
	for k, v := range dict {
		out = append(out, unversioned.UpdatePackage{Name: k, FixedVersion: v})
	}
	return out, nil
}

type UpdatePackageInfo struct {
	Filename string
	Version  string
}

type PackageInfoReader interface {
	GetVersion(string) (string, error)
	GetName(string) (string, error)
}

type UpdateMap map[string]*UpdatePackageInfo

func GetValidatedUpdatesMap(updates unversioned.UpdatePackages, cmp VersionComparer, reader PackageInfoReader, stagingPath string) (UpdateMap, error) {
	m := make(UpdateMap)
	for _, update := range updates {
		m[update.Name] = &UpdatePackageInfo{Version: update.FixedVersion}
	}

	files, err := os.ReadDir(stagingPath)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		log.Warn("No downloaded packages to install")
		return nil, nil
	}

	var allErrors *multierror.Error
	for _, file := range files {
		name, err := reader.GetName(file.Name())
		if err != nil {
			allErrors = multierror.Append(allErrors, err)
			continue
		}
		version, err := reader.GetVersion(file.Name())
		if err != nil {
			allErrors = multierror.Append(allErrors, err)
			continue
		}
		if !cmp.IsValid(version) {
			err := fmt.Errorf("invalid version %s found for package %s", version, name)
			log.Error(err)
			allErrors = multierror.Append(allErrors, err)
			continue
		}

		p, ok := m[name]
		if !ok {
			log.Warnf("Unexpected: ignoring downloaded update package %s not specified in report", name)
			os.Remove(filepath.Join(stagingPath, file.Name()))
			continue
		}

		if cmp.LessThan(version, p.Version) {
			err = fmt.Errorf("downloaded package %s version %s lower than required %s for update", name, version, p.Version)
			log.Error(err)
			allErrors = multierror.Append(allErrors, err)
			continue
		}
		p.Filename = file.Name()
	}

	if allErrors != nil {
		return nil, allErrors.ErrorOrNil()
	}
	return m, nil
}
