package langmgr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-multierror"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const (
	copaPrefix     = "copa-"
	resultsPath    = "/" + copaPrefix + "out"
	downloadPath   = "/" + copaPrefix + "downloads"
	unpackPath     = "/" + copaPrefix + "unpacked"
	resultManifest = "langresults.manifest"
)

type LangManager interface {
	InstallUpdates(context.Context, *llb.State, *unversioned.UpdateManifest, bool) (*llb.State, []string, error)
}

// GetLanguageManagers returns a list of language managers that have relevant packages to process.
// Uses a switch-based approach to determine which managers to include based on package types.
func GetLanguageManagers(config *buildkit.Config, workingFolder string, manifest *unversioned.UpdateManifest) []LangManager {
	var managers []LangManager

	if manifest == nil || len(manifest.LangUpdates) == 0 {
		return managers
	}

	// Determine which package types are present
	packageTypes := getPackageTypes(manifest.LangUpdates)

	// Switch on each package type to add appropriate managers
	for packageType := range packageTypes {
		switch packageType {
		case utils.PythonPackages:
			managers = append(managers, &pythonManager{config: config, workingFolder: workingFolder})
		case utils.NodePackages:
			managers = append(managers, &nodejsManager{config: config, workingFolder: workingFolder})
		default:
			log.Warnf("Unknown package type '%s' found in language updates", packageType)
		}
	}

	return managers
}

// getPackageTypes returns a set of unique package types found in the language updates.
func getPackageTypes(langUpdates unversioned.LangUpdatePackages) map[string]bool {
	packageTypes := make(map[string]bool)
	for _, pkg := range langUpdates {
		if pkg.Type != "" {
			packageTypes[pkg.Type] = true
		}
	}
	return packageTypes
}

// Utility functions for package manager implementations to share

type VersionComparer struct {
	IsValid  func(string) bool
	LessThan func(string, string) bool
}

func GetUniqueLatestUpdates(
	updates unversioned.LangUpdatePackages,
	cmp VersionComparer,
	ignoreErrors bool,
) (unversioned.LangUpdatePackages, error) {
	if len(updates) == 0 {
		return unversioned.LangUpdatePackages{}, nil
	}

	// Track the highest version and collect metadata for each package
	type packageInfo struct {
		version  string
		pkgPaths map[string]bool // Track all unique PkgPaths for this package
		pkgType  string
		pkgClass string
	}
	dict := make(map[string]*packageInfo)
	var allErrors *multierror.Error

	for _, u := range updates {
		switch {
		case u.FixedVersion == "":
			// No suitable version found due to patch level restrictions, skip this update
			log.Debugf("Skipping package %s: no suitable version found according to patch level restrictions", u.Name)
			continue
		case cmp.IsValid(u.FixedVersion):
			info, ok := dict[u.Name]
			if !ok {
				// First time seeing this package
				dict[u.Name] = &packageInfo{
					version:  u.FixedVersion,
					pkgPaths: map[string]bool{u.PkgPath: true},
					pkgType:  u.Type,
					pkgClass: u.Class,
				}
			} else {
				// Package already exists, update version if higher and track PkgPath
				if cmp.LessThan(info.version, u.FixedVersion) {
					info.version = u.FixedVersion
				}
				if u.PkgPath != "" {
					info.pkgPaths[u.PkgPath] = true
				}
			}
		default:
			err := fmt.Errorf("invalid version %s found for package %s", u.FixedVersion, u.Name)
			log.Error(err)
			allErrors = multierror.Append(allErrors, err)
			continue
		}
	}
	if allErrors != nil && !ignoreErrors {
		return nil, allErrors.ErrorOrNil()
	}

	// Build output with preserved metadata
	out := unversioned.LangUpdatePackages{}
	for pkgName, info := range dict {
		// If multiple PkgPaths exist, we'll just pick the first one
		// In practice, for app-level patching, packages should have consistent paths
		var pkgPath string
		for path := range info.pkgPaths {
			pkgPath = path
			break
		}

		out = append(out, unversioned.UpdatePackage{
			Name:         pkgName,
			FixedVersion: info.version,
			PkgPath:      pkgPath,
			Type:         info.pkgType,
			Class:        info.pkgClass,
		})
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

func GetValidatedUpdatesMap(
	updates unversioned.LangUpdatePackages,
	cmp VersionComparer,
	reader PackageInfoReader,
	stagingPath string,
) (UpdateMap, error) {
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
