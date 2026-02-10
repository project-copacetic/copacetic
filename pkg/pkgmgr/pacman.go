package pkgmgr

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	pacmanVer "github.com/parthivsaikia/go-pacman-version"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	log "github.com/sirupsen/logrus"
)

type pacmanManager struct {
	config        *buildkit.Config
	workingFolder string
}

func isValidPacmanVersion(v string) bool {
	return pacmanVer.IsValid(v)
}

func isLessThanPacmanVersion(v1, v2 string) bool {
	return pacmanVer.LessThan(v1, v2)
}

func pacmanReadResultsManifest(b []byte) ([]string, error) {
	if b == nil {
		return nil, fmt.Errorf("nil buffer provided")
	}
	buf := bytes.NewBuffer(b)
	var lines []string
	fs := bufio.NewScanner(buf)
	for fs.Scan() {
		lines = append(lines, fs.Text())
	}
	return lines, nil
}

func validatePacmanPackageVersions(updates unversioned.UpdatePackages, cmp VersionComparer, resultBytes []byte, ignoreErrors bool) ([]string, error) {
	lines, err := pacmanReadResultsManifest(resultBytes)
	if err != nil {
		return nil, err
	}

	if len(lines) > len(updates) {
		err = fmt.Errorf("expected %d updates, installed %d", len(updates), len(lines))
		log.Error(err)
		return nil, err
	}

	sort.SliceStable(updates, func(i, j int) bool {
		return updates[i].Name < updates[j].Name
	})
	log.Debugf("Required updates: %s", updates)

	sort.SliceStable(lines, func(i, j int) bool {
		return lines[i] < lines[j]
	})
	log.Debugf("Resulting updates: %s", lines)

	lineIndex := 0
	var errorPkgs []string
	var allErrors []error

	for _, update := range updates {
		expectedPrefix := update.Name + " "
		if lineIndex >= len(lines) || !strings.HasPrefix(lines[lineIndex], expectedPrefix) {
			log.Warnf("Package %s is not installed, may have been uninstalled during upgrade", update.Name)
			continue
		}

		version := strings.TrimPrefix(lines[lineIndex], expectedPrefix)
		lineIndex++

		if !cmp.IsValid(version) {
			err := fmt.Errorf("invalid version %s found for package %s", version, update.Name)
			log.Error(err)
			errorPkgs = append(errorPkgs, update.Name)
			allErrors = append(allErrors, err)
			continue
		}

		if cmp.LessThan(version, update.FixedVersion) {
			err := fmt.Errorf("downloaded package %s version %s lower than required %s for update", update.Name, version, update.FixedVersion)
			log.Error(err)
			errorPkgs = append(errorPkgs, update.Name)
			allErrors = append(allErrors, err)
			continue
		}

		log.Infof("Validated package %s version %s meets requested version %s", update.Name, version, update.FixedVersion)
	}

	if ignoreErrors {
		return errorPkgs, nil
	}

	return errorPkgs, errors.Join(allErrors...)
}
