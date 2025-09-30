package common

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/project-copacetic/copacetic/pkg/utils" // Assuming this is where the constants are defined
	"github.com/quay/claircore/osrelease"
	log "github.com/sirupsen/logrus"
)

// OSInfo contains the OS type and version information.
type OSInfo struct {
	Type    string
	Version string
}

// GetOSInfo extracts OS type and version from os-release data.
func GetOSInfo(ctx context.Context, osreleaseBytes []byte) (*OSInfo, error) {
	r := bytes.NewReader(osreleaseBytes)
	osData, err := osrelease.Parse(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("unable to parse os-release data %w", err)
	}

	osType := strings.ToLower(osData["NAME"])
	var normalizedType string
	switch {
	case strings.Contains(osType, utils.OSTypeAlpine):
		normalizedType = utils.OSTypeAlpine
	case strings.Contains(osType, utils.OSTypeDebian):
		normalizedType = utils.OSTypeDebian
	case strings.Contains(osType, utils.OSTypeUbuntu):
		normalizedType = utils.OSTypeUbuntu
	case strings.Contains(osType, utils.OSTypeAmazon):
		normalizedType = utils.OSTypeAmazon
	case strings.Contains(osType, utils.OSTypeCentOS):
		normalizedType = utils.OSTypeCentOS
	case strings.Contains(osType, "mariner"):
		normalizedType = utils.OSTypeCBLMariner
	case strings.Contains(osType, "azure linux"):
		normalizedType = utils.OSTypeAzureLinux
	case strings.Contains(osType, "red hat"):
		normalizedType = utils.OSTypeRedHat
	case strings.Contains(osType, utils.OSTypeRocky):
		normalizedType = utils.OSTypeRocky
	case strings.Contains(osType, utils.OSTypeOracle):
		normalizedType = utils.OSTypeOracle
	case strings.Contains(osType, utils.OSTypeAlma):
		normalizedType = utils.OSTypeAlma
	default:
		log.Error("unsupported osType ", osType)
		return nil, errors.ErrUnsupported
	}

	return &OSInfo{
		Type:    normalizedType,
		Version: osData["VERSION_ID"],
	}, nil
}
