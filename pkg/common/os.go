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
	normalizedType := utils.CanonicalOSType(osType)
	if normalizedType == "" {
		log.Error("unsupported osType ", osType)
		return nil, errors.ErrUnsupported
	}

	return &OSInfo{
		Type:    normalizedType,
		Version: osData["VERSION_ID"],
	}, nil
}
