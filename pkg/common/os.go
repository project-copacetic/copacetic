package common

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

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
	case strings.Contains(osType, "alpine"):
		normalizedType = "alpine"
	case strings.Contains(osType, "debian"):
		normalizedType = "debian"
	case strings.Contains(osType, "ubuntu"):
		normalizedType = "ubuntu"
	case strings.Contains(osType, "amazon"):
		normalizedType = "amazon"
	case strings.Contains(osType, "centos"):
		normalizedType = "centos"
	case strings.Contains(osType, "mariner"):
		normalizedType = "cbl-mariner"
	case strings.Contains(osType, "azure linux"):
		normalizedType = "azurelinux"
	case strings.Contains(osType, "red hat"):
		normalizedType = "redhat"
	case strings.Contains(osType, "rocky"):
		normalizedType = "rocky"
	case strings.Contains(osType, "oracle"):
		normalizedType = "oracle"
	case strings.Contains(osType, "alma"):
		normalizedType = "alma"
	default:
		log.Error("unsupported osType ", osType)
		return nil, errors.ErrUnsupported
	}

	return &OSInfo{
		Type:    normalizedType,
		Version: osData["VERSION_ID"],
	}, nil
}

// GetOSType extracts and normalizes the OS type from os-release data.
// Deprecated: Use GetOSInfo instead for better API design.
func GetOSType(ctx context.Context, osreleaseBytes []byte) (string, error) {
	r := bytes.NewReader(osreleaseBytes)
	osData, err := osrelease.Parse(ctx, r)
	if err != nil {
		return "", fmt.Errorf("unable to parse os-release data %w", err)
	}

	osType := strings.ToLower(osData["NAME"])
	switch {
	case strings.Contains(osType, "alpine"):
		return "alpine", nil
	case strings.Contains(osType, "debian"):
		return "debian", nil
	case strings.Contains(osType, "ubuntu"):
		return "ubuntu", nil
	case strings.Contains(osType, "amazon"):
		return "amazon", nil
	case strings.Contains(osType, "centos"):
		return "centos", nil
	case strings.Contains(osType, "mariner"):
		return "cbl-mariner", nil
	case strings.Contains(osType, "azure linux"):
		return "azurelinux", nil
	case strings.Contains(osType, "red hat"):
		return "redhat", nil
	case strings.Contains(osType, "rocky"):
		return "rocky", nil
	case strings.Contains(osType, "oracle"):
		return "oracle", nil
	case strings.Contains(osType, "alma"):
		return "alma", nil
	default:
		log.Error("unsupported osType ", osType)
		return "", errors.ErrUnsupported
	}
}

// GetOSVersion extracts the OS version from os-release data.
// Deprecated: Use GetOSInfo instead for better API design.
func GetOSVersion(ctx context.Context, osreleaseBytes []byte) (string, error) {
	r := bytes.NewReader(osreleaseBytes)
	osData, err := osrelease.Parse(ctx, r)
	if err != nil {
		return "", fmt.Errorf("unable to parse os-release data %w", err)
	}

	return osData["VERSION_ID"], nil
}
