package patch

import (
	"net/url"

	log "github.com/sirupsen/logrus"

	"github.com/project-copacetic/copacetic/pkg/imageloader"
)

// detectLoaderFromBuildkitAddr attempts to determine the appropriate loader
// based on the buildkit connection address scheme.
func detectLoaderFromBuildkitAddr(addr string) string {
	if addr == "" {
		return ""
	}

	u, err := url.Parse(addr)
	if err != nil {
		log.Debugf("Failed to parse buildkit address %q: %v", addr, err)
		return ""
	}

	switch u.Scheme {
	case "podman-container":
		return imageloader.Podman
	case "docker-container", "docker", "buildx":
		return imageloader.Docker
	default:
		// Unknown scheme, let imageloader auto-detect
		return ""
	}
}
