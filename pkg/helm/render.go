package helm

import (
	"fmt"
	"strings"

	"github.com/distribution/reference"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// ChartImage represents a container image reference discovered from a Helm chart.
type ChartImage struct {
	Repository string // e.g., "docker.io/timberio/vector"
	Tag        string // e.g., "0.53.0-distroless-libc"
}

// ExtractImages parses rendered Kubernetes YAML manifests and extracts all
// container image references, including init containers and sidecar containers.
// It deduplicates by full image reference (repository:tag).
func ExtractImages(renderedManifests string) ([]ChartImage, error) {
	seen := make(map[string]struct{})
	var result []ChartImage

	// Split on YAML document separator
	docs := strings.Split(renderedManifests, "\n---")
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" || doc == "---" {
			continue
		}

		var obj map[string]interface{}
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			log.Debugf("helm: skipping non-YAML document during image extraction: %v", err)
			continue
		}
		if obj == nil {
			continue
		}

		images, err := extractImagesFromObject(obj)
		if err != nil {
			return nil, err
		}
		for _, img := range images {
			key := img.Repository + ":" + img.Tag
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				result = append(result, img)
			}
		}
	}

	if result == nil {
		result = []ChartImage{}
	}
	return result, nil
}

// extractImagesFromObject extracts container images from a Kubernetes object.
func extractImagesFromObject(obj map[string]interface{}) ([]ChartImage, error) {
	if items, ok := obj["items"].([]interface{}); ok {
		var images []ChartImage
		for _, item := range items {
			child, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			childImages, err := extractImagesFromObject(child)
			if err != nil {
				return nil, err
			}
			images = append(images, childImages...)
		}
		return images, nil
	}

	spec, _ := obj["spec"].(map[string]interface{})
	if spec == nil {
		return nil, nil
	}

	if tmpl, ok := spec["template"].(map[string]interface{}); ok {
		if tmplSpec, ok := tmpl["spec"].(map[string]interface{}); ok {
			return extractImagesFromPodSpec(tmplSpec)
		}
	}

	if _, hasContainers := spec["containers"]; hasContainers {
		return extractImagesFromPodSpec(spec)
	}

	if jobTemplate, ok := spec["jobTemplate"].(map[string]interface{}); ok {
		if jobSpec, ok := jobTemplate["spec"].(map[string]interface{}); ok {
			if tmpl, ok := jobSpec["template"].(map[string]interface{}); ok {
				if tmplSpec, ok := tmpl["spec"].(map[string]interface{}); ok {
					return extractImagesFromPodSpec(tmplSpec)
				}
			}
		}
	}

	return nil, nil
}

// extractImagesFromPodSpec extracts images from every Kubernetes container class.
func extractImagesFromPodSpec(podSpec map[string]interface{}) ([]ChartImage, error) {
	var images []ChartImage
	for _, key := range []string{"initContainers", "containers", "ephemeralContainers"} {
		containers, _ := podSpec[key].([]interface{})
		for _, value := range containers {
			container, ok := value.(map[string]interface{})
			if !ok {
				continue
			}
			imageRef, _ := container["image"].(string)
			if imageRef == "" {
				continue
			}
			repo, tag, err := parseImageRef(imageRef)
			if err != nil {
				return nil, err
			}
			images = append(images, ChartImage{Repository: repo, Tag: tag})
		}
	}
	return images, nil
}

// parseImageRef returns the repository and tag of a tag-addressed image.
// Digest-addressed images are rejected because replacing their digest with a tag
// would change the selected image identity.
func parseImageRef(imageRef string) (string, string, error) {
	if imageRef == "" {
		return "", "", nil
	}
	if strings.Contains(imageRef, "@") {
		return "", "", fmt.Errorf("digest-pinned image %q is unsupported in chart patching", imageRef)
	}
	named, err := reference.ParseNormalizedNamed(imageRef)
	if err != nil {
		return "", "", fmt.Errorf("invalid image reference %q: %w", imageRef, err)
	}
	if tagged, ok := named.(reference.Tagged); ok {
		tag := tagged.Tag()
		return strings.TrimSuffix(imageRef, ":"+tag), tag, nil
	}
	return imageRef, "latest", nil
}
