package helm

import (
	"strings"

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

		images := extractImagesFromObject(obj)
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

// extractImagesFromObject extracts container images from a Kubernetes object
// represented as an unstructured map.
func extractImagesFromObject(obj map[string]interface{}) []ChartImage {
	spec, _ := obj["spec"].(map[string]interface{})
	if spec == nil {
		return nil
	}

	// Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs: spec.template.spec
	if tmpl, ok := spec["template"].(map[string]interface{}); ok {
		if tmplSpec, ok := tmpl["spec"].(map[string]interface{}); ok {
			return extractImagesFromPodSpec(tmplSpec)
		}
	}

	// Bare Pods: spec.containers
	if _, hasCont := spec["containers"]; hasCont {
		return extractImagesFromPodSpec(spec)
	}

	// CronJobs: spec.jobTemplate.spec.template.spec
	if jobTmpl, ok := spec["jobTemplate"].(map[string]interface{}); ok {
		if jobSpec, ok := jobTmpl["spec"].(map[string]interface{}); ok {
			if tmpl, ok := jobSpec["template"].(map[string]interface{}); ok {
				if tmplSpec, ok := tmpl["spec"].(map[string]interface{}); ok {
					return extractImagesFromPodSpec(tmplSpec)
				}
			}
		}
	}

	return nil
}

// extractImagesFromPodSpec extracts images from containers and initContainers
// in a Kubernetes pod spec map.
func extractImagesFromPodSpec(podSpec map[string]interface{}) []ChartImage {
	var images []ChartImage
	for _, key := range []string{"initContainers", "containers"} {
		containers, _ := podSpec[key].([]interface{})
		for _, c := range containers {
			container, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			ref, _ := container["image"].(string)
			if ref == "" {
				continue
			}
			repo, tag := parseImageRef(ref)
			if repo != "" {
				images = append(images, ChartImage{Repository: repo, Tag: tag})
			}
		}
	}
	return images
}

// parseImageRef splits an image reference string into repository and tag components.
// If no tag is present, "latest" is returned as the tag.
// Returns empty strings for an empty input.
func parseImageRef(imageRef string) (repo, tag string) {
	if imageRef == "" {
		return "", ""
	}

	// Find the last colon to split repo from tag.
	// Handle registry ports: "registry:5000/image" vs "image:tag".
	// Strategy: the last colon that is NOT followed by a slash is the tag separator.
	lastColon := strings.LastIndex(imageRef, ":")
	if lastColon == -1 {
		return imageRef, "latest"
	}

	// If there's a slash after the last colon, it's a port (e.g., "registry:5000/image")
	// and there's no explicit tag.
	if strings.Contains(imageRef[lastColon:], "/") {
		return imageRef, "latest"
	}

	return imageRef[:lastColon], imageRef[lastColon+1:]
}
