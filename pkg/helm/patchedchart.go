package helm

import (
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	helmchart "helm.sh/helm/v3/pkg/chart"
)

// ImageMapping represents the mapping from an original image to its patched replacement.
type ImageMapping struct {
	OriginalRepo string
	OriginalTag  string
	PatchedRepo  string
	PatchedTag   string
}

// ValuePathMapping links a discovered chart image to its values.yaml path.
type ValuePathMapping struct {
	ImageRepo      string // The matched image repository (e.g. "docker.io/timberio/vector")
	RepositoryPath string // Dot-delimited path to the repository value (e.g. "image.repository")
	TagPath        string // Dot-delimited path to the tag value (e.g. "image.tag")
}

// ResolveImageValuePaths auto-detects where each ChartImage's repository and tag
// are defined in the chart's values.yaml. It walks the values tree looking for
// the common pattern of `*.repository` / `*.tag` pairs, matching discovered images
// by suffix comparison.
//
// explicitPaths allows users to override auto-detection for specific images.
// Keys are image repository patterns (same matching as OverrideSpec), values are
// the dot-delimited parent path (e.g. "controller.image").
func ResolveImageValuePaths(
	chartValues map[string]interface{},
	images []ChartImage,
	explicitPaths map[string]string,
) []ValuePathMapping {
	var result []ValuePathMapping
	matched := make(map[string]bool) // track which images have been matched

	// First, apply explicit paths — these take priority
	for _, img := range images {
		path, found := matchExplicitPath(img.Repository, explicitPaths)
		if found {
			result = append(result, ValuePathMapping{
				ImageRepo:      img.Repository,
				RepositoryPath: path + ".repository",
				TagPath:        path + ".tag",
			})
			matched[img.Repository] = true
		}
	}

	// Then auto-detect remaining images
	candidates := findRepositoryPaths(chartValues, "")
	for _, img := range images {
		if matched[img.Repository] {
			continue
		}
		for _, candidate := range candidates {
			if imageMatchesValue(img.Repository, candidate.value) {
				result = append(result, ValuePathMapping{
					ImageRepo:      img.Repository,
					RepositoryPath: candidate.path,
					TagPath:        candidate.tagPath,
				})
				matched[img.Repository] = true
				break
			}
		}
		if !matched[img.Repository] {
			log.Warnf("helm: could not auto-detect values.yaml path for image %q — use overrides.valuePath to specify manually", img.Repository)
		}
	}

	return result
}

// repositoryCandidate represents a discovered repository/tag pair in values.yaml.
type repositoryCandidate struct {
	path    string // dot-delimited path to the "repository" key (e.g. "image.repository")
	tagPath string // dot-delimited path to the sibling "tag" key (e.g. "image.tag")
	value   string // the string value of the repository key
}

// findRepositoryPaths recursively walks a values map looking for keys named "repository"
// that have string values, and checks for a sibling "tag" key.
func findRepositoryPaths(values map[string]interface{}, prefix string) []repositoryCandidate {
	var results []repositoryCandidate

	for key, val := range values {
		currentPath := key
		if prefix != "" {
			currentPath = prefix + "." + key
		}

		switch v := val.(type) {
		case map[string]interface{}:
			// Check if this map has a "repository" string key
			if repoVal, ok := v["repository"]; ok {
				if repoStr, ok := repoVal.(string); ok && repoStr != "" {
					candidate := repositoryCandidate{
						path:  currentPath + ".repository",
						value: repoStr,
					}
					// Look for sibling "tag" key
					if _, hasTag := v["tag"]; hasTag {
						candidate.tagPath = currentPath + ".tag"
					}
					results = append(results, candidate)
				}
			}
			// Recurse into nested maps
			results = append(results, findRepositoryPaths(v, currentPath)...)
		}
	}

	return results
}

// imageMatchesValue checks if a discovered image repository matches a value from values.yaml.
// Uses suffix matching to handle registry prefixes (e.g., "docker.io/library/nginx" matches "nginx").
func imageMatchesValue(imageRepo, valueRepo string) bool {
	if imageRepo == valueRepo {
		return true
	}
	// Suffix match: imageRepo "docker.io/timberio/vector" matches valueRepo "timberio/vector"
	if strings.HasSuffix(imageRepo, "/"+valueRepo) {
		return true
	}
	// Reverse suffix: valueRepo "docker.io/timberio/vector" matches imageRepo "timberio/vector"
	if strings.HasSuffix(valueRepo, "/"+imageRepo) {
		return true
	}
	return false
}

// matchExplicitPath finds the explicit value path for an image repository,
// using the shared MatchRepositoryPattern logic (exact or suffix match).
func matchExplicitPath(imageRepo string, explicitPaths map[string]string) (string, bool) {
	if path, ok := explicitPaths[imageRepo]; ok {
		return path, true
	}
	for key, path := range explicitPaths {
		if MatchRepositoryPattern(imageRepo, key) {
			return path, true
		}
	}
	return "", false
}

// BuildPatchedChart creates an in-memory wrapper Helm chart that depends on the
// original chart and overrides its image values with patched references.
//
// The wrapper chart:
//   - Has name "{original}-patched" and version "{original-version}-patched.1"
//   - Declares the original chart as a dependency
//   - Sets values that override image repository/tag for each patched image
//   - Includes Copa metadata annotations for traceability
func BuildPatchedChart(
	originalChart *helmchart.Chart,
	chartSpec ChartSourceSpec,
	mappings []ImageMapping,
	valuePaths []ValuePathMapping,
) (*helmchart.Chart, error) {
	if originalChart == nil || originalChart.Metadata == nil {
		return nil, fmt.Errorf("original chart or its metadata is nil")
	}

	origName := originalChart.Metadata.Name
	origVersion := originalChart.Metadata.Version

	// Build the subchart-scoped values overrides
	overrideValues := buildOverrideValues(origName, mappings, valuePaths)

	patchedChart := &helmchart.Chart{
		Metadata: &helmchart.Metadata{
			APIVersion:  helmchart.APIVersionV2,
			Name:        origName + "-patched",
			Version:     origVersion + "-patched.1",
			Description: fmt.Sprintf("Copa-patched version of %s %s", origName, origVersion),
			Type:        "application",
			Annotations: map[string]string{
				"copa.sh/source-chart":      origName,
				"copa.sh/source-version":    origVersion,
				"copa.sh/source-repository": chartSpec.Repository,
				"copa.sh/patched-at":        time.Now().UTC().Format(time.RFC3339),
			},
			Dependencies: []*helmchart.Dependency{
				{
					Name:       origName,
					Version:    origVersion,
					Repository: chartSpec.Repository,
				},
			},
		},
		Values: overrideValues,
	}

	return patchedChart, nil
}

// ChartSourceSpec contains the repository information needed for the dependency reference.
type ChartSourceSpec struct {
	Name       string
	Version    string
	Repository string
}

// buildOverrideValues constructs the values.yaml map for the wrapper chart.
// All paths are scoped under the subchart name (Helm convention for dependency overrides).
//
// For example, if the original chart is "vector" and the image path is "image.repository",
// the override key becomes "vector.image.repository".
func buildOverrideValues(
	subchartName string,
	mappings []ImageMapping,
	valuePaths []ValuePathMapping,
) map[string]interface{} {
	// Build a lookup from original repo → patched info
	patchedLookup := make(map[string]ImageMapping)
	for _, m := range mappings {
		patchedLookup[m.OriginalRepo] = m
	}

	// Build the subchart override map
	subchartValues := make(map[string]interface{})

	for _, vp := range valuePaths {
		patched, found := findPatchedMapping(vp.ImageRepo, patchedLookup)
		if !found {
			log.Debugf("helm: no patched mapping found for image %q, skipping value override", vp.ImageRepo)
			continue
		}

		// Strip the first component if it matches the key we'll nest under
		// e.g., "image.repository" → set at path ["image"]["repository"]
		setNestedValue(subchartValues, vp.RepositoryPath, patched.PatchedRepo)
		if vp.TagPath != "" {
			setNestedValue(subchartValues, vp.TagPath, patched.PatchedTag)
		}
	}

	if len(subchartValues) == 0 {
		return map[string]interface{}{}
	}

	return map[string]interface{}{
		subchartName: subchartValues,
	}
}

// findPatchedMapping looks up a patched mapping for an image, supporting suffix matching.
func findPatchedMapping(imageRepo string, lookup map[string]ImageMapping) (ImageMapping, bool) {
	if m, ok := lookup[imageRepo]; ok {
		return m, true
	}
	for repo, m := range lookup {
		if strings.HasSuffix(repo, "/"+imageRepo) || strings.HasSuffix(imageRepo, "/"+repo) {
			return m, true
		}
	}
	return ImageMapping{}, false
}

// setNestedValue sets a value in a nested map using a dot-delimited path.
// For example, setNestedValue(m, "image.repository", "nginx") creates:
//
//	m["image"]["repository"] = "nginx"
func setNestedValue(m map[string]interface{}, path string, value interface{}) {
	parts := strings.Split(path, ".")
	current := m
	for i, part := range parts {
		if i == len(parts)-1 {
			current[part] = value
		} else {
			next, ok := current[part].(map[string]interface{})
			if !ok {
				next = make(map[string]interface{})
				current[part] = next
			}
			current = next
		}
	}
}
