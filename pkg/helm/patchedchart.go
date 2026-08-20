package helm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"

	helmchart "helm.sh/helm/v3/pkg/chart"
)

// ImageMapping represents the mapping from an original image to its patched replacement.
type ImageMapping struct {
	OriginalRepo string
	OriginalTag  string
	PatchedRepo  string
	PatchedTag   string
}

// ValuePathMapping links one discovered chart image to its values path.
type ValuePathMapping struct {
	ImageRepo      string
	ImageTag       string
	RepositoryPath string
	TagPath        string
	RegistryPath   string
	FullReference  bool
}

// ResolveImageValuePaths locates an unambiguous values path for each image.
// Explicit paths take priority. Auto-detection supports repository/tag,
// registry/repository/tag, name/tag, and scalar image fields.
func ResolveImageValuePaths(chartValues map[string]interface{}, images []ChartImage, explicitPaths map[string]string) ([]ValuePathMapping, error) {
	candidates := findRepositoryPaths(chartValues, "")
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].path < candidates[j].path })

	result := make([]ValuePathMapping, 0, len(images))
	for _, image := range images {
		if explicitPath, found := matchExplicitPath(image.Repository, explicitPaths); found {
			candidate, ok := candidateAtPath(candidates, explicitPath)
			if !ok {
				candidate = repositoryCandidate{path: explicitPath + ".repository", tagPath: explicitPath + ".tag"}
			}
			result = append(result, candidate.mapping(image))
			continue
		}

		bestScore := 0
		var best []repositoryCandidate
		for _, candidate := range candidates {
			score := candidate.matchScore(image)
			if score > bestScore {
				bestScore = score
				best = []repositoryCandidate{candidate}
			} else if score > 0 && score == bestScore {
				best = append(best, candidate)
			}
		}
		if len(best) == 0 {
			return nil, fmt.Errorf("could not detect values path for image %q; set overrides.valuePath", image.Repository+":"+image.Tag)
		}
		if len(best) > 1 {
			paths := make([]string, len(best))
			for i := range best {
				paths[i] = best[i].path
			}
			return nil, fmt.Errorf("ambiguous values paths for image %q: %s; set overrides.valuePath", image.Repository+":"+image.Tag, strings.Join(paths, ", "))
		}
		result = append(result, best[0].mapping(image))
	}
	return result, nil
}

type repositoryCandidate struct {
	path          string
	tagPath       string
	registryPath  string
	value         string
	tag           string
	fullReference bool
}

func (candidate *repositoryCandidate) mapping(image ChartImage) ValuePathMapping {
	return ValuePathMapping{
		ImageRepo:      image.Repository,
		ImageTag:       image.Tag,
		RepositoryPath: candidate.path,
		TagPath:        candidate.tagPath,
		RegistryPath:   candidate.registryPath,
		FullReference:  candidate.fullReference,
	}
}

func (candidate *repositoryCandidate) matchScore(image ChartImage) int {
	if !imageMatchesValue(image.Repository, candidate.value) {
		return 0
	}
	score := 1
	if image.Repository == candidate.value {
		score = 3
	}
	if candidate.tag != "" && candidate.tag == image.Tag {
		score += 4
	}
	return score
}

func findRepositoryPaths(values map[string]interface{}, prefix string) []repositoryCandidate {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var results []repositoryCandidate
	for _, key := range keys {
		value := values[key]
		currentPath := key
		if prefix != "" {
			currentPath = prefix + "." + key
		}

		if key == "image" {
			if imageRef, ok := value.(string); ok && imageRef != "" {
				repo, tag, err := parseImageRef(imageRef)
				if err == nil {
					results = append(results, repositoryCandidate{path: currentPath, value: repo, tag: tag, fullReference: true})
				}
			}
		}

		child, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		for _, imageKey := range []string{"repository", "name"} {
			imageRepo, ok := child[imageKey].(string)
			if !ok || imageRepo == "" {
				continue
			}
			candidate := repositoryCandidate{path: currentPath + "." + imageKey, value: imageRepo}
			if tag, ok := child["tag"].(string); ok {
				candidate.tag = tag
				candidate.tagPath = currentPath + ".tag"
			}
			if registry, ok := child["registry"].(string); ok && registry != "" {
				candidate.value = strings.TrimSuffix(registry, "/") + "/" + imageRepo
				candidate.registryPath = currentPath + ".registry"
			}
			results = append(results, candidate)
			break
		}
		results = append(results, findRepositoryPaths(child, currentPath)...)
	}
	return results
}

func candidateAtPath(candidates []repositoryCandidate, path string) (repositoryCandidate, bool) {
	for _, candidate := range candidates {
		base := strings.TrimSuffix(strings.TrimSuffix(candidate.path, ".repository"), ".name")
		if candidate.path == path || base == path {
			return candidate, true
		}
	}
	return repositoryCandidate{}, false
}

func imageMatchesValue(imageRepo, valueRepo string) bool {
	return imageRepo == valueRepo || strings.HasSuffix(imageRepo, "/"+valueRepo) || strings.HasSuffix(valueRepo, "/"+imageRepo)
}

func matchExplicitPath(imageRepo string, explicitPaths map[string]string) (string, bool) {
	if path, ok := explicitPaths[imageRepo]; ok {
		return path, true
	}
	keys := make([]string, 0, len(explicitPaths))
	for key := range explicitPaths {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if MatchRepositoryPattern(imageRepo, key) {
			return explicitPaths[key], true
		}
	}
	return "", false
}

// BuildPatchedChart creates an in-memory wrapper Helm chart that depends on the
// original chart and overrides its image values with patched references.
//
// The wrapper chart:
//   - Has name "{original}-patched" and a deterministic version derived from patched image mappings
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

	overrideValues, err := buildOverrideValues(origName, mappings, valuePaths)
	if err != nil {
		return nil, err
	}

	sanitizedRepository, err := sanitizeRepository(chartSpec.Repository)
	if err != nil {
		return nil, err
	}

	patchedChart := &helmchart.Chart{
		Metadata: &helmchart.Metadata{
			APIVersion:  helmchart.APIVersionV2,
			Name:        origName + "-patched",
			Version:     patchedChartVersion(origVersion, mappings),
			Description: fmt.Sprintf("Copa-patched version of %s %s", origName, origVersion),
			Type:        "application",
			Annotations: map[string]string{
				"copa.sh/source-chart":      origName,
				"copa.sh/source-version":    origVersion,
				"copa.sh/source-repository": sanitizedRepository,
			},
			Dependencies: []*helmchart.Dependency{
				{
					Name:       origName,
					Version:    origVersion,
					Repository: sanitizedRepository,
				},
			},
		},
		Values: overrideValues,
	}
	patchedChart.SetDependencies(originalChart)
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
type imageMappingKey struct {
	repository string
	tag        string
}

func buildOverrideValues(subchartName string, mappings []ImageMapping, valuePaths []ValuePathMapping) (map[string]interface{}, error) {
	lookup := make(map[imageMappingKey]ImageMapping, len(mappings))
	for _, mapping := range mappings {
		lookup[imageMappingKey{repository: mapping.OriginalRepo, tag: mapping.OriginalTag}] = mapping
	}

	subchartValues := make(map[string]interface{})
	for _, valuePath := range valuePaths {
		patched, found := findPatchedMapping(valuePath.ImageRepo, valuePath.ImageTag, lookup)
		if !found {
			return nil, fmt.Errorf("no patched mapping found for image %q", valuePath.ImageRepo+":"+valuePath.ImageTag)
		}
		if valuePath.FullReference {
			setNestedValue(subchartValues, valuePath.RepositoryPath, patched.PatchedRepo+":"+patched.PatchedTag)
			continue
		}

		if valuePath.TagPath == "" {
			return nil, fmt.Errorf("no writable tag path found for image %q", valuePath.ImageRepo+":"+valuePath.ImageTag)
		}

		repository := patched.PatchedRepo
		if valuePath.RegistryPath != "" {
			registry, remainder := splitRegistry(patched.PatchedRepo)
			setNestedValue(subchartValues, valuePath.RegistryPath, registry)
			repository = remainder
		}
		setNestedValue(subchartValues, valuePath.RepositoryPath, repository)
		setNestedValue(subchartValues, valuePath.TagPath, patched.PatchedTag)
	}
	if len(subchartValues) == 0 {
		return map[string]interface{}{}, nil
	}
	return map[string]interface{}{subchartName: subchartValues}, nil
}

func patchedChartVersion(sourceVersion string, mappings []ImageMapping) string {
	entries := make([]string, len(mappings))
	for i, mapping := range mappings {
		entries[i] = strings.Join([]string{mapping.OriginalRepo, mapping.OriginalTag, mapping.PatchedRepo, mapping.PatchedTag}, "\x00")
	}
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return sourceVersion + "-patched." + hex.EncodeToString(sum[:6])
}

func sanitizeRepository(repository string) (string, error) {
	parsed, err := url.Parse(repository)
	if err != nil {
		return "", fmt.Errorf("invalid chart repository: %w", err)
	}
	if parsed.Scheme == "" {
		if strings.ContainsAny(repository, "@?#") {
			return "", fmt.Errorf("chart repository must be a URL when it contains credentials or query data")
		}
		return repository, nil
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func findPatchedMapping(imageRepo, imageTag string, lookup map[imageMappingKey]ImageMapping) (ImageMapping, bool) {
	if mapping, ok := lookup[imageMappingKey{repository: imageRepo, tag: imageTag}]; ok {
		return mapping, true
	}
	for key, mapping := range lookup {
		if key.tag == imageTag && imageMatchesValue(imageRepo, key.repository) {
			return mapping, true
		}
	}
	return ImageMapping{}, false
}

func splitRegistry(repository string) (string, string) {
	first, remainder, found := strings.Cut(repository, "/")
	if found && (strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost") {
		return first, remainder
	}
	return "", repository
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
