package helm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type ImageMapping struct {
	OriginalRepo string
	OriginalTag  string
	PatchedRepo  string
	PatchedTag   string
}

type ValuePathMapping struct {
	ImageRepo      string
	ImageTag       string
	RepositoryPath string
	TagPath        string
	RegistryPath   string
	FullReference  bool
}

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
				bestScore, best = score, []repositoryCandidate{candidate}
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
	path, tagPath, registryPath, value, tag string
	fullReference                           bool
}

func (candidate *repositoryCandidate) mapping(image ChartImage) ValuePathMapping {
	return ValuePathMapping{
		ImageRepo: image.Repository, ImageTag: image.Tag,
		RepositoryPath: candidate.path, TagPath: candidate.tagPath,
		RegistryPath: candidate.registryPath, FullReference: candidate.fullReference,
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

// BuildPatchedChart creates local wrapper chart files and embeds the original archive.
func BuildPatchedChart(original *Chart, chartSpec ChartSourceSpec, mappings []ImageMapping, valuePaths []ValuePathMapping) (*Chart, error) {
	if original == nil {
		return nil, fmt.Errorf("original chart is nil")
	}
	overrideValues, err := buildOverrideValues(original.Metadata.Name, mappings, valuePaths)
	if err != nil {
		return nil, err
	}
	repository, err := sanitizeRepository(chartSpec.Repository)
	if err != nil {
		return nil, err
	}
	return &Chart{
		Metadata: Metadata{
			APIVersion: "v2", Name: original.Metadata.Name + "-patched",
			Version:     patchedChartVersion(original.Metadata.Version, mappings),
			Description: fmt.Sprintf("Copa-patched version of %s %s", original.Metadata.Name, original.Metadata.Version),
			Type:        "application",
			Annotations: map[string]string{
				"copa.sh/source-chart": original.Metadata.Name, "copa.sh/source-version": original.Metadata.Version,
				"copa.sh/source-repository": repository,
			},
			Dependencies: []Dependency{{Name: original.Metadata.Name, Version: original.Metadata.Version, Repository: repository}},
		},
		Values: overrideValues, Archive: original.Archive,
	}, nil
}

type (
	ChartSourceSpec struct{ Name, Version, Repository string }
	imageMappingKey struct{ repository, tag string }
)

func buildOverrideValues(subchartName string, mappings []ImageMapping, valuePaths []ValuePathMapping) (map[string]interface{}, error) {
	lookup := make(map[imageMappingKey]ImageMapping, len(mappings))
	for _, mapping := range mappings {
		lookup[imageMappingKey{mapping.OriginalRepo, mapping.OriginalTag}] = mapping
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
	if mapping, ok := lookup[imageMappingKey{imageRepo, imageTag}]; ok {
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

func setNestedValue(m map[string]interface{}, path string, value interface{}) {
	keys := strings.Split(path, ".")
	for _, key := range keys[:len(keys)-1] {
		child, ok := m[key].(map[string]interface{})
		if !ok {
			child = make(map[string]interface{})
			m[key] = child
		}
		m = child
	}
	m[keys[len(keys)-1]] = value
}
