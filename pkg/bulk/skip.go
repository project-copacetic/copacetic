package bulk

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/report"
	log "github.com/sirupsen/logrus"
)

// skipCheckResult encapsulates the decision about whether to skip patching an image.
type skipCheckResult struct {
	ShouldSkip  bool
	Reason      string
	ResolvedTag string // The tag to use if NOT skipping (versioned)
}

var archTagSuffixSet = struct {
	sync.Once
	values map[string]struct{}
}{}

func knownArchTagSuffixes() map[string]struct{} {
	archTagSuffixSet.Do(func() {
		suffixes := patch.ArchTagSuffixes()
		values := make(map[string]struct{}, len(suffixes))
		for _, suffix := range suffixes {
			values[suffix] = struct{}{}
		}
		archTagSuffixSet.values = values
	})
	return archTagSuffixSet.values
}

// isArchSpecificTag reports whether tag is an architecture-specific variant of baseTag
// (e.g. "3.18.0-patched-386" for baseTag "3.18.0-patched").
// It checks against the suffixes derived from Copa's validPlatforms list.
func isArchSpecificTag(tag, baseTag string) bool {
	prefix := baseTag + "-"
	if !strings.HasPrefix(tag, prefix) {
		return false
	}
	_, found := knownArchTagSuffixes()[tag[len(prefix):]]
	return found
}

// discoverExistingPatchTags lists all tags in the repository that match the base tag pattern.
// It returns tags matching either "<baseTag>" or "<baseTag>-N" where N is a number.
// Architecture-specific tags (e.g. "<baseTag>-386") are excluded.
func discoverExistingPatchTags(repo, baseTag string) ([]string, error) {
	repository, err := name.NewRepository(repo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository name '%s': %w", repo, err)
	}

	allTags, err := listAllTags(repository)
	if err != nil {
		// Fail-open: if we can't list tags, proceed with base tag
		log.Warnf("Failed to list tags for repository '%s': %v", repo, err)
		return []string{}, nil
	}

	type patchTag struct {
		tag     string
		version int
	}

	matching := make([]patchTag, 0, len(allTags))
	for _, tag := range allTags {
		version, ok := patchTagVersion(tag, baseTag)
		if ok {
			matching = append(matching, patchTag{tag: tag, version: version})
		}
	}

	// Sort by version number (ascending)
	sort.Slice(matching, func(i, j int) bool {
		return matching[i].version < matching[j].version
	})

	result := make([]string, len(matching))
	for i, match := range matching {
		result[i] = match.tag
	}
	return result, nil
}

// extractVersionNumber extracts the version number from a tag.
// Returns 0 for the base tag, N for base-N tags.
func extractVersionNumber(tag, baseTag string) int {
	if tag == baseTag {
		return 0
	}
	prefix := baseTag + "-"
	if !strings.HasPrefix(tag, prefix) {
		return 0
	}
	if num, ok := parsePatchTagVersionNumber(tag[len(prefix):]); ok {
		return num
	}
	return 0
}

func parsePatchTagVersionNumber(suffix string) (int, bool) {
	if suffix == "" {
		return 0, false
	}
	for i := 0; i < len(suffix); i++ {
		if suffix[i] < '0' || suffix[i] > '9' {
			return 0, false
		}
	}
	version, err := strconv.Atoi(suffix)
	if err != nil {
		return 0, false
	}
	return version, true
}

func patchTagVersion(tag, baseTag string) (int, bool) {
	if tag == baseTag {
		return 0, true
	}
	prefix := baseTag + "-"
	if !strings.HasPrefix(tag, prefix) {
		return 0, false
	}
	suffix := tag[len(prefix):]
	if suffix == "" {
		return 0, false
	}
	if _, found := knownArchTagSuffixes()[suffix]; found {
		return 0, false
	}
	return parsePatchTagVersionNumber(suffix)
}

// latestPatchTag returns the tag with the highest version number from the list.
func latestPatchTag(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	// Tags are already sorted by version number, so return the last one
	return tags[len(tags)-1]
}

// nextPatchTag computes the next version tag to use for re-patching.
func nextPatchTag(baseTag string, existingTags []string) string {
	if len(existingTags) == 0 {
		return baseTag
	}

	maxVersion := 0
	for _, tag := range existingTags {
		ver := extractVersionNumber(tag, baseTag)
		if ver > maxVersion {
			maxVersion = ver
		}
	}

	return fmt.Sprintf("%s-%d", baseTag, maxVersion+1)
}

// reportIndex maps normalized image references to report file paths.
type reportIndex struct {
	refs map[string]string // normalized ref → file path
}

// buildReportIndex scans a flat directory for JSON report files, extracts ArtifactName
// from each, normalizes references, and builds a lookup map.
// Note: Only top-level JSON files are indexed; subdirectories are not scanned recursively.
func buildReportIndex(reportsDir string) *reportIndex {
	// Read all files in the directory
	entries, err := os.ReadDir(reportsDir)
	idx := &reportIndex{
		refs: make(map[string]string, len(entries)),
	}
	if err != nil {
		log.Warnf("Failed to read reports directory '%s': %v", reportsDir, err)
		return idx
	}

	// Process each JSON file
	for _, entry := range entries {
		if entry.IsDir() {
			log.Debugf("Skipping subdirectory '%s' in reports directory (only top-level JSON files are indexed)", entry.Name())
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(reportsDir, entry.Name())

		artifactName, err := readReportArtifactName(filePath)
		if err != nil {
			log.Debugf("Failed to parse JSON from '%s': %v", filePath, err)
			continue
		}

		if artifactName == "" {
			log.Debugf("Report file '%s' has no ArtifactName field, skipping", filePath)
			continue
		}

		// Normalize the ArtifactName reference
		normalizedRef := artifactName
		if ref, err := name.ParseReference(artifactName); err == nil {
			normalizedRef = ref.Name()
		} else {
			log.Debugf("Failed to normalize reference '%s', using raw value: %v", artifactName, err)
		}

		// Store in the index
		idx.refs[normalizedRef] = filePath
		log.Debugf("Indexed report: %s -> %s (from ArtifactName: %s)", normalizedRef, filePath, artifactName)
	}

	log.Infof("Built report index with %d entries from '%s'", len(idx.refs), reportsDir)
	return idx
}

func readReportArtifactName(filePath string) (string, error) {
	data, err := os.ReadFile(filePath) // #nosec G304 - filePath is from controlled directory scan
	if err != nil {
		return "", err
	}
	if !json.Valid(data) {
		return "", fmt.Errorf("invalid JSON")
	}
	return extractTopLevelStringField(data, "ArtifactName")
}

func extractTopLevelStringField(data []byte, field string) (string, error) {
	i := skipJSONSpace(data, 0)
	if i >= len(data) || data[i] != '{' {
		return "", fmt.Errorf("expected JSON object")
	}
	i++
	var foundValue string

	for {
		i = skipJSONSpace(data, i)
		if i >= len(data) {
			return "", fmt.Errorf("unexpected end of JSON object")
		}
		if data[i] == '}' {
			return foundValue, nil
		}
		if data[i] != '"' {
			return "", fmt.Errorf("expected JSON object key")
		}

		keyStart := i
		var err error
		i, err = skipJSONString(data, i)
		if err != nil {
			return "", err
		}
		key, err := decodeJSONStringToken(data[keyStart:i])
		if err != nil {
			return "", err
		}

		i = skipJSONSpace(data, i)
		if i >= len(data) || data[i] != ':' {
			return "", fmt.Errorf("expected ':' after JSON object key")
		}
		i++
		i = skipJSONSpace(data, i)

		if key == field {
			if i >= len(data) || data[i] != '"' {
				return "", fmt.Errorf("field %q is not a string", field)
			}
			valueStart := i
			i, err = skipJSONString(data, i)
			if err != nil {
				return "", err
			}
			foundValue, err = decodeJSONStringToken(data[valueStart:i])
			if err != nil {
				return "", err
			}
		} else {
			i, err = skipJSONValue(data, i)
			if err != nil {
				return "", err
			}
		}
		i = skipJSONSpace(data, i)
		if i >= len(data) {
			return "", fmt.Errorf("unexpected end after JSON value")
		}
		switch data[i] {
		case ',':
			i++
		case '}':
			return foundValue, nil
		default:
			return "", fmt.Errorf("expected ',' or '}' after JSON value")
		}
	}
}

func decodeJSONStringToken(token []byte) (string, error) {
	var value string
	if err := json.Unmarshal(token, &value); err != nil {
		return "", err
	}
	return value, nil
}

func skipJSONSpace(data []byte, i int) int {
	for i < len(data) {
		switch data[i] {
		case ' ', '\n', '\r', '\t':
			i++
		default:
			return i
		}
	}
	return i
}

func skipJSONString(data []byte, i int) (int, error) {
	if i >= len(data) || data[i] != '"' {
		return i, fmt.Errorf("expected JSON string")
	}
	i++
	for i < len(data) {
		switch data[i] {
		case '"':
			return i + 1, nil
		case '\\':
			i += 2
		default:
			i++
		}
	}
	return i, fmt.Errorf("unterminated JSON string")
}

func skipJSONValue(data []byte, i int) (int, error) {
	i = skipJSONSpace(data, i)
	if i >= len(data) {
		return i, fmt.Errorf("unexpected end of JSON value")
	}

	switch data[i] {
	case '"':
		return skipJSONString(data, i)
	case '{', '[':
		return skipJSONContainer(data, i)
	default:
		start := i
		for i < len(data) {
			switch data[i] {
			case ' ', '\n', '\r', '\t', ',', '}', ']':
				if start == i {
					return i, fmt.Errorf("empty JSON value")
				}
				return i, nil
			default:
				i++
			}
		}
		if start == i {
			return i, fmt.Errorf("empty JSON value")
		}
		return i, nil
	}
}

func skipJSONContainer(data []byte, i int) (int, error) {
	stack := []byte{data[i]}
	i++
	for i < len(data) && len(stack) > 0 {
		switch data[i] {
		case '"':
			var err error
			i, err = skipJSONString(data, i)
			if err != nil {
				return i, err
			}
		case '{', '[':
			stack = append(stack, data[i])
			i++
		case '}':
			if stack[len(stack)-1] != '{' {
				return i, fmt.Errorf("mismatched JSON object close")
			}
			stack = stack[:len(stack)-1]
			i++
		case ']':
			if stack[len(stack)-1] != '[' {
				return i, fmt.Errorf("mismatched JSON array close")
			}
			stack = stack[:len(stack)-1]
			i++
		default:
			i++
		}
	}
	if len(stack) > 0 {
		return i, fmt.Errorf("unterminated JSON container")
	}
	return i, nil
}

// lookup finds a report for the given image reference by normalizing it
// and checking the index.
func (idx *reportIndex) lookup(imageRef string) (string, bool) {
	if idx == nil || idx.refs == nil {
		return "", false
	}

	if path, found := idx.refs[imageRef]; found {
		return path, true
	}

	// Normalize the incoming imageRef
	normalizedRef := imageRef
	if ref, err := name.ParseReference(imageRef); err == nil {
		normalizedRef = ref.Name()
	} else {
		log.Debugf("Failed to normalize lookup reference '%s', using raw value: %v", imageRef, err)
	}

	// Look up in the index
	path, found := idx.refs[normalizedRef]
	return path, found
}

// checkReportForVulnerabilities parses a vulnerability report file to check for fixable vulnerabilities.
// Returns (hasVulns, error) where:
// - hasVulns=true means fixable vulnerabilities were found.
// - error is set if the report couldn't be parsed.
var checkReportForVulnerabilities = func(reportPath, scanner, pkgTypes, libraryPatchLevel string) (bool, error) {
	// Use existing report parsing from pkg/report
	updateManifest, err := report.TryParseScanReport(reportPath, scanner, pkgTypes, libraryPatchLevel)
	if err != nil {
		return false, fmt.Errorf("failed to parse report: %w", err)
	}

	// Check if there are any updates (fixable vulnerabilities)
	hasUpdates := len(updateManifest.OSUpdates) > 0 || len(updateManifest.LangUpdates) > 0
	return hasUpdates, nil
}

// evaluatePatchAction orchestrates the full workflow: discover existing tags, check report if needed, and decide whether to patch.
func evaluatePatchAction(repo, baseTag, scanner string, reports *reportIndex, pkgTypes, libraryPatchLevel string) skipCheckResult {
	// Discover existing patched tags
	existingTags, err := discoverExistingPatchTags(repo, baseTag)
	if err != nil {
		// Fail-open: if we can't discover tags, proceed with patching
		log.Warnf("Failed to discover existing tags for '%s': %v. Proceeding with patch.", repo, err)
		return skipCheckResult{
			ShouldSkip:  false,
			ResolvedTag: baseTag,
		}
	}

	// If no existing patched tags, proceed with base tag
	if len(existingTags) == 0 {
		log.Debugf("No existing patched tags found for '%s', proceeding with base tag '%s'", repo, baseTag)
		return skipCheckResult{
			ShouldSkip:  false,
			ResolvedTag: baseTag,
		}
	}

	// Compute the next version tag
	nextTag := nextPatchTag(baseTag, existingTags)

	// If no reports index provided, fail-open and proceed to patch
	if reports == nil {
		log.Debugf("No reports index provided, proceeding with patch for '%s'", repo)
		return skipCheckResult{
			ShouldSkip:  false,
			ResolvedTag: nextTag,
		}
	}

	// Get the latest existing tag to check
	latestTag := latestPatchTag(existingTags)
	imageRef := fmt.Sprintf("%s:%s", repo, latestTag)

	// Look up the report using the index
	reportPath, found := reports.lookup(imageRef)
	if !found {
		// Report not found, fail-open and proceed to patch
		log.Debugf("No report found for image '%s' in index, proceeding with patch (fail-open)", imageRef)
		return skipCheckResult{
			ShouldSkip:  false,
			ResolvedTag: nextTag,
		}
	}

	log.Debugf("Checking vulnerability report '%s' for image '%s'", reportPath, imageRef)
	hasVulns, err := checkReportForVulnerabilities(reportPath, scanner, pkgTypes, libraryPatchLevel)
	if err != nil {
		// Fail-open: if report parsing fails, proceed with patching
		log.Warnf("Failed to parse report '%s': %v. Proceeding with patch (fail-open).", reportPath, err)
		return skipCheckResult{
			ShouldSkip:  false,
			ResolvedTag: nextTag,
		}
	}

	if !hasVulns {
		// No fixable vulnerabilities, skip patching
		log.Debugf("No fixable vulnerabilities found in report for '%s', skipping patch", imageRef)
		return skipCheckResult{
			ShouldSkip:  true,
			Reason:      "no fixable vulnerabilities",
			ResolvedTag: latestTag,
		}
	}

	// Vulnerabilities found, proceed with patching using next version tag
	log.Debugf("Fixable vulnerabilities found in report for '%s', re-patching with tag '%s'", imageRef, nextTag)
	return skipCheckResult{
		ShouldSkip:  false,
		ResolvedTag: nextTag,
	}
}
