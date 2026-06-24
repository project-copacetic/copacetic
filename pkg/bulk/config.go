package bulk

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	ExpectedAPIVersion = "copa.sh/v1alpha1"
	ExpectedKind       = "PatchConfig"
)

// ChartSpec defines a Helm chart from which images should be discovered.
type ChartSpec struct {
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	Repository string `yaml:"repository"` // "oci://..." or "https://..."
}

// OverrideSpec defines a tag variant substitution for chart-discovered images.
// From and To are substrings of the image tag (e.g., From: "distroless-libc", To: "debian").
type OverrideSpec struct {
	From      string `yaml:"from"`
	To        string `yaml:"to"`
	ValuePath string `yaml:"valuePath,omitempty"` // Explicit values.yaml path for image override (e.g. "controller.image")
}

// PatchConfig represents the top-level structure for the bulk patching configuration.
type PatchConfig struct {
	APIVersion  string                  `yaml:"apiVersion"`
	Kind        string                  `yaml:"kind"`
	Target      TargetSpec              `yaml:"target,omitempty"`      // Default target for all images
	Charts      []ChartSpec             `yaml:"charts,omitempty"`      // Helm charts to discover images from
	ChartTarget *ChartTargetSpec        `yaml:"chartTarget,omitempty"` // Where to push patched wrapper charts
	Overrides   map[string]OverrideSpec `yaml:"overrides,omitempty"`   // Tag variant overrides for chart images
	Images      []ImageSpec             `yaml:"images,omitempty"`      // Explicitly listed images
}

// ChartTargetSpec defines where to push patched wrapper charts.
type ChartTargetSpec struct {
	Registry string `yaml:"registry"` // OCI registry for patched charts (e.g. "oci://ghcr.io/myorg/charts")
}

// ImageSpec defines the configuration for patching a single image.
type ImageSpec struct {
	Name      string      `yaml:"name"`
	Image     string      `yaml:"image"`
	Tags      TagStrategy `yaml:"tags"`
	Target    TargetSpec  `yaml:"target,omitempty"`
	Platforms []string    `yaml:"platforms,omitempty"`
}

// TargetSpec defines how the patched image should be tagged and where it should be pushed.
type TargetSpec struct {
	Registry string `yaml:"registry,omitempty"` // Target registry/namespace prefix (e.g., "ghcr.io/myorg")
	Tag      string `yaml:"tag,omitempty"`      // Tag template (defaults to "{{ .SourceTag }}-patched")
}

// TagStrategy defines the method for discovering image tags to be patched.
type TagStrategy struct {
	Strategy string   `yaml:"strategy"`
	Pattern  string   `yaml:"pattern,omitempty"`
	MaxTags  int      `yaml:"maxTags,omitempty"`
	List     []string `yaml:"list,omitempty"`
	Exclude  []string `yaml:"exclude,omitempty"`

	compiledPattern *regexp.Regexp
}

// validateCharts validates all ChartSpec entries in the config.
func validateCharts(charts []ChartSpec) error {
	for i, c := range charts {
		if c.Name == "" {
			return fmt.Errorf("charts[%d]: name is required", i)
		}
		if c.Version == "" {
			return fmt.Errorf("charts[%d] (%s): version is required", i, c.Name)
		}
		if c.Repository == "" {
			return fmt.Errorf("charts[%d] (%s): repository is required", i, c.Name)
		}
		if !isValidChartRepository(c.Repository) {
			return fmt.Errorf("charts[%d] (%s): repository must start with 'oci://' or 'https://'", i, c.Name)
		}
	}
	return nil
}

// isValidChartRepository checks whether a repository URL has a supported scheme.
func isValidChartRepository(repo string) bool {
	return strings.HasPrefix(repo, "oci://") || strings.HasPrefix(repo, "https://")
}

// validateOverrides validates all OverrideSpec entries in the config.
func validateOverrides(overrides map[string]OverrideSpec) error {
	for key, o := range overrides {
		if o.From == "" {
			return fmt.Errorf("overrides[%q]: from is required", key)
		}
		if o.To == "" {
			return fmt.Errorf("overrides[%q]: to is required", key)
		}
	}
	return nil
}

// validateChartTarget validates the ChartTargetSpec if present.
func validateChartTarget(ct *ChartTargetSpec) error {
	if ct == nil {
		return nil
	}
	if ct.Registry == "" {
		return fmt.Errorf("chartTarget.registry is required")
	}
	if !strings.HasPrefix(ct.Registry, "oci://") {
		return fmt.Errorf("chartTarget.registry must start with 'oci://' (got %q)", ct.Registry)
	}
	return nil
}

func (t *TagStrategy) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawTagStrategy TagStrategy
	raw := rawTagStrategy{}

	if err := unmarshal(&raw); err != nil {
		return err
	}

	switch raw.Strategy {
	// If strategy is "list", ensure the 'list' field is not empty.
	case StrategyList:
		if len(raw.List) == 0 {
			return fmt.Errorf("strategy 'list' requires a non-empty 'list' of tags")
		}
		// If strategy is "pattern", ensure a pattern is provided and compile it.
	case StrategyPattern:
		if raw.Pattern == "" {
			return fmt.Errorf("strategy 'pattern' requires a 'pattern' field")
		}
		re, err := regexp.Compile(raw.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex for pattern '%s': %w", raw.Pattern, err)
		}
		// Store the compiled regex for later use.
		raw.compiledPattern = re
		// If strategy is "latest", no specific validation is needed.
	case StrategyLatest:
	default:
		return fmt.Errorf("unknown tag strategy '%s', must be one of: list, pattern, latest", raw.Strategy)
	}
	*t = TagStrategy(raw)
	return nil
}
