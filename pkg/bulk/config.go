package bulk

import (
	"fmt"
	"regexp"
)

// PatchConfig represents the top-level structure for the bulk patching configuration.
type PatchConfig struct {
	APIVersion string      `yaml:"apiVersion"`
	Kind       string      `yaml:"kind"`
	Images     []ImageSpec `yaml:"images"`
}

// ImageSpec defines the configuration for patching a single image.
type ImageSpec struct {
	Name      string      `yaml:"name"`
	Image     string      `yaml:"image"`
	Tags      TagStrategy `yaml:"tags"`
	Target    TargetSpec  `yaml:"target,omitempty"`
	Platforms []string    `yaml:"platforms,omitempty"`
}

// TargetSpec defines how the patched image's tag should be named.
type TargetSpec struct {
	Tag string `yaml:"tag,omitempty"`
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
