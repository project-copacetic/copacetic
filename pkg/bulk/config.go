package bulk

import (
	"fmt"
	"regexp"
)

type PatchConfig struct {
	APIVersion string      `yaml:"apiVersion"`
	Kind       string      `yaml:"kind"`
	Images     []ImageSpec `yaml:"images"`
}

type ImageSpec struct {
	Name      string      `yaml:"name"`
	Image     string      `yaml:"image"`
	Tags      TagStrategy `yaml:"tags"`
	Target    TargetSpec  `yaml:"target,omitempty"`
	Platforms []string    `yaml:"platforms,omitempty"`
}

type TargetSpec struct {
	Tag string `yaml:"tag,omitempty"`
}

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
	case "list":
		if len(raw.List) == 0 {
			return fmt.Errorf("strategy 'list' requires a non-empty 'list' of tags")
		}
	case "pattern":
		if raw.Pattern == "" {
			return fmt.Errorf("strategy 'pattern' requires a 'pattern' field")
		}
		re, err := regexp.Compile(raw.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex for pattern '%s': %w", raw.Pattern, err)
		}
		raw.compiledPattern = re
	case "latest":
		// no specific validation needed for 'latest'
	default:
		return fmt.Errorf("unknown tag strategy '%s', must be one of: list, pattern, latest", raw.Strategy)
	}

	*t = TagStrategy(raw)
	return nil

}
