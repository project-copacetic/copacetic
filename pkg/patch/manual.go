package patch

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"gopkg.in/yaml.v3"
)

// ManualRuleEntry represents a single file replacement rule.
type ManualRuleEntry struct {
	Target struct {
		Path   string `yaml:"path"`
		Sha256 string `yaml:"sha256"`
	} `yaml:"target"`
	Replacement struct {
		Source       string `yaml:"source"`
		InternalPath string `yaml:"internalPath"`
		Sha256       string `yaml:"sha256"`
		Mode         uint32 `yaml:"mode"`
	} `yaml:"replacement"`
}

// ManualRules represents a collection of manual replacement rules.
type ManualRules struct {
	Rules []ManualRuleEntry `yaml:"rules"`
}

func loadManualRules(path string) (*ManualRules, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var rules ManualRules
	if err := yaml.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	return &rules, nil
}

func verifySha(data []byte, expected string) error {
	if expected == "" {
		return nil
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(data))
	expected = strings.TrimPrefix(strings.ToLower(expected), "sha256:")
	if sum != expected {
		return fmt.Errorf("sha mismatch: expected %s got %s", expected, sum)
	}
	return nil
}

func applyManualRules(ctx context.Context, c gwclient.Client, cfg *buildkit.Config, rules *ManualRules) (llb.State, error) {
	if len(rules.Rules) == 0 {
		return cfg.ImageState, nil
	}

	currentState := cfg.ImageState

	for i, rule := range rules.Rules {
		if rule.Target.Path != "" && rule.Target.Sha256 != "" {
			data, err := buildkit.ExtractFileFromState(ctx, c, &currentState, rule.Target.Path)
			if err != nil {
				return llb.State{}, fmt.Errorf("rule %d: failed to extract %s: %w", i, rule.Target.Path, err)
			}
			if err := verifySha(data, rule.Target.Sha256); err != nil {
				return llb.State{}, fmt.Errorf("rule %d: %w", i, err)
			}
		}

		replacement := llb.Image(rule.Replacement.Source)

		// Validate replacement file SHA256 if provided
		if rule.Replacement.Sha256 != "" {
			replacementData, err := buildkit.ExtractFileFromState(ctx, c, &replacement, rule.Replacement.InternalPath)
			if err != nil {
				return llb.State{}, fmt.Errorf("rule %d: failed to extract replacement file %s from %s: %w", i, rule.Replacement.InternalPath, rule.Replacement.Source, err)
			}
			if err := verifySha(replacementData, rule.Replacement.Sha256); err != nil {
				return llb.State{}, fmt.Errorf("rule %d: replacement file SHA256 validation failed: %w", i, err)
			}
		}

		copyAction := llb.Copy(
			replacement,
			rule.Replacement.InternalPath,
			rule.Target.Path,
			llb.ChmodOpt{Mode: os.FileMode(rule.Replacement.Mode)},
		)

		patchedState := currentState.File(copyAction)

		diff := llb.Diff(currentState, patchedState)
		currentState = llb.Merge([]llb.State{currentState, diff})
	}

	// if there was already a patched state from previous operations (e.g. vulnerability updates)
	// we need to merge our changes with those
	if cfg.PatchedConfigData != nil {
		prevPatchDiff := llb.Diff(cfg.ImageState, cfg.PatchedImageState)
		manualPatchDiff := llb.Diff(cfg.ImageState, currentState)

		combined := llb.Merge([]llb.State{prevPatchDiff, manualPatchDiff})
		squashed := llb.Scratch().File(llb.Copy(combined, "/", "/"))
		merged := llb.Merge([]llb.State{cfg.ImageState, squashed})
		return merged, nil
	}

	return currentState, nil
}
