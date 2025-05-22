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

type ManualRule struct {
	Target struct {
		Path   string `yaml:"path"`
		Sha256 string `yaml:"sha256"`
	} `yaml:"target"`
	Replacement struct {
		Source       string `yaml:"source"`
		InternalPath string `yaml:"internalPath"`
		Sha256       string `yaml:"sha256"`
		Mode         int    `yaml:"mode"`
	} `yaml:"replacement"`
}

func loadManualRule(path string) (*ManualRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var r ManualRule
	if err := yaml.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
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

func applyManualRule(ctx context.Context, c gwclient.Client, cfg *buildkit.Config, rule *ManualRule) (llb.State, error) {
	// verify current file hash if provided
	if rule.Target.Path != "" && rule.Target.Sha256 != "" {
		data, err := buildkit.ExtractFileFromState(ctx, c, &cfg.ImageState, rule.Target.Path)
		if err != nil {
			return llb.State{}, err
		}
		if err := verifySha(data, rule.Target.Sha256); err != nil {
			return llb.State{}, err
		}
	}

	replacement := llb.Image(rule.Replacement.Source)
	patched := cfg.ImageState.File(llb.Copy(replacement, rule.Replacement.InternalPath, rule.Target.Path))

	if cfg.PatchedConfigData != nil {
		prevPatchDiff := llb.Diff(cfg.ImageState, cfg.PatchedImageState)
		combined := llb.Merge([]llb.State{prevPatchDiff, patched})
		squashed := llb.Scratch().File(llb.Copy(combined, "/", "/"))
		merged := llb.Merge([]llb.State{cfg.ImageState, squashed})
		return merged, nil
	}

	diff := llb.Diff(cfg.ImageState, patched)
	merged := llb.Merge([]llb.State{llb.Scratch(), cfg.ImageState, diff})
	return merged, nil
}
