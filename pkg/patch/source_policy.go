package patch

import (
	"context"
	"fmt"
	"strings"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/sourcepolicy"
	policytypes "github.com/moby/buildkit/sourcepolicy/pb"

	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/types"
)

// Resolve input conversions before discovery pins the image. Otherwise an exact
// tag selector would no longer match the immutable reference used by the build.
// The policy is still supplied to BuildKit for its other sources, including tooling.
func policyImageReference(ctx context.Context, image string) (string, error) {
	policy, err := readSourcePolicy()
	if err != nil {
		return "", err
	}
	if policy == nil {
		return image, nil
	}
	if err := validateSourcePolicy(policy); err != nil {
		return "", err
	}
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return "", err
	}
	named = reference.TagNameOnly(named)
	const imageScheme = "docker-image://"
	op := &pb.SourceOp{
		Identifier: imageScheme + named.String(),
		Attrs:      map[string]string{pb.AttrImageResolveMode: llb.ResolveModePreferLocal.String()},
	}
	if _, err := sourcepolicy.NewEngine([]*policytypes.Policy{policy}).Evaluate(ctx, op); err != nil {
		return "", fmt.Errorf("evaluate patch input source policy: %w", err)
	}
	if op.Identifier == imageScheme+named.String() {
		return image, nil // Keep the supplied locator when no conversion occurred.
	}
	converted, ok := strings.CutPrefix(op.Identifier, imageScheme)
	if !ok {
		return "", fmt.Errorf("source policy converted patch input to an unsupported image source")
	}
	if _, err := reference.ParseNormalizedNamed(converted); err != nil {
		return "", fmt.Errorf("parse policy-selected image: %w", err)
	}
	return converted, nil
}

// A policy changes input identity, not the requested output repository or tag.
// Preserve naming before replacing the source and leave caller options intact.
func policyPatchOptions(ctx context.Context, opts *types.Options) (*types.Options, error) {
	image, err := policyImageReference(ctx, opts.Image)
	if err != nil {
		return nil, err
	}
	if image == opts.Image {
		return opts, nil
	}
	original, err := reference.ParseNormalizedNamed(opts.Image)
	if err != nil {
		return nil, err
	}
	output, tag, err := common.ResolvePatchedImageName(reference.TagNameOnly(original), opts.PatchedTag, opts.Suffix)
	if err != nil {
		return nil, err
	}
	selected := *opts
	selected.Image = image
	selected.PatchedTag = output + ":" + tag
	return &selected, nil
}
