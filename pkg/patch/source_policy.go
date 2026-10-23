package patch

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
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
	requested := maps.Clone(op.Attrs)
	if _, err := sourcepolicy.NewEngine([]*policytypes.Policy{policy}).Evaluate(ctx, op); err != nil {
		return "", fmt.Errorf("evaluate patch input source policy: %w", err)
	}
	// Copa captures and pins the input itself, so an attribute such as a
	// registry-only resolve mode would not reach the source BuildKit reads.
	// Fail rather than patch content the policy did not select.
	if changed := changedSourceAttrs(requested, op.Attrs); len(changed) > 0 {
		return "", fmt.Errorf("source policy sets attributes on patch input %s that Copa cannot apply: %s", named.String(), strings.Join(changed, ", "))
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

// changedSourceAttrs lists the attributes a policy added or changed, sorted.
func changedSourceAttrs(before, after map[string]string) []string {
	var changed []string
	for key, value := range after {
		if previous, ok := before[key]; !ok || previous != value {
			changed = append(changed, key+"="+value)
		}
	}
	slices.Sort(changed)
	return changed
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

// authorizePinnedInput carries a source policy's decision for the requested
// input to the digest-pinned references Copa reads instead. Without it, an
// exact-tag ALLOW after a wildcard DENY stops matching once the input is pinned.
// Each pinned reference gets an exact ALLOW rule only when the policy allows the
// requested input unchanged and would deny that pinned reference. Tooling,
// recovered originals and every other source keep the policy as written.
func authorizePinnedInput(
	ctx context.Context, policy *policytypes.Policy, requested string, pinned ...string,
) (*policytypes.Policy, error) {
	if policy == nil || len(pinned) == 0 {
		return policy, nil
	}
	requestedID, err := imageSourceIdentifier(requested)
	if err != nil {
		return nil, err
	}
	if allowed, err := policyAllowsUnchanged(ctx, policy, requestedID); err != nil || !allowed {
		// A denied or converted input keeps the policy's own decision.
		return policy, err
	}
	var extra []*policytypes.Rule
	seen := map[string]struct{}{}
	for _, ref := range pinned {
		named, err := reference.ParseNormalizedNamed(ref)
		if err != nil {
			return nil, err
		}
		if _, ok := named.(reference.Digested); !ok {
			continue // An unpinned reference is matched by the policy as written.
		}
		id := imageSourceScheme + named.String()
		if _, done := seen[id]; done {
			continue
		}
		seen[id] = struct{}{}
		_, err = sourcepolicy.NewEngine([]*policytypes.Policy{policy}).Evaluate(ctx, imageSourceOp(id))
		if err == nil {
			continue // Already allowed, or converted by the policy itself.
		}
		if !errors.Is(err, sourcepolicy.ErrSourceDenied) {
			return nil, fmt.Errorf("evaluate pinned patch input source policy: %w", err)
		}
		extra = append(extra, &policytypes.Rule{
			Action:   policytypes.PolicyAction_ALLOW,
			Selector: &policytypes.Selector{Identifier: id, MatchType: policytypes.MatchType_EXACT},
		})
	}
	if len(extra) == 0 {
		return policy, nil
	}
	// The last matching ALLOW or DENY wins, so these exact rules go last.
	return &policytypes.Policy{Version: policy.Version, Rules: append(slices.Clone(policy.Rules), extra...)}, nil
}

const imageSourceScheme = "docker-image://"

func imageSourceIdentifier(image string) (string, error) {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return "", err
	}
	return imageSourceScheme + reference.TagNameOnly(named).String(), nil
}

func imageSourceOp(id string) *pb.SourceOp {
	return &pb.SourceOp{Identifier: id, Attrs: map[string]string{pb.AttrImageResolveMode: llb.ResolveModePreferLocal.String()}}
}

// policyAllowsUnchanged reports whether the policy allows id without converting it.
func policyAllowsUnchanged(ctx context.Context, policy *policytypes.Policy, id string) (bool, error) {
	op := imageSourceOp(id)
	mutated, err := sourcepolicy.NewEngine([]*policytypes.Policy{policy}).Evaluate(ctx, op)
	if errors.Is(err, sourcepolicy.ErrSourceDenied) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("evaluate patch input source policy: %w", err)
	}
	return !mutated && op.Identifier == id, nil
}
