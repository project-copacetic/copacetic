package patch

import (
	"testing"

	"github.com/moby/buildkit/sourcepolicy"
	policytypes "github.com/moby/buildkit/sourcepolicy/pb"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

// An exact-tag ALLOW after a wildcard DENY authorizes the requested input. Copa
// reads that input by digest, so the pinned reference must stay allowed, while
// every other source keeps the policy's own decision.
func TestAuthorizePinnedInput(t *testing.T) {
	const repo = "example.com/team/app"
	child := repo + "@" + digest.FromString("captured child").String()
	other := repo + "@" + digest.FromString("unrelated digest").String()
	allowlist := func() *policytypes.Policy {
		return &policytypes.Policy{Rules: []*policytypes.Rule{
			{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: "docker-image://" + repo + "*", MatchType: policytypes.MatchType_WILDCARD}},
			{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{Identifier: "docker-image://" + repo + ":approved"}},
		}}
	}
	allowed := func(t *testing.T, policy *policytypes.Policy, ref string) bool {
		t.Helper()
		id, err := imageSourceIdentifier(ref)
		require.NoError(t, err)
		ok, err := policyAllowsUnchanged(t.Context(), policy, id)
		require.NoError(t, err)
		return ok
	}

	t.Run("allowed tag carries to its pinned child", func(t *testing.T) {
		policy := allowlist()
		require.False(t, allowed(t, policy, child), "control: the pinned child is denied as written")
		got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child, child)
		require.NoError(t, err)
		require.True(t, allowed(t, got, child))
		require.Len(t, got.Rules, len(policy.Rules)+1, "one exact rule per pinned reference")
		require.Equal(t, policytypes.MatchType_EXACT, got.Rules[len(got.Rules)-1].Selector.MatchType)
		require.False(t, allowed(t, got, other), "other digests in the repository stay denied")
		require.False(t, allowed(t, got, repo+":unapproved"), "other tags stay denied")
		require.True(t, allowed(t, got, "docker.io/library/busybox:latest"), "unrelated tooling keeps the policy's decision")
		require.Len(t, policy.Rules, 2, "the caller's policy is not modified")
	})

	t.Run("denied input is not authorized", func(t *testing.T) {
		policy := allowlist()
		got, err := authorizePinnedInput(t.Context(), policy, repo+":unapproved", child)
		require.NoError(t, err)
		require.Same(t, policy, got)
		require.False(t, allowed(t, got, child))
	})

	t.Run("converted input keeps the policy", func(t *testing.T) {
		policy := &policytypes.Policy{Rules: []*policytypes.Rule{{
			Action: policytypes.PolicyAction_CONVERT, Selector: &policytypes.Selector{Identifier: "docker-image://" + repo + ":approved"},
			Updates: &policytypes.Update{Identifier: "docker-image://" + other},
		}}}
		got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
		require.NoError(t, err)
		require.Same(t, policy, got)
	})

	t.Run("already allowed or no policy needs no rule", func(t *testing.T) {
		open := &policytypes.Policy{Rules: []*policytypes.Rule{
			{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: "docker-image://example.com/other*", MatchType: policytypes.MatchType_WILDCARD}},
		}}
		got, err := authorizePinnedInput(t.Context(), open, repo+":approved", child)
		require.NoError(t, err)
		require.Same(t, open, got)
		got, err = authorizePinnedInput(t.Context(), nil, repo+":approved", child)
		require.NoError(t, err)
		require.Nil(t, got)
	})

	t.Run("unpinned reference is left to the policy", func(t *testing.T) {
		policy := allowlist()
		got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", repo+":approved")
		require.NoError(t, err)
		require.Same(t, policy, got)
	})

	t.Run("BuildKit engine denies the pinned child without the rule", func(t *testing.T) {
		_, err := sourcepolicy.NewEngine([]*policytypes.Policy{allowlist()}).Evaluate(t.Context(), imageSourceOp("docker-image://"+child))
		require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied)
	})
}
