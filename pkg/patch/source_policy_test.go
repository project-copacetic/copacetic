package patch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/buildkit/sourcepolicy"
	policytypes "github.com/moby/buildkit/sourcepolicy/pb"
	"github.com/opencontainers/go-digest"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestPolicyImageReference(t *testing.T) {
	approved := "docker.io/library/alpine@" + digest.FromString("approved original").String()
	for _, tc := range []struct {
		name     string
		selector string
		action   policytypes.PolicyAction
		update   string
		want     string
		denied   bool
	}{
		{name: "input conversion", selector: "docker-image://docker.io/library/alpine:latest", update: "docker-image://" + approved, want: approved},
		{
			name: "mirror conversion", selector: "docker-image://docker.io/library/alpine:latest",
			update: "docker-image://mirror.example.com/approved@" + digest.FromString("mirror").String(),
			want:   "mirror.example.com/approved@" + digest.FromString("mirror").String(),
		},
		{name: "tooling rule", selector: "docker-image://example.com/tool:latest", update: "docker-image://example.com/tool@" + digest.FromString("tool").String(), want: "alpine"},
		{name: "deny input", selector: "docker-image://docker.io/library/alpine:latest", action: policytypes.PolicyAction_DENY, denied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := &policytypes.Rule{Action: policytypes.PolicyAction_CONVERT, Selector: &policytypes.Selector{Identifier: tc.selector}}
			if tc.denied {
				rule.Action = tc.action
			} else {
				rule.Updates = &policytypes.Update{Identifier: tc.update}
			}
			data, err := json.Marshal(&policytypes.Policy{Rules: []*policytypes.Rule{rule}})
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "source-policy.json")
			require.NoError(t, os.WriteFile(path, data, 0o600))
			t.Setenv("EXPERIMENTAL_BUILDKIT_SOURCE_POLICY", path)
			got, err := policyImageReference(t.Context(), "alpine")
			if tc.denied {
				require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestPolicyImageReferenceWithoutPolicyKeepsLocator(t *testing.T) {
	t.Setenv("EXPERIMENTAL_BUILDKIT_SOURCE_POLICY", "")
	for _, input := range []string{"alpine", "alpine:3.20", "example.com/app:tag@" + digest.FromString("original").String()} {
		got, err := policyImageReference(t.Context(), input)
		require.NoError(t, err)
		require.Equal(t, input, got)
	}
}

func TestPolicyPatchOptionsPreservesOutputAndCaller(t *testing.T) {
	approved := "mirror.example.com/alpine@" + digest.FromString("approved original").String()
	data, err := json.Marshal(&policytypes.Policy{Rules: []*policytypes.Rule{{
		Action:   policytypes.PolicyAction_CONVERT,
		Selector: &policytypes.Selector{Identifier: "docker-image://docker.io/library/alpine:latest"},
		Updates:  &policytypes.Update{Identifier: "docker-image://" + approved},
	}}})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "source-policy.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	t.Setenv("EXPERIMENTAL_BUILDKIT_SOURCE_POLICY", path)
	for _, tc := range []struct{ tag, suffix, want string }{
		{want: "docker.io/library/alpine:latest-patched"},
		{tag: "fixed", want: "docker.io/library/alpine:fixed"},
		{suffix: "fixed", want: "docker.io/library/alpine:latest-fixed"},
		{tag: "output.example.com/app:fixed", want: "output.example.com/app:fixed"},
	} {
		input := &types.Options{Image: "alpine", PatchedTag: tc.tag, Suffix: tc.suffix}
		original := *input
		got, err := policyPatchOptions(t.Context(), input)
		require.NoError(t, err)
		require.Equal(t, approved, got.Image)
		require.Equal(t, tc.want, got.PatchedTag)
		require.Equal(t, original, *input)
	}
}
