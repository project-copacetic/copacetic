package generate

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewGenerateCmdLibraryPatchLevel checks that the level reaches the options only when the flag is set,
// so plugin reports keep their own fixed versions by default.
func TestNewGenerateCmdLibraryPatchLevel(t *testing.T) {
	t.Setenv("COPA_EXPERIMENTAL", "1")
	originalRunGenerate := runGenerate
	t.Cleanup(func() { runGenerate = originalRunGenerate })

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "flag unset", args: []string{"--pkg-types", "os,library"}, want: ""},
		{name: "explicit patch", args: []string{"--pkg-types", "os,library", "--library-patch-level", "patch"}, want: "patch"},
		{name: "explicit minor", args: []string{"--pkg-types", "os,library", "--library-patch-level", "minor"}, want: "minor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got *types.Options
			runGenerate = func(_ context.Context, opts *types.Options) error {
				got = opts
				return nil
			}
			cmd := NewGenerateCmd()
			outputContext := filepath.Join(t.TempDir(), "context.tar")
			cmd.SetArgs(append([]string{"--image", "alpine:latest", "--output-context", outputContext}, tt.args...))
			require.NoError(t, cmd.Execute())
			require.NotNil(t, got)
			assert.Equal(t, tt.want, got.LibraryPatchLevel)
		})
	}
}
