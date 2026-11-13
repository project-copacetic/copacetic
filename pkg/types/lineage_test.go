package types

import (
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSourceLineageIdentity(t *testing.T) {
	selected := digest.FromString("selected")
	for _, tc := range []struct {
		name   string
		kind   string
		ref    string
		digest digest.Digest
		valid  bool
	}{
		{"image reference", PatchOriginImage, "alpine:3.20", selected, true},
		{"immutable image", PatchOriginImage, "alpine@" + selected.String(), selected, true},
		{"nameless layout", PatchOriginOCI, "", selected, true},
		{"named layout", PatchOriginOCI, "example.com/app:v1", selected, true},
		{"image requires name", PatchOriginImage, "", selected, false},
		{"unknown kind", "image", "alpine:3.20", selected, false},
		{"layout path", PatchOriginOCI, "/tmp/source", selected, false},
		{"layout URI", PatchOriginOCI, "oci:///tmp/source", selected, false},
		{"contradictory digest", PatchOriginImage, "alpine@" + digest.FromString("index").String(), selected, false},
		{"invalid digest", PatchOriginImage, "alpine:3.20", "sha256:bad", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lineage := &SourceLineage{Kind: tc.kind, Name: tc.ref, Digest: tc.digest}
			require.Equal(t, tc.valid, lineage.Valid())
			got := SourceLineageFromAnnotations(lineage.Annotations())
			if !tc.valid {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tc.kind, got.Kind)
			assert.Equal(t, tc.digest, got.Digest)
			assert.Equal(t, lineage.Annotations()[AnnotationPatchOriginKind], got.Kind)
			if tc.ref == "" {
				assert.NotContains(t, lineage.Annotations(), AnnotationPatchOriginName)
			}
		})
	}
	assert.Nil(t, SourceLineageFromAnnotations(map[string]string{
		"org.opencontainers.image.base.name":   "alpine:3.20",
		"org.opencontainers.image.base.digest": selected.String(),
	}))
}
