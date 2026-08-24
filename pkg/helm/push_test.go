package helm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageAndPushUsesHelmCLI(t *testing.T) {
	chart := &Chart{Metadata: Metadata{Name: "app", Version: "1.0.0", Dependencies: []Dependency{{Name: "source", Version: "1.0.0"}}}, Archive: testChartArchive(t, "source", "1.0.0", "")}
	orig := RunHelm
	t.Cleanup(func() { RunHelm = orig })
	var pushed string
	RunHelm = func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "package":
			return nil, os.WriteFile(filepath.Join(args[3], "app-1.0.0.tgz"), []byte("packaged"), 0o600)
		case "push":
			pushed = args[2]
			return nil, nil
		default:
			t.Fatalf("unexpected helm command %v", args)
			return nil, nil
		}
	}
	ref, err := PackageAndPush(context.Background(), chart, "oci://example.com/charts/app:1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "oci://example.com/charts/app:1.0.0", ref)
	assert.Equal(t, "oci://example.com/charts", pushed)
}

func TestWriteChartDirectoryEmbedsDependency(t *testing.T) {
	dir := t.TempDir()
	archive := []byte("source chart")
	chart := &Chart{Metadata: Metadata{Name: "app", Version: "1", Dependencies: []Dependency{{Name: "source", Version: "1"}}}, Archive: archive}
	require.NoError(t, writeChartDirectory(dir, chart))
	data, err := os.ReadFile(filepath.Join(dir, "charts", "source-1.tgz"))
	require.NoError(t, err)
	assert.Equal(t, archive, data)
}
