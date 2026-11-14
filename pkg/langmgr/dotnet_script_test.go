package langmgr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const dotnetOriginalFixture = `{
  "targets":{"net8":{
    "App/1.0.0":{"dependencies":{"Audit":"1.0.0"}},
    "Audit/1.0.0":{"runtime":{"old.dll":{}}}
  }},
  "libraries":{"Audit/1.0.0":{"sha512":"old"}},
  "preserve":true
}`

func runDotnetMetadataFixture(t *testing.T, generated string) (result []byte, output string, jqCalls int) {
	t.Helper()
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("metadata script regression requires jq")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("metadata script regression requires POSIX sh")
	}
	dir := t.TempDir()
	for _, name := range []string{"runtime", "output", "tools"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, name), 0o700))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "runtime/original.deps.json"), []byte(dotnetOriginalFixture), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "output/patch.deps.json"), []byte(generated), 0o600))
	tool := filepath.Join(dir, "tools/jq")
	require.NoError(t, os.WriteFile(tool, []byte(`#!/bin/sh
printf 'jq\n' >> "$DOTNET_JQ_LOG"
exec "$DOTNET_REAL_JQ" "$@"
`), 0o600))
	require.NoError(t, os.Chmod(tool, 0o700))
	script := (&dotnetManager{}).buildUpdateDepsJsonScript(unversioned.LangUpdatePackages{
		{Name: "Audit", InstalledVersion: "1.0.0", FixedVersion: "1.0.1"},
	})
	script = strings.NewReplacer(
		"/runtime-tmp/", filepath.Join(dir, "runtime")+"/",
		"/output/", filepath.Join(dir, "output")+"/",
	).Replace(script)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-c", script)
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Join(dir, "tools")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"DOTNET_REAL_JQ="+jq,
		"DOTNET_JQ_LOG="+filepath.Join(dir, "jq.log"),
	)
	log, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", log)
	result, err = os.ReadFile(filepath.Join(dir, "output/updated.deps.json"))
	require.NoError(t, err)
	calls, err := os.ReadFile(filepath.Join(dir, "jq.log"))
	require.NoError(t, err)
	return result, string(log), strings.Count(string(calls), "\n")
}

func TestDotnetMetadataExtraction(t *testing.T) {
	const target = `{"runtime":{"Audit.dll":{"assemblyVersion":"1.0.2.0","fileVersion":"1.0.2.0"}}}`
	const library = `{"sha512":"new","hashPath":"audit.1.0.2.nupkg.sha512"}`
	generated := fmt.Sprintf(`{"targets":{"net8":{"Audit/1.0.2":%s}},"libraries":{"Audit/1.0.2":%s}}`, target, library)
	updated := fmt.Sprintf(`{
  "targets":{"net8":{
    "App/1.0.0":{"dependencies":{"Audit":"1.0.2"}},
    "Audit/1.0.2":%s
  }},
  "libraries":{"Audit/1.0.2":%s},
  "preserve":true
}`, target, library)
	for _, tc := range []struct {
		name      string
		generated string
		expected  string
		fastPath  bool
		wantError bool
	}{
		{"resolved above minimum", generated, updated, true, false},
		{
			"JSON-valued strings retain legacy decoding",
			fmt.Sprintf(`{"targets":{"net8":{"Audit/1.0.2":%s}},"libraries":{"Audit/1.0.2":%s}}`, strconv.Quote(target), strconv.Quote(library)),
			updated, false, false,
		},
		{"malformed generated tail retains earlier values", generated + "\n{", updated, false, false},
		{
			"multiple generated documents retain partial failure",
			"{}\n" + generated,
			strings.Replace(dotnetOriginalFixture, `"Audit":"1.0.0"`, `"Audit":"1.0.2"`, 1),
			false, true,
		},
		{
			"bad target preserves independent library update",
			fmt.Sprintf(`{"targets":{"net8":{"Audit/1.0.2":"not-json"}},"libraries":{"Audit/1.0.2":%s}}`, library),
			fmt.Sprintf(`{
  "targets":{"net8":{
    "App/1.0.0":{"dependencies":{"Audit":"1.0.2"}},
    "Audit/1.0.0":{"runtime":{"old.dll":{}}}
  }},
  "libraries":{"Audit/1.0.2":%s},
  "preserve":true
}`, library),
			false, true,
		},
		{"missing package retains original", `{"targets":{"net8":{}},"libraries":{}}`, dotnetOriginalFixture, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, output, jqCalls := runDotnetMetadataFixture(t, tc.generated)
			assert.JSONEq(t, tc.expected, string(result))
			if tc.fastPath {
				assert.Equal(t, 8, jqCalls, "extract target and library metadata with one jq call")
			}
			if tc.wantError {
				assert.Contains(t, output, "jq:", "legacy transformation errors must remain visible")
			}
		})
	}
}
