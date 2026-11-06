package provenance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errDetectorScriptCaptured = errors.New("detector script captured")

type detectorScriptCapture struct {
	gwclient.Client
	script         string
	solves         int
	targetMounts   int
	targetReadOnly bool
}

//nolint:gocritic // BuildKit's Client interface takes SolveRequest by value.
func (c *detectorScriptCapture) Solve(ctx context.Context, req gwclient.SolveRequest) (*gwclient.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.solves++
	for _, data := range req.Definition.Def {
		var op pb.Op
		if err := op.Unmarshal(data); err != nil {
			return nil, err
		}
		if e := op.GetExec(); e != nil && len(e.Meta.Args) == 3 && strings.Contains(e.Meta.Args[2], "process.sh") {
			c.script = e.Meta.Args[2]
			for _, mount := range e.Mounts {
				if mount.Dest == "/target" {
					c.targetMounts++
					c.targetReadOnly = mount.Readonly
				}
			}
		}
	}
	return nil, errDetectorScriptCaptured
}

func captureDetectorScript(t *testing.T) string {
	t.Helper()
	c := &detectorScriptCapture{}
	state := llb.Scratch()
	_, err := NewDetector().DetectGoBinaries(context.Background(), c, &state,
		&specs.Platform{OS: "linux", Architecture: "amd64"})
	require.ErrorIs(t, err, errDetectorScriptCaptured)
	require.Contains(t, c.script, "process.sh")
	require.Equal(t, 1, c.solves)
	require.Equal(t, 1, c.targetMounts)
	require.True(t, c.targetReadOnly, "discovery must not mutate the target image")
	return c.script
}

type detectorScriptResult struct {
	output      string
	goPaths     []string
	helperCalls int
	statCalls   int
}

func runDetectorScript(t *testing.T, files map[string]os.FileMode, statBehavior string) detectorScriptResult {
	t.Helper()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("detector shell regression requires POSIX sh")
	}
	realStat, err := exec.LookPath("stat")
	if err != nil {
		t.Skip("detector shell regression requires stat")
	}
	find, err := exec.LookPath("find")
	if err != nil {
		t.Skip("detector shell regression requires find")
	}
	dir := t.TempDir()
	if _, err := exec.Command(find, dir, "-prune", "-perm", "/0111").Output(); err != nil {
		t.Skipf("detector shell regression requires find -perm /0111: %v", err)
	}
	for _, sub := range []string{"target", "copa-detect", "tools"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o700))
	}
	for name, mode := range files {
		path := filepath.Join(dir, "target", name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte("fixture"), 0o600))
		require.NoError(t, os.Chmod(path, mode))
	}
	goTool := filepath.Join(dir, "tools", "go")
	require.NoError(t, os.WriteFile(goTool, []byte(`#!/bin/sh
printf '%s\000' "$3" >> "$DETECTOR_GO_LOG"
case "$3" in
    *.rejected)
        printf '%s: go1.25.13\n' "$3"
        echo "synthetic go inspection error" >&2
        exit 1
        ;;
    *.empty)
        exit 0
        ;;
    *.gobin)
        printf '%s: go1.25.13\n\tpath\texample.com/app\n\tbuild\tCGO_ENABLED=0\n' "$3"
        ;;
    *)
        echo "NOT_GO_BINARY"
        exit 1
        ;;
esac
`), 0o600))
	require.NoError(t, os.Chmod(goTool, 0o700))
	statScript := `#!/bin/sh
printf '%s\n' "$*" >> "$DETECTOR_STAT_LOG"
`
	switch statBehavior {
	case "gnu":
		statScript += `case "$1:$2" in
    "-c:%a %u:%g") echo "751 1234:5678" ;;
    "-c:%a") echo "751" ;;
    "-c:%u:%g") echo "1234:5678" ;;
    *) exit 1 ;;
esac
`
	case "bsd":
		statScript += `if [ "$1" = "-f" ] && [ "$2" = "%Lp" ]; then echo "751"; else exit 1; fi
`
	case "missing":
		statScript += "exit 1\n"
	default:
		statScript += "exec \"$DETECTOR_REAL_STAT\" \"$@\"\n"
	}
	statTool := filepath.Join(dir, "tools", "stat")
	require.NoError(t, os.WriteFile(statTool, []byte(statScript), 0o600))
	require.NoError(t, os.Chmod(statTool, 0o700))
	script := captureDetectorScript(t)
	script = strings.NewReplacer(
		"/copa-detect", filepath.Join(dir, "copa-detect"),
		"/target", filepath.Join(dir, "target"),
		"/usr/local/go/bin/go", goTool,
	).Replace(script)
	script = strings.Replace(script, "#!/bin/sh\n",
		"#!/bin/sh\nprintf '%s\\n' helper >> \"$DETECTOR_HELPER_LOG\"\n", 1)
	helperLog := filepath.Join(dir, "helper.log")
	statLog := filepath.Join(dir, "stat.log")
	goLog := filepath.Join(dir, "go.log")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-c", script)
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Join(dir, "tools")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"DETECTOR_REAL_STAT="+realStat,
		"DETECTOR_STAT_LOG="+statLog,
		"DETECTOR_HELPER_LOG="+helperLog,
		"DETECTOR_GO_LOG="+goLog,
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", output)
	readLog := func(path string) string {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return ""
		}
		require.NoError(t, err)
		return string(data)
	}
	goPaths := strings.Split(strings.TrimSuffix(readLog(goLog), "\x00"), "\x00")
	if len(goPaths) == 1 && goPaths[0] == "" {
		goPaths = nil
	}
	for i := range goPaths {
		goPaths[i] = strings.TrimPrefix(goPaths[i], filepath.Join(dir, "target"))
	}
	return detectorScriptResult{
		output:      readLog(filepath.Join(dir, "copa-detect", "binaries.txt")),
		goPaths:     goPaths,
		helperCalls: strings.Count(readLog(helperLog), "\n"),
		statCalls:   strings.Count(readLog(statLog), "\n"),
	}
}

func TestDetectorScriptBatchesHelperArguments(t *testing.T) {
	files := make(map[string]os.FileMode, 33)
	for i := range 32 {
		files[fmt.Sprintf("usr/bin/native-%02d", i)] = 0o755
	}
	files["usr/bin/app.gobin"] = 0o751
	result := runDetectorScript(t, files, "")
	assert.Len(t, result.goPaths, len(files), "every executable must still be inspected")
	assert.Equal(t, 1, result.helperCalls, "one find batch should not start a shell per executable")
	binaries := NewDetector().parseGoVersionOutput(result.output)
	require.Len(t, binaries, 1)
	assert.Equal(t, "/usr/bin/app.gobin", binaries[0].Path)
}

func TestDetectorScriptReadsMetadataOnce(t *testing.T) {
	result := runDetectorScript(t, map[string]os.FileMode{"app/root.gobin": 0o751}, "gnu")
	assert.Equal(t, 1, result.statCalls, "mode and ownership should come from one metadata read")
	binaries := NewDetector().parseGoVersionOutput(result.output)
	require.Len(t, binaries, 1)
	assert.Equal(t, "751", binaries[0].FileMode)
	assert.Equal(t, "1234:5678", binaries[0].FileOwner)
}

func TestDetectorScriptSkipsMetadataForRejectedFiles(t *testing.T) {
	result := runDetectorScript(t, map[string]os.FileMode{
		"app/valid.gobin":  0o751,
		"app/native":       0o755,
		"app/bad.rejected": 0o755,
	}, "gnu")
	assert.Len(t, result.goPaths, 3, "every candidate must still reach the Go tool")
	assert.Equal(t, 1, result.statCalls, "rejected files must not require metadata lookups")
	assert.Contains(t, result.output, "synthetic go inspection error")
	binaries := NewDetector().parseGoVersionOutput(result.output)
	require.Len(t, binaries, 1, "failed inspection must not admit partial Go-looking output")
	assert.Equal(t, "/app/valid.gobin", binaries[0].Path)
	assert.Equal(t, "751", binaries[0].FileMode)
	assert.Equal(t, "1234:5678", binaries[0].FileOwner)
}

func TestDetectorScriptEmptySuccessfulInspection(t *testing.T) {
	result := runDetectorScript(t, map[string]os.FileMode{"app/no-version.empty": 0o755}, "gnu")
	assert.Len(t, result.goPaths, 1)
	assert.Empty(t, NewDetector().parseGoVersionOutput(result.output))
}

func TestDetectorScriptPreservesModesAndOwnership(t *testing.T) {
	if _, err := exec.Command("stat", "-c", "%a %u:%g", ".").Output(); err != nil {
		t.Skip("metadata regression requires GNU-compatible stat")
	}
	files := map[string]os.FileMode{
		"root.gobin":       0o640,
		"app/user.gobin":   0o700,
		"app/setuid.gobin": os.ModeSetuid | 0o751,
		"app/setgid.gobin": os.ModeSetgid | 0o750,
		"app/sticky.gobin": os.ModeSticky | 0o755,
	}
	modes := map[string]string{
		"/root.gobin":       "640",
		"/app/user.gobin":   "700",
		"/app/setuid.gobin": "4751",
		"/app/setgid.gobin": "2750",
		"/app/sticky.gobin": "1755",
	}
	result := runDetectorScript(t, files, "")
	binaries := NewDetector().parseGoVersionOutput(result.output)
	require.Len(t, binaries, len(files))
	for _, binary := range binaries {
		assert.Equal(t, modes[binary.Path], binary.FileMode, binary.Path)
		assert.Equal(t, fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), binary.FileOwner, binary.Path)
	}
	assert.Equal(t, len(files), result.statCalls)
}

func TestDetectorScriptLargeArgumentBatches(t *testing.T) {
	version, err := exec.Command("find", "--version").Output()
	if err != nil || !strings.Contains(string(version), "GNU findutils") {
		t.Skip("argument-budget regression requires GNU find's bounded exec batches")
	}
	files := make(map[string]os.FileMode, 512)
	expected := make([]string, 0, 512)
	for i := range 512 {
		name := fmt.Sprintf("usr/bin/%s-%04d", strings.Repeat("n", 200), i)
		files[name] = 0o755
		expected = append(expected, "/"+name)
	}
	result := runDetectorScript(t, files, "")
	assert.ElementsMatch(t, expected, result.goPaths, "all files must be inspected exactly once across batches")
	assert.Greater(t, result.helperCalls, 1, "fixture must exceed one find argument batch")
	assert.Less(t, result.helperCalls, 10, "batching must remain bounded rather than starting one helper per file")
}

func TestDetectorScriptPreservesFilenameArguments(t *testing.T) {
	files := map[string]os.FileMode{
		"root binary.gobin":                 0o640,
		"usr/bin/spaces and 'quotes'.gobin": 0o751,
		"usr/bin/semi;colon$dollar[].gobin": 0o755,
		"usr/bin/new\nline.gobin":           0o755,
		"app/-leading.gobin":                0o755,
		"app/not-executable.gobin":          0o640,
		"usr/bin/not-a-go-binary":           0o755,
	}
	result := runDetectorScript(t, files, "")
	expected := make([]string, 0, len(files)-1)
	for name := range files {
		if name != "app/not-executable.gobin" {
			expected = append(expected, "/"+name)
		}
	}
	sort.Strings(expected)
	sort.Strings(result.goPaths)
	assert.Equal(t, expected, result.goPaths, "find/helper must preserve argument boundaries, including newlines")
}

func TestDetectorScriptStatFallbacks(t *testing.T) {
	for _, tc := range []struct {
		behavior string
		mode     string
	}{{"bsd", "751"}, {"missing", "755"}} {
		t.Run(tc.behavior, func(t *testing.T) {
			result := runDetectorScript(t, map[string]os.FileMode{"app/bin.gobin": 0o751}, tc.behavior)
			binaries := NewDetector().parseGoVersionOutput(result.output)
			require.Len(t, binaries, 1)
			assert.Equal(t, tc.mode, binaries[0].FileMode)
			assert.Equal(t, "0:0", binaries[0].FileOwner)
		})
	}
}

func TestDetectorScriptEmptyImage(t *testing.T) {
	result := runDetectorScript(t, nil, "")
	assert.Empty(t, result.output)
	assert.Zero(t, result.helperCalls)
	assert.Zero(t, result.statCalls)
}

func TestDetectorCanceledBeforeSolve(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &detectorScriptCapture{}
	state := llb.Scratch()
	_, err := NewDetector().DetectGoBinaries(ctx, c, &state, nil)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, c.script)
	assert.Zero(t, c.solves)
}

type blockingDetectorClient struct {
	gwclient.Client
	started chan struct{}
}

//nolint:gocritic // BuildKit's Client interface takes SolveRequest by value.
func (c *blockingDetectorClient) Solve(ctx context.Context, _ gwclient.SolveRequest) (*gwclient.Result, error) {
	close(c.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestDetectorCanceledDuringSolve(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := &blockingDetectorClient{started: make(chan struct{})}
	state := llb.Scratch()
	result := make(chan error, 1)
	go func() {
		_, err := NewDetector().DetectGoBinaries(ctx, client, &state, nil)
		result <- err
	}()
	select {
	case <-client.started:
	case <-ctx.Done():
		t.Fatal("detector did not start its solve")
	}
	cancel()
	select {
	case err := <-result:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("detector did not propagate in-flight cancellation")
	}
}
