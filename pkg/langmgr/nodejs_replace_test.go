package langmgr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNpmReplaceSh(t *testing.T) {
	// The per-package snippet is not repeated: packages are read from the items file.
	assert.Equal(t, 1, strings.Count(npmReplaceSh, "copa-download"))
	assert.Contains(t, npmReplaceSh, `done 3< "$M/items"`)
	assert.Contains(t, npmReplaceSh, `sh -c '`+nodeDownloadScript(`$1`, `$2`)+`' copa-download "$URL" "$TB"`)
	assert.Contains(t, npmReplaceSh, `sh -c '`+safeTarExtractScript(`"$1"`, `"$2"`)+`' copa-extract "$TB" "$STAGE"`)
	// Download failures are recorded for parseDownloadFailures, with the line it expects.
	assert.Contains(t, npmReplaceSh, `echo "WARN: failed to download $N@$V, skipping" | tee -a "$R/`+npmFailedFile+`"`)
	assert.Equal(t, []string{"@babel/core"}, parseDownloadFailures([]byte("WARN: failed to download @babel/core@7.26.0, skipping\n")))
	assert.Contains(t, npmReplaceSh, `: >> "$R/`+npmFailedFile+`"`)

	// Staging, then one check, then the decisions are applied.
	staged := strings.Index(npmReplaceSh, `echo "$N $dir" >> "$R/plan"`)
	check := strings.Index(npmReplaceSh, `node "$M/check.js" "$R/plan" "$R/decisions" ||`)
	apply := strings.Index(npmReplaceSh, `mv "$STAGE" "$dir"`)
	assert.True(t, staged >= 0 && check > staged && apply > check, "staging, check and apply out of order")
	assert.NotContains(t, npmReplaceSh, `rm -rf "$dir" && mkdir -p "$dir"`)

	// Copies are selected by installed version, never downgraded, and a copy whose
	// package.json cannot be read is left alone instead of failing the step.
	assert.Contains(t, npmReplaceSh, `node -e "`+npmCopyInfoJS+`" "$1" "$2"`)
	assert.Contains(t, npmReplaceSh, `INFO=$(copy_info "$dir/package.json" "$V") || { echo "WARN: cannot read the version of $dir, leaving it untouched"; continue; }`)
	assert.Contains(t, npmReplaceSh, `only:*) case ",${SEL#only:}," in *",$K,"*) ;; *) continue ;; esac ;;`)
	assert.Contains(t, npmReplaceSh, `if [ "${INFO#* }" != 1 ]; then echo "INFO: $dir is already at $V or later, leaving it untouched"; continue; fi`)
	for _, c := range []string{`"`, "$", "`"} {
		assert.NotContains(t, npmCopyInfoJS, c)
	}

	// Symlinks are left alone and not recorded.
	assert.Contains(t, npmReplaceSh, "if [ -L \"$dir\" ]; then\n        echo \"WARN: $dir is a symlink, leaving it untouched\"\n        continue\n")

	// Results go to the report mount, not to the image.
	assert.Contains(t, npmReplaceSh, "R="+npmReportMount+"\n")
	assert.Contains(t, npmReplaceSh, `echo "$N" >> "$R/`+npmSkippedFile+`"`)
	assert.NotContains(t, npmReplaceSh, "/tmp/.copa")
}

func TestNpmReplaceArgs(t *testing.T) {
	assert.Equal(t, []string{"sh", "/copa-npm-scripts/replace.sh", "/srv/my app"}, npmReplaceArgs("/srv/my app"))
	assert.Equal(t, []string{"sh", "/copa-npm-scripts/replace.sh"}, npmReplaceArgs(""))
}

func TestNpmItemsFile(t *testing.T) {
	got := string(npmItemsFile([]npmReplaceItem{
		{Name: "minimatch", Version: "11.0.1", Select: "*"},
		{Name: "@babel/core", Version: "7.26.0", TopLevelOnly: true, Select: "only:6,7"},
		{Name: "ms", Version: "2.1.3"},
	}))
	assert.Equal(t,
		"minimatch 11.0.1 0 https://registry.npmjs.org/minimatch/-/minimatch-11.0.1.tgz /tmp/minimatch-11.0.1.tgz *\n"+
			"@babel/core 7.26.0 1 https://registry.npmjs.org/@babel%2Fcore/-/core-7.26.0.tgz /tmp/core-7.26.0.tgz only:6,7\n"+
			"ms 2.1.3 0 https://registry.npmjs.org/ms/-/ms-2.1.3.tgz /tmp/ms-2.1.3.tgz *\n",
		got)
}

func TestNpmItemsFileSkipsInvalidItems(t *testing.T) {
	got := string(npmItemsFile([]npmReplaceItem{
		{Name: "ms", Version: "2.1.3, 3.0.0"},
		{Name: "bad name", Version: "1.0.0"},
		{Name: "lodash", Version: ""},
		{Name: "ms", Version: "2.1.3", Select: "only:2"},
	}))
	assert.Equal(t, "ms 2.1.3 0 https://registry.npmjs.org/ms/-/ms-2.1.3.tgz /tmp/ms-2.1.3.tgz only:2\n", got)
}

func TestValidNodeUpdates(t *testing.T) {
	updates := unversioned.LangUpdatePackages{
		{Name: "lodash", FixedVersion: "4.17.21"},
		{Name: "bad;name", FixedVersion: "1.0.0"},
		{Name: "ms", FixedVersion: "2.1.3, 3.0.0"},
		{Name: "debug", FixedVersion: "not-a-version"},
		{Name: "nofix"},
	}
	valid, invalid, err := validNodeUpdates(updates, true)
	require.NoError(t, err)
	assert.Equal(t, unversioned.LangUpdatePackages{{Name: "lodash", FixedVersion: "4.17.21"}, {Name: "nofix"}}, valid)
	assert.Equal(t, []string{"bad;name", "ms", "debug"}, invalid)

	_, _, err = validNodeUpdates(updates, false)
	assert.ErrorContains(t, err, "package name validation failed for bad;name")
	_, _, err = validNodeUpdates(updates[2:3], false)
	assert.ErrorContains(t, err, "not a single version")
}

// TestNpmReplaceStepSize checks that the size of the command line of a replace step
// does not grow with the number of packages (the Linux limit for one argument is
// 128 KiB), and that the step can be marshaled.
func TestNpmReplaceStepSize(t *testing.T) {
	var items []npmReplaceItem
	for i := 0; i < 500; i++ {
		items = append(items, npmReplaceItem{Name: fmt.Sprintf("@scope-%d/package-%d", i, i), Version: "1.2.3", Select: "*"})
	}
	assert.Greater(t, len(npmItemsFile(items)), 64*1024)
	for _, arg := range npmReplaceArgs("/usr/local/lib/node_modules/some-global-package") {
		assert.Less(t, len(arg), 256)
	}

	report := newNpmReport()
	st := llb.Image("node:24-alpine")
	out := report.run(&st, "/app", items)
	_, err := out.Marshal(context.Background())
	require.NoError(t, err)
	_, err = report.state.Marshal(context.Background())
	require.NoError(t, err)
	assert.True(t, report.used)
}

func TestNpmReportSnapshot(t *testing.T) {
	report := newNpmReport()
	before := report.snapshot()
	st := llb.Image("node:24-alpine")
	_ = report.run(&st, "/app", []npmReplaceItem{{Name: "ms", Version: "2.1.3"}})
	assert.True(t, report.used)
	report.restore(&before)
	assert.False(t, report.used)
}

func TestNpmCompatKey(t *testing.T) {
	for v, want := range map[string]string{"1.2.3": "1", "11.0.1": "11", "0.3.4": "0.3", "0.0.1": "0.0", "v2.0.0-beta.1": "2", "v1.0.0": "1"} {
		got, ok := npmCompatKey(v)
		assert.True(t, ok, v)
		assert.Equal(t, want, got, v)
	}
	_, ok := npmCompatKey("")
	assert.False(t, ok)
}

func TestNpmReplaceItems(t *testing.T) {
	t.Run("one version per package", func(t *testing.T) {
		updates := unversioned.LangUpdatePackages{
			{Name: "lodash", InstalledVersion: "4.17.20", FixedVersion: "4.17.21"},
			{Name: "minimatch", InstalledVersion: "10.2.5", FixedVersion: "11.0.1"},
			{Name: "lodash", InstalledVersion: "4.17.19", FixedVersion: "4.17.21"},
			{Name: "nofix"},
		}
		assert.Equal(t, []npmReplaceItem{
			{Name: "lodash", Version: "4.17.21", TopLevelOnly: true, Select: "only:4"},
			{Name: "minimatch", Version: "11.0.1", Select: "only:10"},
		}, npmReplaceItems(updates, map[string]bool{"lodash": true}, "/app"))
		assert.Empty(t, npmReplaceItems(nil, nil, "/app"))
	})

	t.Run("fixed version chosen per installed major", func(t *testing.T) {
		updates := unversioned.LangUpdatePackages{
			{Name: "minimatch", InstalledVersion: "3.0.4", FixedVersion: "3.1.2"},
			{Name: "minimatch", InstalledVersion: "9.0.1", FixedVersion: "9.0.7"},
			{Name: "minimatch", InstalledVersion: "10.2.5", FixedVersion: "10.2.6"},
			{Name: "minimatch", InstalledVersion: "3.0.8", FixedVersion: "3.1.3"},
			{Name: "debug", InstalledVersion: "0.7.4", FixedVersion: "0.7.5"},
			{Name: "debug", InstalledVersion: "2.6.8", FixedVersion: "2.6.9"},
		}
		assert.Equal(t, []npmReplaceItem{
			{Name: "minimatch", Version: "3.1.3", Select: "only:3"},
			{Name: "minimatch", Version: "9.0.7", Select: "only:9"},
			{Name: "minimatch", Version: "10.2.6", Select: "only:10"},
			{Name: "debug", Version: "0.7.5", Select: "only:0.7"},
			{Name: "debug", Version: "2.6.9", Select: "only:2"},
		}, npmReplaceItems(updates, nil, "npm"))
	})

	t.Run("copies without a reported installed version", func(t *testing.T) {
		// Only the reported installed versions are replaced.
		updates := unversioned.LangUpdatePackages{
			{Name: "minimatch", InstalledVersion: "3.0.4", FixedVersion: "3.1.2"},
			{Name: "minimatch", FixedVersion: "10.2.6"},
		}
		assert.Equal(t, []npmReplaceItem{{Name: "minimatch", Version: "3.1.2", Select: "only:3"}},
			npmReplaceItems(updates, nil, "npm"))

		// Without any, the highest fixed version applies to every copy.
		updates = unversioned.LangUpdatePackages{
			{Name: "minimatch", FixedVersion: "3.1.2"},
			{Name: "minimatch", FixedVersion: "10.2.6"},
		}
		assert.Equal(t, []npmReplaceItem{{Name: "minimatch", Version: "10.2.6", Select: "*"}},
			npmReplaceItems(updates, nil, "npm"))
	})
}

func TestParseSkippedPackages(t *testing.T) {
	data := []byte("minimatch\n@babel/core\n\nminimatch\n  glob \n")
	assert.Equal(t, []string{"minimatch", "@babel/core", "glob"}, parseSkippedPackages(data))
	assert.Empty(t, parseSkippedPackages(nil))
}

func TestSkippedPackagesFromRead(t *testing.T) {
	got, err := skippedPackagesFromRead([]byte("minimatch\n"), nil)
	assert.NoError(t, err)
	assert.Equal(t, []string{"minimatch"}, got)

	got, err = skippedPackagesFromRead([]byte(""), nil)
	assert.NoError(t, err)
	assert.Empty(t, got)

	cause := errors.New("process did not complete successfully")
	_, err = skippedPackagesFromRead(nil, &buildkit.ReadFileErr{Err: cause, SolveFailed: true})
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "npm package replacement failed")

	_, err = skippedPackagesFromRead(nil, &buildkit.ReadFileErr{Err: cause, ReadFailed: true})
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "could not read")
}

func TestReadSkippedPackagesWithoutReplaceSteps(t *testing.T) {
	nm := &nodejsManager{config: &buildkit.Config{}}
	got, err := nm.readSkippedPackages(context.Background(), newNpmReport())
	assert.NoError(t, err)
	assert.Empty(t, got)
	got, err = nm.readSkippedPackages(context.Background(), nil)
	assert.NoError(t, err)
	assert.Empty(t, got)
}

func TestReportSkippedPackages(t *testing.T) {
	assert.Empty(t, reportSkippedPackages(nil))
	assert.Equal(t, []string{"minimatch", "glob"}, reportSkippedPackages([]string{"minimatch", "glob"}))
}

// fakeSemver implements the part of the semver API used by npmCheckJS for plain
// x.y.z versions and caret (^x.y.z) or exact (x.y.z) ranges; anything else is not a
// valid range.
const fakeSemver = `
function parse(v){var m=/^(\d+)\.(\d+)\.(\d+)$/.exec(v);return m?{major:+m[1],minor:+m[2],patch:+m[3]}:null}
function cmp(a,b){return a.major-b.major||a.minor-b.minor||a.patch-b.patch}
module.exports={
  parse:parse,
  validRange:function(r){return /^\^?\d+\.\d+\.\d+$/.test(r)?r:null},
  satisfies:function(v,r){
    var a=parse(v);if(!a){return false}
    if(r.charAt(0)!=='^'){var e=parse(r);return Boolean(e&&cmp(a,e)===0)}
    var b=parse(r.slice(1));if(!b||cmp(a,b)<0){return false}
    if(b.major>0){return a.major===b.major}
    if(b.minor>0){return a.major===0&&a.minor===b.minor}
    return cmp(a,b)===0
  }
};`

type npmTestEnv struct {
	node, checkJS, semver, noSemver string
}

func newNpmTestEnv(t *testing.T) npmTestEnv {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found on PATH")
	}
	dir := t.TempDir()
	env := npmTestEnv{
		node:     node,
		checkJS:  filepath.Join(dir, "check.js"),
		semver:   filepath.Join(dir, "semver.js"),
		noSemver: filepath.Join(dir, "missing"),
	}
	require.NoError(t, os.WriteFile(env.checkJS, []byte(npmCheckJS), 0o600))
	require.NoError(t, os.WriteFile(env.semver, []byte(fakeSemver), 0o600))
	return env
}

// TestNpmCopyInfoJS runs the program that npmReplaceSh uses to select installed
// copies. It needs node on PATH and is skipped otherwise.
func TestNpmCopyInfoJS(t *testing.T) {
	env := newNpmTestEnv(t)
	dir := t.TempDir()
	run := func(pkgJSON, version string) (string, error) {
		f := filepath.Join(dir, "package.json")
		require.NoError(t, os.WriteFile(f, []byte(pkgJSON), 0o600))
		out, err := exec.Command(env.node, "-e", npmCopyInfoJS, f, version).CombinedOutput() //nolint:gosec // node runs a test script
		return strings.TrimSpace(string(out)), err
	}
	for _, tc := range []struct{ installed, fixed, want string }{
		{"v1.0.0", "1.0.1", "1 1"},       // a leading v is ignored, as in npmCompatKey
		{"4.0.0", "3.1.3", "4 0"},        // an unreported 4.0.0 copy: key 4 (not in only:3), not lower
		{"3.0.4", "3.1.3", "3 1"},        // replaced
		{"1.0.0", "1.0.0", "1 0"},        // already at the fixed version
		{"1.0.0-beta.1", "1.0.0", "1 1"}, // a prerelease is lower than its release
		{"0.3.1", "0.4.0", "0.3 1"},      // 0.x key
		{"not-a-version", "1.0.0", "not-a-version 1"},
	} {
		got, err := run(`{"name":"x","version":"`+tc.installed+`"}`, tc.fixed)
		require.NoError(t, err, got)
		assert.Equal(t, tc.want, got, tc.installed)
		if key, ok := npmCompatKey(tc.installed); ok {
			assert.Equal(t, key, strings.Fields(got)[0], "key of %s must match npmCompatKey", tc.installed)
		}
	}
	_, err := run(`{"name":"x",`, "1.0.0")
	assert.Error(t, err, "malformed package.json")
}

func TestNpmCheckJSBreaksDependent(t *testing.T) {
	env := newNpmTestEnv(t)
	script := fmt.Sprintf(`var m=require(%q),sv=require(%q);console.log(JSON.stringify([`+
		`m.breaksDependent(sv,'1.0.0','1.0.0','1.0.1'),`+ // exact pin, patch bump: accepted
		`m.breaksDependent(sv,'^1.0.0','1.0.0','2.0.0'),`+ // ^1 dependent, 2.0.0: breaks
		`m.breaksDependent(sv,'^0.3.0','0.3.1','0.4.0'),`+ // 0.3.x dependent, 0.4.0: breaks
		`m.breaksDependent(sv,'^0.3.0','0.3.1','0.3.2'),`+ // within 0.3: accepted
		`m.breaksDependent(sv,'^1.0.0','0.9.0','2.0.0'),`+ // installed already outside the range
		`m.breaksDependent(sv,'npm:b@1','1.0.0','2.0.0'),`+ // not a plain range
		`m.breaksDependent(null,'^1.0.0','1.0.0','2.0.0')`+ // no semver
		`]))`, env.checkJS, env.semver)
	out, err := exec.Command(env.node, "-e", script).CombinedOutput() //nolint:gosec // node runs a test script
	require.NoError(t, err, string(out))
	assert.Equal(t, "[false,true,true,false,false,false,false]", strings.TrimSpace(string(out)))
}

type npmTree struct {
	t    *testing.T
	env  npmTestEnv
	root string
}

func (tr *npmTree) pkg(rel, content string) {
	tr.t.Helper()
	dir := filepath.Join(tr.root, filepath.FromSlash(rel))
	require.NoError(tr.t, os.MkdirAll(dir, 0o755))
	require.NoError(tr.t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0o600))
}

// stage writes the new version of the package at app/<rel> and returns its plan line.
func (tr *npmTree) stage(name, rel, content string) string {
	tr.pkg("app/"+rel+".copa-new", content)
	return name + " " + rel
}

// check runs the check program in app/ and returns the decisions by directory.
func (tr *npmTree) check(semver string, plan ...string) (map[string]string, string, error) {
	tr.t.Helper()
	planFile := filepath.Join(tr.root, "plan")
	decisionsFile := filepath.Join(tr.root, "decisions")
	require.NoError(tr.t, os.WriteFile(planFile, []byte(strings.Join(plan, "\n")+"\n"), 0o600))
	cmd := exec.Command(tr.env.node, tr.env.checkJS, planFile, decisionsFile, semver) //nolint:gosec // node runs the check program on test files
	cmd.Dir = filepath.Join(tr.root, "app")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, string(out), err
	}
	data, rerr := os.ReadFile(decisionsFile)
	require.NoError(tr.t, rerr)
	decisions := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		f := strings.SplitN(line, " ", 3)
		require.Len(tr.t, f, 3)
		decisions[f[2]] = f[0]
	}
	return decisions, string(out), nil
}

// TestNpmCheckJS runs the check program against fake node_modules trees. It needs
// node on PATH and is skipped otherwise.
func TestNpmCheckJS(t *testing.T) {
	env := newNpmTestEnv(t)

	newTree := func(t *testing.T) *npmTree {
		tr := &npmTree{t: t, env: env, root: t.TempDir()}
		tr.pkg("app", `{"name":"app","version":"1.0.0","dependencies":{"a":"^1.0.0"}}`)
		tr.pkg("app/node_modules/a", `{"name":"a","version":"1.0.0","dependencies":{"b":"^1.0.0"}}`)
		tr.pkg("app/node_modules/b", `{"name":"b","version":"1.0.0"}`)
		return tr
	}

	t.Run("new dependency not installed", func(t *testing.T) {
		tr := newTree(t)
		got, out, err := tr.check(env.semver,
			tr.stage("a", "node_modules/a", `{"name":"a","version":"1.1.0","dependencies":{"b":"^1.0.0","@isaacs/new-dep":"^1.0.1"}}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/a": "reject"}, got)
		assert.Contains(t, out, "WARN: not patching a in node_modules/a to 1.1.0")
		assert.Contains(t, out, "@isaacs/new-dep@^1.0.1 is not installed")
	})

	t.Run("packages updated together are checked against each other", func(t *testing.T) {
		tr := newTree(t)
		for _, plan := range [][]string{
			{
				tr.stage("a", "node_modules/a", `{"name":"a","version":"1.1.0","dependencies":{"b":"^2.0.0"}}`),
				tr.stage("b", "node_modules/b", `{"name":"b","version":"2.0.0"}`),
			},
			{
				tr.stage("b", "node_modules/b", `{"name":"b","version":"2.0.0"}`),
				tr.stage("a", "node_modules/a", `{"name":"a","version":"1.1.0","dependencies":{"b":"^2.0.0"}}`),
			},
		} {
			got, out, err := tr.check(env.semver, plan...)
			require.NoError(t, err, out)
			assert.Equal(t, map[string]string{"node_modules/a": "accept", "node_modules/b": "accept"}, got)
		}
	})

	t.Run("a rejection propagates to packages that needed the new version", func(t *testing.T) {
		tr := newTree(t)
		got, out, err := tr.check(env.semver,
			tr.stage("a", "node_modules/a", `{"name":"a","version":"1.1.0","dependencies":{"b":"^2.0.0"}}`),
			tr.stage("b", "node_modules/b", `{"name":"b","version":"2.0.0","dependencies":{"c":"^1.0.0"}}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/a": "reject", "node_modules/b": "reject"}, got)
		assert.Contains(t, out, "c@^1.0.0 is not installed")
		assert.Contains(t, out, "b@^2.0.0 resolves to 1.0.0")
	})

	t.Run("the staged dependency that breaks a staged dependent is the one kept", func(t *testing.T) {
		tr := newTree(t)
		// a is restaged at its version and needs b@^1.0.0; b would go 1.0.0 -> 2.0.0.
		got, out, err := tr.check(env.semver,
			tr.stage("a", "node_modules/a", `{"name":"a","version":"1.0.0","dependencies":{"b":"^1.0.0"}}`),
			tr.stage("b", "node_modules/b", `{"name":"b","version":"2.0.0"}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/a": "accept", "node_modules/b": "reject"}, got)
		assert.Contains(t, out, "required as b@^1.0.0 by a 1.0.0")
	})

	t.Run("an exact pin in both versions of a staged dependent accepts a patch update", func(t *testing.T) {
		tr := newTree(t)
		tr.pkg("app/node_modules/a", `{"name":"a","version":"1.0.0","dependencies":{"b":"1.0.0"}}`)
		got, out, err := tr.check(env.semver,
			tr.stage("a", "node_modules/a", `{"name":"a","version":"1.0.1","dependencies":{"b":"1.0.0"}}`),
			tr.stage("b", "node_modules/b", `{"name":"b","version":"1.0.1"}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/a": "accept", "node_modules/b": "accept"}, got)
	})

	t.Run("installed dependents", func(t *testing.T) {
		tr := newTree(t)
		// a@1.0.0 (not replaced) requires b@^1.0.0: a new major breaks it.
		got, out, err := tr.check(env.semver, tr.stage("b", "node_modules/b", `{"name":"b","version":"2.0.0"}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/b": "reject"}, got)
		assert.Contains(t, out, "required as b@^1.0.0 by a")

		// An exact pin and a patch update within the same major: accepted.
		tr.pkg("app/node_modules/a", `{"name":"a","version":"1.0.0","dependencies":{"b":"1.0.0"}}`)
		got, out, err = tr.check(env.semver, tr.stage("b", "node_modules/b", `{"name":"b","version":"1.0.1"}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/b": "accept"}, got)

		// A 0.x dependent and a new minor: breaks it.
		tr.pkg("app/node_modules/a", `{"name":"a","version":"1.0.0","dependencies":{"b":"^0.3.0"}}`)
		tr.pkg("app/node_modules/b", `{"name":"b","version":"0.3.1"}`)
		got, out, err = tr.check(env.semver, tr.stage("b", "node_modules/b", `{"name":"b","version":"0.4.0"}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/b": "reject"}, got)

		// A dependent that the installed version already did not satisfy is not made worse.
		tr.pkg("app/node_modules/a", `{"name":"a","version":"1.0.0","dependencies":{"b":"^0.2.0"}}`)
		got, out, err = tr.check(env.semver, tr.stage("b", "node_modules/b", `{"name":"b","version":"2.0.0"}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/b": "accept"}, got)
	})

	t.Run("the root package is not a dependent", func(t *testing.T) {
		tr := newTree(t)
		tr.pkg("app", `{"name":"app","version":"1.0.0","dependencies":{"a":"1.0.0","b":"^1.0.0"}}`)
		tr.pkg("app/node_modules/a", `{"name":"a","version":"1.0.0"}`)
		got, out, err := tr.check(env.semver,
			tr.stage("a", "node_modules/a", `{"name":"a","version":"1.0.1"}`),
			tr.stage("b", "node_modules/b", `{"name":"b","version":"2.0.0"}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/a": "accept", "node_modules/b": "accept"}, got)
	})

	t.Run("nested node_modules of the installed version is carried over", func(t *testing.T) {
		tr := newTree(t)
		tr.pkg("app/node_modules/a/node_modules/c", `{"name":"c","version":"3.0.0"}`)
		got, out, err := tr.check(env.semver,
			tr.stage("a", "node_modules/a", `{"name":"a","version":"1.1.0","dependencies":{"c":"^3.0.0"}}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/a": "accept"}, got)

		// Unless the tarball bundles its own.
		require.NoError(t, os.MkdirAll(filepath.Join(tr.root, "app", "node_modules", "a.copa-new", "node_modules"), 0o755))
		got, out, err = tr.check(env.semver, "a node_modules/a")
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/a": "reject"}, got)
	})

	t.Run("copies inside a replaced bundling parent are dropped", func(t *testing.T) {
		tr := newTree(t)
		tr.pkg("app/node_modules/a/node_modules/b", `{"name":"b","version":"1.0.0"}`)
		tr.pkg("app/node_modules/a.copa-new/node_modules/b", `{"name":"b","version":"1.0.5"}`)
		got, out, err := tr.check(env.semver,
			tr.stage("a", "node_modules/a", `{"name":"a","version":"1.1.0","dependencies":{"b":"^1.0.0"}}`),
			tr.stage("b", "node_modules/a/node_modules/b", `{"name":"b","version":"1.0.1"}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/a": "accept", "node_modules/a/node_modules/b": "dropped"}, got)
	})

	t.Run("optional dependencies and non-semver ranges", func(t *testing.T) {
		tr := newTree(t)
		got, out, err := tr.check(env.semver,
			tr.stage("a", "node_modules/a", `{"name":"a","version":"1.1.0","dependencies":{"b":"npm:b@1","opt":"^1.0.0"},"optionalDependencies":{"opt":"^1.0.0"}}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/a": "accept"}, got)
	})

	t.Run("without semver only presence is checked", func(t *testing.T) {
		tr := newTree(t)
		got, out, err := tr.check(env.noSemver,
			tr.stage("a", "node_modules/a", `{"name":"a","version":"1.1.0","dependencies":{"b":"^2.0.0"}}`))
		require.NoError(t, err, out)
		if strings.Contains(out, "semver module not found") {
			assert.Equal(t, map[string]string{"node_modules/a": "accept"}, got)
		} else { // npm's semver found next to node
			assert.Equal(t, map[string]string{"node_modules/a": "reject"}, got)
		}
	})

	t.Run("dependents reached through a symlink use its real path", func(t *testing.T) {
		tr := newTree(t)
		// app/node_modules/ws -> ../../ws (a workspace package) requires b@^1.0.0,
		// which it resolves from <root>/node_modules through its real path.
		tr.pkg("app/node_modules/a", `{"name":"a","version":"1.0.0"}`)
		tr.pkg("ws", `{"name":"ws","version":"1.0.0","dependencies":{"b":"^1.0.0"}}`)
		if err := os.Symlink(filepath.Join("..", "..", "ws"), filepath.Join(tr.root, "app", "node_modules", "ws")); err != nil {
			t.Skipf("cannot create symlinks: %v", err)
		}
		tr.pkg("node_modules/b", `{"name":"b","version":"1.0.0"}`)
		got, out, err := tr.check(env.semver, tr.stage("b", "node_modules/b", `{"name":"b","version":"2.0.0"}`))
		require.NoError(t, err, out)
		assert.Equal(t, map[string]string{"node_modules/b": "accept"}, got)
	})

	t.Run("malformed staged package.json is an error", func(t *testing.T) {
		tr := newTree(t)
		_, out, err := tr.check(env.semver, tr.stage("a", "node_modules/a", `not json`))
		assert.Error(t, err)
		assert.Contains(t, out, "SyntaxError")
	})
}
