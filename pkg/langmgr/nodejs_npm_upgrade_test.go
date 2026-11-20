package langmgr

import (
	"context"
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

func TestNpmTreeLocation(t *testing.T) {
	tests := []struct {
		pkgPath, dir, rel string
		ok                bool
	}{
		{"usr/local/lib/node_modules/npm/node_modules/minimatch/package.json", "/usr/local/lib/node_modules/npm", "node_modules/minimatch/package.json", true},
		{"/usr/local/lib/node_modules/npm/node_modules/@sigstore/core/package.json", "/usr/local/lib/node_modules/npm", "node_modules/@sigstore/core/package.json", true},
		{"usr/local/lib/node_modules/npm/node_modules/a/node_modules/b/package.json", "/usr/local/lib/node_modules/npm", "node_modules/a/node_modules/b/package.json", true},
		{"usr/local/lib/node_modules/npm/package.json", "/usr/local/lib/node_modules/npm", "package.json", true},
		{"opt/node/lib/node_modules/npm/node_modules/tar/package.json", "/opt/node/lib/node_modules/npm", "node_modules/tar/package.json", true},
		{"app/node_modules/minimatch/package.json", "", "", false},
		{"usr/local/lib/node_modules/npm/node_modules/../../x/package.json", "", "", false},
		{"usr/../lib/node_modules/npm/node_modules/tar/package.json", "", "", false},
		{"usr/local/lib/node_modules/npm/node_modules/tar/lib/package.json", "", "", false},
		{"my dir/node_modules/npm/node_modules/tar/package.json", "", "", false},
		{"usr/local/lib/node_modules/npm/node_modules/tar", "", "", false},
	}
	for _, tt := range tests {
		dir, rel, ok := npmTreeLocation(tt.pkgPath)
		assert.Equal(t, tt.ok, ok, tt.pkgPath)
		assert.Equal(t, tt.dir, dir, tt.pkgPath)
		assert.Equal(t, tt.rel, rel, tt.pkgPath)
	}
}

func npmTreeTestUpdates() unversioned.LangUpdatePackages {
	return unversioned.LangUpdatePackages{
		{Name: "minimatch", InstalledVersion: "9.0.5", FixedVersion: "11.0.1", PkgPath: "usr/local/lib/node_modules/npm/node_modules/minimatch/package.json"},
		{Name: "lodash", InstalledVersion: "4.17.20", FixedVersion: "4.17.21", PkgPath: "app/node_modules/lodash/package.json"},
		{Name: "tar", InstalledVersion: "6.2.1", FixedVersion: "7.5.21", PkgPath: "usr/local/lib/node_modules/npm/node_modules/tar/package.json"},
		{Name: "npm", InstalledVersion: "10.8.2", FixedVersion: "10.9.0", PkgPath: "usr/local/lib/node_modules/npm/package.json"},
		{Name: "diff", InstalledVersion: "5.2.0", FixedVersion: "", PkgPath: "usr/local/lib/node_modules/npm/node_modules/diff/package.json"},
		{Name: "ip-address", InstalledVersion: "9.0.5", FixedVersion: "10.7.4", PkgPath: "usr/local/lib/node_modules/npm/node_modules/ip-address/package.json"},
		{Name: "bad;name", InstalledVersion: "1.0.0", FixedVersion: "1.0.1", PkgPath: "usr/local/lib/node_modules/npm/node_modules/x/package.json"},
	}
}

func TestNpmTreeItems(t *testing.T) {
	items := npmTreeItems(npmTreeTestUpdates())
	require.Len(t, items, 4)
	assert.Equal(t, npmTreeItem{update: 0, name: "minimatch", npmDir: "/usr/local/lib/node_modules/npm", rel: "node_modules/minimatch/package.json", fixed: "11.0.1"}, items[0])
	assert.Equal(t, 2, items[1].update)
	assert.Equal(t, npmTreeItem{update: 3, name: "npm", npmDir: "/usr/local/lib/node_modules/npm", rel: "package.json", fixed: "10.9.0", isOwner: true}, items[2])
	assert.Equal(t, 5, items[3].update)

	assert.Equal(t,
		"0 minimatch /usr/local/lib/node_modules/npm node_modules/minimatch/package.json 11.0.1\n"+
			"1 tar /usr/local/lib/node_modules/npm node_modules/tar/package.json 7.5.21\n"+
			"2 npm /usr/local/lib/node_modules/npm package.json 10.9.0\n"+
			"3 ip-address /usr/local/lib/node_modules/npm node_modules/ip-address/package.json 10.7.4\n",
		string(npmUpgradeItemsFile(items)))
}

func TestNpmSelfUpgradeEnabled(t *testing.T) {
	t.Setenv(npmSelfUpgradeEnv, "")
	assert.False(t, npmSelfUpgradeEnabled())
	t.Setenv("COPA_EXPERIMENTAL", "1")
	assert.False(t, npmSelfUpgradeEnabled(), "COPA_EXPERIMENTAL alone must not enable it")
	t.Setenv(npmSelfUpgradeEnv, "true")
	assert.False(t, npmSelfUpgradeEnabled())
	t.Setenv(npmSelfUpgradeEnv, "1")
	assert.True(t, npmSelfUpgradeEnabled())
}

func TestNpmUpgradeScope(t *testing.T) {
	assert.Equal(t, npmScopeSameMinor, npmUpgradeScope(""))
	assert.Equal(t, npmScopeSameMinor, npmUpgradeScope("patch"))
	assert.Equal(t, npmScopeSameMajor, npmUpgradeScope("minor"))
	assert.Equal(t, npmScopeSameMajor, npmUpgradeScope("major"))
}

func TestNpmUpgradeScript(t *testing.T) {
	sh := npmUpgradeScript(npmUpgradeScriptsMount, npmUpgradeOutMount, npmUpgradeWorkMount)
	assert.Equal(t, []string{"sh", "/copa-npm-upgrade-scripts/upgrade.sh", "same-major"}, npmUpgradeArgs(npmScopeSameMajor))
	// Results go to a scratch mount; npm's cache, the backup and compile caches stay off the image.
	assert.Contains(t, sh, "O='"+npmUpgradeOutMount+"'\n")
	assert.Contains(t, sh, `NPM_CONFIG_CACHE="$W/cache"`)
	assert.Contains(t, sh, "NODE_DISABLE_COMPILE_CACHE=1")
	assert.Contains(t, sh, "NPM_CONFIG_FETCH_RETRIES=1 NPM_CONFIG_FETCH_TIMEOUT=30000")
	assert.Contains(t, sh, `cp -a "$NPM_DIR" "$W/backup/npm"`)
	// Never another major version; same minor version unless the scope allows more.
	assert.Contains(t, sh, `RANGE=">$OLD <$((MAJOR + 1)).0.0"`)
	assert.Contains(t, sh, `RANGE=">$OLD <$MAJOR.$((MINOR + 1)).0"`)
	assert.Contains(t, sh, `npm view "npm@$RANGE" version engines deprecated time --json`)
	assert.Contains(t, sh, `npm install -g --ignore-scripts "npm@$NEW"`)
	// Every failure after the backup restores it, including what npm wrote outside its directory.
	assert.Equal(t, 3, strings.Count(sh, "rollback; REASON="))
	assert.Contains(t, sh, `rm -rf "${NPM_DIR%/*}"/.npm-*`)
	assert.Contains(t, sh, `while IFS= read -r l; do rm -f "$l" || restore_failed "$l"; done < "$W/man.after"`)
	// The result file is written last; a failed check in a command substitution still stops the script.
	assert.True(t, strings.HasSuffix(sh, `} > "$O/`+npmUpgradeResultFile+`" || exit 1`+"\n"))
	assert.Contains(t, sh, `BEFORE=$(check "$W/items.before") || fail_check`)
	assert.Contains(t, sh, `AFTER=$(check "$W/items.after") || fail_check`)
}

func TestNpmSelfUpgradeStep(t *testing.T) {
	st := llb.Image("node:18")
	root, out := npmSelfUpgradeStep(&st, npmTreeItems(npmTreeTestUpdates()), npmScopeSameMajor)
	for _, s := range []llb.State{root, out} {
		_, err := s.Marshal(context.Background())
		require.NoError(t, err)
	}
}

func TestUpgradeNpmSelfWithoutClient(t *testing.T) {
	nm := &nodejsManager{config: &buildkit.Config{}}
	st := llb.Image("node:18")
	report := newNpmReport()
	updates := npmTreeTestUpdates()
	got, remaining, err := nm.upgradeNpmSelf(context.Background(), &st, &unversioned.Metadata{}, updates, report)
	require.NoError(t, err)
	assert.Equal(t, &st, got)
	assert.Equal(t, updates, remaining)
	assert.Empty(t, report.selfUpgradeSkipped)
}

func TestNpmReportSnapshotSelfUpgradeSkipped(t *testing.T) {
	report := newNpmReport()
	before := report.snapshot()
	report.selfUpgradeSkipped = append(report.selfUpgradeSkipped, "npm")
	report.restore(&before)
	assert.Empty(t, report.selfUpgradeSkipped)
}

func TestParseNpmUpgradeResult(t *testing.T) {
	res, err := parseNpmUpgradeResult([]byte("upgraded 10.8.2 10.9.11\nitem 0 9.0.9 left\nitem 1 7.5.22 fixed\n" +
		"item 3 - fixed\nitem 4 12.0.0 skip-unverified\nitem 5 10.9.11 skip-owner\n" +
		"added picomatch 4.0.3\nmajor tar 6.2.1 7.5.22\n"))
	require.NoError(t, err)
	assert.Equal(t, &npmUpgradeResult{
		upgraded: true, from: "10.8.2", to: "10.9.11",
		items: map[int]npmItemState{
			0: {"9.0.9", npmItemLeft}, 1: {"7.5.22", npmItemFixed}, 3: {"-", npmItemFixed},
			4: {"12.0.0", npmItemSkipUnverified}, 5: {"10.9.11", npmItemSkipOwner},
		},
		added:  []string{"picomatch 4.0.3"},
		majors: []string{"tar 6.2.1 -> 7.5.22"},
	}, res)

	res, err = parseNpmUpgradeResult([]byte("unchanged 10.9.11 no suitable newer npm release\n"))
	require.NoError(t, err)
	assert.False(t, res.upgraded)
	assert.Equal(t, "10.9.11", res.from)
	assert.Equal(t, "no suitable newer npm release", res.reason)
	assert.Empty(t, res.items)

	res, err = parseNpmUpgradeResult([]byte("unchanged - npm is not installed\n"))
	require.NoError(t, err)
	assert.Equal(t, "npm is not installed", res.reason)

	for _, bad := range []string{
		"", "upgraded 10.8.2", "upgraded 1 2 3", "done 1 2", "unchanged 1 x\nitem 0 1.0.0",
		"unchanged 1 x\nitem a 1.0.0 fixed", "unchanged 1 x\nitem 0 1.0.0 1", "unchanged 1 x\nadded a",
		"unchanged 1 x\nmajor a 1.0.0",
	} {
		_, err := parseNpmUpgradeResult([]byte(bad))
		assert.Error(t, err, bad)
	}
}

func TestApplyNpmUpgradeResult(t *testing.T) {
	updates := npmTreeTestUpdates()
	items := npmTreeItems(updates)
	res := &npmUpgradeResult{upgraded: true, items: map[int]npmItemState{
		0: {"9.0.9", npmItemLeft},            // minimatch: still vulnerable, now at 9.0.9
		1: {"7.5.22", npmItemFixed},          // tar: fixed
		2: {"10.9.11", npmItemFixed},         // npm: fixed
		3: {"11.0.0", npmItemSkipUnverified}, // ip-address: another major than its fix
	}}
	o := applyNpmUpgradeResult(updates, items, res)
	assert.Equal(t, []string{"tar", "npm"}, o.fixed)
	assert.Equal(t, []string{"minimatch"}, o.left)
	require.Len(t, o.skipped, 1)
	assert.Contains(t, o.skipped["ip-address"], "not known to be fixed")
	require.Len(t, o.remaining, 4)
	assert.Equal(t, "minimatch", o.remaining[0].Name)
	assert.Equal(t, "9.0.9", o.remaining[0].InstalledVersion)
	assert.Equal(t, "11.0.1", o.remaining[0].FixedVersion)
	assert.Equal(t, []string{"lodash", "diff", "bad;name"}, []string{o.remaining[1].Name, o.remaining[2].Name, o.remaining[3].Name})
	// The input is not modified.
	assert.Equal(t, "9.0.5", updates[0].InstalledVersion)

	// npm itself still vulnerable: reported as skipped with its own reason; an unreadable
	// version keeps the reported one; items the step did not report on are kept.
	res = &npmUpgradeResult{items: map[int]npmItemState{0: {"?", npmItemLeft}, 2: {"10.8.2", npmItemSkipOwner}}}
	o = applyNpmUpgradeResult(updates, items, res)
	assert.Empty(t, o.fixed)
	assert.Equal(t, []string{"minimatch"}, o.left)
	assert.Contains(t, o.skipped["npm"], "npm 10.8.2 is installed and its fix (10.9.0)")
	assert.Len(t, o.remaining, 6)
	assert.Equal(t, "9.0.5", o.remaining[0].InstalledVersion)
}

// fakeNpmSemver stands in for npm's semver module in the npm directory.
const fakeNpmSemver = `module.exports = { satisfies: function (v, r) { return r === 'ok'; } };`

type npmJSEnv struct {
	node, js, dir, npmDir string
}

func newNpmJSEnv(t *testing.T) npmJSEnv {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found on PATH")
	}
	dir := t.TempDir()
	e := npmJSEnv{node: node, js: filepath.Join(dir, "upgrade.js"), dir: dir, npmDir: filepath.Join(dir, "lib", "node_modules", "npm")}
	require.NoError(t, os.WriteFile(e.js, []byte(npmUpgradeJS), 0o600))
	return e
}

func (e npmJSEnv) write(t *testing.T, rel, content string) {
	t.Helper()
	f := filepath.Join(e.npmDir, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(f), 0o755))
	require.NoError(t, os.WriteFile(f, []byte(content), 0o600))
}

func (e npmJSEnv) run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(e.node, append([]string{e.js}, args...)...).Output() //#nosec G204
	require.NoError(t, err)
	return strings.TrimSpace(string(out))
}

// TestNpmUpgradeJS runs the helper of the upgrade step. It needs node on PATH and is
// skipped otherwise.
func TestNpmUpgradeJS(t *testing.T) {
	e := newNpmJSEnv(t)
	e.write(t, "package.json", `{"name":"npm","version":"10.8.2"}`)
	e.write(t, "node_modules/semver/index.js", fakeNpmSemver)
	assert.Equal(t, "10.8.2", e.run(t, "version", e.npmDir))

	const now = "1800000000000" // 2027-01-15
	old, recent := `"2026-11-01T00:00:00.000Z"`, `"2027-01-14T00:00:00.000Z"`
	view := filepath.Join(e.dir, "view.json")
	pick := func(scope, content string) string {
		require.NoError(t, os.WriteFile(view, []byte(content), 0o600))
		return e.run(t, "pick", e.npmDir, view, scope, "7", now)
	}
	releases := `[
		{"version":"10.8.1","engines":{"node":"ok"},"time":{"10.8.1":` + old + `}},
		{"version":"10.8.3","engines":{"node":"ok"},"time":{"10.8.3":` + old + `}},
		{"version":"10.8.4","engines":{"node":"ok"},"time":{"10.8.4":` + old + `},"deprecated":"broken"},
		{"version":"10.9.10","engines":{"node":"ok"},"time":{"10.9.10":` + old + `}},
		{"version":"10.9.11","engines":{"node":"ok"},"time":{"10.9.11":` + recent + `}},
		{"version":"10.9.12","engines":{"node":"too new"},"time":{"10.9.12":` + old + `}},
		{"version":"10.9.13","engines":{"node":"ok"}},
		{"version":"10.10.0-pre.0","engines":{"node":"ok"},"time":{"10.10.0-pre.0":` + old + `}},
		{"version":"11.0.0","engines":{"node":"ok"},"time":{"11.0.0":` + old + `}}]`
	assert.Equal(t, "10.9.10", pick(npmScopeSameMajor, releases))
	assert.Equal(t, "10.8.3", pick(npmScopeSameMinor, releases))
	assert.Equal(t, "10.9.0", pick(npmScopeSameMajor, `{"version":"10.9.0","time":{"10.9.0":`+old+`}}`))
	assert.Empty(t, pick(npmScopeSameMajor, `{"error":{"code":"E404"}}`))
	assert.Empty(t, pick(npmScopeSameMajor, `not json`))

	// After an upgrade: minimatch fixed at its path, tar not, glob gone from its path
	// with a lower nested copy left, sigstore gone entirely, diff unreadable, and
	// @scope/d, undici and ip-address at other majors than their fixed versions.
	e.write(t, "package.json", `{"name":"npm","version":"10.9.11"}`)
	e.write(t, "node_modules/minimatch/package.json", `{"version":"9.0.9"}`)
	e.write(t, "node_modules/tar/package.json", `{"version":"6.2.1"}`)
	e.write(t, "node_modules/a/node_modules/glob/package.json", `{"version":"10.4.2"}`)
	e.write(t, "node_modules/b/node_modules/glob/package.json", `{"version":"10.5.0"}`)
	e.write(t, "node_modules/@scope/c/node_modules/@scope/d/package.json", `{"version":"2.0.0"}`)
	e.write(t, "node_modules/diff/package.json", `{}`)
	e.write(t, "node_modules/undici/package.json", `{"version":"7.0.0"}`)
	e.write(t, "node_modules/ip-address/package.json", `{"version":"10.1.0"}`)
	itemsFile := filepath.Join(e.dir, "items")
	other := filepath.Join(e.dir, "other", "node_modules", "npm")
	d := e.npmDir
	require.NoError(t, os.WriteFile(itemsFile, []byte(strings.Join([]string{
		"0 minimatch " + d + " node_modules/minimatch/package.json 9.0.7",
		"1 tar " + d + " node_modules/tar/package.json 7.5.21",
		"2 glob " + d + " node_modules/glob/package.json 10.5.0",
		"3 sigstore " + d + " node_modules/sigstore/package.json 4.1.1",
		"4 diff " + d + " node_modules/diff/package.json 5.2.2",
		"5 npm " + d + " package.json 10.9.0",
		"6 npm " + d + " package.json 11.0.0",
		"7 @scope/d " + d + " node_modules/@scope/d/package.json 1.0.0",
		"8 undici " + d + " node_modules/undici/package.json 6.29.1",
		"9 ip-address " + d + " node_modules/ip-address/package.json 9.0.6",
		"10 tar " + other + " node_modules/tar/package.json 7.5.21",
	}, "\n")+"\n"), 0o600))
	out := filepath.Join(e.dir, "out")
	// Fixed: 0, 3, 5. Actionable: the ones left (1, 2, 4); npm 11 is out of scope.
	assert.Equal(t, "10 3 3", e.run(t, "check", d, itemsFile, npmScopeSameMajor, out))
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "item 0 9.0.9 fixed\nitem 1 6.2.1 left\nitem 2 10.4.2 left\nitem 3 - fixed\nitem 4 ? left\n"+
		"item 5 10.9.11 fixed\nitem 6 10.9.11 skip-owner\nitem 7 2.0.0 skip-unverified\n"+
		"item 8 7.0.0 skip-unverified\nitem 9 10.1.0 skip-unverified\n", string(data))
	res, err := parseNpmUpgradeResult(append([]byte("upgraded 10.8.2 10.9.11\n"), data...))
	require.NoError(t, err)
	assert.Len(t, res.items, 10)

	// npm itself with a fix in scope is actionable.
	require.NoError(t, os.WriteFile(itemsFile, []byte("0 npm "+d+" package.json 10.10.0\n1 npm "+d+" package.json 11.0.1\n"), 0o600))
	assert.Equal(t, "2 0 1", e.run(t, "check", d, itemsFile, npmScopeSameMajor, out))
	assert.Equal(t, "2 0 0", e.run(t, "check", d, itemsFile, npmScopeSameMinor, out))

	// list and diff: added packages and packages with a version in another major.
	before, after := filepath.Join(e.dir, "before"), filepath.Join(e.dir, "after")
	e.run(t, "list", d, before)
	data, err = os.ReadFile(before)
	require.NoError(t, err)
	assert.Contains(t, string(data), "glob 10.4.2\nglob 10.5.0\n")
	assert.Contains(t, string(data), "@scope/d 2.0.0\n")
	require.NoError(t, os.WriteFile(before, []byte("tar 6.2.1\nglob 10.4.2\nms 0.7.1\nkeep 1.0.0\n"), 0o600))
	require.NoError(t, os.WriteFile(after, []byte("tar 7.5.22\nglob 10.5.0\nglob 11.0.0\nglob 11.0.0\nms 0.8.0\nkeep 1.2.0\npicomatch 4.0.3\n"), 0o600))
	assert.Equal(t, "major glob 10.4.2 10.5.0,11.0.0\nmajor ms 0.7.1 0.8.0\nadded picomatch 4.0.3\nmajor tar 6.2.1 7.5.22",
		e.run(t, "diff", before, after))
}

// fakeNpm is a stand-in for npm, for running the upgrade script. FAKE_PREFIX is the
// global prefix; "npm install -g" runs the FAKE_INSTALL script; FAKE_BROKEN makes the
// verification install fail.
const fakeNpm = `#!/bin/sh
D="$FAKE_PREFIX/lib/node_modules"
case "$1" in
  root) echo "$D" ;;
  prefix) echo "$FAKE_PREFIX" ;;
  --version) node -p "require(process.argv[1]).version" "$D/npm/package.json" ;;
  view) cat "$FAKE_VIEW" ;;
  install)
    if [ "$2" = -g ]; then exec sh "$FAKE_INSTALL" "$D" "$FAKE_PREFIX"; fi
    [ -z "$FAKE_BROKEN" ] ;;
  ls) [ -z "$FAKE_BROKEN" ] ;;
  *) exit 1 ;;
esac
`

// fakeNpmInstall installs a fake npm 10.9.11 that fixes minimatch and tar, adds
// picomatch, leaves a staging directory, and adds an npx link and a man page link.
const fakeNpmInstall = `D=$1
P=$2
mkdir -p "$D/.npm-AbCd" "$D/npm/node_modules/picomatch" || exit 1
echo '{"name":"npm","version":"10.9.11"}' > "$D/npm/package.json"
echo '{"version":"9.0.9"}' > "$D/npm/node_modules/minimatch/package.json"
echo '{"version":"7.5.22"}' > "$D/npm/node_modules/tar/package.json"
echo '{"version":"4.0.3"}' > "$D/npm/node_modules/picomatch/package.json"
ln -s ../lib/node_modules/npm/bin/npx-cli.js "$P/bin/npx"
ln -s ../../../lib/node_modules/npm/man/man1/npm-install.1 "$P/share/man/man1/npm-install.1"
exit ${FAKE_INSTALL_RC:-0}
`

type npmScriptEnv struct {
	dir, prefix, npmDir, out string
	env                      []string
}

func newNpmScriptEnv(t *testing.T) *npmScriptEnv {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not found on PATH")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not found on PATH")
	}
	dir := t.TempDir()
	e := &npmScriptEnv{dir: dir, prefix: filepath.Join(dir, "prefix"), out: filepath.Join(dir, "out")}
	e.npmDir = filepath.Join(e.prefix, "lib", "node_modules", "npm")
	w := func(f, content string) {
		require.NoError(t, os.MkdirAll(filepath.Dir(f), 0o755))
		require.NoError(t, os.WriteFile(f, []byte(content), 0o600))
	}
	w(filepath.Join(e.npmDir, "package.json"), `{"name":"npm","version":"10.8.2"}`)
	w(filepath.Join(e.npmDir, "node_modules", "minimatch", "package.json"), `{"version":"9.0.5"}`)
	w(filepath.Join(e.npmDir, "node_modules", "tar", "package.json"), `{"version":"6.2.1"}`)
	w(filepath.Join(e.prefix, "share", "man", "man1", "other.1"), "")
	require.NoError(t, os.MkdirAll(filepath.Join(e.prefix, "bin"), 0o755))
	require.NoError(t, os.Symlink("../lib/node_modules/npm/bin/npm-cli.js", filepath.Join(e.prefix, "bin", "npm")))
	require.NoError(t, os.Symlink("../../../lib/node_modules/npm/man/man1/npm.1", filepath.Join(e.prefix, "share", "man", "man1", "npm.1")))

	scripts := filepath.Join(dir, "scripts")
	w(filepath.Join(scripts, "upgrade.sh"), npmUpgradeScript(scripts, e.out, filepath.Join(dir, "work")))
	w(filepath.Join(scripts, "upgrade.js"), npmUpgradeJS)
	w(filepath.Join(scripts, "items"),
		"0 minimatch "+e.npmDir+" node_modules/minimatch/package.json 9.0.7\n"+
			"1 tar "+e.npmDir+" node_modules/tar/package.json 7.5.21\n")
	fakeBin := filepath.Join(dir, "fakebin")
	w(filepath.Join(fakeBin, "npm"), fakeNpm)
	require.NoError(t, os.Chmod(filepath.Join(fakeBin, "npm"), 0o700)) //#nosec G302
	w(filepath.Join(dir, "install.sh"), fakeNpmInstall)
	w(filepath.Join(dir, "view.json"), `[{"version":"10.9.11","time":{"10.9.11":"2026-01-01T00:00:00.000Z"}}]`)
	require.NoError(t, os.MkdirAll(e.out, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "work"), 0o755))
	e.env = append(os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_PREFIX="+e.prefix, "FAKE_VIEW="+filepath.Join(dir, "view.json"), "FAKE_INSTALL="+filepath.Join(dir, "install.sh"))
	return e
}

func (e *npmScriptEnv) run(t *testing.T, scope string, env ...string) (string, *npmUpgradeResult) {
	t.Helper()
	cmd := exec.Command("sh", filepath.Join(e.dir, "scripts", "upgrade.sh"), scope) //#nosec G204
	cmd.Env = append(append([]string{}, e.env...), env...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	data, err := os.ReadFile(filepath.Join(e.out, npmUpgradeResultFile))
	require.NoError(t, err, string(out))
	res, err := parseNpmUpgradeResult(data)
	require.NoError(t, err, string(data))
	return string(out), res
}

// assertOriginal checks that npm and what it installed outside its directory are as
// before the upgrade.
func (e *npmScriptEnv) assertOriginal(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.npmDir, "package.json"))
	require.NoError(t, err)
	assert.Contains(t, string(data), `"10.8.2"`)
	assert.NoDirExists(t, filepath.Join(e.npmDir, "node_modules", "picomatch"))
	assert.NoDirExists(t, filepath.Join(e.prefix, "lib", "node_modules", ".npm-AbCd"))
	_, err = os.Lstat(filepath.Join(e.prefix, "bin", "npx"))
	assert.True(t, os.IsNotExist(err), "npx link added by the install is removed")
	_, err = os.Lstat(filepath.Join(e.prefix, "share", "man", "man1", "npm-install.1"))
	assert.True(t, os.IsNotExist(err), "man page link added by the install is removed")
	l, err := os.Readlink(filepath.Join(e.prefix, "bin", "npm"))
	require.NoError(t, err)
	assert.Equal(t, "../lib/node_modules/npm/bin/npm-cli.js", l)
	l, err = os.Readlink(filepath.Join(e.prefix, "share", "man", "man1", "npm.1"))
	require.NoError(t, err)
	assert.Equal(t, "../../../lib/node_modules/npm/man/man1/npm.1", l)
	assert.FileExists(t, filepath.Join(e.prefix, "share", "man", "man1", "other.1"))
}

// TestNpmUpgradeScriptRun runs the upgrade script against a fake npm. It needs sh and
// node on PATH and is skipped otherwise.
func TestNpmUpgradeScriptRun(t *testing.T) {
	t.Run("upgraded", func(t *testing.T) {
		e := newNpmScriptEnv(t)
		_, res := e.run(t, npmScopeSameMajor)
		assert.True(t, res.upgraded)
		assert.Equal(t, "10.9.11", res.to)
		assert.Equal(t, map[int]npmItemState{0: {"9.0.9", npmItemFixed}, 1: {"7.5.22", npmItemFixed}}, res.items)
		assert.Equal(t, []string{"picomatch 4.0.3"}, res.added)
		assert.Equal(t, []string{"tar 6.2.1 -> 7.5.22"}, res.majors)
	})
	t.Run("out of scope", func(t *testing.T) {
		e := newNpmScriptEnv(t)
		_, res := e.run(t, npmScopeSameMinor)
		assert.False(t, res.upgraded)
		assert.Contains(t, res.reason, "no suitable newer npm release")
		assert.Equal(t, npmItemLeft, res.items[0].state)
		e.assertOriginal(t)
	})
	rollbacks := []struct {
		name, reason string
		env          []string
	}{
		{"install fails", "could not be installed", []string{"FAKE_INSTALL_RC=1"}},
		{"verification fails", "does not work", []string{"FAKE_BROKEN=1"}},
	}
	for _, tt := range rollbacks {
		t.Run(tt.name, func(t *testing.T) {
			e := newNpmScriptEnv(t)
			out, res := e.run(t, npmScopeSameMajor, tt.env...)
			assert.Contains(t, out, "INFO: restoring npm 10.8.2")
			assert.False(t, res.upgraded)
			assert.Contains(t, res.reason, tt.reason)
			assert.Equal(t, map[int]npmItemState{0: {"9.0.5", npmItemLeft}, 1: {"6.2.1", npmItemLeft}}, res.items)
			assert.Empty(t, res.added)
			e.assertOriginal(t)
		})
	}
	t.Run("fixes nothing", func(t *testing.T) {
		e := newNpmScriptEnv(t)
		// The fixed versions are in another major than what the new npm bundles.
		require.NoError(t, os.WriteFile(filepath.Join(e.dir, "scripts", "items"), []byte(
			"0 minimatch "+e.npmDir+" node_modules/minimatch/package.json 11.0.1\n"), 0o600))
		_, res := e.run(t, npmScopeSameMajor)
		assert.False(t, res.upgraded)
		assert.Contains(t, res.reason, "fixes none of the reported packages")
		e.assertOriginal(t)
	})
	t.Run("only npm itself, fixed in another major", func(t *testing.T) {
		e := newNpmScriptEnv(t)
		require.NoError(t, os.WriteFile(filepath.Join(e.dir, "scripts", "items"), []byte(
			"0 npm "+e.npmDir+" package.json 11.0.0\n"), 0o600))
		out, res := e.run(t, npmScopeSameMajor)
		assert.NotContains(t, out, "upgrading npm")
		assert.Contains(t, res.reason, "no npm release in scope")
		assert.Equal(t, map[int]npmItemState{0: {"10.8.2", npmItemSkipOwner}}, res.items)
	})
}
