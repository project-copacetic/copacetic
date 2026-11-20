package langmgr

import (
	"context"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// Experimental, opt-in: vulnerable packages inside npm's own directory can first be
// handled by upgrading npm itself, as a unit, to a newer release of the installed npm
// (same minor version, or same major version with --library-patch-level minor or
// major) that the image's Node.js supports. npm bundles all of its dependencies and
// tests each release with them, whereas the fixed versions reported for its bundled
// packages are often majors that the installed npm cannot use (see npmCheckJS).
// Whatever is still vulnerable afterwards goes through the per-package replacement.
//
// It is off by default because a newer npm can bundle packages that the image did not
// have, or other majors of the ones it had, and those can have vulnerabilities of their
// own that the scan report does not cover (e.g. npm 10.9.5+ adds picomatch 4.0.3). Such
// changes are logged as warnings when it is enabled.
//
// It is enabled with its own variable rather than COPA_EXPERIMENTAL, which also turns
// on unrelated experimental flags (and is set by the e2e tests), and it is read from
// the environment of the copa process: the BuildKit frontend does not enable it.
const npmSelfUpgradeEnv = "COPA_EXPERIMENTAL_NPM_SELF_UPGRADE"

const (
	// npmUpgradeScriptsMount holds the upgrade step's script, its items and helper.
	npmUpgradeScriptsMount = "/copa-npm-upgrade-scripts"
	// npmUpgradeOutMount is a scratch mount on which the upgrade step writes its result.
	npmUpgradeOutMount = "/copa-npm-upgrade-out"
	// npmUpgradeWorkMount is a tmpfs for the backup of npm, npm's cache and logs, so that
	// none of them end up in the image.
	npmUpgradeWorkMount = "/copa-npm-upgrade-work"
	// npmUpgradeResultFile (on npmUpgradeOutMount) is written last by the upgrade step.
	npmUpgradeResultFile = "result"
	// npmUpgradeMinAgeDays is the minimum age of an npm release to upgrade to.
	npmUpgradeMinAgeDays = 7

	// Upgrade scopes: npm releases with the installed major.minor, or major version.
	npmScopeSameMinor = "same-minor"
	npmScopeSameMajor = "same-major"
)

// npmSelfUpgradeEnabled tells whether the experimental npm self-upgrade is enabled.
func npmSelfUpgradeEnabled() bool {
	return os.Getenv(npmSelfUpgradeEnv) == "1"
}

// npmUpgradeScope returns the npm releases allowed by a library patch level: the
// installed minor version for "patch" (the default when the level is not set), the
// installed major version for "minor" and "major". npm never changes major version.
func npmUpgradeScope(libraryPatchLevel string) string {
	switch libraryPatchLevel {
	case utils.PatchTypeMinor, utils.PatchTypeMajor:
		return npmScopeSameMajor
	default:
		return npmScopeSameMinor
	}
}

// npmTreeRelPathPattern matches the path of a package.json relative to npm's package
// directory: npm's own package.json, or one of a package in its node_modules.
var npmTreeRelPathPattern = regexp.MustCompile(
	`^(node_modules/(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*/)*package\.json$`)

// npmDirPattern matches the directory of npm's package as derived from a report path.
var npmDirPattern = regexp.MustCompile(`^(/[A-Za-z0-9._@+~-]+)*/node_modules/npm$`)

// npmTreeLocation splits a reported package path inside npm's own directory into that
// directory and the path of the package.json relative to it. For example
// "usr/local/lib/node_modules/npm/node_modules/minimatch/package.json" gives
// "/usr/local/lib/node_modules/npm" and "node_modules/minimatch/package.json".
func npmTreeLocation(pkgPath string) (npmDir, rel string, ok bool) {
	const marker = "/node_modules/npm/"
	p := "/" + strings.TrimPrefix(pkgPath, "/")
	i := strings.Index(p, marker)
	if i < 0 {
		return "", "", false
	}
	npmDir, rel = p[:i+len(marker)-1], p[i+len(marker):]
	if !npmDirPattern.MatchString(npmDir) || path.Clean(npmDir) != npmDir || !npmTreeRelPathPattern.MatchString(rel) {
		return "", "", false
	}
	return npmDir, rel, true
}

// npmTreeItem is a reported vulnerable package in npm's own directory.
type npmTreeItem struct {
	update  int // index in the updates
	name    string
	npmDir  string
	rel     string
	fixed   string
	isOwner bool // npm itself (rel is package.json)
}

// npmTreeItems returns the updates that have a fixed version and are located inside
// an npm package directory. Their names, versions and paths are validated.
func npmTreeItems(updates unversioned.LangUpdatePackages) []npmTreeItem {
	var items []npmTreeItem
	for i, u := range updates {
		if u.FixedVersion == "" || validateNodePackageName(u.Name) != nil || validateNodeVersion(u.FixedVersion) != nil {
			continue
		}
		npmDir, rel, ok := npmTreeLocation(u.PkgPath)
		if !ok {
			continue
		}
		items = append(items, npmTreeItem{
			update: i, name: u.Name, npmDir: npmDir, rel: rel,
			fixed: cleanAndGetFirstVersion(u.FixedVersion), isOwner: rel == "package.json",
		})
	}
	return items
}

// npmUpgradeItemsFile returns the items file read by npmUpgradeJS, one
// "<index> <name> <npm dir> <relative package.json path> <fixed version>" line per item.
func npmUpgradeItemsFile(items []npmTreeItem) []byte {
	var b strings.Builder
	for i, it := range items {
		fmt.Fprintf(&b, "%d %s %s %s %s\n", i, it.name, it.npmDir, it.rel, it.fixed)
	}
	return []byte(b.String())
}

// Item states written by the check command of npmUpgradeJS.
const (
	// npmItemFixed: no copy left, or at or above the fixed version with the same
	// compatibility key (see npmCompatKey).
	npmItemFixed = "fixed"
	// npmItemLeft: still below the fixed version (or unreadable): left to the
	// per-package replacement.
	npmItemLeft = "left"
	// npmItemSkipOwner: npm itself, still vulnerable.
	npmItemSkipOwner = "skip-owner"
	// npmItemSkipUnverified: at a version above the fixed version but with another
	// compatibility key, so not known to be fixed; the per-package replacement would
	// leave it alone and count it as patched.
	npmItemSkipUnverified = "skip-unverified"
)

// npmUpgradeJS is the helper of the upgrade script (see npmUpgradeScript). Usage:
//
//	node upgrade.js version <npm dir>
//	  prints npm's version if it is a plain x.y.z version.
//	node upgrade.js pick <npm dir> <npm view output> <scope> <min age days> [<now ms>]
//	  prints the newest x.y.z release listed by "npm view npm@<range> version engines
//	  deprecated time --json" that is newer than the installed npm and in the same
//	  major (scope same-major) or major.minor (same-minor) version, is not deprecated,
//	  was published at least <min age days> ago, and whose engines.node accepts this
//	  Node.js; or nothing.
//	node upgrade.js check <npm dir> <items> <scope> <out>
//	  writes "item <index> <version> <state>" for each item of this npm dir (states:
//	  see npmItemFixed and the following constants). The version is the one at the
//	  item's path, else the lowest of the copies of the package in npm's tree, "-" if
//	  there is none and "?" if it cannot be read. It prints "<items> <fixed>
//	  <actionable>", actionable items being those that an npm release in scope could
//	  fix: the ones left, and npm itself if its fixed version is in scope.
//	node upgrade.js list <npm dir> <out>
//	  writes "<name> <version>" for every package in npm's node_modules.
//	node upgrade.js diff <list before> <list after>
//	  prints "added <name> <versions>" for the packages that were not in the tree before
//	  and "major <name> <versions before> <versions after>" for those with a version in
//	  another compatibility class (major, or minor for 0.x) than before.
//
// When required as a module it only exports its helpers, for tests.
const npmUpgradeJS = `'use strict';
var fs = require('fs');
var p = require('path');

// parse returns [major, minor, patch, 1 for a release or 0 for a prerelease], or null.
function parse(v) {
  var m = /^v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/.exec(String(v).trim());
  return m ? [+m[1], +m[2], +m[3], m[4] ? 0 : 1] : null;
}
function cmp(a, b) {
  for (var i = 0; i < 4; i++) { if (a[i] !== b[i]) { return a[i] < b[i] ? -1 : 1; } }
  return 0;
}
// key is the compatibility class of a parsed version: its major, or 0.<minor> for 0.x.
function key(x) { return x[0] === 0 ? '0.' + x[1] : String(x[0]); }
// inScope tells whether parsed version x can be reached from cur by an upgrade in scope.
function inScope(x, cur, scope) { return x[0] === cur[0] && (scope === 'same-major' || x[1] === cur[1]); }
function readVersion(f) {
  try { return String(JSON.parse(fs.readFileSync(f, 'utf8')).version || ''); } catch (e) { return null; }
}
function rp(x) { try { return fs.realpathSync(x); } catch (e) { return p.resolve(x); } }
var plain = /^\d+\.\d+\.\d+$/;

function pick(npmDir, viewFile, scope, minAgeDays, sv, now) {
  var cur = parse(readVersion(p.join(npmDir, 'package.json')) || '');
  if (!cur) { return ''; }
  var data;
  try { data = JSON.parse(fs.readFileSync(viewFile, 'utf8')); } catch (e) { return ''; }
  if (!Array.isArray(data)) { data = [data]; }
  var best = '', bp = null, why = {};
  function skip(r) { why[r] = (why[r] || 0) + 1; }
  data.forEach(function (d) {
    if (!d || typeof d.version !== 'string' || !plain.test(d.version)) { return; }
    var x = parse(d.version);
    if (!inScope(x, cur, scope) || cmp(x, cur) <= 0) { return; }
    if (d.deprecated) { skip('deprecated'); return; }
    var t = Date.parse((d.time && d.time[d.version]) || '');
    if (isNaN(t) || now - t < minAgeDays * 86400000) { skip('published less than ' + minAgeDays + ' days ago'); return; }
    var r = d.engines && d.engines.node;
    if (typeof r === 'string' && r.trim() && !(sv && sv.satisfies(process.version, r))) { skip('not for Node.js ' + process.version); return; }
    if (!bp || cmp(x, bp) > 0) { best = d.version; bp = x; }
  });
  Object.keys(why).forEach(function (r) { console.error('INFO: skipping ' + why[r] + ' newer npm release(s): ' + r); });
  return best;
}

// tree returns {name: [versions]} for the packages in npm's node_modules.
function tree(npmDir) {
  var t = {};
  (function walk(nm, scope) {
    var es;
    try { es = fs.readdirSync(nm); } catch (e) { return; }
    es.sort().forEach(function (e) {
      if (e.charAt(0) === '.') { return; }
      var f = p.join(nm, e);
      if (!scope && e.charAt(0) === '@') { walk(f, e); return; }
      var name = scope ? scope + '/' + e : e, v = readVersion(p.join(f, 'package.json'));
      if (v !== null) { (t[name] = t[name] || []).push(v || '?'); }
      walk(p.join(f, 'node_modules'));
    });
  })(p.join(npmDir, 'node_modules'));
  return t;
}

function check(npmDir, itemsFile, scope, outFile) {
  var dir = rp(npmDir), copies = null;
  var cur = parse(readVersion(p.join(dir, 'package.json')) || '');
  var out = [], fixedCount = 0, actionable = 0;
  fs.readFileSync(itemsFile, 'utf8').split('\n').forEach(function (l) {
    var f = l.split(' ');
    if (f.length !== 5 || rp(f[2]) !== dir) { return; }
    var owner = f[3] === 'package.json', v = readVersion(p.join(dir, f[3]));
    if (v === null && !owner) {
      if (!copies) { copies = tree(dir); }
      // The lowest copy, an unparsable one counting as the lowest.
      var vs = copies[f[1]] || [];
      v = vs.length ? vs.reduce(function (a, b) {
        var xa = parse(a), xb = parse(b);
        return !xa ? a : !xb ? b : cmp(xb, xa) < 0 ? b : a;
      }) : '-';
    }
    if (v === null || v === '') { v = '?'; }
    var x = parse(v), want = parse(f[4]), state;
    if (v === '-' || (x && want && key(x) === key(want) && cmp(x, want) >= 0)) { state = 'fixed'; }
    else if (owner) { state = 'skip-owner'; }
    else if (x && want && cmp(x, want) > 0) { state = 'skip-unverified'; }
    else { state = 'left'; }
    if (state === 'fixed') { fixedCount++; }
    if (state === 'left' || (state === 'skip-owner' && cur && want && inScope(want, cur, scope))) { actionable++; }
    out.push('item ' + f[0] + ' ' + v.replace(/\s/g, '') + ' ' + state);
  });
  fs.writeFileSync(outFile, out.length ? out.join('\n') + '\n' : '');
  return out.length + ' ' + fixedCount + ' ' + actionable;
}

function readList(f) {
  var t = {};
  fs.readFileSync(f, 'utf8').split('\n').forEach(function (l) {
    var i = l.indexOf(' ');
    if (i > 0) { (t[l.slice(0, i)] = t[l.slice(0, i)] || []).push(l.slice(i + 1)); }
  });
  return t;
}

function uniq(vs) { return vs.filter(function (v, i) { return vs.indexOf(v) === i; }); }
function diff(before, after) {
  var out = [];
  Object.keys(after).sort().forEach(function (n) {
    var a = uniq(after[n]), b = before[n] && uniq(before[n]);
    if (!b) { out.push('added ' + n + ' ' + a.join(',')); return; }
    var keys = {};
    b.forEach(function (v) { var x = parse(v); keys[x ? key(x) : v] = true; });
    if (a.some(function (v) { var x = parse(v); return !keys[x ? key(x) : v]; })) {
      out.push('major ' + n + ' ' + b.join(',') + ' ' + a.join(','));
    }
  });
  return out;
}

if (require.main === module) {
  var a = process.argv;
  if (a[2] === 'version') {
    var v = readVersion(p.join(a[3], 'package.json'));
    if (v && plain.test(v)) { console.log(v); }
  } else if (a[2] === 'pick') {
    var sv = null;
    try { sv = require(p.join(a[3], 'node_modules', 'semver')); } catch (e) {
      console.error('WARN: semver module not found in ' + a[3] + ', cannot check engines.node');
    }
    var best = pick(a[3], a[4], a[5], Number(a[6]), sv, a[7] ? Number(a[7]) : Date.now());
    if (best) { console.log(best); }
  } else if (a[2] === 'check') {
    console.log(check(a[3], a[4], a[5], a[6]));
  } else if (a[2] === 'list') {
    var t = tree(a[3]), lines = [];
    Object.keys(t).sort().forEach(function (n) { t[n].forEach(function (v) { lines.push(n + ' ' + v); }); });
    fs.writeFileSync(a[4], lines.length ? lines.join('\n') + '\n' : '');
  } else if (a[2] === 'diff') {
    diff(readList(a[3]), readList(a[4])).forEach(function (l) { console.log(l); });
  } else {
    console.error('usage: upgrade.js version|pick|check|list|diff ...');
    process.exit(2);
  }
} else {
  module.exports = { parse: parse, pick: pick, check: check, diff: diff };
}
`

// npmUpgradeScript returns the script of the npm self-upgrade step, run as
// "sh upgrade.sh <scope>" with its scripts, its output and a work directory at the given
// paths (the mounts in a build, temporary directories in tests). It upgrades the npm
// found with "npm root -g" when that is where reported packages are, and writes the
// result to <out>/result: a "upgraded <old> <new>" or "unchanged <old|-> <reason>" line,
// then the "item" lines of the check command of npmUpgradeJS, then, after an upgrade,
// its "added" and "major" lines.
//
// npm is installed with npm itself (npm install -g npm@<version>), which respects the
// image's registry and proxy settings, after a backup of npm's directory, of its bin
// links and of the man page links into it. The new npm must report its version and
// install an empty project, and must fix more reported packages than the installed one;
// otherwise the backup is restored, npm's leftover staging directories and any bin or
// man link it added are removed. Failures to list releases, to install or to verify
// leave npm as it was with a warning. A failed check or restore fails the step, which
// the caller then discards (see upgradeNpmThenGlobalPackages).
func npmUpgradeScript(scripts, out, work string) string {
	return `# Generated by Copa (pkg/langmgr/nodejs_npm_upgrade.go).
M=` + shellQuote(scripts) + `
O=` + shellQuote(out) + `
W=` + shellQuote(work) + `
SCOPE=${1:-` + npmScopeSameMinor + `}
MIN_AGE_DAYS=` + strconv.Itoa(npmUpgradeMinAgeDays) + `
export NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false NPM_CONFIG_AUDIT=false NPM_CONFIG_CACHE="$W/cache" \
  NPM_CONFIG_FETCH_RETRIES=1 NPM_CONFIG_FETCH_TIMEOUT=30000 NODE_DISABLE_COMPILE_CACHE=1

if ! command -v npm >/dev/null 2>&1 || ! command -v node >/dev/null 2>&1; then
  echo "unchanged - npm is not installed" > "$O/` + npmUpgradeResultFile + `"
  exit 0
fi
NPM_DIR="$(npm root -g 2>/dev/null)/npm"
if [ -L "$NPM_DIR" ] || [ ! -f "$NPM_DIR/package.json" ]; then
  echo "unchanged - npm's package directory was not found at $NPM_DIR" > "$O/` + npmUpgradeResultFile + `"
  exit 0
fi
OLD=$(node "$M/upgrade.js" version "$NPM_DIR")
if [ -z "$OLD" ]; then
  echo "unchanged - cannot read the version of npm" > "$O/` + npmUpgradeResultFile + `"
  exit 0
fi

# check writes the state of the items to $1 and prints "<items> <fixed> <actionable>".
check() {
  node "$M/upgrade.js" check "$NPM_DIR" "$M/items" "$SCOPE" "$1"
}
fail_check() {
  echo "ERROR: cannot read the versions of the reported packages in $NPM_DIR" >&2
  exit 1
}
# npm_man_links lists the links under $MAN that point into npm's directory.
npm_man_links() {
  [ -d "$MAN" ] || return 0
  find "$MAN" -type l 2>/dev/null | while IFS= read -r l; do
    case "$(readlink "$l")" in *node_modules/npm/*) echo "$l" ;; esac
  done
}

backup() {
  rm -rf "$W/backup" && mkdir -p "$W/backup/bin" "$W/backup/man" && cp -a "$NPM_DIR" "$W/backup/npm" || return 1
  for b in npm npx; do
    if [ -e "$BIN/$b" ] || [ -L "$BIN/$b" ]; then cp -a "$BIN/$b" "$W/backup/bin/$b" || return 1; fi
  done
  npm_man_links > "$W/backup/man.list" || return 1
  while IFS= read -r l; do
    mkdir -p "$W/backup/man/${l%/*}" && cp -a "$l" "$W/backup/man/$l" || return 1
  done < "$W/backup/man.list"
}

restore_failed() {
  echo "ERROR: failed to restore $1" >&2
  exit 1
}
rollback() {
  echo "INFO: restoring npm $OLD"
  { rm -rf "$NPM_DIR" && cp -a "$W/backup/npm" "$NPM_DIR"; } || restore_failed "$NPM_DIR"
  rm -rf "${NPM_DIR%/*}"/.npm-* || restore_failed "${NPM_DIR%/*}"
  for b in npm npx; do
    rm -f "$BIN/$b" || restore_failed "$BIN/$b"
    if [ -e "$W/backup/bin/$b" ] || [ -L "$W/backup/bin/$b" ]; then
      cp -a "$W/backup/bin/$b" "$BIN/$b" || restore_failed "$BIN/$b"
    fi
  done
  npm_man_links > "$W/man.after" || restore_failed "$MAN"
  while IFS= read -r l; do rm -f "$l" || restore_failed "$l"; done < "$W/man.after"
  while IFS= read -r l; do cp -a "$W/backup/man/$l" "$l" || restore_failed "$l"; done < "$W/backup/man.list"
  if [ "$(npm --version 2>/dev/null)" != "$OLD" ]; then restore_failed "npm $OLD (it does not run)"; fi
}

verify() {
  V=$(npm --version 2>/dev/null)
  if [ "$V" != "$NEW" ]; then echo "WARN: npm --version reports '$V' instead of $NEW"; return 1; fi
  rm -rf "$W/verify" && mkdir -p "$W/verify" &&
    echo '{"name":"copa-npm-verify","version":"1.0.0","private":true}' > "$W/verify/package.json" || return 1
  if ! (cd "$W/verify" && npm install --offline --ignore-scripts && npm ls) > "$W/verify.log" 2>&1; then
    echo "WARN: npm $NEW cannot install an empty project:"; tail -n 20 "$W/verify.log"; return 1
  fi
}

# upgrade sets REASON and returns non-zero when npm is left at its installed version.
upgrade() {
  BEFORE=$(check "$W/items.before") || fail_check
  set -- $BEFORE
  if [ "$1" -eq 0 ]; then REASON="no reported package is in $NPM_DIR"; return 1; fi
  FIXED_BEFORE=$2
  if [ "$3" -eq 0 ]; then REASON="no npm release in scope ($SCOPE) can fix the reported packages"; return 1; fi
  MAJOR=${OLD%%.*}
  MINOR=${OLD#*.}
  MINOR=${MINOR%%.*}
  if [ "$SCOPE" = ` + npmScopeSameMajor + ` ]; then
    RANGE=">$OLD <$((MAJOR + 1)).0.0"
  else
    RANGE=">$OLD <$MAJOR.$((MINOR + 1)).0"
  fi
  npm view "npm@$RANGE" version engines deprecated time --json > "$W/view.json" 2> "$W/view.err"
  VIEW=$?
  NEW=$(node "$M/upgrade.js" pick "$NPM_DIR" "$W/view.json" "$SCOPE" "$MIN_AGE_DAYS")
  if [ -z "$NEW" ]; then
    if [ "$VIEW" -ne 0 ] && ! grep -q E404 "$W/view.json" "$W/view.err"; then
      echo "WARN: cannot list npm releases:"; tail -n 5 "$W/view.err"
      REASON="cannot list npm releases"
    else
      REASON="no suitable newer npm release ($SCOPE, $MIN_AGE_DAYS+ days old, for Node.js $(node --version))"
    fi
    return 1
  fi
  PREFIX=$(npm prefix -g 2>/dev/null)
  BIN="$PREFIX/bin"
  MAN="$PREFIX/share/man"
  if ! backup; then REASON="cannot back up npm"; return 1; fi
  node "$M/upgrade.js" list "$NPM_DIR" "$W/tree.before" || { REASON="cannot list npm's packages"; return 1; }
  echo "INFO: upgrading npm $OLD to $NEW"
  if ! npm install -g --ignore-scripts "npm@$NEW" > "$W/install.log" 2>&1; then
    echo "WARN: npm install -g npm@$NEW failed:"; tail -n 20 "$W/install.log"
    rollback; REASON="npm $NEW could not be installed"; return 1
  fi
  if ! verify; then rollback; REASON="npm $NEW does not work"; return 1; fi
  AFTER=$(check "$W/items.after") || fail_check
  set -- $AFTER
  if [ "$2" -le "$FIXED_BEFORE" ]; then
    rollback; REASON="npm $NEW fixes none of the reported packages"; return 1
  fi
  node "$M/upgrade.js" list "$NPM_DIR" "$W/tree.after" &&
    node "$M/upgrade.js" diff "$W/tree.before" "$W/tree.after" > "$W/changes" || fail_check
  echo "INFO: upgraded npm $OLD to $NEW"
}

: > "$W/changes" || exit 1
if upgrade; then
  HEAD="upgraded $OLD $NEW"
else
  echo "INFO: keeping npm $OLD: $REASON"
  HEAD="unchanged $OLD $REASON"
  : > "$W/changes"
fi
check "$W/items" > /dev/null || fail_check
{ echo "$HEAD" && cat "$W/items" "$W/changes"; } > "$O/` + npmUpgradeResultFile + `" || exit 1
`
}

// npmUpgradeArgs is the command line of the npm self-upgrade step.
func npmUpgradeArgs(scope string) []string {
	return []string{"sh", npmUpgradeScriptsMount + "/upgrade.sh", scope}
}

// npmSelfUpgradeStep adds the npm self-upgrade step for items on top of st. It returns
// the new root and the state of the mount holding the result.
func npmSelfUpgradeStep(st *llb.State, items []npmTreeItem, scope string) (llb.State, llb.State) {
	scripts := llb.Scratch().File(
		llb.Mkfile("/upgrade.sh", 0o644, []byte(npmUpgradeScript(npmUpgradeScriptsMount, npmUpgradeOutMount, npmUpgradeWorkMount))).
			Mkfile("/items", 0o644, npmUpgradeItemsFile(items)).
			Mkfile("/upgrade.js", 0o644, []byte(npmUpgradeJS)),
	)
	es := st.Run(
		llb.Args(npmUpgradeArgs(scope)),
		llb.AddMount(npmUpgradeScriptsMount, scripts, llb.Readonly),
		llb.AddMount(npmUpgradeWorkMount, llb.Scratch(), llb.Tmpfs()),
		llb.WithProxy(utils.GetProxy()),
	)
	out := es.AddMount(npmUpgradeOutMount, llb.Scratch())
	return es.Root(), out
}

// npmItemState is the state of a reported package after the upgrade step.
type npmItemState struct {
	version string // "-": no copy left, "?": unreadable
	state   string // npmItemFixed, ...
}

// npmUpgradeResult is what the upgrade step wrote to npmUpgradeResultFile.
type npmUpgradeResult struct {
	upgraded bool
	from, to string
	reason   string
	items    map[int]npmItemState // by item index
	added    []string             // "<name> <versions>"
	majors   []string             // "<name> <versions before> -> <versions after>"
}

// parseNpmUpgradeResult parses the result file of the upgrade step.
func parseNpmUpgradeResult(data []byte) (*npmUpgradeResult, error) {
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	head := strings.Fields(lines[0])
	if len(head) < 2 {
		return nil, fmt.Errorf("unexpected npm upgrade result %q", lines[0])
	}
	res := &npmUpgradeResult{from: head[1], items: map[int]npmItemState{}}
	switch head[0] {
	case "upgraded":
		if len(head) != 3 {
			return nil, fmt.Errorf("unexpected npm upgrade result %q", lines[0])
		}
		res.upgraded, res.to = true, head[2]
	case "unchanged":
		res.reason = strings.Join(head[2:], " ")
	default:
		return nil, fmt.Errorf("unexpected npm upgrade result %q", lines[0])
	}
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		switch {
		case len(f) == 4 && f[0] == "item":
			i, err := strconv.Atoi(f[1])
			if err != nil {
				return nil, fmt.Errorf("unexpected npm upgrade result line %q", l)
			}
			switch f[3] {
			case npmItemFixed, npmItemLeft, npmItemSkipOwner, npmItemSkipUnverified:
			default:
				return nil, fmt.Errorf("unexpected npm upgrade result line %q", l)
			}
			res.items[i] = npmItemState{version: f[2], state: f[3]}
		case len(f) == 3 && f[0] == "added":
			res.added = append(res.added, f[1]+" "+f[2])
		case len(f) == 4 && f[0] == "major":
			res.majors = append(res.majors, f[1]+" "+f[2]+" -> "+f[3])
		default:
			return nil, fmt.Errorf("unexpected npm upgrade result line %q", l)
		}
	}
	return res, nil
}

// npmUpgradeOutcome is what applying the upgrade result to the updates gives.
type npmUpgradeOutcome struct {
	// remaining are the updates left for the per-package replacement.
	remaining unversioned.LangUpdatePackages
	// fixed and left are the names of the packages fixed by the upgrade and of those
	// left to the per-package replacement.
	fixed, left []string
	// skipped are the packages to report as not patched, with the reason.
	skipped map[string]string
}

// applyNpmUpgradeResult applies the upgrade result to the updates: fixed packages are
// removed (they count as patched); packages that cannot be verified as fixed and npm
// itself when still vulnerable are removed and reported as skipped; the others are
// kept with their installed version set to the version found after the upgrade, so
// that the replacement selects the copies that are there now. Updates the step did not
// report on are kept unchanged.
func applyNpmUpgradeResult(updates unversioned.LangUpdatePackages, items []npmTreeItem, res *npmUpgradeResult) npmUpgradeOutcome {
	var o npmUpgradeOutcome
	o.skipped = map[string]string{}
	byUpdate := make(map[int]int, len(items))
	for i, it := range items {
		byUpdate[it.update] = i
	}
	for i, u := range updates {
		idx, ok := byUpdate[i]
		if !ok {
			o.remaining = append(o.remaining, u)
			continue
		}
		st, ok := res.items[idx]
		if !ok {
			o.remaining = append(o.remaining, u)
			continue
		}
		switch st.state {
		case npmItemFixed:
			o.fixed = append(o.fixed, u.Name)
		case npmItemSkipOwner:
			o.skipped[u.Name] = fmt.Sprintf("npm %s is installed and its fix (%s) needs an npm release that Copa did not install", st.version, items[idx].fixed)
		case npmItemSkipUnverified:
			o.skipped[u.Name] = fmt.Sprintf("now at %s, another major version than the fixed version %s, so it is not known to be fixed", st.version, items[idx].fixed)
		default:
			o.left = append(o.left, u.Name)
			if isValidNodeVersion(st.version) {
				u.InstalledVersion = st.version
			}
			o.remaining = append(o.remaining, u)
		}
	}
	o.fixed = utils.DeduplicateStringSlice(o.fixed)
	o.left = utils.DeduplicateStringSlice(o.left)
	return o
}

// upgradeNpmSelf upgrades npm itself when reported packages are in npm's own
// directory. It returns the new state with the updates left to apply, and records in
// report the packages to report as not patched.
func (nm *nodejsManager) upgradeNpmSelf(
	ctx context.Context,
	currentState *llb.State,
	metadata *unversioned.Metadata,
	updates unversioned.LangUpdatePackages,
	report *npmReport,
) (*llb.State, unversioned.LangUpdatePackages, error) {
	items := npmTreeItems(updates)
	if len(items) == 0 || metadata == nil || nm.config == nil || nm.config.Client == nil {
		return currentState, updates, nil
	}
	scope := npmUpgradeScope(metadata.LibraryPatchLevel)
	log.Infof("%d reported vulnerable package location(s) are in npm's own directory; trying to upgrade npm (%s) first (%s=1)",
		len(items), scope, npmSelfUpgradeEnv)
	root, out := npmSelfUpgradeStep(currentState, items, scope)
	data, rerr := buildkit.TryExtractFileFromState(ctx, nm.config.Client, &out, "/"+npmUpgradeResultFile)
	if rerr != nil {
		return nil, nil, fmt.Errorf("npm self-upgrade step failed: %w", rerr.Err)
	}
	res, err := parseNpmUpgradeResult(data)
	if err != nil {
		return nil, nil, err
	}
	if res.upgraded {
		log.Infof("Upgraded npm %s to %s", res.from, res.to)
		for _, a := range res.added {
			log.Warnf("npm %s adds bundled package %s that the image did not have; the scan report does not cover it", res.to, a)
		}
		for _, m := range res.majors {
			log.Warnf("npm %s changes the major version of bundled package %s; the scan report does not cover the new version", res.to, m)
		}
	} else {
		log.Infof("Keeping npm %s: %s", res.from, res.reason)
	}
	o := applyNpmUpgradeResult(updates, items, res)
	if len(o.fixed) > 0 {
		log.Infof("Fixed by upgrading npm: %v", o.fixed)
	}
	if len(o.left) > 0 {
		log.Infof("Still vulnerable in npm's directory, trying per-package replacement: %v", o.left)
	}
	names := make([]string, 0, len(o.skipped))
	for name, why := range o.skipped {
		log.Warnf("Not patching %s in npm's directory: %s", name, why)
		names = append(names, name)
	}
	report.selfUpgradeSkipped = append(report.selfUpgradeSkipped, names...)
	return &root, o.remaining, nil
}

// upgradeNpmThenGlobalPackages patches global packages with upgradeGlobalPackages,
// after trying to upgrade npm itself first if that is enabled (see npmSelfUpgradeEnv).
// If the npm upgrade fails, its step is discarded and the global packages, npm's tree
// included, are patched as if it had not been tried.
func (nm *nodejsManager) upgradeNpmThenGlobalPackages(
	ctx context.Context,
	currentState *llb.State,
	metadata *unversioned.Metadata,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
	report *npmReport,
) (*llb.State, error) {
	state, remaining := currentState, updates
	if npmSelfUpgradeEnabled() {
		before := report.snapshot()
		st, rem, err := nm.upgradeNpmSelf(ctx, currentState, metadata, updates, report)
		if err != nil {
			report.restore(&before)
			log.Warnf("npm self-upgrade failed, patching npm's bundled packages individually instead: %v", err)
		} else {
			state, remaining = st, rem
		}
	}
	if len(remaining) == 0 {
		return state, nil
	}
	return nm.upgradeGlobalPackages(ctx, state, metadata, remaining, ignoreErrors, report)
}
