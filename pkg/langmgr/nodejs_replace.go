package langmgr

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// npm library patching replaces packages in place: the fixed version's tarball is
// extracted over the installed package directory, without npm install (which would
// re-resolve the whole tree). To avoid leaving a broken tree behind, each tree (an
// application, a global package, or npm itself) is patched in one step that stages
// all new versions first, checks them together, and only then moves in the ones that
// keep the tree working. See npmReplaceSh and npmCheckJS.

const (
	// npmReportMount is a scratch mount, kept out of the image's root filesystem, on
	// which the replace steps record their results.
	npmReportMount = "/copa-npm-report"
	// npmSkippedFile (on npmReportMount) lists, one name per line, the packages that
	// were left at their installed version because replacing them would break the
	// dependency tree. Every replace step creates it, so a missing file is an error.
	npmSkippedFile = "skipped"
	// npmFailedFile (on npmReportMount) records the packages whose tarball could not be
	// downloaded, one "WARN: failed to download <name>@<version>, skipping" line per
	// package, read back by readDownloadFailures. Every replace step creates it.
	npmFailedFile = "failed"
	// npmScriptsMount is a read-only mount holding the replace step's script, its list
	// of packages and the check program. They are files rather than arguments so that
	// the size of a step does not depend on the number of packages (ARG_MAX).
	npmScriptsMount = "/copa-npm-scripts"
)

// npmReport collects what the replace steps record on npmReportMount. Each replace
// step mounts the output of the previous one, so state holds the combined record of
// every step run through it.
type npmReport struct {
	state llb.State
	used  bool
}

func newNpmReport() *npmReport {
	return &npmReport{state: llb.Scratch()}
}

// run adds a replace step for items in the tree rooted at root (npm's own tree when
// root is empty) on top of st, and returns the new root.
//
// The report records the steps run through it whether or not the caller keeps the
// returned state, so a caller that discards the state must also restore the report
// (see snapshot and restore).
func (r *npmReport) run(st *llb.State, root string, items []npmReplaceItem) llb.State {
	scripts := llb.Scratch().File(
		llb.Mkfile("/replace.sh", 0o644, []byte(npmReplaceSh)).
			Mkfile("/items", 0o644, npmItemsFile(items)).
			Mkfile("/check.js", 0o644, []byte(npmCheckJS)),
	)
	es := st.Run(
		llb.Args(npmReplaceArgs(root)),
		llb.AddMount(npmScriptsMount, scripts, llb.Readonly),
		llb.WithProxy(utils.GetProxy()),
	)
	r.state = es.AddMount(npmReportMount, r.state)
	r.used = true
	return es.Root()
}

// snapshot returns a copy of the report to restore if the steps added after it are
// discarded.
func (r *npmReport) snapshot() npmReport {
	return *r
}

// restore resets the report to a snapshot.
func (r *npmReport) restore(s *npmReport) {
	*r = *s
}

// npmReplaceArgs returns the command line of a replace step.
func npmReplaceArgs(root string) []string {
	args := []string{"sh", npmScriptsMount + "/replace.sh"}
	if root != "" {
		args = append(args, root)
	}
	return args
}

// npmReplaceItem is one package version to install by a replace step.
type npmReplaceItem struct {
	Name    string
	Version string
	// TopLevelOnly replaces only <root>/node_modules/<name> (a direct dependency of
	// the root package) instead of every copy in the tree.
	TopLevelOnly bool
	// Select restricts the installed copies this version replaces, by compatibility
	// key of the installed version (see npmCompatKey): "*" for all copies,
	// "only:<k1>,<k2>".
	Select string
}

// npmCompatKey returns the compatibility class of a version: its major version, or
// "0.<minor>" for 0.x versions. It must match npmCopyInfoJS.
func npmCompatKey(v string) (string, bool) {
	sv, err := semver.NewVersion(cleanAndGetFirstVersion(v))
	if err != nil {
		return "", false
	}
	if sv.Major() == 0 {
		return "0." + strconv.FormatUint(sv.Minor(), 10), true
	}
	return strconv.FormatUint(sv.Major(), 10), true
}

// npmReplaceItems returns the replace items for updates in the tree at where (used
// for logging only). Packages in directDeps are replaced only at the top level.
//
// The report gives one update per package location, with its installed version, and
// copies at different locations can have different fixed versions. Each fixed
// version replaces only the copies whose installed version has the same
// compatibility key as an installed version it was chosen for, so copies that the
// report did not list are left alone. Only when no installed version is known does
// the highest fixed version apply to every copy. In all cases the replace step
// leaves alone a copy that is already at the fixed version or later.
func npmReplaceItems(updates unversioned.LangUpdatePackages, directDeps map[string]bool, where string) []npmReplaceItem {
	type group struct {
		highest string
		byKey   map[string]string // compat key of the installed version -> highest fixed version
		unknown bool              // some update has no usable installed version
	}
	var names []string
	groups := make(map[string]*group)
	for _, u := range updates {
		if u.FixedVersion == "" {
			continue
		}
		g, ok := groups[u.Name]
		if !ok {
			g = &group{highest: u.FixedVersion, byKey: map[string]string{}}
			groups[u.Name] = g
			names = append(names, u.Name)
		} else if isLessThanNodeVersion(g.highest, u.FixedVersion) {
			g.highest = u.FixedVersion
		}
		key, ok := npmCompatKey(u.InstalledVersion)
		if !ok {
			g.unknown = true
			continue
		}
		if cur, exists := g.byKey[key]; !exists || isLessThanNodeVersion(cur, u.FixedVersion) {
			g.byKey[key] = u.FixedVersion
		}
	}

	var items []npmReplaceItem
	for _, name := range names {
		g := groups[name]
		kind := "transitive"
		if directDeps[name] {
			kind = "direct"
		}
		if len(g.byKey) == 0 {
			log.Infof("Replacing %s dependency %s@%s in %s", kind, name, g.highest, where)
			items = append(items, npmReplaceItem{Name: name, Version: g.highest, TopLevelOnly: directDeps[name], Select: "*"})
			continue
		}
		if g.unknown {
			log.Warnf("Some reported copies of %s have no installed version; only copies matching a reported installed version are replaced", name)
		}
		keysByVersion := map[string][]string{}
		var versions []string
		for k, v := range g.byKey {
			if _, seen := keysByVersion[v]; !seen {
				versions = append(versions, v)
			}
			keysByVersion[v] = append(keysByVersion[v], k)
		}
		sort.Slice(versions, func(i, j int) bool { return isLessThanNodeVersion(versions[i], versions[j]) })
		for _, v := range versions {
			keys := keysByVersion[v]
			sort.Strings(keys)
			log.Infof("Replacing %s dependency %s@%s in %s (installed versions %v)", kind, name, v, where, keys)
			items = append(items, npmReplaceItem{Name: name, Version: v, TopLevelOnly: directDeps[name], Select: "only:" + strings.Join(keys, ",")})
		}
	}
	return items
}

// npmItemsFile returns the items file read by npmReplaceSh, one
// "<name> <version> <top-level-only 0|1> <tarball URL> <tarball file> <select>"
// line per item. Names and versions are validated upstream (validNodeUpdates); an item
// with whitespace in a field would shift the fields, so it is left out with an error
// logged rather than written.
func npmItemsFile(items []npmReplaceItem) []byte {
	var b strings.Builder
	for _, it := range items {
		if it.Name == "" || it.Version == "" || strings.ContainsAny(it.Name+it.Version+it.Select, " \t\r\n") {
			log.Errorf("Not replacing npm package %q at version %q: invalid name or version", it.Name, it.Version)
			continue
		}
		top := "0"
		if it.TopLevelOnly {
			top = "1"
		}
		sel := it.Select
		if sel == "" {
			sel = "*"
		}
		fmt.Fprintf(&b, "%s %s %s %s /tmp/%s-%s.tgz %s\n",
			it.Name, it.Version, top, getNpmTarballURL(it.Name, it.Version),
			getPackageBaseName(it.Name), it.Version, sel)
	}
	return []byte(b.String())
}

// npmCopyInfoJS is run by npmReplaceSh as node -e "<this>" <package.json> <version>.
// It prints "<key> <lower>": the compatibility key of the installed version (as
// npmCompatKey: major, or 0.<minor>; a leading "v" is ignored), and 1 if the
// installed version is lower than <version>, else 0. Versions are compared on
// major.minor.patch, a prerelease being lower than its release; an installed version
// that cannot be parsed counts as lower. It exits non-zero if package.json cannot be
// read or parsed. It must not contain double quotes, dollar signs or backticks,
// because it is embedded in a double-quoted shell word.
const npmCopyInfoJS = `var fs=require('fs'),a=process.argv,v;` +
	`try{v=String(JSON.parse(fs.readFileSync(a[1],'utf8')).version||'').replace(/^v/,'')}catch(e){process.exit(2)}` +
	`function n(x){var m=/^(\d+)\.(\d+)\.(\d+)(-)?/.exec(x);return m?[+m[1],+m[2],+m[3],m[4]?0:1]:null}` +
	`var k=v.split('.'),o=n(v),t=n(String(a[2]).replace(/^v/,'')),lower=1;` +
	`if(o&&t){lower=0;for(var i=0;i<4;i++){if(o[i]!==t[i]){lower=o[i]<t[i]?1:0;break}}}` +
	`console.log((k[0]==='0'?'0.'+k[1]:k[0])+' '+lower)`

// npmReplaceSh is the script of a replace step, run as "sh replace.sh [root]" with
// npmScriptsMount and npmReportMount mounted. root is an application or global
// package directory; without it, the step patches npm's own tree.
//
// For each item it downloads the tarball and extracts it next to each installed copy
// ("<dir>.copa-new"), leaving the installed copies untouched. It then runs the check
// program on all staged copies at once and applies its decisions: accepted copies
// are moved into place (keeping the installed copy's nested node_modules unless the
// tarball has its own), rejected ones are removed and the package is recorded as
// skipped. Symlinked package directories are left alone. A failed download is
// skipped with a warning, as before; an extraction failure, a failure of the check
// program or of a move fails the step.
//
// Inside it, the download and extraction snippets shared with the rest of this
// package (written for sh -c '...') run through sh -c with their inputs as arguments.
var npmReplaceSh = `# Generated by Copa (pkg/langmgr/nodejs_replace.go).
M=` + npmScriptsMount + `
R=` + npmReportMount + `
if [ -n "${1:-}" ]; then
  ROOT=$1
  # As before: in application and global package trees, transitive copies are found
  # below node_modules/*/ only.
  FIND_BASE=node_modules
  NPM_GLOBAL_ROOT=$(npm root -g 2>/dev/null)
else
  NPM_GLOBAL_ROOT=$(npm root -g)
  ROOT="$NPM_GLOBAL_ROOT/npm"
  FIND_BASE="$ROOT/node_modules"
fi
# The image's own npm ships the semver module that check.js needs to compare versions.
SEMVER="${NPM_GLOBAL_ROOT:-/nonexistent}/npm/node_modules/semver"
cd -- "$ROOT" || exit 1
{ : >> "$R/` + npmSkippedFile + `" && : >> "$R/` + npmFailedFile + `" && : > "$R/plan"; } || exit 1

# copy_info prints the compatibility key of an installed copy and whether its
# version is lower than the given one (1 or 0); it fails if package.json is unreadable.
copy_info() {
  node -e "` + npmCopyInfoJS + `" "$1" "$2"
}

while read -r N V TOP URL TB SEL <&3; do
  FOUND=0
  if sh -c '` + nodeDownloadScript(`$1`, `$2`) + `' copa-download "$URL" "$TB"; then
    if [ "$TOP" = 1 ]; then
      DIRS="node_modules/$N"
    else
      DIRS=$(find "$FIND_BASE" -type d -path "*/node_modules/$N" 2>/dev/null)
    fi
    for dir in $DIRS; do
      case "$dir" in *.copa-new/*) continue ;; esac
      if [ -L "$dir" ]; then
        echo "WARN: $dir is a symlink, leaving it untouched"
        continue
      fi
      [ -f "$dir/package.json" ] || continue
      INFO=$(copy_info "$dir/package.json" "$V") || { echo "WARN: cannot read the version of $dir, leaving it untouched"; continue; }
      K=${INFO% *}
      case "$SEL" in
        only:*) case ",${SEL#only:}," in *",$K,"*) ;; *) continue ;; esac ;;
      esac
      if [ "${INFO#* }" != 1 ]; then echo "INFO: $dir is already at $V or later, leaving it untouched"; continue; fi
      echo "INFO: Staging $N $V for $dir"
      STAGE="$dir.copa-new"
      { rm -rf "$STAGE" && mkdir -p "$STAGE" &&
        sh -c '` + safeTarExtractScript(`"$1"`, `"$2"`) + `' copa-extract "$TB" "$STAGE" &&
        [ -f "$STAGE/package.json" ]; } ||
        { rm -rf "$STAGE"; echo "ERROR: extraction failed for $N in $dir" >&2; exit 1; }
      echo "$N $dir" >> "$R/plan"
      FOUND=$((FOUND+1))
    done
    rm -f "$TB"
    if [ "$FOUND" -eq 0 ]; then echo "WARN: no installed copy of $N to replace with $V, skipping"; fi
  else
    echo "WARN: failed to download $N@$V, skipping" | tee -a "$R/` + npmFailedFile + `"
  fi
done 3< "$M/items"

if [ -s "$R/plan" ]; then
  node "$M/check.js" "$R/plan" "$R/decisions" "$SEMVER" || { echo "ERROR: npm dependency check failed" >&2; exit 1; }
  while read -r ACT N dir <&4; do
    STAGE="$dir.copa-new"
    case "$ACT" in
      accept)
        if [ ! -f "$STAGE/package.json" ]; then echo "ERROR: staged copy of $N for $dir is missing" >&2; exit 1; fi
        if [ -d "$dir/node_modules" ] && [ ! -e "$STAGE/node_modules" ]; then
          mv "$dir/node_modules" "$STAGE/node_modules" || { echo "ERROR: failed to move $dir/node_modules" >&2; exit 1; }
        fi
        { rm -rf "$dir" && mv "$STAGE" "$dir"; } || { echo "ERROR: failed to move $N into $dir" >&2; exit 1; }
        echo "INFO: Replaced $N in $dir" ;;
      reject)
        rm -rf "$STAGE"
        echo "$N" >> "$R/` + npmSkippedFile + `" ;;
      dropped)
        # Inside the nested node_modules of a parent replaced by a version that bundles
        # its own: removed along with it.
        rm -rf "$STAGE"
        echo "INFO: $dir is removed with its parent package" ;;
      *) echo "ERROR: unexpected dependency check result: $ACT" >&2; exit 1 ;;
    esac
  done 4< "$R/decisions"
fi
rm -f "$R/plan" "$R/decisions"
`

// npmCheckJS is the Node.js program that decides which staged copies can be moved
// into place. Usage: node check.js <plan> <decisions> [semver module path]. It runs
// in the root directory of the tree being patched. The plan has one "<name> <dir>"
// line per staged copy (the new version extracted in "<dir>.copa-new"); it writes one
// "accept|reject|dropped <name> <dir>" line per plan line. The semver module (normally
// npm's own copy in the image, passed by npmReplaceSh) falls back to npm next to node;
// without it the check fails closed: every staged copy is rejected.
// Any error (unreadable plan, staged package.json that is not JSON) exits non-zero.
// When required as a module it only exports its helpers, for tests.
const npmCheckJS = `'use strict';
var fs = require('fs');
var p = require('path');

// compatKey returns the compatibility class of a version: its major version, or
// 0.<minor> for 0.x versions, or null if it cannot be parsed.
function compatKey(sv, v) {
  var x = sv.parse(v);
  if (!x) { return null; }
  return x.major === 0 ? '0.' + x.minor : String(x.major);
}

// breaksDependent tells whether replacing the installed version of a package
// (oldV) with newV breaks a package that depends on it with range r. Only plain
// semver ranges are checked. It does if the installed version satisfied the range,
// the new one does not, and the new one is in a different compatibility class
// (another major, or another minor for 0.x). Patch and minor updates within the
// class are accepted even when an exact or tilde range excludes them: they are the
// fixes that in-place patching has always applied.
function breaksDependent(sv, r, oldV, newV) {
  if (!sv || !sv.validRange(r) || !oldV) { return false; }
  var opts = { includePrerelease: true };
  if (!sv.satisfies(oldV, r, opts) || sv.satisfies(newV || '', r, opts)) { return false; }
  var ko = compatKey(sv, oldV), kn = compatKey(sv, newV || '');
  return ko === null || kn === null || ko !== kn;
}

// loadSemver loads semver from override, else from npm next to node (unless
// noFallback, for tests), else returns null.
function loadSemver(override, noFallback) {
  var bin = p.dirname(process.execPath);
  var candidates = noFallback ? [override] : [override,
    p.join(bin, '..', 'lib', 'node_modules', 'npm', 'node_modules', 'semver'),
    p.join(bin, 'node_modules', 'npm', 'node_modules', 'semver')];
  for (var i = 0; i < candidates.length; i++) {
    if (!candidates[i]) { continue; }
    try { return require(candidates[i]); } catch (e) { /* try the next one */ }
  }
  return null;
}

function main(planFile, decisionsFile, semverPath, noFallback) {
  var sv = loadSemver(semverPath, noFallback);
  if (!sv) { console.log('WARN: semver module not found (tried ' + (semverPath || 'no path given') + ' and npm next to node), keeping every installed version'); }
  var opts = { includePrerelease: true };

  function rp(x) { try { return fs.realpathSync(x); } catch (e) { return x; } }
  var cache = {};
  function readPkg(d) {
    if (!(d in cache)) {
      try { cache[d] = JSON.parse(fs.readFileSync(p.join(d, 'package.json'), 'utf8')); } catch (e) { cache[d] = null; }
    }
    return cache[d];
  }
  // deps returns the dependencies that must be installed: dependencies minus optional ones.
  function deps(k) {
    var r = {}, d = (k && k.dependencies) || {}, o = (k && k.optionalDependencies) || {};
    Object.keys(d).forEach(function (n) {
      if (!Object.prototype.hasOwnProperty.call(o, n) && typeof d[n] === 'string') { r[n] = d[n]; }
    });
    return r;
  }

  // Staged copies, by real path of the installed directory.
  var C = {}, order = [];
  fs.readFileSync(planFile, 'utf8').split('\n').forEach(function (l) {
    if (!l) { return; }
    var i = l.indexOf(' '), name = l.slice(0, i), dir = l.slice(i + 1);
    var rd = rp(p.resolve(dir)), stage = p.resolve(dir) + '.copa-new';
    C[rd] = {
      name: name, dir: dir, stage: stage,
      pkg: JSON.parse(fs.readFileSync(p.join(stage, 'package.json'), 'utf8')),
      old: readPkg(rd), ok: true, why: '',
      bundled: fs.existsSync(p.join(stage, 'node_modules'))
    };
    order.push(rd);
  });

  // The tree as it would be with every accepted copy in place.
  function active(d) { return Boolean(C[d] && C[d].ok); }
  function pkgAt(d) { return active(d) ? C[d].pkg : readPkg(d); }
  function nmOf(d) { return active(d) && C[d].bundled ? p.join(C[d].stage, 'node_modules') : p.join(d, 'node_modules'); }
  // resolve finds package n from the (real) directory from, the way Node.js does.
  function resolve(from, n) {
    var c = [p.join(nmOf(from), n)];
    for (var d = p.dirname(from); ; d = p.dirname(d)) {
      if (p.basename(d) !== 'node_modules') { c.push(p.join(d, 'node_modules', n)); }
      if (d === p.dirname(d)) { break; }
    }
    for (var i = 0; i < c.length; i++) {
      var r = rp(c[i]), k = pkgAt(r);
      if (k) { return { dir: r, pkg: k }; }
    }
    return null;
  }

  // Installed packages that can depend on staged copies. The root package itself is
  // not included: replacing its direct dependencies is what was asked for.
  var root = rp(p.resolve('.')), all = [];
  (function walk(nm) {
    var es;
    try { es = fs.readdirSync(nm); } catch (e) { return; }
    es.forEach(function (e) {
      if (e.charAt(0) === '.' || e.slice(-9) === '.copa-new') { return; }
      var f = p.join(nm, e), s;
      if (e.charAt(0) === '@') { walk(f); return; }
      try { s = fs.lstatSync(f); } catch (x) { return; }
      if (s.isSymbolicLink()) { all.push(rp(f)); return; }
      if (s.isDirectory()) { all.push(f); walk(p.join(f, 'node_modules')); }
    });
  })(p.join(root, 'node_modules'));

  var changed = true;
  function reject(c, why) { c.ok = false; c.why = why; changed = true; }
  if (!sv) {
    // Fail closed: without semver, no version range can be checked, so a new version
    // could silently break the packages that depend on it. Keep every installed copy.
    order.forEach(function (d) { reject(C[d], 'version ranges cannot be checked (semver module not found)'); });
    changed = false;
  }
  // Rejections only shrink the accepted set, so this ends.
  while (changed) {
    changed = false;
    // The new version's own dependencies must resolve and satisfy their ranges.
    order.forEach(function (d) {
      var c = C[d];
      if (!c.ok) { return; }
      var ds = deps(c.pkg), why = [];
      Object.keys(ds).forEach(function (n) {
        var r = resolve(d, n);
        if (!r) { why.push(n + '@' + ds[n] + ' is not installed'); }
        else if (sv && sv.validRange(ds[n]) && !sv.satisfies(r.pkg.version || '', ds[n], opts)) {
          // If the dependency resolves to a staged copy whose installed version would
          // satisfy the range, judge that copy as for an installed dependent: keep it
          // at its installed version only if the new one leaves the compatibility
          // class, and otherwise accept both (e.g. an exact pin and a patch update).
          var c2 = active(r.dir) ? C[r.dir] : null;
          if (c2 && c2.old && sv.satisfies(c2.old.version || '', ds[n], opts)) {
            if (breaksDependent(sv, ds[n], c2.old.version, c2.pkg.version)) {
              reject(c2, 'required as ' + n + '@' + ds[n] + ' by ' + c.name + ' ' + c.pkg.version);
            }
          } else {
            why.push(n + '@' + ds[n] + ' resolves to ' + r.pkg.version);
          }
        }
      });
      if (why.length) { reject(c, 'requires ' + why.join(', ')); }
    });
    // Installed packages that are not replaced must not be broken by a new version.
    all.forEach(function (d) {
      if (active(d)) { return; }
      var k = readPkg(d), ds = deps(k);
      Object.keys(ds).forEach(function (n) {
        var r = resolve(d, n);
        if (!r || !active(r.dir)) { return; }
        var c = C[r.dir];
        if (breaksDependent(sv, ds[n], c.old && c.old.version, c.pkg.version)) {
          reject(c, 'required as ' + n + '@' + ds[n] + ' by ' + ((k && k.name) || d));
        }
      });
    });
  }

  // Copies inside the nested node_modules of an accepted copy whose tarball bundles
  // its own node_modules disappear with it.
  function dropped(d) {
    for (var x = p.dirname(d); x !== p.dirname(x); x = p.dirname(x)) {
      if (p.basename(x) === 'node_modules' && active(p.dirname(x)) && C[p.dirname(x)].bundled) { return true; }
    }
    return false;
  }

  var out = [];
  order.forEach(function (d) {
    var c = C[d];
    if (c.ok && dropped(d)) { out.push('dropped ' + c.name + ' ' + c.dir); }
    else if (c.ok) { out.push('accept ' + c.name + ' ' + c.dir); }
    else {
      out.push('reject ' + c.name + ' ' + c.dir);
      console.log('WARN: not patching ' + c.name + ' in ' + c.dir + ' to ' + c.pkg.version + ' (keeping the installed version): ' + c.why);
    }
  });
  fs.writeFileSync(decisionsFile, out.join('\n') + '\n');
}

if (require.main === module) {
  main(process.argv[2], process.argv[3], process.argv[4]);
} else {
  module.exports = { compatKey: compatKey, breaksDependent: breaksDependent, main: main };
}
`

// parseSkippedPackages returns the unique package names in the skipped record.
func parseSkippedPackages(data []byte) []string {
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		if name := strings.TrimSpace(line); name != "" {
			names = append(names, name)
		}
	}
	return utils.DeduplicateStringSlice(names)
}

// skippedPackagesFromRead interprets the result of reading the skipped record.
// A failed solve means that a replace step failed; since every replace step
// creates the record, a missing record is an error too.
func skippedPackagesFromRead(data []byte, rerr *buildkit.ReadFileErr) ([]string, error) {
	if rerr == nil {
		return parseSkippedPackages(data), nil
	}
	if rerr.SolveFailed {
		return nil, fmt.Errorf("npm package replacement failed: %w", rerr.Err)
	}
	return nil, fmt.Errorf("could not read the list of npm packages left unpatched: %w", rerr.Err)
}

// readSkippedPackages returns the packages that the replace steps recorded in report
// as left at their installed version.
func (nm *nodejsManager) readSkippedPackages(ctx context.Context, report *npmReport) ([]string, error) {
	if report == nil || !report.used || nm.config == nil || nm.config.Client == nil {
		return nil, nil
	}
	data, rerr := buildkit.TryExtractFileFromState(ctx, nm.config.Client, &report.state, "/"+npmSkippedFile)
	return skippedPackagesFromRead(data, rerr)
}

// downloadFailureRe matches the lines written by the replace steps to npmFailedFile.
// The name is greedy so that scoped packages (@scope/name@1.2.3) keep their scope.
var downloadFailureRe = regexp.MustCompile(`failed to download (.+)@([^@,\s]+), skipping`)

// parseDownloadFailures returns the unique package names recorded in npmFailedFile.
func parseDownloadFailures(data []byte) []string {
	var failed []string
	for _, line := range strings.Split(string(data), "\n") {
		if m := downloadFailureRe.FindStringSubmatch(line); m != nil {
			failed = append(failed, m[1])
		}
	}
	return utils.DeduplicateStringSlice(failed)
}

// readDownloadFailures returns the packages whose tarball download failed in the
// replace steps recorded in report.
func (nm *nodejsManager) readDownloadFailures(ctx context.Context, report *npmReport) ([]string, error) {
	if report == nil || !report.used || nm.config == nil || nm.config.Client == nil {
		return nil, nil
	}
	data, rerr := buildkit.TryExtractFileFromState(ctx, nm.config.Client, &report.state, "/"+npmFailedFile)
	if _, err := skippedPackagesFromRead(nil, rerr); err != nil {
		return nil, err
	}
	return parseDownloadFailures(data), nil
}

// reportSkippedPackages logs the packages kept at their installed version and returns
// them, to be reported as not patched (errored packages: excluded from the VEX
// document and counted as skipped in the patch summary).
//
// This is deliberately not an error, even without --ignore-errors: keeping a package
// whose fixed version would break the tree is the safe outcome rather than a failure,
// and most real images (e.g. npm's own tree under --library-patch-level major) have
// such packages, so failing would leave every other fix unshipped. Real failures
// (download aside, as before) still fail the run.
func reportSkippedPackages(skipped []string) []string {
	if len(skipped) == 0 {
		return nil
	}
	log.Warnf("%d Node.js package(s) not patched: their fixed version would break the installed dependency tree, "+
		"so the installed version was kept (see the \"not patching\" warnings in the build output): %v", len(skipped), skipped)
	return skipped
}
