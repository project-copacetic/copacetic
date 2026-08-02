package pkgmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	copachisel "github.com/project-copacetic/copacetic/pkg/chisel"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const (
	// TODO: replace the tag with the published multi-platform digest before the
	// tooling image is released. The image build is defined in images/chisel.
	chiselToolImage   = "ghcr.io/project-copacetic/copacetic/chisel@sha256:587015954e14bf51aea440e69c8bf30bd010abd57ed8dd42c19e2159577e8c80"
	chiselToolVersion = "v1.4.2"

	chiselStageRoot        = "/copa-chisel-root"
	chiselReleaseRoot      = "/copa-chisel-release"
	chiselExpectedFilePath = "/copa-chisel-expected.json"
	chiselValidationMark   = "/copa-chisel-validation-ok"
	chiselOldExpectedPath  = "/copa-chisel-old.json"
	chiselNewExpectedPath  = "/copa-chisel-new.json"
	maxLocalReleaseBytes   = 64 << 20
	maxLocalReleaseFiles   = 10000
	// Bound the compressed input before ParseManifest applies the same limit
	// to the decompressed JSONWall data.
	maxChiselManifestInputBytes = copachisel.MaxManifestSize
	// Keep extraction aligned with the limit enforced by chisel.InferRelease.
	maxChiselOSReleaseBytes = 1 << 20
)

const nativeTargetedPatchError = NativeChiselTargetedPatchError

type chiselExpectedManifest struct {
	Paths []chiselExpectedPath `json:"paths"`
}

type chiselExpectedPath struct {
	Path        string   `json:"path"`
	Mode        string   `json:"mode"`
	Slices      []string `json:"slices,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	FinalSHA256 string   `json:"final_sha256,omitempty"`
	Size        uint64   `json:"size,omitempty"`
	Link        string   `json:"link,omitempty"`
	Inode       uint64   `json:"inode,omitempty"`
}

func extractNativeChiselManifest(
	ctx context.Context,
	client gwclient.Client,
	state *llb.State,
) ([]byte, error) {
	return buildkit.ExtractFileFromStateWithLimit(
		ctx,
		client,
		state,
		chiselManifestPath,
		maxChiselManifestInputBytes,
	)
}

func extractChiselOSRelease(
	ctx context.Context,
	client gwclient.Client,
	state *llb.State,
) ([]byte, error) {
	return buildkit.ExtractFileFromStateWithLimit(
		ctx,
		client,
		state,
		"/etc/os-release",
		maxChiselOSReleaseBytes,
	)
}

func (dm *dpkgManager) installNativeChiselUpdates(ctx context.Context, updateManifest *unversioned.UpdateManifest) (*llb.State, []string, error) {
	if updateManifest != nil {
		return nil, nil, errors.New(nativeTargetedPatchError)
	}

	current := dm.currentImageState()
	platform, err := current.GetPlatform(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to determine native Chisel image platform: %w", err)
	}
	chiselArch, err := copachisel.OCIPlatformToChiselArch(*platform)
	if err != nil {
		return nil, nil, err
	}

	oldManifestBytes, err := extractNativeChiselManifest(ctx, dm.config.Client, &current)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read native Chisel manifest %s: %w", chiselManifestPath, err)
	}
	oldManifest, err := copachisel.ParseManifest(bytes.NewReader(oldManifestBytes))
	if err != nil {
		return nil, nil, err
	}

	var release copachisel.Release
	if dm.chiselRelease != "" {
		release, err = copachisel.ParseRelease(dm.chiselRelease)
	} else {
		osReleaseBytes, extractErr := extractChiselOSRelease(ctx, dm.config.Client, &current)
		if extractErr != nil {
			return nil, nil, fmt.Errorf("unable to read /etc/os-release for Chisel release inference: %w", extractErr)
		}
		release, err = copachisel.InferRelease(bytes.NewReader(osReleaseBytes))
	}
	if err != nil {
		return nil, nil, err
	}

	tooling, err := tryImage(ctx, chiselToolImage, dm.config.Client, platform)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to resolve Chisel tooling image %s for %s: %w", chiselToolImage, formatOCIPlatform(platform), err)
	}

	tooling, releaseArgument, releaseProvenance, err := materializeChiselRelease(ctx, dm.config.Client, tooling, release)
	if err != nil {
		return nil, nil, err
	}

	staged, err := runChiselCut(tooling, platform, releaseArgument, chiselArch, oldManifest.Slices)
	if err != nil {
		return nil, nil, err
	}
	newManifestBytes, err := extractNativeChiselManifest(ctx, dm.config.Client, &staged)
	if err != nil {
		return nil, nil, fmt.Errorf("chisel did not generate %s in the staged root: %w", chiselManifestPath, err)
	}
	newManifest, err := copachisel.ParseManifest(bytes.NewReader(newManifestBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("generated Chisel manifest failed validation: %w", err)
	}

	if err := validateChiselUpgrade(oldManifest, newManifest, chiselArch); err != nil {
		return nil, nil, err
	}
	if _, err := validateChiselState(ctx, dm.config.Client, tooling, staged, newManifest); err != nil {
		return nil, nil, fmt.Errorf("staged Chisel root failed validation: %w", err)
	}

	if chiselManifestsEqual(oldManifest, newManifest) {
		if _, err := validateChiselState(ctx, dm.config.Client, tooling, current, oldManifest); err == nil {
			log.Info("No Chisel package or managed-filesystem updates were found for this image.")
			return nil, nil, types.ErrNoUpdatesFound
		} else {
			log.Warnf("Chisel manifest is current but managed filesystem drift was detected; rebuilding managed paths: %v", err)
		}
	}

	validatedFinal, err := reconcileChiselState(ctx, dm.config.Client, tooling, current, staged, oldManifest, newManifest)
	if err != nil {
		return nil, nil, fmt.Errorf("final native Chisel image reconciliation failed: %w", err)
	}

	dm.chiselAnnotations = map[string]string{
		ChiselReleaseAnnotation: releaseProvenance,
		ChiselVersionAnnotation: chiselToolVersion,
	}
	return &validatedFinal, nil, nil
}

//nolint:gocritic // llb.State is an immutable graph handle passed by value throughout the BuildKit API.
func runChiselCut(tooling llb.State, platform *ocispecs.Platform, release, arch string, slices []string) (llb.State, error) {
	if len(slices) == 0 {
		return llb.State{}, fmt.Errorf("native Chisel manifest contains no selected slices")
	}
	args := []string{"/usr/local/bin/chisel", "cut", "--release", release, "--root", chiselStageRoot, "--arch", arch}
	args = append(args, slices...)

	run := tooling.Run(
		llb.Args(args),
		llb.AddEnv("HOME", "/tmp/copa-chisel-home"),
		llb.AddEnv("XDG_CACHE_HOME", "/tmp/copa-chisel-cache"),
		llb.WithProxy(utils.GetProxy()),
		llb.IgnoreCache,
		llb.WithCustomName(fmt.Sprintf("Re-cutting %d Chisel slices for %s", len(slices), formatOCIPlatform(platform))),
	)
	return run.AddMount(chiselStageRoot, llb.Scratch()), nil
}

//nolint:gocritic // llb.State is an immutable graph handle passed by value throughout the BuildKit API.
func materializeChiselRelease(ctx context.Context, client gwclient.Client, tooling llb.State, release copachisel.Release) (llb.State, string, string, error) {
	switch release.Kind {
	case copachisel.ReleaseNamed:
		return tooling, release.Location, release.Location, nil
	case copachisel.ReleaseGit:
		const revisionFile = chiselReleaseRoot + "/.copa-revision"
		const cloneScript = `set -eu
export GIT_CONFIG_NOSYSTEM=1
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=/bin/false
export SSH_ASKPASS=/bin/false
rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR" "$HOME"
git init -q "$RELEASE_DIR"
git -C "$RELEASE_DIR" remote add origin "$RELEASE_URL"

fetch_ref=""
if git ls-remote --exit-code --tags "$RELEASE_URL" "refs/tags/$RELEASE_REV" "refs/tags/$RELEASE_REV^{}" >/dev/null 2>&1; then
    fetch_ref="refs/tags/$RELEASE_REV"
elif printf '%s' "$RELEASE_REV" | grep -Eq '^[0-9a-fA-F]{7,40}$'; then
    matches=$(git ls-remote "$RELEASE_URL" | awk -v prefix="$RELEASE_REV" 'index($1, prefix) == 1 {print $1}' | sort -u)
    count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
    if [ "$count" -eq 1 ]; then
        fetch_ref=$matches
    elif [ "${#RELEASE_REV}" -eq 40 ]; then
        fetch_ref=$RELEASE_REV
    else
        echo "Git revision $RELEASE_REV does not uniquely resolve to an advertised commit" >&2
        exit 1
    fi
else
    echo "Git revision $RELEASE_REV is neither an exact tag nor a pinned commit" >&2
    exit 1
fi

git -c credential.helper= -C "$RELEASE_DIR" fetch --depth=1 --no-tags origin "$fetch_ref"
git -C "$RELEASE_DIR" checkout -q --detach FETCH_HEAD
resolved=$(git -C "$RELEASE_DIR" rev-parse HEAD)
printf '%s\n' "$resolved" > "$REVISION_FILE"
rm -rf "$RELEASE_DIR/.git"
`
		gitTooling := tooling.Run(
			llb.Args([]string{"/bin/sh", "-c", cloneScript}),
			llb.AddEnv("RELEASE_DIR", chiselReleaseRoot),
			llb.AddEnv("REVISION_FILE", revisionFile),
			llb.AddEnv("RELEASE_URL", release.Location),
			llb.AddEnv("RELEASE_REV", release.Revision),
			llb.AddEnv("HOME", "/tmp/copa-chisel-git-home"),
			llb.WithProxy(utils.GetProxy()),
			llb.IgnoreCache,
			llb.WithCustomName("Fetching pinned Chisel release definitions"),
		).Root()
		resolvedBytes, err := buildkit.ExtractFileFromState(ctx, client, &gitTooling, revisionFile)
		if err != nil {
			return llb.State{}, "", "", fmt.Errorf("resolve pinned Chisel Git release %s: %w", release.String(), err)
		}
		resolved := strings.TrimSpace(string(resolvedBytes))
		if len(resolved) != 40 {
			return llb.State{}, "", "", fmt.Errorf("resolved Chisel Git release returned invalid commit %q", resolved)
		}
		gitTooling = gitTooling.File(llb.Rm(revisionFile))
		return gitTooling, chiselReleaseRoot, release.Location + "#" + resolved, nil
	case copachisel.ReleaseLocal:
		releaseState, digest, err := localChiselReleaseState(release.Location)
		if err != nil {
			return llb.State{}, "", "", err
		}
		withRelease := tooling.File(llb.Copy(releaseState, "/", chiselReleaseRoot, &llb.CopyInfo{
			CopyDirContentsOnly: true,
			CreateDestPath:      true,
		}))
		provenance := fmt.Sprintf("local:%s@sha256:%s", filepath.Base(release.Location), digest)
		return withRelease, chiselReleaseRoot, provenance, nil
	default:
		return llb.State{}, "", "", fmt.Errorf("unsupported Chisel release source kind %q", release.Kind)
	}
}

func localChiselReleaseState(root string) (llb.State, string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return llb.State{}, "", fmt.Errorf("resolve local Chisel release path: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return llb.State{}, "", fmt.Errorf("resolve local Chisel release symlinks: %w", err)
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return llb.State{}, "", fmt.Errorf("open local Chisel release root: %w", err)
	}
	defer rootHandle.Close()

	state := llb.Scratch()
	hash := sha256.New()
	fileCount := 0
	var totalBytes int64
	err = fs.WalkDir(rootHandle.FS(), ".", func(relative string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if relative == "." {
			return nil
		}
		if relative == ".git" || strings.HasPrefix(relative, ".git/") {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		fileCount++
		if fileCount > maxLocalReleaseFiles {
			return fmt.Errorf("local Chisel release contains more than %d entries", maxLocalReleaseFiles)
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}
		destination := "/" + filepath.ToSlash(relative)
		fmt.Fprintf(hash, "%s\x00%o\x00", destination, info.Mode())
		switch {
		case entry.IsDir():
			state = state.File(llb.Mkdir(destination, info.Mode().Perm(), llb.WithParents(true)))
		case info.Mode().IsRegular():
			if info.Size() > maxLocalReleaseBytes || totalBytes+info.Size() > maxLocalReleaseBytes {
				return fmt.Errorf("local Chisel release exceeds the %d MiB size limit", maxLocalReleaseBytes>>20)
			}
			contents, err := rootHandle.ReadFile(relative)
			if err != nil {
				return err
			}
			totalBytes += int64(len(contents))
			writeLocalChiselReleaseHashPayload(hash, contents)
			state = state.File(llb.Mkfile(destination, info.Mode().Perm(), contents))
		case info.Mode()&os.ModeSymlink != 0:
			target, err := rootHandle.Readlink(relative)
			if err != nil {
				return err
			}
			if filepath.IsAbs(target) {
				return fmt.Errorf("local Chisel release symlink %q has an absolute target", relative)
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(relative), target))
			if resolved == ".." || strings.HasPrefix(resolved, ".."+string(filepath.Separator)) {
				return fmt.Errorf("local Chisel release symlink %q escapes the release directory", relative)
			}
			// Lexical cleaning alone is insufficient when another in-tree symlink
			// appears before a '..' component. Root.Stat resolves the full chain and
			// rejects escapes, dangling links, and cycles without leaving the root.
			if _, err := rootHandle.Stat(relative); err != nil {
				return fmt.Errorf("local Chisel release symlink %q does not resolve safely within the release directory: %w", relative, err)
			}
			writeLocalChiselReleaseHashPayload(hash, []byte(target))
			state = state.File(llb.Symlink(filepath.ToSlash(target), destination))
		default:
			return fmt.Errorf("local Chisel release contains unsupported file type at %q", relative)
		}
		return nil
	})
	if err != nil {
		return llb.State{}, "", fmt.Errorf("materialize local Chisel release %q: %w", root, err)
	}
	return state, hex.EncodeToString(hash.Sum(nil)), nil
}

func writeLocalChiselReleaseHashPayload(digest hash.Hash, payload []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(payload)))
	digest.Write(length[:])
	digest.Write(payload)
}

func validateChiselUpgrade(oldManifest, newManifest *copachisel.Manifest, expectedArch string) error {
	newSlices := make(map[string]struct{}, len(newManifest.Slices))
	for _, sliceName := range newManifest.Slices {
		newSlices[sliceName] = struct{}{}
	}
	for _, sliceName := range oldManifest.Slices {
		if _, exists := newSlices[sliceName]; !exists {
			return fmt.Errorf("generated Chisel root dropped originally selected slice %q", sliceName)
		}
	}

	for name, oldPackage := range oldManifest.Packages {
		newPackage, exists := newManifest.Packages[name]
		if !exists {
			return fmt.Errorf("generated Chisel root dropped package %q", name)
		}
		if !isValidDebianVersion(oldPackage.Version) || !isValidDebianVersion(newPackage.Version) {
			return fmt.Errorf("cannot compare Chisel package %q versions %q and %q", name, oldPackage.Version, newPackage.Version)
		}
		if isLessThanDebianVersion(newPackage.Version, oldPackage.Version) {
			return fmt.Errorf("chisel package %q would be downgraded from %s to %s", name, oldPackage.Version, newPackage.Version)
		}
	}
	for name, pkg := range newManifest.Packages {
		if pkg.SHA256 == "" || pkg.Architecture == "" {
			return fmt.Errorf("generated Chisel package %q is missing archive digest or architecture", name)
		}
		if pkg.Architecture != expectedArch && pkg.Architecture != "all" {
			return fmt.Errorf("generated Chisel package %q architecture %q does not match target %q", name, pkg.Architecture, expectedArch)
		}
		if _, existed := oldManifest.Packages[name]; !existed {
			log.Infof("Chisel selected new transitive dependency package %s %s", name, pkg.Version)
		}
	}
	oldSlices := make(map[string]struct{}, len(oldManifest.Slices))
	for _, name := range oldManifest.Slices {
		oldSlices[name] = struct{}{}
	}
	for _, name := range newManifest.Slices {
		if _, existed := oldSlices[name]; !existed {
			log.Infof("Chisel selected new transitive dependency slice %s", name)
		}
	}
	return nil
}

func chiselManifestsEqual(oldManifest, newManifest *copachisel.Manifest) bool {
	return maps.Equal(oldManifest.Packages, newManifest.Packages) &&
		reflect.DeepEqual(oldManifest.Slices, newManifest.Slices) &&
		maps.EqualFunc(oldManifest.OwnedPaths, newManifest.OwnedPaths, func(left, right copachisel.PathMetadata) bool { return reflect.DeepEqual(left, right) })
}

//nolint:gocritic // llb.State is an immutable graph handle passed by value throughout the BuildKit API.
func validateChiselState(ctx context.Context, client gwclient.Client, tooling, target llb.State, manifest *copachisel.Manifest) (llb.State, error) {
	expectedBytes, err := marshalChiselExpectedManifest(manifest)
	if err != nil {
		return llb.State{}, err
	}
	validator := tooling.
		File(llb.Mkfile(chiselExpectedFilePath, 0o600, expectedBytes)).
		File(llb.Rm(chiselValidationMark, llb.WithAllowNotFound(true)))
	run := validator.Run(
		llb.Args([]string{"/bin/sh", "-c", "/usr/local/bin/copa-chisel-validate --root /target --expected " + chiselExpectedFilePath + " && touch " + chiselValidationMark}),
		llb.WithCustomName(fmt.Sprintf("Validating %d Chisel-managed paths", len(manifest.OwnedPaths))),
	)
	validatedTarget := run.AddMount("/target", target)
	validationRoot := run.Root()
	if _, err := buildkit.ExtractFileFromState(ctx, client, &validationRoot, chiselValidationMark); err != nil {
		return llb.State{}, err
	}
	return validatedTarget, nil
}

func marshalChiselExpectedManifest(manifest *copachisel.Manifest) ([]byte, error) {
	paths := make([]string, 0, len(manifest.OwnedPaths))
	for ownedPath := range manifest.OwnedPaths {
		paths = append(paths, ownedPath)
	}
	sort.Strings(paths)

	expected := chiselExpectedManifest{Paths: make([]chiselExpectedPath, 0, len(paths))}
	for _, ownedPath := range paths {
		metadata := manifest.OwnedPaths[ownedPath]
		expected.Paths = append(expected.Paths, chiselExpectedPath{
			Path:        metadata.Path,
			Mode:        fmt.Sprintf("0%o", metadata.Mode),
			Slices:      metadata.Slices,
			SHA256:      metadata.SHA256,
			FinalSHA256: metadata.FinalSHA256,
			Size:        metadata.Size,
			Link:        metadata.Link,
			Inode:       metadata.Inode,
		})
	}
	data, err := json.Marshal(expected)
	if err != nil {
		return nil, fmt.Errorf("marshal Chisel filesystem expectations: %w", err)
	}
	return data, nil
}

//nolint:gocritic // llb.State is an immutable graph handle passed by value throughout the BuildKit API.
func reconcileChiselState(ctx context.Context, client gwclient.Client, tooling, current, staged llb.State, oldManifest, newManifest *copachisel.Manifest) (llb.State, error) {
	oldExpected, err := marshalChiselExpectedManifest(oldManifest)
	if err != nil {
		return llb.State{}, err
	}
	newExpected, err := marshalChiselExpectedManifest(newManifest)
	if err != nil {
		return llb.State{}, err
	}

	reconciler := tooling.
		File(llb.Mkfile(chiselOldExpectedPath, 0o600, oldExpected)).
		File(llb.Mkfile(chiselNewExpectedPath, 0o600, newExpected)).
		File(llb.Rm(chiselValidationMark, llb.WithAllowNotFound(true)))
	command := strings.Join([]string{
		"/usr/local/bin/copa-chisel-validate reconcile",
		"--target /target",
		"--staged /staged",
		"--old " + chiselOldExpectedPath,
		"--new " + chiselNewExpectedPath,
		"&& touch " + chiselValidationMark,
	}, " ")
	run := reconciler.Run(
		llb.Args([]string{"/bin/sh", "-c", command}),
		llb.WithCustomName(fmt.Sprintf("Reconciling %d Chisel-managed paths", len(newManifest.OwnedPaths))),
	)
	targetOutput := run.AddMount("/target", current)
	_ = run.AddMount("/staged", staged, llb.Readonly)
	rootOutput := run.Root()
	if _, err := buildkit.ExtractFileFromState(ctx, client, &rootOutput, chiselValidationMark); err != nil {
		return llb.State{}, err
	}
	return targetOutput, nil
}

func formatOCIPlatform(platform *ocispecs.Platform) string {
	formatted := platform.OS + "/" + platform.Architecture
	if platform.Variant != "" {
		formatted += "/" + platform.Variant
	}
	return formatted
}

// Annotations returns OCI annotations describing the Chisel release and tool
// version used for a successful native re-cut.
func (dm *dpkgManager) Annotations() map[string]string {
	return maps.Clone(dm.chiselAnnotations)
}
