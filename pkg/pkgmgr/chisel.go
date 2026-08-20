package pkgmgr

import (
	"archive/tar"
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
	"time"

	"github.com/klauspost/compress/zstd"
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
	chiselToolImage   = "ghcr.io/project-copacetic/copacetic/chisel@sha256:adc238182bcbc07ff5f030929732a46d7f1aab801fadb70b320805a1d56c817c"
	chiselToolVersion = "v1.4.2"

	chiselStageRoot                 = "/copa-chisel-root"
	chiselReleaseRoot               = "/copa-chisel-release"
	chiselGitRevisionFile           = "/tmp/copa-chisel-git-home/revision"
	chiselExpectedFilePath          = "/copa-chisel-expected.json"
	chiselValidationMark            = "/copa-chisel-validation-ok"
	chiselOldExpectedPath           = "/copa-chisel-old.json"
	chiselNewExpectedPath           = "/copa-chisel-new.json"
	chiselLocalReleaseArchivePath   = "/release.tar.zst"
	chiselLocalReleaseArchiveMount  = "/copa-chisel-release-input"
	maxChiselExpectationInlineBytes = 8 << 20
	// Leave half of BuildKit's 16 MiB gateway request allowance for the
	// surrounding protobuf and LLB graph.
	maxLocalReleaseInlineBytes = 8 << 20
	maxLocalReleaseBytes       = 64 << 20
	maxLocalReleaseFiles       = 10000
	// Bound the compressed input before ParseManifest applies the same limit
	// to the decompressed JSONWall data.
	maxChiselManifestInputBytes = copachisel.MaxManifestSize
	// Keep extraction aligned with the limit enforced by chisel.InferRelease.
	maxChiselOSReleaseBytes = 1 << 20
)

const nativeTargetedPatchError = NativeChiselTargetedPatchError

const gitChiselReleaseCloneScript = `set -eu
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
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
rm -rf "$RELEASE_DIR/.git"

release_real=$(readlink -f "$RELEASE_DIR")
paths_file="$HOME/copa-chisel-release-paths"
entries_file="$HOME/copa-chisel-release-entries"
sizes_file="$HOME/copa-chisel-release-sizes"
rm -f "$paths_file" "$entries_file" "$sizes_file"
: > "$entries_file"
: > "$sizes_file"
cleanup_release_validation() {
    rm -f "$paths_file" "$entries_file" "$sizes_file"
}
trap cleanup_release_validation EXIT HUP INT TERM

find "$RELEASE_DIR" -mindepth 1 -print0 > "$paths_file"
export RELEASE_DIR release_real entries_file sizes_file
# The single-quoted program is intentionally expanded by the nested shell.
# shellcheck disable=SC2016
if ! xargs -0 sh -c '
    for release_path do
        relative=${release_path#"$RELEASE_DIR/"}
        printf ".\n" >> "$entries_file"
        if [ -L "$release_path" ]; then
            link_target=$(readlink "$release_path") || {
                printf "unable to read pinned Git Chisel release symlink %s\n" "$relative" >&2
                exit 1
            }
            case "$link_target" in
                /*)
                    printf "pinned Git Chisel release symlink %s has an absolute target\n" "$relative" >&2
                    exit 1
                    ;;
            esac
            resolved_path=$(readlink -f "$release_path") || {
                printf "pinned Git Chisel release symlink %s does not resolve safely within the release directory\n" "$relative" >&2
                exit 1
            }
            if [ ! -e "$resolved_path" ]; then
                printf "pinned Git Chisel release symlink %s does not resolve safely within the release directory\n" "$relative" >&2
                exit 1
            fi
            case "$resolved_path" in
                "$release_real"|"$release_real"/*) ;;
                *)
                    printf "pinned Git Chisel release symlink %s escapes the release directory\n" "$relative" >&2
                    exit 1
                    ;;
            esac
        elif [ -f "$release_path" ]; then
            file_bytes=$(wc -c < "$release_path") || {
                printf "unable to measure pinned Git Chisel release file %s\n" "$relative" >&2
                exit 1
            }
            file_bytes=$(printf "%s" "$file_bytes" | tr -d "[:space:]")
            printf "%s\n" "$file_bytes" >> "$sizes_file"
        elif [ -d "$release_path" ]; then
            :
        else
            printf "pinned Git Chisel release contains an unsupported file type at %s\n" "$relative" >&2
            exit 1
        fi
    done
' sh < "$paths_file"; then
    exit 1
fi

entry_count=$(wc -l < "$entries_file" | tr -d '[:space:]')
if [ "$entry_count" -gt "$MAX_RELEASE_FILES" ]; then
    echo "pinned Git Chisel release contains more than $MAX_RELEASE_FILES entries" >&2
    exit 1
fi
total_bytes=$(awk '{ total += $1 } END { print total + 0 }' "$sizes_file")
if [ "$total_bytes" -gt "$MAX_RELEASE_BYTES" ]; then
    echo "pinned Git Chisel release exceeds the configured content size limit" >&2
    exit 1
fi

cleanup_release_validation
trap - EXIT HUP INT TERM
printf '%s\n' "$resolved" > "$REVISION_FILE"
`

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
	if err := validateOriginalChiselPackageArchitectures(oldManifest, chiselArch); err != nil {
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
		gitTooling := chiselGitReleaseState(tooling, release.Location, release.Revision)
		resolvedBytes, err := buildkit.ExtractFileFromState(ctx, client, &gitTooling, chiselGitRevisionFile)
		if err != nil {
			return llb.State{}, "", "", fmt.Errorf("resolve pinned Chisel Git release %s: %w", release.String(), err)
		}
		resolved := strings.TrimSpace(string(resolvedBytes))
		if len(resolved) != 40 {
			return llb.State{}, "", "", fmt.Errorf("resolved Chisel Git release returned invalid commit %q", resolved)
		}
		// The tag or abbreviated revision used for discovery can move before the
		// returned graph is solved again. Rebuild that graph from the immutable
		// commit observed by the first solve so its contents match provenance.
		gitTooling = chiselGitReleaseState(tooling, release.Location, resolved).
			File(llb.Rm(chiselGitRevisionFile))
		return gitTooling, chiselReleaseRoot, release.Location + "#" + resolved, nil
	case copachisel.ReleaseLocal:
		releaseState, digest, err := localChiselReleaseState(release.Location)
		if err != nil {
			return llb.State{}, "", "", err
		}
		const materializeScript = `set -eu
rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"
zstd -q -d -c "$RELEASE_ARCHIVE" | tar -xpf - -C "$RELEASE_DIR"
`
		run := tooling.Run(
			llb.Args([]string{"/bin/sh", "-c", materializeScript}),
			llb.AddEnv("RELEASE_DIR", chiselReleaseRoot),
			llb.AddEnv("RELEASE_ARCHIVE", chiselLocalReleaseArchiveMount+chiselLocalReleaseArchivePath),
			llb.WithCustomName("Materializing local Chisel release definitions"),
		)
		_ = run.AddMount(chiselLocalReleaseArchiveMount, releaseState, llb.Readonly)
		provenance := fmt.Sprintf("local:%s@sha256:%s", filepath.Base(release.Location), digest)
		return run.Root(), chiselReleaseRoot, provenance, nil
	default:
		return llb.State{}, "", "", fmt.Errorf("unsupported Chisel release source kind %q", release.Kind)
	}
}

//nolint:gocritic // llb.State is an immutable graph handle passed by value throughout the BuildKit API.
func chiselGitReleaseState(tooling llb.State, location, revision string) llb.State {
	return tooling.Run(
		llb.Args([]string{"/bin/sh", "-c", gitChiselReleaseCloneScript}),
		llb.AddEnv("RELEASE_DIR", chiselReleaseRoot),
		llb.AddEnv("REVISION_FILE", chiselGitRevisionFile),
		llb.AddEnv("RELEASE_URL", location),
		llb.AddEnv("RELEASE_REV", revision),
		llb.AddEnv("MAX_RELEASE_FILES", fmt.Sprintf("%d", maxLocalReleaseFiles)),
		llb.AddEnv("MAX_RELEASE_BYTES", fmt.Sprintf("%d", maxLocalReleaseBytes)),
		llb.AddEnv("HOME", "/tmp/copa-chisel-git-home"),
		llb.WithProxy(utils.GetProxy()),
		llb.IgnoreCache,
		llb.WithCustomName("Fetching pinned Chisel release definitions"),
	).Root()
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

	hash := sha256.New()
	fileCount := 0
	var totalBytes int64
	var archive bytes.Buffer
	encoder, err := zstd.NewWriter(
		&archive,
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderLevel(zstd.SpeedBetterCompression),
	)
	if err != nil {
		return llb.State{}, "", fmt.Errorf("create local Chisel release compressor: %w", err)
	}
	tarWriter := tar.NewWriter(encoder)
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
		header := &tar.Header{
			Name:    filepath.ToSlash(relative),
			Mode:    int64(info.Mode().Perm()),
			ModTime: time.Unix(0, 0).UTC(),
		}
		switch {
		case entry.IsDir():
			header.Name += "/"
			header.Typeflag = tar.TypeDir
			if err := tarWriter.WriteHeader(header); err != nil {
				return fmt.Errorf("archive directory %q: %w", relative, err)
			}
		case info.Mode().IsRegular():
			if info.Size() > maxLocalReleaseBytes || totalBytes+info.Size() > maxLocalReleaseBytes {
				return fmt.Errorf("local Chisel release exceeds the %d MiB size limit", maxLocalReleaseBytes>>20)
			}
			contents, err := rootHandle.ReadFile(relative)
			if err != nil {
				return err
			}
			if int64(len(contents)) != info.Size() {
				return fmt.Errorf("local Chisel release file %q changed size during materialization", relative)
			}
			totalBytes += int64(len(contents))
			writeLocalChiselReleaseHashPayload(hash, contents)
			header.Typeflag = tar.TypeReg
			header.Size = int64(len(contents))
			if err := tarWriter.WriteHeader(header); err != nil {
				return fmt.Errorf("archive regular file %q: %w", relative, err)
			}
			if _, err := tarWriter.Write(contents); err != nil {
				return fmt.Errorf("archive regular file contents %q: %w", relative, err)
			}
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
			header.Typeflag = tar.TypeSymlink
			header.Linkname = filepath.ToSlash(target)
			if err := tarWriter.WriteHeader(header); err != nil {
				return fmt.Errorf("archive symlink %q: %w", relative, err)
			}
		default:
			return fmt.Errorf("local Chisel release contains unsupported file type at %q", relative)
		}
		return nil
	})
	tarCloseErr := tarWriter.Close()
	encoderCloseErr := encoder.Close()
	if err != nil {
		return llb.State{}, "", fmt.Errorf("materialize local Chisel release %q: %w", root, err)
	}
	if tarCloseErr != nil {
		return llb.State{}, "", fmt.Errorf("finish local Chisel release archive %q: %w", root, tarCloseErr)
	}
	if encoderCloseErr != nil {
		return llb.State{}, "", fmt.Errorf("finish local Chisel release compression %q: %w", root, encoderCloseErr)
	}
	if archive.Len() > maxLocalReleaseInlineBytes {
		return llb.State{}, "", fmt.Errorf(
			"compressed local Chisel release %q is %d bytes, exceeding the %d MiB BuildKit inline transfer limit; reduce the release contents or use a named Chisel release",
			root, archive.Len(), maxLocalReleaseInlineBytes>>20,
		)
	}
	state := llb.Scratch().File(llb.Mkfile(chiselLocalReleaseArchivePath, 0o600, archive.Bytes()))
	return state, hex.EncodeToString(hash.Sum(nil)), nil
}

func writeLocalChiselReleaseHashPayload(digest hash.Hash, payload []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(payload)))
	digest.Write(length[:])
	digest.Write(payload)
}

func validateChiselUpgrade(oldManifest, newManifest *copachisel.Manifest, expectedArch string) error {
	if err := validateOriginalChiselPackageArchitectures(oldManifest, expectedArch); err != nil {
		return err
	}

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

func validateOriginalChiselPackageArchitectures(manifest *copachisel.Manifest, expectedArch string) error {
	for name, pkg := range manifest.Packages {
		if pkg.Architecture != expectedArch && pkg.Architecture != "all" {
			return fmt.Errorf("original Chisel package %q architecture %q does not match target %q", name, pkg.Architecture, expectedArch)
		}
	}
	return nil
}

func chiselManifestsEqual(oldManifest, newManifest *copachisel.Manifest) bool {
	return maps.Equal(oldManifest.Packages, newManifest.Packages) &&
		reflect.DeepEqual(oldManifest.Slices, newManifest.Slices) &&
		maps.EqualFunc(oldManifest.OwnedPaths, newManifest.OwnedPaths, func(left, right copachisel.PathMetadata) bool { return reflect.DeepEqual(left, right) })
}

func compressChiselExpectations(payloads ...[]byte) ([][]byte, error) {
	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderLevel(zstd.SpeedBetterCompression),
	)
	if err != nil {
		return nil, fmt.Errorf("create chisel expectation compressor: %w", err)
	}
	defer encoder.Close()

	compressed := make([][]byte, 0, len(payloads))
	totalCompressed := 0
	for _, payload := range payloads {
		if len(payload) > copachisel.MaxManifestSize {
			return nil, fmt.Errorf(
				"chisel filesystem expectation is %d bytes, exceeding the %d MiB generated-input limit",
				len(payload), copachisel.MaxManifestSize>>20,
			)
		}
		encoded := encoder.EncodeAll(payload, nil)
		totalCompressed += len(encoded)
		if totalCompressed > maxChiselExpectationInlineBytes {
			return nil, fmt.Errorf(
				"compressed chisel filesystem expectations are %d bytes, exceeding the %d MiB BuildKit inline transfer limit",
				totalCompressed, maxChiselExpectationInlineBytes>>20,
			)
		}
		compressed = append(compressed, encoded)
	}
	return compressed, nil
}

func decompressChiselExpectationCommand(compressedPath, destinationPath string) string {
	return "zstd -q -d -c " + compressedPath + " > " + destinationPath
}

//nolint:gocritic // llb.State is an immutable graph handle passed by value throughout the BuildKit API.
func validateChiselState(ctx context.Context, client gwclient.Client, tooling, target llb.State, manifest *copachisel.Manifest) (llb.State, error) {
	expectedBytes, err := marshalChiselExpectedManifest(manifest)
	if err != nil {
		return llb.State{}, err
	}
	compressed, err := compressChiselExpectations(expectedBytes)
	if err != nil {
		return llb.State{}, err
	}
	compressedPath := chiselExpectedFilePath + ".zst"
	validator := tooling.
		File(llb.Mkfile(compressedPath, 0o600, compressed[0])).
		File(llb.Rm(chiselValidationMark, llb.WithAllowNotFound(true)))
	command := decompressChiselExpectationCommand(compressedPath, chiselExpectedFilePath) +
		" && /usr/local/bin/copa-chisel-validate --root /target --expected " + chiselExpectedFilePath +
		" && touch " + chiselValidationMark
	run := validator.Run(
		llb.Args([]string{"/bin/sh", "-c", command}),
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
	compressed, err := compressChiselExpectations(oldExpected, newExpected)
	if err != nil {
		return llb.State{}, err
	}
	oldCompressedPath := chiselOldExpectedPath + ".zst"
	newCompressedPath := chiselNewExpectedPath + ".zst"

	reconciler := tooling.
		File(llb.Mkfile(oldCompressedPath, 0o600, compressed[0])).
		File(llb.Mkfile(newCompressedPath, 0o600, compressed[1])).
		File(llb.Rm(chiselValidationMark, llb.WithAllowNotFound(true)))
	command := decompressChiselExpectationCommand(oldCompressedPath, chiselOldExpectedPath) + " && " +
		decompressChiselExpectationCommand(newCompressedPath, chiselNewExpectedPath) + " && " + strings.Join([]string{
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
