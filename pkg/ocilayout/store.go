package ocilayout

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// errReadOnlyLayout is returned for every content-store write. The store is
// also exposed to BuildKit through the session, so a daemon must not be able to
// add, relabel or delete blobs in the input layout.
var errReadOnlyLayout = fmt.Errorf("OCI layout input is read-only: %w", errdefs.ErrPermissionDenied)

// readOnlyStore serves blobs from an OCI Image Layout without writing to it.
// containerd's local store is not used because opening it probes fs-verity by
// creating a temporary directory in the layout root, and it implements writes.
type readOnlyStore struct {
	root string
}

var _ content.Store = (*readOnlyStore)(nil)

func newReadOnlyStore(root string) *readOnlyStore {
	return &readOnlyStore{root: root}
}

// resolveLayoutBlob returns the regular file holding dgst, after resolving
// symlinks and confirming that it stays inside the layout's blob directory.
func resolveLayoutBlob(root string, dgst digest.Digest) (string, error) {
	if err := dgst.Validate(); err != nil {
		return "", fmt.Errorf("invalid digest %q: %w", dgst, errors.Join(err, errdefs.ErrInvalidArgument))
	}
	blobRoot := filepath.Join(root, "blobs")
	resolved, err := filepath.EvalSymlinks(filepath.Join(blobRoot, dgst.Algorithm().String(), dgst.Encoded()))
	if err != nil {
		return "", fmt.Errorf("resolve blob path %s: %w", dgst, notFound(err))
	}
	rel, err := filepath.Rel(blobRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("blob %s resolves outside OCI layout blob directory", dgst)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat blob path %s: %w", dgst, notFound(err))
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("blob %s is not a regular file", dgst)
	}
	return resolved, nil
}

func notFound(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return errors.Join(err, errdefs.ErrNotFound)
	}
	return err
}

func (s *readOnlyStore) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
	if err := ctx.Err(); err != nil {
		return content.Info{}, err
	}
	path, err := resolveLayoutBlob(s.root, dgst)
	if err != nil {
		return content.Info{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return content.Info{}, notFound(err)
	}
	return content.Info{Digest: dgst, Size: info.Size(), CreatedAt: info.ModTime(), UpdatedAt: info.ModTime()}, nil
}

//nolint:gocritic // The content.Provider interface passes descriptors by value.
func (s *readOnlyStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := resolveLayoutBlob(s.root, desc.Digest)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, notFound(err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	return &fileReaderAt{File: file, size: info.Size()}, nil
}

type fileReaderAt struct {
	*os.File
	size int64
}

func (r *fileReaderAt) Size() int64 {
	return r.size
}

func (s *readOnlyStore) Update(context.Context, content.Info, ...string) (content.Info, error) {
	return content.Info{}, errReadOnlyLayout
}

func (s *readOnlyStore) Walk(context.Context, content.WalkFunc, ...string) error {
	return fmt.Errorf("walk OCI layout input: %w", errdefs.ErrNotImplemented)
}

func (s *readOnlyStore) Delete(context.Context, digest.Digest) error {
	return errReadOnlyLayout
}

func (s *readOnlyStore) Status(_ context.Context, ref string) (content.Status, error) {
	return content.Status{}, fmt.Errorf("ingest %q: %w", ref, errdefs.ErrNotFound)
}

func (s *readOnlyStore) ListStatuses(context.Context, ...string) ([]content.Status, error) {
	return nil, nil
}

func (s *readOnlyStore) Abort(context.Context, string) error {
	return errReadOnlyLayout
}

func (s *readOnlyStore) Writer(context.Context, ...content.WriterOpt) (content.Writer, error) {
	return nil, errReadOnlyLayout
}
