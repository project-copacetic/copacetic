package buildkit

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/opencontainers/go-digest"
)

// LocalSourceArchive shares one save of a locally named source among the
// manifest lookups of one patch operation, so a multi-platform source is not
// saved again for each platform. The first lookup that reads the archive gets
// the outcome its own read would have. The archive is kept only when its root
// is the captured source root; otherwise every later lookup reads the archive
// itself, so moved or unreadable content is never reused. A nil archive reads
// for each lookup.
type LocalSourceArchive struct {
	mu      sync.Mutex
	name    string
	root    digest.Digest
	read    bool
	archive *localArchiveMetadata
}

// NewLocalSourceArchive returns an unread archive of image bound to the
// captured root digest.
func NewLocalSourceArchive(image string, root digest.Digest) *LocalSourceArchive {
	return &LocalSourceArchive{name: localSourceName(image), root: root}
}

func localSourceName(image string) string {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return ""
	}
	return reference.TagNameOnly(named).String()
}

// shares reports whether a lookup through image may use the shared read.
func (s *LocalSourceArchive) shares(image string) bool {
	return s != nil && s.name != "" && s.root.Validate() == nil && localSourceName(image) == s.name
}

// readArchive reads the archive for the first lookup. The caller keeps it only
// after that lookup has accepted it.
func (s *LocalSourceArchive) readArchive(ctx context.Context, image string) (*localArchiveMetadata, error) {
	s.read = true
	return readLocalImageArchive(ctx, image)
}

func (s *LocalSourceArchive) keep(archive *localArchiveMetadata) {
	if archive != nil && digest.Digest(archive.root.Digest.String()) == s.root {
		s.archive = archive
	}
}

// ManifestAnnotations returns what LocalImageManifestAnnotations returns for
// the same lookup, reading the archive at most once while it has the captured
// root.
func (s *LocalSourceArchive) ManifestAnnotations(ctx context.Context, image string, selected digest.Digest) (map[string]string, error) {
	if !s.shares(image) {
		return LocalImageManifestAnnotations(ctx, image, selected)
	}
	if err := selected.Validate(); err != nil {
		return nil, fmt.Errorf("invalid selected local manifest: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	archive := s.archive
	if archive == nil {
		if s.read {
			return LocalImageManifestAnnotations(ctx, image, selected)
		}
		var err error
		archive, err = s.readArchive(ctx, image)
		var saveErr *localSaveError
		if errors.As(err, &saveErr) {
			err = saveErr.error
		}
		if err != nil || archive == nil {
			return nil, err // A classic Docker-save archive has no manifests.
		}
		s.keep(archive)
	}
	desc, err := archive.descriptorForManifest(selected)
	if err != nil || desc == nil {
		return nil, err
	}
	return desc.Annotations, nil
}

// Metadata returns what LocalImageMetadata returns for the same lookup,
// reading the archive at most once while it has the captured root. Unavailable
// local sources are still detected before any save.
func (s *LocalSourceArchive) Metadata(ctx context.Context, parent string, selected digest.Digest) (*remote.Descriptor, []byte, error) {
	if !s.shares(parent) {
		return LocalImageMetadata(ctx, parent, selected)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.archive == nil {
		if s.read {
			return LocalImageMetadata(ctx, parent, selected)
		}
		var read *localArchiveMetadata
		desc, config, err := localImageMetadata(ctx, parent, selected, func(ctx context.Context, image string) (*localArchiveMetadata, error) {
			archive, err := s.readArchive(ctx, image)
			read = archive
			return archive, err
		})
		if err == nil {
			s.keep(read)
		}
		return desc, config, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := selected.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid selected local manifest: %w", err)
	}
	if !selected.Algorithm().Available() {
		return nil, nil, fmt.Errorf("selected local manifest uses an unavailable digest algorithm")
	}
	return s.archive.selectedMetadata(selected)
}
