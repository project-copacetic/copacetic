package testenv

import (
	"context"
	"fmt"

	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	fstypes "github.com/tonistiigi/fsutil/types"
)

// RefInspector provides methods to inspect a BuildKit Reference's filesystem.
// This allows tests to read files, check file existence, and list directories
// without exporting the image.
type RefInspector struct {
	ctx context.Context
	ref gwclient.Reference
}

// NewRefInspector creates an inspector from a gateway Result.
// The result must contain exactly one reference (use SingleRef internally).
func NewRefInspector(ctx context.Context, result *gwclient.Result) (*RefInspector, error) {
	if result == nil {
		return nil, fmt.Errorf("result is nil")
	}

	ref, err := result.SingleRef()
	if err != nil {
		return nil, fmt.Errorf("failed to get single ref from result: %w", err)
	}

	if ref == nil {
		return nil, fmt.Errorf("reference is nil")
	}

	return &RefInspector{ctx: ctx, ref: ref}, nil
}

// NewRefInspectorFromRef creates an inspector from a specific Reference.
// This is useful when working with multi-platform results where you need
// to inspect a specific platform's reference.
func NewRefInspectorFromRef(ctx context.Context, ref gwclient.Reference) (*RefInspector, error) {
	if ref == nil {
		return nil, fmt.Errorf("reference is nil")
	}
	return &RefInspector{ctx: ctx, ref: ref}, nil
}

// ReadFile reads the contents of a file at the given path.
// Returns the file contents as bytes, or an error if the file doesn't exist
// or cannot be read.
func (r *RefInspector) ReadFile(path string) ([]byte, error) {
	return r.ref.ReadFile(r.ctx, gwclient.ReadRequest{
		Filename: path,
	})
}

// ReadFileRange reads a range of bytes from a file.
// Offset specifies the starting position, length specifies how many bytes to read.
func (r *RefInspector) ReadFileRange(path string, offset, length int) ([]byte, error) {
	req := gwclient.ReadRequest{
		Filename: path,
		Range: &gwclient.FileRange{
			Offset: offset,
			Length: length,
		},
	}
	return r.ref.ReadFile(r.ctx, req)
}

// StatFile returns file metadata for the given path.
// This is useful for checking file permissions, size, modification time, etc.
func (r *RefInspector) StatFile(path string) (*fstypes.Stat, error) {
	return r.ref.StatFile(r.ctx, gwclient.StatRequest{
		Path: path,
	})
}

// ReadDir lists the contents of a directory.
// Returns a slice of file stats for all entries in the directory.
func (r *RefInspector) ReadDir(path string) ([]*fstypes.Stat, error) {
	return r.ref.ReadDir(r.ctx, gwclient.ReadDirRequest{
		Path: path,
	})
}

// FileExists checks if a file exists at the given path.
// Returns true if the file exists, false otherwise.
func (r *RefInspector) FileExists(path string) bool {
	_, err := r.StatFile(path)
	return err == nil
}

// DirExists checks if a directory exists at the given path.
// Returns true if the path exists and is a directory.
func (r *RefInspector) DirExists(path string) bool {
	stat, err := r.StatFile(path)
	if err != nil {
		return false
	}
	return stat.IsDir()
}

// IsSymlink checks if the path is a symbolic link.
func (r *RefInspector) IsSymlink(path string) bool {
	stat, err := r.StatFile(path)
	if err != nil {
		return false
	}
	// Check if it's a symlink (mode & os.ModeSymlink)
	return stat.Linkname != ""
}

// ReadSymlink returns the target of a symbolic link.
func (r *RefInspector) ReadSymlink(path string) (string, error) {
	stat, err := r.StatFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat %s: %w", path, err)
	}
	if stat.Linkname == "" {
		return "", fmt.Errorf("%s is not a symbolic link", path)
	}
	return stat.Linkname, nil
}

// Reference returns the underlying gateway Reference.
// This can be useful for advanced operations not covered by this inspector.
func (r *RefInspector) Reference() gwclient.Reference {
	return r.ref
}
