package vex

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

const existingVEXContent = "existing vex content"

func TestTryOutputVexDocument(t *testing.T) {
	config := &buildkit.Config{}
	alpineManager, _ := pkgmgr.GetPackageManager("alpine", "", config, utils.DefaultTempWorkingFolder)
	patchedImageName := "patched"

	type args struct {
		updates          *unversioned.UpdateManifest
		pkgmgr           pkgmgr.PackageManager
		patchedImageName string
		format           string
		file             string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "invalid format",
			args: args{
				updates:          &unversioned.UpdateManifest{},
				pkgmgr:           nil,
				patchedImageName: patchedImageName,
				format:           "fakevex",
				file:             "",
			},
			wantErr: true,
		},
		{
			name: "valid format",
			args: args{
				updates:          &unversioned.UpdateManifest{},
				pkgmgr:           alpineManager,
				patchedImageName: patchedImageName,
				format:           "openvex",
				file:             "/tmp/test",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pkgType string
			if tt.args.pkgmgr != nil {
				pkgType = tt.args.pkgmgr.GetPackageType()
			}
			if err := TryOutputVexDocument(tt.args.updates, pkgType, tt.args.patchedImageName, tt.args.format, tt.args.file); (err != nil) != tt.wantErr {
				t.Errorf("TryOutputVexDocument() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWriteVEXDocumentFilePreservesExistingFileOnWriteError(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "vex.json")
	if err := os.WriteFile(outputPath, []byte(existingVEXContent), 0o600); err != nil {
		t.Fatalf("failed to seed output file: %v", err)
	}

	writeErr := errors.New("write failed")
	err := writeVEXDocumentFile(outputPath, func(w io.Writer) error {
		if _, err := w.Write([]byte("partial")); err != nil {
			return err
		}
		return writeErr
	})
	if !errors.Is(err, writeErr) {
		t.Fatalf("writeVEXDocumentFile() error = %v, want %v", err, writeErr)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if string(got) != existingVEXContent {
		t.Fatalf("output file content = %q, want %q", got, existingVEXContent)
	}

	tmpFiles, err := filepath.Glob(filepath.Join(dir, ".vex.json.tmp-*"))
	if err != nil {
		t.Fatalf("failed to glob temp files: %v", err)
	}
	if len(tmpFiles) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", tmpFiles)
	}
}

func TestWriteVEXDocumentFileReplacesOutputOnSuccess(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "vex.json")
	if err := os.WriteFile(outputPath, []byte(existingVEXContent), 0o600); err != nil {
		t.Fatalf("failed to seed output file: %v", err)
	}

	const updatedContent = "updated vex content"
	if err := writeVEXDocumentFile(outputPath, func(w io.Writer) error {
		_, err := w.Write([]byte(updatedContent))
		return err
	}); err != nil {
		t.Fatalf("writeVEXDocumentFile() error = %v", err)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if string(got) != updatedContent {
		t.Fatalf("output file content = %q, want %q", got, updatedContent)
	}
}

func TestWriteVEXDocumentFilePreservesExistingFileMode(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "vex.json")
	const existingMode = 0o640
	if err := os.WriteFile(outputPath, []byte(existingVEXContent), existingMode); err != nil {
		t.Fatalf("failed to seed output file: %v", err)
	}

	if err := writeVEXDocumentFile(outputPath, func(w io.Writer) error {
		_, err := w.Write([]byte("updated"))
		return err
	}); err != nil {
		t.Fatalf("writeVEXDocumentFile() error = %v", err)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("failed to stat output file: %v", err)
	}
	if got := info.Mode().Perm(); got != existingMode {
		t.Fatalf("output file mode = %v, want %v", got, os.FileMode(existingMode))
	}
}
