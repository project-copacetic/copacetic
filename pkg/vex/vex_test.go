package vex

import (
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

func TestTryOutputVexDocument(t *testing.T) {
	config := &buildkit.Config{}
	workingFolder := "/tmp"
	alpineManager, _ := pkgmgr.GetPackageManager("alpine", config, workingFolder)
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
			if err := TryOutputVexDocument(tt.args.updates, tt.args.pkgmgr, tt.args.patchedImageName, tt.args.format, tt.args.file); (err != nil) != tt.wantErr {
				t.Errorf("TryOutputVexDocument() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
