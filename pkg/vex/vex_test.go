package vex

import (
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

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
