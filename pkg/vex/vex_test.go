package vex

import (
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types"
)

func TestTryOutputVexDocument(t *testing.T) {
	config := &buildkit.Config{}
	workingFolder := "/tmp"
	alpineManager, _ := pkgmgr.GetPackageManager("alpine", config, workingFolder)

	type args struct {
		updates *types.UpdateManifest
		pkgmgr  pkgmgr.PackageManager
		format  string
		file    string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "invalid format",
			args: args{
				updates: &types.UpdateManifest{},
				pkgmgr:  nil,
				format:  "fakevex",
				file:    "",
			},
			wantErr: true,
		},
		{
			name: "valid format",
			args: args{
				updates: &types.UpdateManifest{},
				pkgmgr:  alpineManager,
				format:  "openvex",
				file:    "/tmp/test",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := TryOutputVexDocument(tt.args.updates, tt.args.pkgmgr, tt.args.format, tt.args.file); (err != nil) != tt.wantErr {
				t.Errorf("TryOutputVexDocument() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
