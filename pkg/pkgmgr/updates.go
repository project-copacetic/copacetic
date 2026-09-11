package pkgmgr

import (
	"context"
	_ "embed"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

const updatesAvailableMarker = "/updates.txt"

//go:embed scripts/check_updates.sh
var checkUpdatesScript string

func checkAvailableUpdates(ctx context.Context, client gwclient.Client, state *llb.State, manager, tool string) error {
	checked := state.Run(
		llb.Args([]string{"/bin/sh", "-c", checkUpdatesScript, "copa-check-updates", manager, tool, updatesAvailableMarker}),
		llb.WithProxy(utils.GetProxy()),
		// Repository contents can change without changing this image or command.
		llb.IgnoreCache,
		llb.WithCustomName("Checking for available updates"),
	).Root()
	return checkUpdatesMarker(ctx, client, &checked, updatesAvailableMarker)
}

// A missing marker means no updates only after the build completed successfully.
// Preserve solve, cancellation, and unrelated file-read errors for the caller.
func checkUpdatesMarker(ctx context.Context, client gwclient.Client, state *llb.State, marker string) error {
	_, err := buildkit.TryExtractFileFromState(ctx, client, state, marker)
	if err != nil {
		if isMarkerMissingErr(err, marker) {
			return types.ErrNoUpdatesFound
		}
		return err
	}
	return nil
}
