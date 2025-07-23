package common

import (
	"context"
	"os"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/util/progress/progressui"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// DisplayProgress starts a goroutine to display build progress.
// This encapsulates the common pattern used in both generate and patch commands.
func DisplayProgress(ctx context.Context, eg *errgroup.Group, buildChannel chan *client.SolveStatus) {
	eg.Go(func() error {
		// Display progress
		mode := progressui.AutoMode
		if log.GetLevel() >= log.DebugLevel {
			mode = progressui.PlainMode
		}
		display, err := progressui.NewDisplay(os.Stderr, mode)
		if err != nil {
			return err
		}

		_, err = display.UpdateFrom(ctx, buildChannel)
		return err
	})
}
