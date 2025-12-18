package common

import (
	"context"
	"os"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/util/progress/progressui"
	"github.com/project-copacetic/copacetic/pkg/tui"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// DisplayProgress starts a goroutine to display build progress.
// This encapsulates the common pattern used in both generate and patch commands.
// Uses progrock-based TUI for improved display when in TTY mode, falls back to
// BuildKit's progressui for debug mode or non-TTY environments.
func DisplayProgress(ctx context.Context, eg *errgroup.Group, buildChannel chan *client.SolveStatus, progress progressui.DisplayMode) {
	eg.Go(func() error {
		isDebug := log.GetLevel() >= log.DebugLevel

		// Use the new TUI display which handles progrock vs progressui internally
		display, err := tui.NewDisplay(os.Stderr, isDebug)
		if err != nil {
			return err
		}

		_, err = display.UpdateFrom(ctx, buildChannel)
		return err
	})
}
