package common

import (
	"context"
	"os"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/util/progress/progressui"
	"github.com/opencontainers/go-digest"
	"github.com/project-copacetic/copacetic/pkg/tui"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// DisplayProgress starts a goroutine to display build progress.
// This encapsulates the common pattern used in both generate and patch commands.
// Uses progrock-based TUI for improved display when progress mode is auto/tty and TTY is available.
// Falls back to BuildKit's progressui for explicit modes (plain, quiet, rawjson) or debug mode.
func DisplayProgress(ctx context.Context, eg *errgroup.Group, buildChannel chan *client.SolveStatus, progress progressui.DisplayMode) {
	eg.Go(func() error {
		isDebug := log.GetLevel() >= log.DebugLevel

		// Pass the progress mode so user's --progress flag is respected
		display, err := tui.NewDisplay(os.Stderr, isDebug, progress)
		if err != nil {
			return err
		}

		_, err = display.UpdateFrom(ctx, buildChannel)
		return err
	})
}

// ForwardProgressWithPrefix forwards progress from src to dst, prefixing vertex names with the given prefix.
// This allows multiplexing multiple build progress streams into a single display.
func ForwardProgressWithPrefix(ctx context.Context, src <-chan *client.SolveStatus, dst chan<- *client.SolveStatus, prefix string) {
	for {
		select {
		case status, ok := <-src:
			if !ok {
				return
			}
			if status == nil {
				continue
			}

			// Clone and prefix vertex names
			prefixed := &client.SolveStatus{
				Vertexes: make([]*client.Vertex, len(status.Vertexes)),
				Statuses: status.Statuses, // Statuses reference vertices by digest, no need to modify
				Logs:     status.Logs,     // Logs reference vertices by digest, no need to modify
				Warnings: status.Warnings,
			}

			for i, v := range status.Vertexes {
				// Clone the vertex and prefix its name
				cloned := *v
				cloned.Name = "[" + prefix + "] " + v.Name
				// Create a new digest that includes the prefix to avoid collisions
				cloned.Digest = digest.FromString(prefix + ":" + v.Digest.String())
				prefixed.Vertexes[i] = &cloned
			}

			// Also update status and log references to use new digests
			prefixed.Statuses = make([]*client.VertexStatus, len(status.Statuses))
			for i, s := range status.Statuses {
				cloned := *s
				cloned.Vertex = digest.FromString(prefix + ":" + s.Vertex.String())
				prefixed.Statuses[i] = &cloned
			}

			prefixed.Logs = make([]*client.VertexLog, len(status.Logs))
			for i, l := range status.Logs {
				cloned := *l
				cloned.Vertex = digest.FromString(prefix + ":" + l.Vertex.String())
				prefixed.Logs[i] = &cloned
			}

			select {
			case dst <- prefixed:
			case <-ctx.Done():
				return
			}

		case <-ctx.Done():
			return
		}
	}
}
