// Package tui provides a terminal user interface for Copa using progrock.
package tui

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/util/progress/progressui"
	"github.com/vito/progrock"
	"golang.org/x/term"
)

// Display wraps either progrock or standard progressui based on debug mode.
type Display interface {
	UpdateFrom(ctx context.Context, ch chan *client.SolveStatus) ([]client.VertexWarning, error)
}

// NewDisplay creates a new display interface.
// Uses progrock TUI when not in debug mode, falls back to progressui in debug mode.
func NewDisplay(output *os.File, debugMode bool) (Display, error) {
	if debugMode {
		// Use plain text mode for debug (existing behavior)
		return progressui.NewDisplay(output, progressui.PlainMode)
	}

	// Check if we have a TTY for interactive display
	if !term.IsTerminal(int(output.Fd())) {
		// No TTY, use plain mode
		return progressui.NewDisplay(output, progressui.PlainMode)
	}

	// Use progrock for improved TUI experience
	return NewProgrockDisplay(output)
}

// progrockDisplay implements Display interface using progrock.
type progrockDisplay struct {
	output *os.File
	tape   *progrock.Tape
	ui     *progrock.UI
	rec    *progrock.Recorder
}

// NewProgrockDisplay creates a progrock-based display.
func NewProgrockDisplay(output *os.File) (Display, error) {
	tape := progrock.NewTape()
	tape.Focus(false)        // Don't focus by default
	tape.ShowInternal(false) // Hide internal vertices by default

	return &progrockDisplay{
		output: output,
		tape:   tape,
		ui:     progrock.DefaultUI(),
		rec:    progrock.NewRecorder(tape),
	}, nil
}

// UpdateFrom bridges buildkit progress to progrock.
func (d *progrockDisplay) UpdateFrom(ctx context.Context, ch chan *client.SolveStatus) ([]client.VertexWarning, error) {
	var warnings []client.VertexWarning
	var processErr error

	// Save terminal state before running progrock UI
	fd := int(d.output.Fd())
	oldState, stateErr := term.GetState(fd)
	if stateErr == nil {
		// Ensure terminal is restored no matter what happens
		defer func() {
			_ = term.Restore(fd, oldState)
		}()
	}

	// Create a cancelable context for the UI.
	// We cancel this when progress processing is done.
	uiCtx, cancelUI := context.WithCancel(ctx)
	defer cancelUI()

	// Run the progrock UI.
	// IMPORTANT:
	// - Ctrl+C is handled by bubbletea/progrock by canceling the callback ctx (runCtx).
	// - We must still cancel uiCtx to force ui.Run() to exit immediately after progress processing ends.
	err := d.ui.Run(uiCtx, d.tape, func(runCtx context.Context, _ progrock.UIClient) error {
		// procCtx cancels when either uiCtx is canceled (normal completion) or runCtx is
		// canceled (Ctrl+C handled by bubbletea).
		procCtx, cancelProc := context.WithCancel(uiCtx)
		defer cancelProc()
		go func() {
			select {
			case <-runCtx.Done():
				cancelProc()
			case <-procCtx.Done():
			}
		}()

		processErr = d.processBuildkitProgress(procCtx, ch, &warnings)

		// Ensure progrock exits promptly on both completion and Ctrl+C.
		d.tape.Close()
		cancelUI()
		return nil
	})

	// Close the recorder
	if closeErr := d.rec.Close(); closeErr != nil && err == nil {
		err = closeErr
	}

	// Return process error if UI exited cleanly but processing failed
	if err == nil && processErr != nil && processErr != context.Canceled {
		return warnings, processErr
	}

	// If canceled (Ctrl+C), return the process error
	if err == context.Canceled || processErr == context.Canceled {
		return warnings, context.Canceled
	}

	return warnings, err
}

// processBuildkitProgress processes buildkit progress events and translates them to progrock.
func (d *progrockDisplay) processBuildkitProgress(ctx context.Context, ch chan *client.SolveStatus, warnings *[]client.VertexWarning) error {
	vertices := make(map[string]*progrock.VertexRecorder)

	for {
		select {
		case status, ok := <-ch:
			if !ok {
				// Channel closed, mark remaining vertices as done and exit
				for _, vtx := range vertices {
					vtx.Done(nil)
				}
				return nil
			}

			if status == nil {
				continue
			}

			// Process vertex information
			for _, vertex := range status.Vertexes {
				vtxID := vertex.Digest.String()

				// Create or get existing vertex recorder
				vtx, exists := vertices[vtxID]
				if !exists {
					name := vertex.Name
					if name == "" {
						name = fmt.Sprintf("Step %s", vtxID[:8])
					}
					vtx = d.rec.Vertex(vertex.Digest, name)
					vertices[vtxID] = vtx
				}

				// Update vertex status based on buildkit vertex state
				if vertex.Cached {
					vtx.Cached()
				}

				if vertex.Completed != nil {
					// Vertex completed
					if vertex.Error != "" {
						vtx.Done(fmt.Errorf("%s", vertex.Error))
					} else {
						vtx.Done(nil)
					}
					delete(vertices, vtxID)
				}
			}

			// Process status updates (progress bars, etc)
			for _, statusUpdate := range status.Statuses {
				vtxID := statusUpdate.Vertex.String()
				if vtx, exists := vertices[vtxID]; exists {
					// Create progress task if we have total progress
					if statusUpdate.Total > 0 {
						progressTask := vtx.ProgressTask(statusUpdate.Total, "%s", statusUpdate.Name)
						progressTask.Current(statusUpdate.Current)
						if statusUpdate.Completed != nil {
							progressTask.Done(nil)
						}
					}
				}
			}

			// Process logs
			for _, log := range status.Logs {
				vtxID := log.Vertex.String()
				if vtx, exists := vertices[vtxID]; exists {
					// Format log message
					msg := string(log.Data)
					if !strings.HasSuffix(msg, "\n") {
						msg += "\n"
					}

					// Send to appropriate stream
					if log.Stream == 2 { // stderr
						fmt.Fprint(vtx.Stderr(), msg)
					} else { // stdout
						fmt.Fprint(vtx.Stdout(), msg)
					}
				}
			}

			// Collect warnings
			for _, w := range status.Warnings {
				*warnings = append(*warnings, *w)
			}

		case <-ctx.Done():
			// Context canceled (Ctrl+C), mark remaining vertices as done
			for _, vtx := range vertices {
				vtx.Done(nil)
			}
			return ctx.Err()
		}
	}
}


