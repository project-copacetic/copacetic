// Package tui provides a terminal user interface for Copa using progrock.
package tui

import (
	"context"
	"errors"
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
// Uses progrock TUI when progress mode is auto/tty and we have a TTY.
// Falls back to BuildKit's progressui for explicit modes (plain, quiet, rawjson) or debug mode.
func NewDisplay(output *os.File, debugMode bool, progress progressui.DisplayMode) (Display, error) {
	// Debug mode always uses plain text for easier log reading
	if debugMode {
		return progressui.NewDisplay(output, progressui.PlainMode)
	}

	// Respect explicit user-specified modes (not auto/tty)
	switch progress {
	case progressui.PlainMode, progressui.QuietMode, progressui.RawJSONMode:
		// User explicitly requested a non-interactive mode
		return progressui.NewDisplay(output, progress)
	case progressui.AutoMode, progressui.TtyMode:
		// Auto or TTY mode: use progrock if we have a TTY
		if term.IsTerminal(int(output.Fd())) { //nolint:gosec // G115: fd always fits in int
			return NewProgrockDisplay(output)
		}
		// No TTY available, fall back to plain mode
		return progressui.NewDisplay(output, progressui.PlainMode)
	default:
		// Unknown mode, default to auto behavior
		if term.IsTerminal(int(output.Fd())) { //nolint:gosec // G115: fd always fits in int
			return NewProgrockDisplay(output)
		}
		return progressui.NewDisplay(output, progressui.PlainMode)
	}
}

// progrockDisplay implements Display interface using progrock.
type progrockDisplay struct {
	fd   int // file descriptor for terminal operations
	tape *progrock.Tape
	ui   *progrock.UI
	rec  *progrock.Recorder
}

// NewProgrockDisplay creates a progrock-based display.
func NewProgrockDisplay(output *os.File) (Display, error) {
	tape := progrock.NewTape()
	tape.Focus(false)        // Don't focus by default
	tape.ShowInternal(false) // Hide internal vertices by default

	return &progrockDisplay{
		fd:   int(output.Fd()), //nolint:gosec // G115: fd always fits in int
		tape: tape,
		ui:   progrock.DefaultUI(),
		rec:  progrock.NewRecorder(tape),
	}, nil
}

// UpdateFrom bridges buildkit progress to progrock.
func (d *progrockDisplay) UpdateFrom(ctx context.Context, ch chan *client.SolveStatus) ([]client.VertexWarning, error) {
	var warnings []client.VertexWarning
	var processErr error

	// Save terminal state before running progrock UI
	oldState, stateErr := term.GetState(d.fd)
	if stateErr == nil {
		// Ensure terminal is restored no matter what happens
		defer func() {
			_ = term.Restore(d.fd, oldState)
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
	type vertexState struct {
		rec   *progrock.VertexRecorder
		tasks map[string]progrockTask
	}

	vertices := make(map[string]*vertexState)

	for {
		select {
		case status, ok := <-ch:
			if !ok {
				// Channel closed, mark remaining vertices as done and exit
				for _, vtx := range vertices {
					vtx.rec.Done(nil)
				}
				return nil
			}

			if status == nil {
				continue
			}
			completedVertices := make([]string, 0, len(status.Vertexes))

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
					vtx = &vertexState{
						rec:   d.rec.Vertex(vertex.Digest, name),
						tasks: make(map[string]progrockTask),
					}
					vertices[vtxID] = vtx
				}

				// Update vertex status based on buildkit vertex state
				if vertex.Cached {
					vtx.rec.Cached()
				}

				if vertex.Completed != nil {
					// Vertex completed
					if vertex.Error != "" {
						vtx.rec.Done(errors.New(vertex.Error))
					} else {
						vtx.rec.Done(nil)
					}
					// Drop this vertex's progress tasks with the vertex state instead of
					// scanning unrelated task bookkeeping. Defer the deletion until this
					// entire SolveStatus batch is processed so final status/log records for
					// this vertex in the same BuildKit message are not dropped.
					completedVertices = append(completedVertices, vtxID)
				}
			}

			// Process status updates (progress bars, etc)
			for _, statusUpdate := range status.Statuses {
				vtxID := statusUpdate.Vertex.String()
				if vtx, exists := vertices[vtxID]; exists {
					// Create/update progress task if we have total progress.
					// Dedupe by status name within each vertex so we don't spam new tasks on every update.
					if statusUpdate.Total > 0 {
						task, ok := vtx.tasks[statusUpdate.Name]
						if !ok || task.total != statusUpdate.Total {
							task = progrockTask{
								rec:   vtx.rec.ProgressTask(statusUpdate.Total, "%s", statusUpdate.Name),
								total: statusUpdate.Total,
							}
							vtx.tasks[statusUpdate.Name] = task
						}
						task.rec.Current(statusUpdate.Current)
						if statusUpdate.Completed != nil {
							task.rec.Done(nil)
							delete(vtx.tasks, statusUpdate.Name)
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
						fmt.Fprint(vtx.rec.Stderr(), msg)
					} else { // stdout
						fmt.Fprint(vtx.rec.Stdout(), msg)
					}
				}
			}

			// Collect warnings
			for _, w := range status.Warnings {
				if w != nil {
					*warnings = append(*warnings, *w)
				}
			}

			for _, vtxID := range completedVertices {
				delete(vertices, vtxID)
			}

		case <-ctx.Done():
			// Context canceled (Ctrl+C), mark remaining vertices as done
			for _, vtx := range vertices {
				vtx.rec.Done(nil)
			}
			return ctx.Err()
		}
	}
}

type progrockTask struct {
	rec   *progrock.TaskRecorder
	total int64
}
