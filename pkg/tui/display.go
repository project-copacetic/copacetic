package tui

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/vito/progrock"
	"github.com/moby/buildkit/util/progress/progressui"
	"github.com/moby/buildkit/client"
)

// Display wraps either progrock or standard progressui based on debug mode
type Display interface {
	UpdateFrom(ctx context.Context, ch chan *client.SolveStatus) ([]client.VertexWarning, error)
}

// NewDisplay creates a new display interface
// Uses progrock TUI when not in debug mode, falls back to progressui in debug mode
func NewDisplay(output io.Writer, debugMode bool) (Display, error) {
	if debugMode {
		// Use plain text mode for debug (existing behavior)
		return progressui.NewDisplay(output, progressui.PlainMode)
	}
	
	// Use progrock for improved TUI experience
	return NewProgrockDisplay(output)
}

// progrockDisplay implements Display interface using progrock
type progrockDisplay struct {
	output io.Writer
	tape   *progrock.Tape
	ui     *progrock.UI
	rec    *progrock.Recorder
}

// NewProgrockDisplay creates a progrock-based display
func NewProgrockDisplay(output io.Writer) (Display, error) {
	tape := progrock.NewTape()
	tape.Focus(false) // Don't focus by default
	tape.ShowInternal(false) // Hide internal vertices by default

	ui := progrock.DefaultUI()
	
	return &progrockDisplay{
		output: output,
		tape:   tape,
		ui:     ui,
		rec:    progrock.NewRecorder(tape),
	}, nil
}

// UpdateFrom bridges buildkit progress to progrock
func (d *progrockDisplay) UpdateFrom(ctx context.Context, ch chan *client.SolveStatus) ([]client.VertexWarning, error) {
	// Context with progrock recorder
	ctx = progrock.ToContext(ctx, d.rec)
	
	// Run the progrock UI in a separate goroutine
	errChan := make(chan error, 1)
	var warnings []client.VertexWarning
	
	go func() {
		err := d.ui.Run(ctx, d.tape, func(ctx context.Context, ui progrock.UIClient) error {
			return d.processBuildkitProgress(ctx, ui, ch)
		})
		errChan <- err
	}()
	
	select {
	case err := <-errChan:
		return warnings, err
	case <-ctx.Done():
		return warnings, ctx.Err()
	}
}

// processBuildkitProgress processes buildkit progress events and translates them to progrock
func (d *progrockDisplay) processBuildkitProgress(ctx context.Context, ui progrock.UIClient, ch chan *client.SolveStatus) error {
	rec := progrock.FromContext(ctx)
	vertices := make(map[string]*progrock.VertexRecorder)
	
	for {
		select {
		case status, ok := <-ch:
			if !ok {
				// Channel closed, we're done
				if err := rec.Close(); err != nil {
					return err
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
					vtx = rec.Vertex(vertex.Digest, name)
					vertices[vtxID] = vtx
				}
				
				// Update vertex status based on buildkit vertex state
				if vertex.Completed != nil {
					// Vertex completed
					if vertex.Error != "" {
						vtx.Done(fmt.Errorf("%s", vertex.Error))
					} else {
						vtx.Done(nil)
					}
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
					if log.Stream == 1 { // stdout
						fmt.Fprint(vtx.Stdout(), msg)
					} else { // stderr or default
						fmt.Fprint(vtx.Stderr(), msg)
					}
				}
			}
			
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}