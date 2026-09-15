package helm

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// CommandRunner runs the Helm CLI without invoking a shell.
type CommandRunner func(context.Context, ...string) ([]byte, error)

// RunHelm is replaceable in tests.
var RunHelm CommandRunner = runHelm

func runHelm(ctx context.Context, args ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, "helm", args...).CombinedOutput()
	if err == nil {
		return output, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
		return nil, fmt.Errorf("helm chart patching requires the helm CLI in PATH: %w", err)
	}
	return nil, fmt.Errorf("helm %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
}
