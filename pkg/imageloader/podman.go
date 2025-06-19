package imageloader

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

type podmanLoader struct{}

// probePodman now just checks the CLI is available.
func probePodman(_ context.Context) (Loader, bool) {
	if _, err := exec.LookPath("podman"); err != nil {
		log.Debug("podman CLI not found in $PATH")
		return nil, false
	}
	return &podmanLoader{}, true
}

// Load streams the tar straight into `podman load` via stdin.
func (p *podmanLoader) Load(ctx context.Context, tar io.Reader, _ string) error {
	log.Debug("Loading image stream using podman CLI")
	cmd := exec.CommandContext(ctx, "podman", "load")
	cmd.Stdin = tar

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf("podman load: %v: %s", err, strings.TrimSpace(string(out)))
		return fmt.Errorf("podman load: %w", err)
	}

	log.Debugf("image loaded via podman CLI: %s", strings.TrimSpace(string(out)))
	return nil
}
