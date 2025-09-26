package frontend

import (
	"flag"
	"fmt"
	"os"
	"testing"
)

var (
	copaPath      string
	frontendImage string
	buildkitAddr  string
)

func TestMain(m *testing.M) {
	flag.StringVar(&buildkitAddr, "addr", "docker://", "buildkit address to pass through to buildctl")
	flag.StringVar(&copaPath, "copa", "./copa", "path to copa binary")
	flag.StringVar(&frontendImage, "frontend-image", "copa-frontend:test", "copa frontend image to use for testing")
	flag.Parse()

	if copaPath == "" {
		fmt.Fprintf(os.Stderr, "Error: missing --copa flag\n")
		os.Exit(1)
	}

	if frontendImage == "" {
		fmt.Fprintf(os.Stderr, "Error: missing --frontend-image flag\n")
		os.Exit(1)
	}

	ec := m.Run()
	os.Exit(ec)
}
