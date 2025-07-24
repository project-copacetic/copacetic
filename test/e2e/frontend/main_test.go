package frontend

import (
	"flag"
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
		panic("missing --copa")
	}

	if frontendImage == "" {
		panic("missing --frontend-image")
	}

	ec := m.Run()
	os.Exit(ec)
}
