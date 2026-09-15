package generate

import (
	"flag"
	"os"
	"testing"
)

var (
	copaPath     string
	buildkitAddr string
)

func TestMain(m *testing.M) {
	flag.StringVar(&buildkitAddr, "addr", "docker://", "buildkit address to pass through to copa binary")
	flag.StringVar(&copaPath, "copa", "./copa", "path to copa binary")
	flag.Parse()

	if copaPath == "" {
		panic("missing --copa")
	}

	ec := m.Run()
	os.Exit(ec)
}
