package chisel

import (
	"flag"
	"os"
	"testing"
)

var (
	buildkitAddr string
	copaPath     string
)

func TestMain(m *testing.M) {
	flag.StringVar(&buildkitAddr, "addr", "docker://", "buildkit address to pass through to copa binary")
	flag.StringVar(&copaPath, "copa", "../../../dist/linux_amd64/release/copa", "path to copa binary")
	flag.Parse()

	if copaPath == "" {
		panic("missing --copa")
	}

	os.Exit(m.Run())
}
