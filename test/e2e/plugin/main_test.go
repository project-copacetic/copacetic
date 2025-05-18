package plugin

import (
	"flag"
	"os"
	"testing"
)

var (
	buildkitAddr  string
	copaPath      string
	scannerPlugin string
)

func TestMain(m *testing.M) {
	flag.StringVar(&buildkitAddr, "addr", "", "buildkit address to pass through to copa binary")
	flag.StringVar(&copaPath, "copa", "./copa", "path to copa binary")
	flag.StringVar(&scannerPlugin, "scanner", "trivy", "Scanner used to generate the report")
	flag.Parse()

	if copaPath == "" {
		panic("missing --copa")
	}

	ec := m.Run()
	os.Exit(ec)
}
