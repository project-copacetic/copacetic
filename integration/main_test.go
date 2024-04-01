package integration

import (
	"flag"
	"os"
	"testing"
)

var (
	buildkitAddr  string
	copaPath      string
	ignoreErrors  bool
	scannerPlugin string
	reportFile    bool
)

func TestMain(m *testing.M) {
	flag.StringVar(&buildkitAddr, "addr", "", "buildkit address to pass through to copa binary")
	flag.StringVar(&copaPath, "copa", "./copa", "path to copa binary")
	flag.StringVar(&scannerPlugin, "scanner", "trivy", "Scanner used to generate the report")
	flag.BoolVar(&ignoreErrors, "ignore-errors", false, "Ignore errors and continue patching")
	flag.BoolVar(&reportFile, "report-file", false, "report file")
	flag.Parse()

	if copaPath == "" {
		panic("missing --copa")
	}

	ec := m.Run()
	os.Exit(ec)
}
