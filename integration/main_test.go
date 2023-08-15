package integration

import (
	"flag"
	"os"
	"testing"
)

var (
	buildkitAddr string
	copaPath     string
	cacheFrom    string
	cacheTo      string
)

func TestMain(m *testing.M) {
	flag.StringVar(&buildkitAddr, "addr", "", "buildkit address to pass through to copa binary")
	flag.StringVar(&copaPath, "copa", "./copa", "path to copa binary")
	flag.StringVar(&cacheFrom, "cache-from", "", "pass through cache-from to copa binary")
	flag.StringVar(&cacheTo, "cache-to", "", "pass through cache-to to copa binary")
	flag.Parse()

	if copaPath == "" {
		panic("missing --copa")
	}

	ec := m.Run()
	os.Exit(ec)
}
