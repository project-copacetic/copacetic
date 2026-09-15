package integration

import (
	"flag"
	"os"
	"testing"
)

var copaPath string

func TestMain(m *testing.M) {
	flag.StringVar(&copaPath, "copa", "./copa", "path to copa binary")

	flag.Parse()

	if copaPath == "" {
		panic("missing --copa")
	}

	ec := m.Run()
	os.Exit(ec)
}
