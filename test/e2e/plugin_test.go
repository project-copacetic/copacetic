package e2e

import (
	"fmt"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlugins(t *testing.T) {
	testCases := []struct {
		image  string
		report string
		err    error
	}{
		{
			image:  "docker.io/library/nginx:1.23",
			report: "./testdata/fake_report.json",
			err:    fmt.Errorf("Error: unsupported osType FakeOS specified\n"),
		},
		{
			image:  "docker.io/library/alpine:3.14.0",
			report: "./testdata/invalid_report.json",
			err:    fmt.Errorf("Error: error running scanner fake: exit status 1\n"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.image, func(t *testing.T) {
			out, _ := runPatch(t, tc.image, tc.report)
			assert.Equal(t, tc.err, fmt.Errorf(string(out)))
		})
	}
}

func runPatch(t *testing.T, image, report string) ([]byte, error) {
	cmd := exec.Command(
		copaPath,
		"patch",
		"-i="+image,
		"-r="+report,
		"-s="+scannerPlugin,
		"-a="+buildkitAddr,
	)
	out, err := cmd.CombinedOutput()
	return out, err
}
