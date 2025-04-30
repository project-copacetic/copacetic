package plugin

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
			image:  "docker.io/library/alpine:3.14.0",
			report: "./testdata/invalid_report.json",
			err:    fmt.Errorf("exit status 1"),
		},
		{
			image:  "docker.io/library/alpine:3.7.3",
			report: "./testdata/valid_report.json",
			err:    nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.image, func(t *testing.T) {
			t.Parallel()
			_, err := runPatch(tc.image, tc.report)
			if err != nil {
				assert.Equal(t, tc.err, fmt.Errorf("%s", err.Error()))
			} else {
				assert.Equal(t, tc.err, nil)
			}
		})
	}
}

func runPatch(image, report string) ([]byte, error) {
	//#nosec G204
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
