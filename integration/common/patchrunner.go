package common

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Patch(t *testing.T,
	ref, patchedTag, reportDir string,
	ignoreErrors, reportFile bool,
	buildkitAddr, copaPath, scannerPlugin string,
	dockerEnv []string, push, multiarch bool) {
	var addrFl string
	if buildkitAddr != "" {
		addrFl = "-a=" + buildkitAddr
	}

	var reportPath string
	if !multiarch {
		if reportFile {
			reportPath = "-r" + reportDir + "/scan.json"
		}
	} else {
		reportPath = "--report=" + reportDir
	}

	args := []string{
		"patch",
		"-i=" + ref,
		"-t=" + patchedTag,
		reportPath,
		"-s=" + scannerPlugin,
		"--timeout=30m",
		addrFl,
		"--ignore-errors=" + strconv.FormatBool(ignoreErrors),
		"--debug",
	}
	if multiarch && push {
		args = append(args, "--push")
	}

	//#nosec G204
	cmd := exec.Command(
		copaPath,
		args...,
	)

	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, DockerDINDAddress.Env()...)

	out, err := cmd.CombinedOutput()

	if !multiarch && strings.Contains(ref, "oracle") && reportFile && !ignoreErrors {
		assert.Contains(t, string(out), "Error: detected Oracle image passed in\n"+
			"Please read https://project-copacetic.github.io/copacetic/website/troubleshooting before patching your Oracle image")
	} else {
		require.NoError(t, err, string(out))
	}

}
