package connhelpers

import (
	"testing"

	"github.com/moby/buildkit/client/connhelper"
	"github.com/stretchr/testify/assert"
)

func TestDocker(t *testing.T) {
	_, err := connhelper.GetConnectionHelper("docker://")
	assert.NoError(t, err)
}
