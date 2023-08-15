package connhelpers

import (
	"testing"

	"github.com/moby/buildkit/client/connhelper"
	"github.com/stretchr/testify/assert"
)

func TestBuildx(t *testing.T) {
	_, err := connhelper.GetConnectionHelper("buildx://")
	assert.NoError(t, err)

	_, err = connhelper.GetConnectionHelper("buildx://foobar")
	assert.NoError(t, err)
}
