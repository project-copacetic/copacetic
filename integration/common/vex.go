package common

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ValidateVEXJSON(t *testing.T, dir string) {
	vexFile := filepath.Join(dir, "vex.json")
	if _, err := os.Stat(vexFile); os.IsNotExist(err) {
		t.Errorf("VEX file does not exist: %s", vexFile)
		return
	}
	content, err := os.ReadFile(vexFile)
	require.NoError(t, err, "Failed to read VEX file")
	var vexData any
	err = json.Unmarshal(content, &vexData)
	require.NoError(t, err, "VEX file contains invalid JSON")
	assert.True(t, json.Valid(content), "vex.json is not valid json")
	t.Logf("VEX file is valid JSON with %d bytes", len(content))
}
