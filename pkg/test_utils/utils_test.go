package testutils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateTempFileWithContent(t *testing.T) {
	// Create a temporary directory for the test files
	dir := t.TempDir()
	defer os.RemoveAll(dir)

	// Test creating a file with a given database type and content
	t.Run("creates_file_with_content", func(t *testing.T) {
		dbType := "testdb"
		CreateTempFileWithContent(dir, dbType)
		path := filepath.Join(dir, dbType)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("Error reading file %s: %v", path, err)
		}
		if string(content) != "test" {
			t.Errorf("Unexpected content in file %s: %s", path, content)
		}
	})

	// Test that the file is created in the correct directory
	t.Run("creates_file_in_correct_directory", func(t *testing.T) {
		dbType := "otherdb"
		CreateTempFileWithContent(dir, dbType)
		path := filepath.Join(dir, dbType)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("File %s does not exist", path)
		}
	})
}
