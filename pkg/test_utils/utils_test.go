/*
Copyright (c) Project Copacetic authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
