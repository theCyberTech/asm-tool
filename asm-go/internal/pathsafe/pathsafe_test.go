package pathsafe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFileAllowsFileInWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	content := []byte(`{"domain":"example.com"}`)
	if err := os.WriteFile("input.json", content, 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := ReadFile("input.json", MaxReportJSONBytes)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("ReadFile() = %q, want %q", got, content)
	}
}

func TestReadFileAllowsSiblingPathUnderProjectRoot(t *testing.T) {
	root := t.TempDir()
	asmGo := filepath.Join(root, "asm-go")
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(asmGo, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.example.yaml"), []byte("example"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(asmGo, "go.mod"), []byte("module example\n"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	content := []byte(`{"domains":{}}`)
	if err := os.WriteFile(filepath.Join(dataDir, "asm.db"), content, 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	t.Chdir(asmGo)

	got, err := ReadFile("../data/asm.db", MaxMigrateFileBytes)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("ReadFile() = %q, want %q", got, content)
	}
}

func TestReadFileRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	outside := filepath.Join(dir, "..", "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	_, err := ReadFile("../outside.txt", MaxReportJSONBytes)
	if err == nil {
		t.Fatal("ReadFile() expected error for path traversal")
	}
	if !strings.Contains(err.Error(), "outside the allowed directory") {
		t.Fatalf("ReadFile() error = %v, want outside allowed directory", err)
	}
}

func TestReadFileRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if err := os.WriteFile("large.json", make([]byte, 32), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := ReadFile("large.json", 16)
	if err == nil {
		t.Fatal("ReadFile() expected error for oversized file")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("ReadFile() error = %v, want size limit error", err)
	}
}

func TestStatRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if err := os.Mkdir("data", 0755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}

	_, err := Stat("data")
	if err == nil {
		t.Fatal("Stat() expected error for directory")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Stat() error = %v, want not a regular file", err)
	}
}
