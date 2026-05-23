package pathsafe

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// MaxReportJSONBytes caps report-convert input size.
	MaxReportJSONBytes = 64 << 20
	// MaxMigrateFileBytes caps TinyDB migration input size.
	MaxMigrateFileBytes = 512 << 20
)

// ReadFile reads a regular file that resolves under the allowed project tree.
// Relative paths are resolved from the current working directory. Paths must
// remain inside the detected project root (or the working directory when no
// project root is found) after symlink evaluation.
func ReadFile(path string, maxBytes int64) ([]byte, error) {
	return readResolvedFile(path, maxBytes, true)
}

// Stat checks that path resolves to a regular file under the allowed project tree.
func Stat(path string) (os.FileInfo, error) {
	_, info, err := resolveRegularFile(path)
	return info, err
}

func readResolvedFile(path string, maxBytes int64, requireRegular bool) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("maxBytes must be positive")
	}

	evalPath, info, err := resolveRegularFile(path)
	if err != nil {
		return nil, err
	}
	if requireRegular && info != nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("path %q is not a regular file", path)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file exceeds maximum size of %d bytes", maxBytes)
	}

	f, err := os.Open(evalPath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds maximum size of %d bytes", maxBytes)
	}

	return data, nil
}

func resolveRegularFile(path string) (string, os.FileInfo, error) {
	baseDir, err := resolveAllowedBase()
	if err != nil {
		return "", nil, err
	}

	candidate := path
	if !filepath.IsAbs(candidate) {
		wd, err := resolveWorkingDirectory()
		if err != nil {
			return "", nil, err
		}
		candidate = filepath.Join(wd, candidate)
	}
	absPath, err := filepath.Abs(filepath.Clean(candidate))
	if err != nil {
		return "", nil, fmt.Errorf("resolving path: %w", err)
	}
	if !withinBase(absPath, baseDir) {
		return "", nil, fmt.Errorf("path %q is outside the allowed directory", path)
	}

	evalPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", nil, fmt.Errorf("resolving path: %w", err)
	}
	if !withinBase(evalPath, baseDir) {
		return "", nil, fmt.Errorf("path %q resolves outside the allowed directory", path)
	}

	info, err := os.Stat(evalPath)
	if err != nil {
		return "", nil, fmt.Errorf("reading file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("path %q is not a regular file", path)
	}

	return evalPath, info, nil
}

func resolveWorkingDirectory() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolving working directory: %w", err)
	}

	baseDir, err := filepath.Abs(wd)
	if err != nil {
		return "", fmt.Errorf("resolving working directory: %w", err)
	}

	evalBase, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return baseDir, nil
	}

	return evalBase, nil
}

func resolveAllowedBase() (string, error) {
	wd, err := resolveWorkingDirectory()
	if err != nil {
		return "", err
	}

	dir := wd
	for {
		if isProjectRoot(dir) {
			evalRoot, err := filepath.EvalSymlinks(dir)
			if err != nil {
				return dir, nil
			}
			return evalRoot, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return wd, nil
}

func isProjectRoot(dir string) bool {
	if pathExists(filepath.Join(dir, ".git")) {
		return true
	}

	hasASMGo := pathExists(filepath.Join(dir, "asm-go", "go.mod"))
	if !hasASMGo {
		return false
	}

	return pathExists(filepath.Join(dir, "config.example.yaml")) ||
		pathExists(filepath.Join(dir, "asm.sh"))
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func withinBase(path, base string) bool {
	path = filepath.Clean(path)
	base = filepath.Clean(base)
	if path == base {
		return true
	}

	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}

	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
