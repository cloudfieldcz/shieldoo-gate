package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Allowed values mirror the API's `?ecosystem=` query param.
var validEcosystems = map[string]bool{
	"pypi": true, "npm": true, "docker": true, "go": true, "multi": true,
}

// detectEcosystem returns one of {docker,go,npm,pypi,multi} based on the
// presence of well-known marker files in dir. The order encodes precedence.
func detectEcosystem(dir string) (string, error) {
	type marker struct {
		file string
		eco  string
	}
	markers := []marker{
		{"Dockerfile", "docker"},
		{"Containerfile", "docker"},
		{"go.mod", "go"},
		{"package.json", "npm"},
		{"requirements.txt", "pypi"},
		{"pyproject.toml", "pypi"},
	}
	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(dir, m.file)); err == nil {
			return m.eco, nil
		}
	}
	return "multi", nil
}

// resolveEcosystem returns explicit when explicit != "auto", else falls back
// to detection. Errors when explicit is set but invalid.
//
// When hasImage is true and explicit is empty/"auto", the function returns
// "docker" without inspecting the filesystem — an image scan's source shape
// is the image itself, not the surrounding directory.
func resolveEcosystem(explicit, dir string, hasImage bool) (string, error) {
	if explicit != "" && explicit != "auto" {
		if !validEcosystems[explicit] {
			return "", fmt.Errorf("unsupported ecosystem %q (allowed: pypi|npm|docker|go|multi|auto)", explicit)
		}
		return explicit, nil
	}
	if hasImage {
		return "docker", nil
	}
	return detectEcosystem(dir)
}
