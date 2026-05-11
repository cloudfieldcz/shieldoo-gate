package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectEcosystem_Dockerfile_ReturnsDocker(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile")
	got, err := detectEcosystem(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "docker" {
		t.Errorf("got %q, want docker", got)
	}
}

// --image short-circuits filesystem-marker detection: even when the dir
// contains a go.mod / package.json / etc., hasImage=true returns "docker".
func TestResolveEcosystem_ImageDefaultsToDocker(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod") // misleading marker
	got, err := resolveEcosystem("auto", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != "docker" {
		t.Errorf("got %q, want docker (image short-circuits filesystem markers)", got)
	}
}

// Empty explicit + hasImage also resolves to docker (defensive: shdg
// internally passes "" sometimes).
func TestResolveEcosystem_ImageEmptyExplicit_DefaultsToDocker(t *testing.T) {
	dir := t.TempDir()
	got, err := resolveEcosystem("", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != "docker" {
		t.Errorf("got %q, want docker", got)
	}
}

// Explicit ecosystem value beats the --image auto-default, so the user can
// label an image scan as "multi" if they really want to.
func TestResolveEcosystem_ImageExplicitOverride(t *testing.T) {
	dir := t.TempDir()
	got, err := resolveEcosystem("multi", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != "multi" {
		t.Errorf("got %q, want multi (explicit overrides hasImage)", got)
	}
}

func TestDetectEcosystem_GoMod_ReturnsGo(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod")
	got, _ := detectEcosystem(dir)
	if got != "go" {
		t.Errorf("got %q, want go", got)
	}
}

func TestDetectEcosystem_PackageJSON_ReturnsNpm(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json")
	got, _ := detectEcosystem(dir)
	if got != "npm" {
		t.Errorf("got %q, want npm", got)
	}
}

func TestDetectEcosystem_RequirementsTxt_ReturnsPypi(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt")
	got, _ := detectEcosystem(dir)
	if got != "pypi" {
		t.Errorf("got %q, want pypi", got)
	}
}

func TestDetectEcosystem_PyprojectToml_ReturnsPypi(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pyproject.toml")
	got, _ := detectEcosystem(dir)
	if got != "pypi" {
		t.Errorf("got %q, want pypi", got)
	}
}

func TestDetectEcosystem_DockerWinsOverGo(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile")
	writeFile(t, dir, "go.mod")
	got, _ := detectEcosystem(dir)
	if got != "docker" {
		t.Errorf("got %q, want docker (priority order)", got)
	}
}

func TestDetectEcosystem_NothingRecognised_ReturnsMulti(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md")
	got, _ := detectEcosystem(dir)
	if got != "multi" {
		t.Errorf("got %q, want multi (fallback)", got)
	}
}

func TestResolveEcosystem_ExplicitOverridesDetection(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile")
	got, err := resolveEcosystem("npm", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "npm" {
		t.Errorf("got %q, want npm (explicit override)", got)
	}
}

func TestResolveEcosystem_InvalidValue_Errors(t *testing.T) {
	if _, err := resolveEcosystem("scala", ".", false); err == nil {
		t.Errorf("expected error for unsupported ecosystem")
	}
}
