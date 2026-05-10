package main

import (
	"archive/tar"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrivyCachePath_HonoursOverride(t *testing.T) {
	t.Setenv("SHDG_CACHE_DIR", "/tmp/shdg-test")
	got := trivyCachePath("0.70.0")
	if !strings.HasPrefix(got, "/tmp/shdg-test/trivy-0.70.0") {
		t.Errorf("path %q missing override prefix", got)
	}
}

func TestParseChecksums_FindsAsset(t *testing.T) {
	raw := `aaaa1111  trivy_0.70.0_Linux-64bit.tar.gz
bbbb2222  trivy_0.70.0_macOS-ARM64.tar.gz`
	got, err := parseChecksums(raw, "trivy_0.70.0_macOS-ARM64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if got != "bbbb2222" {
		t.Errorf("got %q, want bbbb2222", got)
	}
}

func TestParseChecksums_AssetMissing_Errors(t *testing.T) {
	if _, err := parseChecksums("aaaa  other.tar.gz", "trivy_0.70.0_Linux-64bit.tar.gz"); err == nil {
		t.Errorf("expected error for missing asset")
	}
}

func TestVerifySHA256_MatchAndMismatch(t *testing.T) {
	// SHA-256 of "hello\n" = 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
	tmp := t.TempDir()
	p := filepath.Join(tmp, "x")
	if err := os.WriteFile(p, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256(p, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"); err != nil {
		t.Errorf("expected match: %v", err)
	}
	if err := verifySHA256(p, "deadbeef"); err == nil {
		t.Errorf("expected mismatch error")
	}
}

// TestExpectedChecksums_AllPinned is a build-gate. The map MUST contain a
// real 64-char lowercase hex SHA-256 for every supported platform; any
// REPLACE_ME placeholder fails the build, preventing the placeholder from
// silently shipping (security-review requirement).
func TestExpectedChecksums_AllPinned(t *testing.T) {
	required := []string{
		"trivy_0.70.0_Linux-64bit.tar.gz",
		"trivy_0.70.0_Linux-ARM64.tar.gz",
		"trivy_0.70.0_macOS-64bit.tar.gz",
		"trivy_0.70.0_macOS-ARM64.tar.gz",
	}
	for _, asset := range required {
		v, ok := expectedChecksums[asset]
		if !ok {
			t.Errorf("expectedChecksums missing entry for %s", asset)
			continue
		}
		if strings.HasPrefix(v, "REPLACE_ME") {
			t.Errorf("expectedChecksums[%s] is still a placeholder: %q", asset, v)
		}
		if len(v) != 64 {
			t.Errorf("expectedChecksums[%s] is not 64 chars (sha256 hex): len=%d value=%q", asset, len(v), v)
		}
		for _, c := range v {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("expectedChecksums[%s] has non-hex char %q in %q", asset, c, v)
				break
			}
		}
	}
}

// TestExtractTrivyBinary_RejectsSymlink — guard against a crafted tarball
// where the "trivy" entry is a symlink to e.g. /etc/passwd.
func TestExtractTrivyBinary_RejectsSymlink(t *testing.T) {
	tmp := t.TempDir()
	tarPath := filepath.Join(tmp, "evil.tar.gz")
	target := filepath.Join(tmp, "trivy")

	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: "trivy", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink, Size: 0}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	f.Close()

	if err := extractTrivyBinary(tarPath, target); err == nil {
		t.Errorf("expected extractTrivyBinary to reject symlink entry")
	}
}

// TestExtractTrivyBinary_RejectsDotDotName — ../trivy must not slip past via filepath.Base.
func TestExtractTrivyBinary_RejectsDotDotName(t *testing.T) {
	tmp := t.TempDir()
	tarPath := filepath.Join(tmp, "evil.tar.gz")
	target := filepath.Join(tmp, "trivy")

	f, _ := os.Create(tarPath)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: "../trivy", Typeflag: tar.TypeReg, Size: 4}
	_ = tw.WriteHeader(hdr)
	_, _ = tw.Write([]byte("fake"))
	tw.Close()
	gz.Close()
	f.Close()

	err := extractTrivyBinary(tarPath, target)
	if err == nil || !strings.Contains(err.Error(), "..") {
		t.Errorf("expected '..' rejection, got %v", err)
	}
}

func TestEnsureTrivy_ReusesCachedBinary(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("SHDG_CACHE_DIR", tmp)
	cachePath := trivyCachePath("0.70.0")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("ensureTrivy should not download when binary already cached")
	}))
	defer srv.Close()
	got, err := ensureTrivy("0.70.0", srv.URL)
	if err != nil {
		t.Fatalf("ensureTrivy: %v", err)
	}
	if got != cachePath {
		t.Errorf("got %q, want %q", got, cachePath)
	}
}
