package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// trivyVersion is the pinned Trivy release shdg downloads at first run.
	// Bumping requires updating expectedChecksums below.
	trivyVersion = "0.72.0"

	// defaultTrivyBaseURL is the GitHub releases host. Override via the second
	// arg to ensureTrivy in tests.
	defaultTrivyBaseURL = "https://github.com/aquasecurity/trivy/releases/download"
)

// expectedChecksums pins the SHA-256 of each platform tarball at the
// trivyVersion above. **This is the primary trust anchor** — github.com is
// fetched over TLS but a CA compromise could swap both tarball and the live
// checksums.txt file. The pinned hex below is the only thing that defeats
// that. CLAUDE.md security invariant 4: pinned scanner deps.
//
// IMPLEMENTER: replace the placeholders below with real values from
//
//	curl -L https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_checksums.txt
//
// A unit test (TestExpectedChecksums_AllPinned) FAILS the build if any value
// is missing or still starts with the placeholder, so the placeholder cannot
// ship to production.
var expectedChecksums = map[string]string{
	"trivy_0.72.0_Linux-64bit.tar.gz": "bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea",
	"trivy_0.72.0_Linux-ARM64.tar.gz": "2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467",
	"trivy_0.72.0_macOS-64bit.tar.gz": "ee5e60df8a98e5b89fd74a6d86f9e5c7e9a266a35002cb1e43291698b3bfee08",
	"trivy_0.72.0_macOS-ARM64.tar.gz": "88f208680dc05da2b459e19b4f5aa2b4dc7c2117892ba4aab2ae63baba330016",
}

// ErrUnsupportedPlatform is returned when shdg runs on a (GOOS, GOARCH) for
// which Trivy publishes no tarball — current Phase 1 covers Linux/macOS amd64+arm64.
var ErrUnsupportedPlatform = errors.New("unsupported platform for bundled Trivy")

// platformAsset returns the tarball name for the current GOOS/GOARCH.
func platformAsset(version string) (string, error) {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "linux/amd64":
		return fmt.Sprintf("trivy_%s_Linux-64bit.tar.gz", version), nil
	case "linux/arm64":
		return fmt.Sprintf("trivy_%s_Linux-ARM64.tar.gz", version), nil
	case "darwin/amd64":
		return fmt.Sprintf("trivy_%s_macOS-64bit.tar.gz", version), nil
	case "darwin/arm64":
		return fmt.Sprintf("trivy_%s_macOS-ARM64.tar.gz", version), nil
	default:
		return "", fmt.Errorf("%w: %s/%s", ErrUnsupportedPlatform, runtime.GOOS, runtime.GOARCH)
	}
}

// trivyCachePath returns the absolute path where the bundled Trivy binary is cached.
func trivyCachePath(version string) string {
	if dir := os.Getenv("SHDG_CACHE_DIR"); dir != "" {
		return filepath.Join(dir, "trivy-"+version, "trivy")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".cache", "shdg", "trivy-"+version, "trivy")
}

// ensureTrivy returns a path to a runnable Trivy binary, downloading +
// verifying it on first call and re-using the cache on subsequent calls.
func ensureTrivy(version, baseURL string) (string, error) {
	target := trivyCachePath(version)
	if st, err := os.Stat(target); err == nil && st.Mode()&0o111 != 0 {
		return target, nil
	}
	asset, err := platformAsset(version)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", fmt.Errorf("mkdir cache: %w", err)
	}

	tarballURL := fmt.Sprintf("%s/v%s/%s", baseURL, version, asset)
	checksumsURL := fmt.Sprintf("%s/v%s/trivy_%s_checksums.txt", baseURL, version, version)

	// 1. Resolve the pinned SHA-256 from expectedChecksums. This is the
	// primary trust anchor — fail closed when missing or placeholder is
	// still in place (defense-in-depth against a build that forgot to fill
	// the pin).
	pinned, ok := expectedChecksums[asset]
	if !ok {
		return "", fmt.Errorf("no pinned checksum for %s — refusing to download", asset)
	}
	if strings.HasPrefix(pinned, "REPLACE_ME") || len(pinned) != 64 {
		return "", fmt.Errorf("pinned checksum for %s is not a real SHA-256 (got %q) — refusing to download", asset, pinned)
	}

	// 2. Fetch the live checksums.txt and confirm it agrees with the pin.
	// The live file is fetched from the same origin as the tarball; on its
	// own it provides no real protection. Pinning catches a compromised
	// origin; the live file mostly catches *upstream republishing* of the
	// same version (which would also be a security concern but a different
	// failure mode).
	checksumsRaw, err := httpGet(checksumsURL)
	if err != nil {
		return "", fmt.Errorf("fetch checksums: %w", err)
	}
	live, err := parseChecksums(string(checksumsRaw), asset)
	if err != nil {
		return "", fmt.Errorf("parse checksums: %w", err)
	}
	if live != pinned {
		return "", fmt.Errorf("checksum drift for %s: pinned=%s live=%s", asset, pinned, live)
	}

	// 2. Download tarball to a temp file next to the cache target.
	tarPath := target + ".tar.gz"
	if err := download(tarballURL, tarPath); err != nil {
		return "", fmt.Errorf("download tarball: %w", err)
	}
	if err := verifySHA256(tarPath, pinned); err != nil {
		_ = os.Remove(tarPath)
		return "", fmt.Errorf("verify tarball: %w", err)
	}

	// 3. Extract just the `trivy` binary.
	if err := extractTrivyBinary(tarPath, target); err != nil {
		return "", fmt.Errorf("extract: %w", err)
	}
	_ = os.Remove(tarPath)
	if err := os.Chmod(target, 0o755); err != nil {
		return "", err
	}
	return target, nil
}

func httpGet(url string) ([]byte, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func download(url, path string) error {
	c := &http.Client{Timeout: 5 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, io.LimitReader(resp.Body, 200<<20))
	return err
}

func parseChecksums(raw, asset string) (string, error) {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[len(fields)-1] == asset {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("asset %q not in checksums file", asset)
}

func verifySHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != strings.ToLower(want) {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, want)
	}
	return nil
}

func extractTrivyBinary(tarPath, target string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		// Defense-in-depth — a compromised tarball must not be able to
		// influence the target path or follow a symlink we don't expect.
		// Checks are ordered so that traversal attempts are rejected on
		// *any* tar entry, not silently filtered by the exact-name match:
		//   1. no '..' anywhere in the entry name (rejected before name match
		//      so a crafted `../trivy` or symlink named `../trivy` errors out
		//      explicitly rather than being skipped)
		//   2. exact-name match (not filepath.Base — `subdir/trivy` is skipped)
		//   3. only regular files (no symlinks / hardlinks / devices)
		//   4. per-entry size cap (200 MiB — Trivy v0.70 binary is ~70 MB
		//      compressed, ~150 MB raw; pick a value comfortably above the real
		//      binary and below "abuse"). The outer 200 MiB cap on the on-disk
		//      tarball is independent.
		if strings.Contains(h.Name, "..") {
			return fmt.Errorf("tar entry name contains '..' — refusing: %q", h.Name)
		}
		if h.Name != "trivy" {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return fmt.Errorf("tar entry 'trivy' is not a regular file (typeflag=%d) — refusing", h.Typeflag)
		}
		const perEntryCap = 200 << 20
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		n, err := io.Copy(out, io.LimitReader(tr, perEntryCap))
		if err != nil {
			out.Close()
			return err
		}
		if n == perEntryCap {
			out.Close()
			return fmt.Errorf("tar entry 'trivy' hit %d-byte cap — refusing potential bomb", perEntryCap)
		}
		return out.Close()
	}
	return errors.New("trivy binary not found in tarball")
}
