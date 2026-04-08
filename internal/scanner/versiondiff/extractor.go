package versiondiff

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractLimits controls safety limits during archive extraction.
type ExtractLimits struct {
	MaxSizeMB int // Maximum total decompressed size in MB. Abort if exceeded.
	MaxFiles  int // Maximum number of files to extract. Abort if exceeded.
}

// maxSingleFileBytes is the per-file size limit within an archive (50 MB).
const maxSingleFileBytes = 50 * 1024 * 1024

var (
	errDecompressionBomb = errors.New("extraction aborted: decompressed size exceeds limit")
	errTooManyFiles      = errors.New("extraction aborted: file count exceeds limit")
	errPathTraversal     = errors.New("extraction aborted: path traversal detected")
	errSymlink           = errors.New("extraction aborted: symlink or hardlink rejected")
)

// binaryExtensions are skipped during Maven .jar extraction (only source/config extracted).
var binaryExtensions = map[string]bool{
	".class": true,
}

// ExtractArchive detects the archive format by extension and extracts it safely.
// Supported formats:
//   - .whl, .zip, .nupkg, .jar → zip
//   - .tgz, .tar.gz → tar+gzip
//   - .gem → outer tar containing data.tar.gz → extract inner tar.gz
func ExtractArchive(archivePath, destDir string, limits ExtractLimits) error {
	ext := strings.ToLower(filepath.Ext(archivePath))
	base := strings.ToLower(archivePath)

	switch {
	case ext == ".whl" || ext == ".zip" || ext == ".nupkg" || ext == ".jar":
		return extractZip(archivePath, destDir, limits, ext == ".jar")
	case ext == ".tgz" || strings.HasSuffix(base, ".tar.gz"):
		return extractTarGz(archivePath, destDir, limits)
	case ext == ".gem":
		return extractGem(archivePath, destDir, limits)
	default:
		// Unknown format — try zip first, then tar.gz
		if err := extractZip(archivePath, destDir, limits, false); err == nil {
			return nil
		}
		return extractTarGz(archivePath, destDir, limits)
	}
}

// extractZip extracts a zip archive with safety limits.
// If skipBinary is true, .class files are skipped (for Maven .jar).
func extractZip(archivePath, destDir string, limits ExtractLimits, skipBinary bool) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open zip %s: %w", archivePath, err)
	}
	defer r.Close()

	maxBytes := int64(limits.MaxSizeMB) * 1024 * 1024
	var totalBytes int64
	fileCount := 0

	for _, f := range r.File {
		// Safety: file count limit
		fileCount++
		if fileCount > limits.MaxFiles {
			return errTooManyFiles
		}

		// Safety: reject symlinks
		if f.Mode()&os.ModeSymlink != 0 {
			return errSymlink
		}

		// Safety: path traversal check
		cleanName, err := safePath(f.Name, destDir)
		if err != nil {
			return err
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(cleanName, 0o700); err != nil {
				return fmt.Errorf("mkdir %s: %w", cleanName, err)
			}
			continue
		}

		// Skip binary files for .jar
		if skipBinary && binaryExtensions[strings.ToLower(filepath.Ext(f.Name))] {
			continue
		}

		// Skip individual files > 50 MB
		if f.UncompressedSize64 > maxSingleFileBytes {
			continue
		}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(cleanName), 0o700); err != nil {
			return fmt.Errorf("mkdir parent %s: %w", cleanName, err)
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open entry %s: %w", f.Name, err)
		}

		written, err := writeFile(cleanName, rc, maxBytes-totalBytes)
		rc.Close()
		if err != nil {
			return err
		}
		totalBytes += written

		if totalBytes > maxBytes {
			return errDecompressionBomb
		}
	}

	return nil
}

// extractTarGz extracts a gzipped tar archive with safety limits.
func extractTarGz(archivePath, destDir string, limits ExtractLimits) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open %s: %w", archivePath, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader %s: %w", archivePath, err)
	}
	defer gz.Close()

	return extractTar(gz, destDir, limits)
}

// extractTar extracts from a tar reader with safety limits.
func extractTar(r io.Reader, destDir string, limits ExtractLimits) error {
	tr := tar.NewReader(r)
	maxBytes := int64(limits.MaxSizeMB) * 1024 * 1024
	var totalBytes int64
	fileCount := 0

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}

		// Safety: file count limit
		fileCount++
		if fileCount > limits.MaxFiles {
			return errTooManyFiles
		}

		// Safety: reject symlinks and hardlinks
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			return errSymlink
		}

		// Safety: path traversal check
		cleanName, err := safePath(header.Name, destDir)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(cleanName, 0o700); err != nil {
				return fmt.Errorf("mkdir %s: %w", cleanName, err)
			}

		case tar.TypeReg:
			// Skip individual files > 50 MB
			if header.Size > maxSingleFileBytes {
				if _, err := io.Copy(io.Discard, tr); err != nil {
					return fmt.Errorf("skip large file %s: %w", header.Name, err)
				}
				continue
			}

			if err := os.MkdirAll(filepath.Dir(cleanName), 0o700); err != nil {
				return fmt.Errorf("mkdir parent %s: %w", cleanName, err)
			}

			written, err := writeFile(cleanName, tr, maxBytes-totalBytes)
			if err != nil {
				return err
			}
			totalBytes += written

			if totalBytes > maxBytes {
				return errDecompressionBomb
			}
		}
	}

	return nil
}

// extractGem extracts a .gem file (outer tar containing data.tar.gz).
// Only the contents of data.tar.gz are extracted to destDir.
func extractGem(archivePath, destDir string, limits ExtractLimits) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open gem %s: %w", archivePath, err)
	}
	defer f.Close()

	tr := tar.NewReader(f)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("data.tar.gz not found in gem %s", archivePath)
		}
		if err != nil {
			return fmt.Errorf("gem tar next: %w", err)
		}

		if header.Name == "data.tar.gz" {
			gz, err := gzip.NewReader(tr)
			if err != nil {
				return fmt.Errorf("gem data.tar.gz gzip: %w", err)
			}
			defer gz.Close()
			return extractTar(gz, destDir, limits)
		}
	}
}

// safePath validates and resolves an archive entry name against a destination directory.
// Returns the full resolved path or an error if the path is unsafe.
func safePath(name, destDir string) (string, error) {
	cleaned := filepath.Clean(name)

	// Reject absolute paths
	if filepath.IsAbs(cleaned) {
		return "", errPathTraversal
	}

	// Reject path traversal components
	if strings.Contains(cleaned, "..") {
		return "", errPathTraversal
	}

	fullPath := filepath.Join(destDir, cleaned)

	// Verify the resolved path stays within destDir
	if !strings.HasPrefix(fullPath, filepath.Clean(destDir)+string(os.PathSeparator)) &&
		fullPath != filepath.Clean(destDir) {
		return "", errPathTraversal
	}

	return fullPath, nil
}

// writeFile creates a file at path and copies up to remaining bytes from r.
// Returns the number of bytes written.
func writeFile(path string, r io.Reader, remaining int64) (int64, error) {
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, fmt.Errorf("create file %s: %w", path, err)
	}
	defer out.Close()

	// Use LimitReader to enforce per-extraction byte budget
	limited := io.LimitReader(r, remaining+1) // +1 to detect overflow
	written, err := io.Copy(out, limited)
	if err != nil {
		return written, fmt.Errorf("write file %s: %w", path, err)
	}

	if written > remaining {
		return written, errDecompressionBomb
	}

	return written, nil
}
