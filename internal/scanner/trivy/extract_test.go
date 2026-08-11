package trivy

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// zipEntry / tarEntry describe one archive member for the builders below.
type zipEntry struct {
	name string
	body string
}

func writeZipArchive(t *testing.T, entries []zipEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "archive.zip")
	f, err := os.Create(path) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	defer f.Close()

	zw := zip.NewWriter(f)
	for _, e := range entries {
		// zip.Writer.Create sanitizes nothing, which is exactly what we need
		// to forge a malicious "../" member.
		w, err := zw.Create(e.name)
		require.NoError(t, err)
		_, err = w.Write([]byte(e.body))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return path
}

type tarEntry struct {
	name     string
	body     string
	typeflag byte
	linkname string
}

func writeTarGzArchive(t *testing.T, entries []tarEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "archive.tar.gz")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Size:     int64(len(e.body)),
			Typeflag: typeflag,
			Linkname: e.linkname,
		}
		if typeflag != tar.TypeReg {
			hdr.Size = 0
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if typeflag == tar.TypeReg {
			_, err := tw.Write([]byte(e.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())

	f, err := os.Create(path) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	defer f.Close()
	gw := gzip.NewWriter(f)
	_, err = gw.Write(buf.Bytes())
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	return path
}

func TestArchiveEntryPath_TraversalName_ReturnsError(t *testing.T) {
	dest := t.TempDir()
	for _, name := range []string{
		"../escape.txt",
		"../../etc/passwd",
		"pkg/../../escape.txt",
		"./../escape.txt",
		"/absolute.txt/../../escape.txt",
	} {
		_, err := archiveEntryPath(dest, name)
		assert.Error(t, err, "expected %q to be rejected", name)
	}
}

func TestArchiveEntryPath_SiblingPrefixName_ReturnsError(t *testing.T) {
	// "/tmp/a" must not accept a target of "/tmp/abc" — the guard appends a
	// separator to the prefix precisely to stop this.
	base := t.TempDir()
	dest := filepath.Join(base, "a")
	require.NoError(t, os.MkdirAll(dest, 0o755))
	_, err := archiveEntryPath(dest, "../abc/file.txt")
	assert.Error(t, err)
}

func TestArchiveEntryPath_AbsoluteName_StaysInsideDest(t *testing.T) {
	// filepath.Join drops the leading separator, so an absolute entry name
	// lands under dest rather than at the filesystem root.
	dest := t.TempDir()
	target, err := archiveEntryPath(dest, "/etc/passwd")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dest, "etc/passwd"), target)
}

func TestArchiveEntryPath_DotPrefixedName_IsAccepted(t *testing.T) {
	// A legitimate member literally named "..foo" is not traversal. The
	// previous filepath.Rel + HasPrefix("..") guard rejected these.
	dest := t.TempDir()
	for _, name := range []string{"..foo", "pkg/..bar", "...", "..foo/..bar"} {
		target, err := archiveEntryPath(dest, name)
		require.NoError(t, err, "expected %q to be accepted", name)
		assert.Equal(t, filepath.Join(dest, name), target)
	}
}

func TestArchiveRootEntry_RootNames_ReturnsTrue(t *testing.T) {
	for _, name := range []string{"", ".", "./", "/", "//"} {
		assert.True(t, archiveRootEntry(name), "expected %q to be a root entry", name)
	}
}

func TestArchiveRootEntry_TraversalNames_ReturnsFalse(t *testing.T) {
	// ".." must NOT be swallowed as a root entry — it has to reach
	// archiveEntryPath so the escape is reported.
	for _, name := range []string{"..", "../", "pkg", "./pkg", "..foo"} {
		assert.False(t, archiveRootEntry(name), "expected %q not to be a root entry", name)
	}
}

func TestUnzip_TraversalEntry_ReturnsErrorAndWritesNothing(t *testing.T) {
	src := writeZipArchive(t, []zipEntry{
		{name: "pkg/ok.txt", body: "fine"},
		{name: "../escaped.txt", body: "pwned"},
	})
	base := t.TempDir()
	dest := filepath.Join(base, "extract")
	require.NoError(t, os.MkdirAll(dest, 0o755))

	err := unzip(src, dest)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "escapes extraction dir")

	assert.NoFileExists(t, filepath.Join(base, "escaped.txt"))
}

func TestUnzip_CleanArchive_ExtractsAllEntries(t *testing.T) {
	src := writeZipArchive(t, []zipEntry{
		{name: "pkg/", body: ""},
		{name: "pkg/ok.txt", body: "fine"},
		{name: "pkg/..metadata", body: "dot-prefixed"},
	})
	dest := t.TempDir()

	require.NoError(t, unzip(src, dest))

	body, err := os.ReadFile(filepath.Join(dest, "pkg", "ok.txt")) //nolint:gosec // test temp path
	require.NoError(t, err)
	assert.Equal(t, "fine", string(body))

	body, err = os.ReadFile(filepath.Join(dest, "pkg", "..metadata")) //nolint:gosec // test temp path
	require.NoError(t, err)
	assert.Equal(t, "dot-prefixed", string(body))
}

func TestUntar_TraversalEntry_ReturnsErrorAndWritesNothing(t *testing.T) {
	src := writeTarGzArchive(t, []tarEntry{
		{name: "package/ok.txt", body: "fine"},
		{name: "../escaped.txt", body: "pwned"},
	})
	base := t.TempDir()
	dest := filepath.Join(base, "extract")
	require.NoError(t, os.MkdirAll(dest, 0o755))

	err := untar(src, dest, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "escapes extraction dir")

	assert.NoFileExists(t, filepath.Join(base, "escaped.txt"))
}

func TestUntar_RootDotEntry_ExtractsRemainingEntries(t *testing.T) {
	// GNU tar prefixes archives built from a directory with a "./" member.
	// It must be skipped, not treated as an escape, or extraction of the
	// whole archive would fail.
	src := writeTarGzArchive(t, []tarEntry{
		{name: "./", typeflag: tar.TypeDir},
		{name: "./package/", typeflag: tar.TypeDir},
		{name: "./package/ok.txt", body: "fine"},
		{name: "./package/..metadata", body: "dot-prefixed"},
	})
	dest := t.TempDir()

	require.NoError(t, untar(src, dest, true))

	body, err := os.ReadFile(filepath.Join(dest, "package", "ok.txt")) //nolint:gosec // test temp path
	require.NoError(t, err)
	assert.Equal(t, "fine", string(body))

	body, err = os.ReadFile(filepath.Join(dest, "package", "..metadata")) //nolint:gosec // test temp path
	require.NoError(t, err)
	assert.Equal(t, "dot-prefixed", string(body))
}

func TestUntar_SymlinkEntry_IsSkipped(t *testing.T) {
	// Symlinks are skipped so the sandbox stays link-free and a later entry
	// cannot be redirected through one.
	src := writeTarGzArchive(t, []tarEntry{
		{name: "package/link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		{name: "package/ok.txt", body: "fine"},
	})
	dest := t.TempDir()

	require.NoError(t, untar(src, dest, true))

	_, err := os.Lstat(filepath.Join(dest, "package", "link"))
	assert.True(t, os.IsNotExist(err), "symlink entry must not be materialized")
	assert.FileExists(t, filepath.Join(dest, "package", "ok.txt"))
}

func TestUnzip_SymlinkModeEntry_WrittenAsRegularFile(t *testing.T) {
	// zip members can carry symlink mode bits; we never create a symlink.
	path := filepath.Join(t.TempDir(), "archive.zip")
	f, err := os.Create(path) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	zw := zip.NewWriter(f)
	hdr := &zip.FileHeader{Name: "link"}
	hdr.SetMode(os.ModeSymlink | 0o777)
	w, err := zw.CreateHeader(hdr)
	require.NoError(t, err)
	_, err = w.Write([]byte("/etc/passwd"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, f.Close())

	dest := t.TempDir()
	require.NoError(t, unzip(path, dest))

	info, err := os.Lstat(filepath.Join(dest, "link"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0), info.Mode()&os.ModeSymlink, "must be a regular file, not a symlink")
}
