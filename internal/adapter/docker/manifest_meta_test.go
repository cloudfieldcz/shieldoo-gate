package docker

import (
	"context"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func TestParseManifestMeta_DockerV2_SingleArch_ReturnsTotalSize(t *testing.T) {
	body := []byte(`{
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "schemaVersion": 2,
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 1234},
        "layers": [
            {"size": 1000},
            {"size": 2000},
            {"size": 3000}
        ]
    }`)

	m, err := ParseManifestMeta(body)
	require.NoError(t, err)
	assert.Equal(t, "application/vnd.docker.distribution.manifest.v2+json", m.MediaType)
	assert.False(t, m.IsIndex)
	assert.False(t, m.IsAttestation)
	require.NotNil(t, m.TotalSizeBytes)
	assert.Equal(t, int64(1234+1000+2000+3000), *m.TotalSizeBytes)
	require.NotNil(t, m.LayerCount)
	assert.Equal(t, 3, *m.LayerCount)
	assert.Equal(t, ManifestMetaSchemaVersion, m.SchemaVersion)
}

func TestParseManifestMeta_OCIManifestV1_ReturnsTotalSize(t *testing.T) {
	body := []byte(`{
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "schemaVersion": 2,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
        "layers": [{"size": 500}]
    }`)

	m, err := ParseManifestMeta(body)
	require.NoError(t, err)
	assert.Equal(t, "application/vnd.oci.image.manifest.v1+json", m.MediaType)
	assert.False(t, m.IsIndex)
	require.NotNil(t, m.TotalSizeBytes)
	assert.Equal(t, int64(600), *m.TotalSizeBytes)
}

func TestParseManifestMeta_DockerManifestList_ReturnsIsIndex(t *testing.T) {
	body := []byte(`{
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "schemaVersion": 2,
        "manifests": [
            {"digest": "sha256:aaa", "platform": {"architecture": "amd64", "os": "linux"}},
            {"digest": "sha256:bbb", "platform": {"architecture": "arm64", "os": "linux"}}
        ]
    }`)

	m, err := ParseManifestMeta(body)
	require.NoError(t, err)
	assert.True(t, m.IsIndex)
	assert.Nil(t, m.TotalSizeBytes)
	assert.Nil(t, m.LayerCount)
}

func TestParseManifestMeta_OCIImageIndex_ReturnsIsIndex(t *testing.T) {
	body := []byte(`{
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "schemaVersion": 2,
        "manifests": [
            {"digest": "sha256:ccc", "platform": {"architecture": "amd64", "os": "linux"}}
        ]
    }`)

	m, err := ParseManifestMeta(body)
	require.NoError(t, err)
	assert.True(t, m.IsIndex)
	assert.Nil(t, m.TotalSizeBytes)
}

func TestParseManifestMeta_AttestationManifest_FlagsIsAttestation(t *testing.T) {
	// BuildKit attestation manifests carry an in-toto config and a reference-type annotation.
	body := []byte(`{
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "schemaVersion": 2,
        "config": {"mediaType": "application/vnd.in-toto+json", "size": 167},
        "layers": [{"size": 800}],
        "annotations": {"vnd.docker.reference.type": "attestation-manifest"}
    }`)

	m, err := ParseManifestMeta(body)
	require.NoError(t, err)
	assert.True(t, m.IsAttestation)
	require.NotNil(t, m.TotalSizeBytes)
	assert.Equal(t, int64(967), *m.TotalSizeBytes, "attestation total is computed; UI is responsible for not labelling it Image size")
}

func TestParseManifestMeta_AttestationManifest_AnnotationOnly(t *testing.T) {
	body := []byte(`{
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "schemaVersion": 2,
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 1},
        "layers": [{"size": 1}],
        "annotations": {"vnd.docker.reference.type": "attestation-manifest"}
    }`)

	m, err := ParseManifestMeta(body)
	require.NoError(t, err)
	assert.True(t, m.IsAttestation)
}

func TestParseManifestMeta_MalformedJSON_ReturnsError(t *testing.T) {
	_, err := ParseManifestMeta([]byte(`{not valid json`))
	require.Error(t, err)
}

func TestParseManifestMeta_UnknownMediaType_FallsBackGracefully(t *testing.T) {
	body := []byte(`{"mediaType": "application/vnd.example.unknown.v999+json", "schemaVersion": 99}`)
	m, err := ParseManifestMeta(body)
	require.NoError(t, err)
	assert.Equal(t, "application/vnd.example.unknown.v999+json", m.MediaType)
	assert.False(t, m.IsIndex)
	require.NotNil(t, m.TotalSizeBytes)
	assert.Equal(t, int64(0), *m.TotalSizeBytes, "no config, no layers => total is 0, not nil")
	require.NotNil(t, m.LayerCount)
	assert.Equal(t, 0, *m.LayerCount)
}

func TestParseManifestMeta_OversizeInput_ReturnsError(t *testing.T) {
	big := strings.Repeat("a", maxManifestMetaInput+1)
	_, err := ParseManifestMeta([]byte(big))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestParseManifestMeta_NegativeLayerSize_ReturnsNilTotal(t *testing.T) {
	body := []byte(`{
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"size": 100},
        "layers": [{"size": -1}]
    }`)
	m, err := ParseManifestMeta(body)
	require.NoError(t, err)
	assert.Nil(t, m.TotalSizeBytes, "negative size saturates to nil")
}

func TestParseManifestMeta_NegativeConfigSize_ReturnsNilTotal(t *testing.T) {
	body := []byte(`{
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"size": -1},
        "layers": [{"size": 100}]
    }`)
	m, err := ParseManifestMeta(body)
	require.NoError(t, err)
	assert.Nil(t, m.TotalSizeBytes, "negative config size saturates to nil")
}

func TestParseManifestMeta_LayerSizeOverflow_ReturnsNilTotal(t *testing.T) {
	body := fmt.Appendf(nil, `{
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"size": 100},
        "layers": [{"size": %d}, {"size": 100}]
    }`, int64(math.MaxInt64))
	m, err := ParseManifestMeta(body)
	require.NoError(t, err)
	assert.Nil(t, m.TotalSizeBytes, "MaxInt64 + 100 must saturate to nil rather than wrap")
}

func TestParseManifestMeta_PlatformOnSingleArchManifest(t *testing.T) {
	body := []byte(`{
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"size": 100},
        "layers": [{"size": 200}],
        "platform": {"architecture": "amd64", "os": "linux"}
    }`)
	m, err := ParseManifestMeta(body)
	require.NoError(t, err)
	assert.Equal(t, "amd64", m.Architecture)
	assert.Equal(t, "linux", m.OS)
}

// ---------- UpsertManifestMeta integration tests (SQLite) -----------------

func newTestDB(t *testing.T) *config.GateDB {
	t.Helper()
	raw, err := sqlx.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })

	db := &config.GateDB{DB: raw}
	_, err = db.Exec(`CREATE TABLE artifacts (
        id TEXT PRIMARY KEY,
        ecosystem TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT NOT NULL DEFAULT '',
        size_bytes INTEGER NOT NULL DEFAULT 0
    )`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE docker_manifest_meta (
        artifact_id      TEXT PRIMARY KEY REFERENCES artifacts(id) ON DELETE CASCADE,
        media_type       TEXT NOT NULL,
        is_index         INTEGER NOT NULL DEFAULT 0,
        is_attestation   INTEGER NOT NULL DEFAULT 0,
        total_size_bytes INTEGER,
        layer_count      INTEGER,
        architecture     TEXT,
        os               TEXT,
        schema_version   INTEGER NOT NULL DEFAULT 1,
        parsed_at        DATETIME NOT NULL
    )`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO artifacts (id, ecosystem, name) VALUES ('docker:reg:img:v1', 'docker', 'reg/img')`)
	require.NoError(t, err)
	return db
}

func TestUpsertManifestMeta_InsertsRow(t *testing.T) {
	db := newTestDB(t)
	total := int64(12345)
	count := 3
	err := UpsertManifestMeta(context.Background(), db, "docker:reg:img:v1", ManifestMeta{
		MediaType:      "application/vnd.oci.image.manifest.v1+json",
		IsIndex:        false,
		IsAttestation:  false,
		TotalSizeBytes: &total,
		LayerCount:     &count,
		SchemaVersion:  1,
	})
	require.NoError(t, err)

	var got struct {
		MediaType     string `db:"media_type"`
		IsIndex       bool   `db:"is_index"`
		Total         *int64 `db:"total_size_bytes"`
		LayerCount    *int   `db:"layer_count"`
		SchemaVersion int    `db:"schema_version"`
	}
	require.NoError(t, db.Get(&got, `SELECT media_type, is_index, total_size_bytes, layer_count, schema_version FROM docker_manifest_meta WHERE artifact_id = ?`, "docker:reg:img:v1"))
	assert.Equal(t, "application/vnd.oci.image.manifest.v1+json", got.MediaType)
	assert.False(t, got.IsIndex)
	require.NotNil(t, got.Total)
	assert.Equal(t, int64(12345), *got.Total)
	require.NotNil(t, got.LayerCount)
	assert.Equal(t, 3, *got.LayerCount)
	assert.Equal(t, 1, got.SchemaVersion)
}

func TestUpsertManifestMeta_Idempotent(t *testing.T) {
	db := newTestDB(t)
	first := int64(100)
	second := int64(200)
	count := 1

	err := UpsertManifestMeta(context.Background(), db, "docker:reg:img:v1", ManifestMeta{
		MediaType:      "application/vnd.oci.image.manifest.v1+json",
		TotalSizeBytes: &first,
		LayerCount:     &count,
		SchemaVersion:  1,
	})
	require.NoError(t, err)

	// Re-upsert with a different total — should overwrite, not error or duplicate.
	err = UpsertManifestMeta(context.Background(), db, "docker:reg:img:v1", ManifestMeta{
		MediaType:      "application/vnd.oci.image.manifest.v1+json",
		TotalSizeBytes: &second,
		LayerCount:     &count,
		SchemaVersion:  1,
	})
	require.NoError(t, err)

	var rows int
	require.NoError(t, db.Get(&rows, `SELECT COUNT(*) FROM docker_manifest_meta WHERE artifact_id = ?`, "docker:reg:img:v1"))
	assert.Equal(t, 1, rows)

	var total *int64
	require.NoError(t, db.Get(&total, `SELECT total_size_bytes FROM docker_manifest_meta WHERE artifact_id = ?`, "docker:reg:img:v1"))
	require.NotNil(t, total)
	assert.Equal(t, int64(200), *total)
}

func TestUpsertManifestMeta_NilArchitecture_StoresNULL(t *testing.T) {
	db := newTestDB(t)
	err := UpsertManifestMeta(context.Background(), db, "docker:reg:img:v1", ManifestMeta{
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		SchemaVersion: 1,
	})
	require.NoError(t, err)

	var arch *string
	require.NoError(t, db.Get(&arch, `SELECT architecture FROM docker_manifest_meta WHERE artifact_id = ?`, "docker:reg:img:v1"))
	assert.Nil(t, arch, "empty Architecture string must persist as SQL NULL, not empty string")
}
