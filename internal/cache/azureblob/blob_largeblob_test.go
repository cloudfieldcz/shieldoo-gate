package azureblob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// TestAzureBlobStore_TwoGBBlob_RoundTrips uploads a 2 GB blob via UploadBuffer to
// confirm the SDK stages blocks rather than hitting the 256 MB single-shot limit.
// Requires a running Azurite (the e2e stack provides one) and connection details
// in env: SHIELDOO_AZURITE_CONN. Skipped otherwise.
func TestAzureBlobStore_TwoGBBlob_RoundTrips(t *testing.T) {
	if os.Getenv("SHIELDOO_AZURITE_CONN") == "" || os.Getenv("SHIELDOO_LARGE_BLOB_SPIKE") != "1" {
		t.Skip("set SHIELDOO_LARGE_BLOB_SPIKE=1 and SHIELDOO_AZURITE_CONN to run")
	}
	// config.AzureBlobConfig has NO literal connection-string field — it names the
	// env var that holds it (ConnectionStrEnv) and the container (ContainerName).
	store, err := NewAzureBlobStore(config.AzureBlobConfig{
		ContainerName:    "spike",
		ConnectionStrEnv: "SHIELDOO_AZURITE_CONN",
	})
	if err != nil {
		t.Fatalf("NewAzureBlobStore: %v", err)
	}
	const size = 2 << 30
	data := bytes.Repeat([]byte{0xCD}, size)
	want := sha256.Sum256(data)

	ctx := context.Background()
	if err := store.PutBlob(ctx, "docker-push/blobs/sha256/cd/spike", data); err != nil {
		t.Fatalf("PutBlob 2GB: %v", err)
	}
	got, err := store.GetBlob(ctx, "docker-push/blobs/sha256/cd/spike")
	if err != nil {
		t.Fatalf("GetBlob 2GB: %v", err)
	}
	if sha256.Sum256(got) != want {
		t.Fatal("2GB round-trip hash mismatch")
	}
}
