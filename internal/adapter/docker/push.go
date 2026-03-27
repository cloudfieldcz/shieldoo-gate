package docker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
)

// uploadSession tracks an in-progress blob upload.
type uploadSession struct {
	uuid string
	name string // image name
}

// pushHandler manages OCI push operations.
type pushHandler struct {
	sessions  sync.Map // uuid → *uploadSession
	blobStore *BlobStore
}

func newPushHandler(blobStore *BlobStore) *pushHandler {
	return &pushHandler{blobStore: blobStore}
}

// handleBlobUploadInit handles POST /v2/{name}/blobs/uploads/
func (ph *pushHandler) handleBlobUploadInit(w http.ResponseWriter, r *http.Request, name string) {
	sessionUUID := uuid.New().String()
	ph.sessions.Store(sessionUUID, &uploadSession{
		uuid: sessionUUID,
		name: name,
	})

	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, sessionUUID))
	w.Header().Set("Docker-Upload-UUID", sessionUUID)
	w.Header().Set("Range", "0-0")
	w.WriteHeader(http.StatusAccepted)
}

// handleBlobUploadComplete handles PUT /v2/{name}/blobs/uploads/{uuid}?digest=sha256:...
func (ph *pushHandler) handleBlobUploadComplete(w http.ResponseWriter, r *http.Request, name, uploadUUID string) {
	digest := r.URL.Query().Get("digest")
	if digest == "" {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "missing digest",
			Reason: "digest query parameter is required",
		})
		return
	}

	_, ok := ph.sessions.LoadAndDelete(uploadUUID)
	if !ok {
		http.Error(w, "upload session not found", http.StatusNotFound)
		return
	}

	// Read blob body (monolithic upload).
	const maxBlobSize = 2 << 30 // 2 GB
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBlobSize))
	if err != nil {
		log.Error().Err(err).Msg("docker push: failed to read blob body")
		http.Error(w, "failed to read blob", http.StatusInternalServerError)
		return
	}

	// Verify digest.
	h := sha256.Sum256(body)
	computedDigest := "sha256:" + hex.EncodeToString(h[:])
	if computedDigest != digest {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "digest mismatch",
			Reason: fmt.Sprintf("computed %s, expected %s", computedDigest, digest),
		})
		return
	}

	// Store blob.
	if err := ph.blobStore.Put(digest, body); err != nil {
		log.Error().Err(err).Str("digest", digest).Msg("docker push: failed to store blob")
		http.Error(w, "failed to store blob", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
	w.WriteHeader(http.StatusCreated)
}

// handleBlobHead handles HEAD /v2/{name}/blobs/{digest}
func (ph *pushHandler) handleBlobHead(w http.ResponseWriter, r *http.Request, digest string) {
	if ph.blobStore.Exists(digest) {
		size, err := ph.blobStore.GetSize(digest)
		if err == nil {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.NotFound(w, r)
}
