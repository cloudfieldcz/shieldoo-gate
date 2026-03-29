package alert

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPayload() AlertPayload {
	return AlertPayload{
		EventType:  "BLOCKED",
		ArtifactID: "pypi/requests/2.31.0",
		Reason:     "malicious package detected",
		Timestamp:  time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC),
		Metadata:   map[string]any{"scanner": "guarddog", "verdict": "MALICIOUS"},
	}
}

func TestWebhookSender_SendsCorrectPayload(t *testing.T) {
	var receivedBody []byte
	var receivedHeaders http.Header

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := NewWebhookSender(srv.URL, []byte("test-secret"))
	payload := testPayload()

	err := sender.Send(context.Background(), payload)
	require.NoError(t, err)

	// Verify JSON body.
	var got AlertPayload
	err = json.Unmarshal(receivedBody, &got)
	require.NoError(t, err)
	assert.Equal(t, payload.EventType, got.EventType)
	assert.Equal(t, payload.ArtifactID, got.ArtifactID)
	assert.Equal(t, payload.Reason, got.Reason)

	// Verify headers.
	assert.Equal(t, "application/json", receivedHeaders.Get("Content-Type"))
	assert.Equal(t, "shieldoo-gate/1.1", receivedHeaders.Get("User-Agent"))
	assert.Equal(t, "BLOCKED", receivedHeaders.Get("X-Shieldoo-Event"))
	assert.NotEmpty(t, receivedHeaders.Get("X-Shieldoo-Timestamp"))
	assert.Contains(t, receivedHeaders.Get("X-Shieldoo-Signature"), "sha256=")
}

func TestWebhookSender_HMACSignatureWithTimestamp(t *testing.T) {
	secret := []byte("my-webhook-secret")
	var capturedBody []byte
	var capturedTimestamp string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTimestamp = r.Header.Get("X-Shieldoo-Timestamp")
		var err error
		capturedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)

		// Verify the signature ourselves.
		sigHeader := r.Header.Get("X-Shieldoo-Signature")
		require.True(t, len(sigHeader) > 7, "signature header too short")

		hexSig := sigHeader[7:] // strip "sha256="

		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(capturedTimestamp))
		mac.Write([]byte("."))
		mac.Write(capturedBody)
		expected := hex.EncodeToString(mac.Sum(nil))

		assert.Equal(t, expected, hexSig, "HMAC signature mismatch")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := NewWebhookSender(srv.URL, secret)
	err := sender.Send(context.Background(), testPayload())
	require.NoError(t, err)

	// The timestamp must be a reasonable Unix timestamp.
	assert.NotEmpty(t, capturedTimestamp)
}

func TestWebhookSender_NoSignatureWithoutSecret(t *testing.T) {
	var receivedHeaders http.Header

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := NewWebhookSender(srv.URL, nil)
	err := sender.Send(context.Background(), testPayload())
	require.NoError(t, err)

	assert.Empty(t, receivedHeaders.Get("X-Shieldoo-Signature"),
		"signature header should be absent when no secret is configured")
	// Other headers should still be present.
	assert.Equal(t, "application/json", receivedHeaders.Get("Content-Type"))
	assert.Equal(t, "BLOCKED", receivedHeaders.Get("X-Shieldoo-Event"))
}

func TestWebhookSender_ReturnsErrorOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sender := NewWebhookSender(srv.URL, nil)
	err := sender.Send(context.Background(), testPayload())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")

	// Should NOT be an HTTPError (5xx is a plain error, retryable).
	var httpErr *HTTPError
	assert.False(t, isHTTPError(err, &httpErr),
		"5xx should not return HTTPError — it should be retried")
}

func TestWebhookSender_ReturnsHTTPErrorOnClientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	sender := NewWebhookSender(srv.URL, nil)
	err := sender.Send(context.Background(), testPayload())

	require.Error(t, err)

	// Should be an HTTPError so the worker knows not to retry.
	var httpErr *HTTPError
	require.True(t, isHTTPError(err, &httpErr), "4xx should return HTTPError")
	assert.Equal(t, http.StatusBadRequest, httpErr.StatusCode)

	// Also verify it works with the isClientError helper from alerter.go.
	assert.True(t, isClientError(err))
}

// isHTTPError is a test helper that checks if err is an *HTTPError
// and assigns it to *target if so.
func isHTTPError(err error, target **HTTPError) bool {
	if err == nil {
		return false
	}
	he, ok := err.(*HTTPError)
	if ok {
		*target = he
	}
	return ok
}
