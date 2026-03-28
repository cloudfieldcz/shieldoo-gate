package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Compile-time interface check.
var _ ChannelSender = (*WebhookSender)(nil)

// WebhookSender sends alert payloads to a webhook URL via HTTP POST.
type WebhookSender struct {
	url        string
	httpClient *http.Client
	secretKey  []byte // for HMAC signing; empty means no signature
}

// NewWebhookSender creates a WebhookSender with the given URL and optional
// HMAC secret key. If secretKey is nil or empty, the signature header is
// omitted from requests.
func NewWebhookSender(url string, secretKey []byte) *WebhookSender {
	return &WebhookSender{
		url: url,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		secretKey: secretKey,
	}
}

// Name returns the channel name for metrics and logging.
func (w *WebhookSender) Name() string {
	return "webhook"
}

// Send marshals the payload to JSON and POSTs it to the configured webhook URL.
// It adds HMAC-SHA256 signature headers when a secret key is configured.
// Returns HTTPError for 4xx responses (caller should not retry) and a plain
// error for 5xx or other failures.
func (w *WebhookSender) Send(ctx context.Context, payload AlertPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook sender: marshal payload: %w", err)
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook sender: create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "shieldoo-gate/1.1")
	req.Header.Set("X-Shieldoo-Event", payload.EventType)
	req.Header.Set("X-Shieldoo-Timestamp", timestamp)

	if len(w.secretKey) > 0 {
		sig := computeHMAC(w.secretKey, timestamp, body)
		req.Header.Set("X-Shieldoo-Signature", "sha256="+sig)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook sender: HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	// Drain body to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= http.StatusBadRequest && resp.StatusCode < http.StatusInternalServerError {
		return &HTTPError{
			StatusCode: resp.StatusCode,
			Err:        fmt.Errorf("webhook sender: HTTP %d from %s", resp.StatusCode, w.url),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook sender: HTTP %d from %s", resp.StatusCode, w.url)
	}

	return nil
}

// computeHMAC calculates HMAC-SHA256(secret, "<timestamp>.<body>") and
// returns the hex-encoded result.
func computeHMAC(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
