package alert

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Compile-time interface check.
var _ ChannelSender = (*EmailSender)(nil)

// DefaultBatchWait is the default duration to accumulate events before
// sending a digest email.
const DefaultBatchWait = 30 * time.Second

// EmailSender accumulates alert payloads and sends them as batched
// digest emails via SMTP. It runs an internal goroutine that flushes
// accumulated events every batchWait interval.
type EmailSender struct {
	host          string
	port          int
	from          string
	to            []string
	username      string
	password      string
	useTLS        bool
	tlsSkipVerify bool
	batchWait     time.Duration

	mu      sync.Mutex
	pending []AlertPayload
	done    chan struct{}
	stopped chan struct{}

	// sendFunc overrides the actual SMTP send for testing.
	// When set, it receives the batched payloads instead of
	// connecting to a real SMTP server.
	sendFunc func([]AlertPayload) error
}

// NewEmailSender creates an EmailSender and starts its background
// batch-flush goroutine.
func NewEmailSender(
	host string,
	port int,
	from string,
	to []string,
	username, password string,
	useTLS, tlsSkipVerify bool,
	batchWait time.Duration,
) *EmailSender {
	if batchWait <= 0 {
		batchWait = DefaultBatchWait
	}

	e := &EmailSender{
		host:          host,
		port:          port,
		from:          from,
		to:            to,
		username:      username,
		password:      password,
		useTLS:        useTLS,
		tlsSkipVerify: tlsSkipVerify,
		batchWait:     batchWait,
		done:          make(chan struct{}),
		stopped:       make(chan struct{}),
	}

	go e.batchLoop()
	return e
}

// Name returns the channel name for metrics and logging.
func (e *EmailSender) Name() string {
	return "email"
}

// Send accumulates the payload for batched delivery. The actual email
// is sent when the batchWait timer fires in the background goroutine.
func (e *EmailSender) Send(_ context.Context, payload AlertPayload) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pending = append(e.pending, payload)
	return nil
}

// Close stops the background goroutine and flushes any remaining
// pending payloads.
func (e *EmailSender) Close() {
	close(e.done)
	<-e.stopped
}

// batchLoop runs in a goroutine, periodically flushing pending payloads.
func (e *EmailSender) batchLoop() {
	defer close(e.stopped)

	ticker := time.NewTicker(e.batchWait)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.flush()
		case <-e.done:
			// Final flush on shutdown.
			e.flush()
			return
		}
	}
}

// flush sends all accumulated payloads as a single digest email.
func (e *EmailSender) flush() {
	e.mu.Lock()
	if len(e.pending) == 0 {
		e.mu.Unlock()
		return
	}
	batch := e.pending
	e.pending = nil
	e.mu.Unlock()

	if e.sendFunc != nil {
		_ = e.sendFunc(batch)
		return
	}

	_ = e.sendSMTP(batch)
}

// FormatSubject builds the email subject line from a batch of payloads.
func FormatSubject(batch []AlertPayload) string {
	seen := make(map[string]bool, len(batch))
	var types []string
	for _, p := range batch {
		if !seen[p.EventType] {
			seen[p.EventType] = true
			types = append(types, p.EventType)
		}
	}
	sort.Strings(types)
	return fmt.Sprintf("[Shieldoo Gate] %d security event(s): %s",
		len(batch), strings.Join(types, ", "))
}

// FormatBody builds the plain-text email body from a batch of payloads.
func FormatBody(batch []AlertPayload) string {
	var b strings.Builder
	b.WriteString("Shieldoo Gate Security Alert\n")
	b.WriteString("=============================\n\n")
	fmt.Fprintf(&b, "%d event(s) detected:\n\n", len(batch))

	for i, p := range batch {
		fmt.Fprintf(&b, "%d. [%s] %s\n", i+1, p.EventType, p.ArtifactID)
		fmt.Fprintf(&b, "   Reason: %s\n", p.Reason)
		fmt.Fprintf(&b, "   Time: %s\n\n", p.Timestamp.Format(time.RFC3339))
	}

	return b.String()
}

// sendSMTP delivers the digest email via SMTP.
func (e *EmailSender) sendSMTP(batch []AlertPayload) error {
	subject := FormatSubject(batch)
	body := FormatBody(batch)

	msg := buildMIME(e.from, e.to, subject, body)
	addr := net.JoinHostPort(e.host, fmt.Sprintf("%d", e.port))

	tlsCfg := &tls.Config{
		ServerName:         e.host,
		InsecureSkipVerify: e.tlsSkipVerify, //nolint:gosec // user-configured
	}

	var client *smtp.Client
	var err error

	if e.port == 465 || e.useTLS {
		// Implicit TLS (SMTPS).
		conn, dialErr := tls.Dial("tcp", addr, tlsCfg)
		if dialErr != nil {
			return fmt.Errorf("email sender: TLS dial %s: %w", addr, dialErr)
		}
		client, err = smtp.NewClient(conn, e.host)
		if err != nil {
			return fmt.Errorf("email sender: new client: %w", err)
		}
	} else {
		// Plain connection, optionally upgraded with STARTTLS.
		client, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("email sender: dial %s: %w", addr, err)
		}
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err = client.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("email sender: STARTTLS: %w", err)
			}
		}
	}
	defer client.Close()

	// Authenticate if credentials are provided.
	if e.username != "" {
		auth := smtp.PlainAuth("", e.username, e.password, e.host)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("email sender: auth: %w", err)
		}
	}

	if err = client.Mail(e.from); err != nil {
		return fmt.Errorf("email sender: MAIL FROM: %w", err)
	}
	for _, rcpt := range e.to {
		if err = client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("email sender: RCPT TO %s: %w", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("email sender: DATA: %w", err)
	}
	if _, err = w.Write(msg); err != nil {
		return fmt.Errorf("email sender: write body: %w", err)
	}
	if err = w.Close(); err != nil {
		return fmt.Errorf("email sender: close data: %w", err)
	}

	return client.Quit()
}

// buildMIME constructs a minimal RFC 2822 message.
func buildMIME(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}
