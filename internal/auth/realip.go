package auth

import (
	"net"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// TrustedProxyMiddleware returns middleware that resolves the real client IP from
// forwarding headers ONLY when the immediate peer is a configured trusted proxy.
//
// chi's middleware.RealIP trusts X-Forwarded-For / X-Real-IP unconditionally, which
// lets any client spoof the IP recorded in audit rows (a stated security invariant)
// and the key used for IP-based rate limiting. This middleware instead:
//
//   - leaves r.RemoteAddr as the real TCP peer when no trusted proxies are configured
//     or when the peer is NOT in the trusted set (forwarding headers are ignored), and
//   - rewrites r.RemoteAddr to the right-most untrusted X-Forwarded-For entry (falling
//     back to X-Real-IP) when the peer IS a trusted proxy.
//
// Invalid CIDR entries are logged once at startup and skipped.
func TrustedProxyMiddleware(cidrs []string) func(http.Handler) http.Handler {
	trusted := parseCIDRs(cidrs)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(trusted) > 0 {
				if peer := peerIP(r.RemoteAddr); peer != nil && ipInAny(peer, trusted) {
					if client := clientFromHeaders(r, trusted); client != "" {
						r.RemoteAddr = client
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// parseCIDRs converts string CIDRs (or bare IPs) into *net.IPNet, skipping invalid
// entries with a warning.
func parseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			// Bare IP — treat as a single-host CIDR.
			if ip := net.ParseIP(c); ip != nil {
				if ip.To4() != nil {
					c += "/32"
				} else {
					c += "/128"
				}
			}
		}
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			log.Warn().Str("entry", c).Msg("auth: ignoring invalid trusted_proxies CIDR")
			continue
		}
		out = append(out, ipnet)
	}
	return out
}

// peerIP extracts the IP from a "host:port" RemoteAddr.
func peerIP(remoteAddr string) net.IP {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	return net.ParseIP(host)
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientFromHeaders returns the most trustworthy client IP from forwarding headers.
// It walks X-Forwarded-For from right to left and returns the first address that is
// not itself a trusted proxy. Falls back to X-Real-IP. Returns "" when nothing usable.
func clientFromHeaders(r *http.Request, trusted []*net.IPNet) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			cand := strings.TrimSpace(parts[i])
			ip := net.ParseIP(cand)
			if ip == nil {
				continue
			}
			if ipInAny(ip, trusted) {
				continue // hop through another trusted proxy
			}
			return cand
		}
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		if net.ParseIP(xrip) != nil {
			return xrip
		}
	}
	return ""
}
