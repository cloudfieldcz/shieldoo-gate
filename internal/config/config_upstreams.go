package config

import (
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"

	"github.com/go-viper/mapstructure/v2"
	"github.com/rs/zerolog/log"
)

// UpstreamSet describes a multiplexed upstream for a non-Docker ecosystem.
// A bare string in YAML/env (e.g. `pypi: "https://pypi.org"`) decodes to
// UpstreamSet{Default: "..."} via stringToUpstreamSetHookFunc, preserving the
// historical single-upstream behaviour.
type UpstreamSet struct {
	Default      string          `mapstructure:"default"`
	ExtraIndexes []UpstreamIndex `mapstructure:"extra_indexes"`
}

// UpstreamIndex is one secondary index queried via ordered fallback.
type UpstreamIndex struct {
	// Name is a stable identifier used for artifact-ID namespacing and download
	// routing. Validated to ^[a-z0-9-]+$ at config load (no underscores, so the
	// `eco__name` artifact-ID boundary is unambiguous).
	Name string `mapstructure:"name"`
	// URL is the index base URL (https only).
	URL string `mapstructure:"url"`
	// FilesHost is the PyPI-only separate file CDN (https only). Ignored by other ecosystems.
	FilesHost string `mapstructure:"files_host"`
	// Packages is an optional glob scope (filepath.Match patterns) restricting
	// which package names route to this index.
	Packages []string `mapstructure:"packages"`
	// Auth, if set, supplies upstream credentials via an environment variable.
	Auth *UpstreamAuth `mapstructure:"auth"`
}

// UpstreamAuth supplies upstream credentials. Mirrors DockerRegistryAuth but is
// deliberately a separate type (Docker is not migrated onto it — see issue #32).
// Credentials are NEVER stored in plaintext config; TokenEnv names an env var.
type UpstreamAuth struct {
	Type     string `mapstructure:"type"`      // "bearer" | "basic"
	TokenEnv string `mapstructure:"token_env"` // env var holding the token / basic credential
}

// DefaultOr returns the configured default upstream URL, or fallback when unset.
func (u UpstreamSet) DefaultOr(fallback string) string {
	if u.Default != "" {
		return u.Default
	}
	return fallback
}

// stringToUpstreamSetHookFunc decodes a bare string into UpstreamSet{Default:...}.
// This keeps `pypi: "https://pypi.org"` (and SGW_UPSTREAMS_PYPI=...) working after
// the field type changes from string to UpstreamSet. Non-string sources and
// non-UpstreamSet targets pass through untouched.
func stringToUpstreamSetHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if from.Kind() != reflect.String {
			return data, nil
		}
		if to != reflect.TypeOf(UpstreamSet{}) {
			return data, nil
		}
		return UpstreamSet{Default: data.(string)}, nil
	}
}

var upstreamIndexNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// validateHTTPSURL rejects anything that is not an absolute https URL with a
// host and no userinfo. Fail-closed control against SSRF / credential leakage.
func validateHTTPSURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("config: %s %q: %w", field, raw, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("config: %s %q must use https", field, raw)
	}
	if u.Host == "" {
		return fmt.Errorf("config: %s %q must have a host", field, raw)
	}
	if u.User != nil {
		return fmt.Errorf("config: %s %q must not contain userinfo (use auth.token_env)", field, raw)
	}
	return nil
}

// validateUpstreamSet validates one ecosystem's upstream configuration.
// A default-only set (the historical single-string case) always passes.
func validateUpstreamSet(eco string, set UpstreamSet) error {
	if set.Default != "" {
		if err := validateHTTPSURL(eco+".default", set.Default); err != nil {
			return err
		}
		// PyPI download-URL rewrite is hardcoded to files.pythonhosted.org. A
		// non-pypi.org default mirror whose files live elsewhere would NOT be
		// rewritten, so its artifacts would bypass scanning. Warn loudly; this is
		// a documented unsupported configuration (security review finding #5).
		if eco == "pypi" {
			if u, err := url.Parse(set.Default); err == nil && u.Host != "pypi.org" && u.Host != "www.pypi.org" {
				log.Warn().Str("default", set.Default).
					Msg("pypi.default is not pypi.org — package file downloads from a non-PyPI mirror are NOT rewritten through the scan pipeline and will bypass scanning; this is unsupported")
			}
		}
	}
	seen := make(map[string]struct{}, len(set.ExtraIndexes))
	for i, idx := range set.ExtraIndexes {
		where := fmt.Sprintf("%s.extra_indexes[%d]", eco, i)
		if !upstreamIndexNameRe.MatchString(idx.Name) {
			return fmt.Errorf("config: %s name %q must match ^[a-z0-9-]+$", where, idx.Name)
		}
		if _, dup := seen[idx.Name]; dup {
			return fmt.Errorf("config: %s duplicate index name %q", where, idx.Name)
		}
		seen[idx.Name] = struct{}{}
		if err := validateHTTPSURL(where+".url", idx.URL); err != nil {
			return err
		}
		if idx.FilesHost != "" {
			// files_host is a PyPI-only concept (separate file CDN). npm/nuget/etc.
			// serve artifacts from the registry origin and the download leg ignores
			// files_host, so honoring it on a non-pypi index would silently fail
			// closed on every download. Reject at load time instead of trapping
			// the operator at runtime (issue #32 security review).
			if eco != "pypi" {
				return fmt.Errorf("config: %s.files_host is only supported for pypi (remove it for %s)", where, eco)
			}
			if err := validateHTTPSURL(where+".files_host", idx.FilesHost); err != nil {
				return err
			}
		}
		for j, pat := range idx.Packages {
			// Reject the most common operator mistakes that silently unscope an
			// index and defeat dependency-confusion protection. Note: other
			// catch-all globs (e.g. "???*") are not exhaustively enumerated here —
			// they are much rarer in practice.
			if pat == "" || pat == "*" || pat == "**" {
				return fmt.Errorf("config: %s.packages[%d] pattern %q is empty or matches everything", where, j, pat)
			}
			if _, err := filepath.Match(pat, "probe"); err != nil {
				return fmt.Errorf("config: %s.packages[%d] invalid glob %q: %w", where, j, pat, err)
			}
		}
		if idx.Auth != nil {
			if idx.Auth.Type != "bearer" && idx.Auth.Type != "basic" {
				return fmt.Errorf("config: %s.auth.type %q must be \"bearer\" or \"basic\"", where, idx.Auth.Type)
			}
			if idx.Auth.TokenEnv == "" {
				return fmt.Errorf("config: %s.auth.token_env is required when auth is set", where)
			}
			// An authenticated index that can still be shadowed by a public default
			// is almost always a misconfiguration → WARN (not fatal).
			if len(idx.Packages) == 0 {
				log.Warn().Str("ecosystem", eco).Str("index", idx.Name).
					Msg("upstream index has auth but no `packages` scope — it can be shadowed by the default index; add a packages scope to pin its namespace")
			}
		}
	}
	return nil
}
