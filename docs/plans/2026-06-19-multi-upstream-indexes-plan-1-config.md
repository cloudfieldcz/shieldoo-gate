# Multi-Upstream Indexes — Phase 1: Config Foundation

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce the shared `UpstreamSet` / `UpstreamIndex` / `UpstreamAuth` config types, a back-compatible `string → UpstreamSet` decode hook, env-var binding, and config-load validation — with **zero behaviour change** (a default-only config behaves exactly as today's single string).

**Architecture:** A new `internal/config/config_upstreams.go` holds the types, a `DefaultOr` accessor, the mapstructure decode hook, and a per-set validator. `UpstreamsConfig`'s six non-Docker fields change `string → UpstreamSet`. `Load` wires the decode hook (preserving viper's existing duration/slice hooks) and binds `SGW_UPSTREAMS_*` env vars explicitly. `main.go` routes every non-Docker adapter through `UpstreamSet.DefaultOr(...)`, preserving single-upstream behaviour until later phases consume the full set.

**Tech Stack:** Go 1.25, `github.com/spf13/viper` v1.21.0, `github.com/go-viper/mapstructure/v2` v2.4.0 (already in `go.mod` as indirect — this phase promotes it to direct), `github.com/stretchr/testify`.

**Index:** [`plan-index.md`](./2026-06-19-multi-upstream-indexes-plan-index.md)

---

## File structure

- **Create:** `internal/config/config_upstreams.go` — types, `DefaultOr`, decode hook, validator.
- **Create:** `internal/config/config_upstreams_test.go` — unit tests for the above.
- **Modify:** `internal/config/config.go` — `UpstreamsConfig` field types; `Load` decode hook + `BindEnv`; `Validate` calls per-set validator.
- **Modify:** `cmd/shieldoo-gate/main.go:495-501` — route the six non-Docker upstreams through `.DefaultOr(...)`.
- **Modify:** `internal/config/config_test.go` — add back-compat assertions (bare string + env override).

---

## Task 1: Shared upstream config types + decode hook

**Files:**
- Create: `internal/config/config_upstreams.go`
- Test: `internal/config/config_upstreams_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/config/config_upstreams_test.go`:

```go
package config

import (
	"reflect"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpstreamSet_DefaultOr_EmptyReturnsFallback(t *testing.T) {
	var u UpstreamSet
	assert.Equal(t, "https://pypi.org", u.DefaultOr("https://pypi.org"))
}

func TestUpstreamSet_DefaultOr_SetReturnsDefault(t *testing.T) {
	u := UpstreamSet{Default: "https://mirror.example.com"}
	assert.Equal(t, "https://mirror.example.com", u.DefaultOr("https://pypi.org"))
}

func TestStringToUpstreamSetHook_BareStringDecodesToDefault(t *testing.T) {
	var out UpstreamSet
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: stringToUpstreamSetHookFunc(),
		Result:     &out,
	})
	require.NoError(t, err)
	require.NoError(t, dec.Decode("https://pypi.org"))
	assert.Equal(t, "https://pypi.org", out.Default)
	assert.Empty(t, out.ExtraIndexes)
}

func TestStringToUpstreamSetHook_StructDecodesUnchanged(t *testing.T) {
	in := map[string]interface{}{
		"default": "https://pypi.org",
		"extra_indexes": []interface{}{
			map[string]interface{}{
				"name":     "corp",
				"url":      "https://pkgs.internal.example.com/simple/",
				"packages": []interface{}{"mycompany-*"},
				"auth": map[string]interface{}{
					"type":      "basic",
					"token_env": "SGW_CORP_INDEX_TOKEN",
				},
			},
		},
	}
	var out UpstreamSet
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: stringToUpstreamSetHookFunc(),
		Result:     &out,
	})
	require.NoError(t, err)
	require.NoError(t, dec.Decode(in))
	assert.Equal(t, "https://pypi.org", out.Default)
	require.Len(t, out.ExtraIndexes, 1)
	assert.Equal(t, "corp", out.ExtraIndexes[0].Name)
	assert.Equal(t, []string{"mycompany-*"}, out.ExtraIndexes[0].Packages)
	require.NotNil(t, out.ExtraIndexes[0].Auth)
	assert.Equal(t, "basic", out.ExtraIndexes[0].Auth.Type)
	assert.Equal(t, "SGW_CORP_INDEX_TOKEN", out.ExtraIndexes[0].Auth.TokenEnv)
}

func TestStringToUpstreamSetHook_NonUpstreamTargetUntouched(t *testing.T) {
	// The hook must only fire for UpstreamSet targets, leaving e.g. plain strings alone.
	hook := stringToUpstreamSetHookFunc().(func(reflect.Type, reflect.Type, interface{}) (interface{}, error))
	out, err := hook(reflect.TypeOf(""), reflect.TypeOf(""), "hello")
	require.NoError(t, err)
	assert.Equal(t, "hello", out)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'UpstreamSet|UpstreamSetHook' -v`
Expected: FAIL to compile — `undefined: UpstreamSet`, `undefined: stringToUpstreamSetHookFunc`.

- [ ] **Step 3: Create the types + hook**

Create `internal/config/config_upstreams.go`:

```go
package config

import (
	"reflect"

	"github.com/go-viper/mapstructure/v2"
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -run 'UpstreamSet|UpstreamSetHook' -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Promote mapstructure to a direct dependency & commit**

Run: `go mod tidy && go build ./internal/config/`
Expected: `go.mod` now lists `github.com/go-viper/mapstructure/v2` without the `// indirect` comment; build succeeds.

```bash
git add internal/config/config_upstreams.go internal/config/config_upstreams_test.go go.mod go.sum
git commit -m "feat(config): add UpstreamSet types + string-to-set decode hook"
```

---

## Task 2: Switch UpstreamsConfig to UpstreamSet, wire hook + env, keep behaviour identical

**Files:**
- Modify: `internal/config/config.go` (`UpstreamsConfig` ~line 235-244; `Load` ~line 586-696)
- Modify: `cmd/shieldoo-gate/main.go:495-501`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing back-compat tests**

Add to `internal/config/config_test.go`:

```go
func TestLoad_PyPIBareString_DecodesToDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
upstreams:
  pypi: "https://pypi.org"
  npm: "https://registry.npmjs.org"
cache:
  backend: "local"
  local:
    path: "/tmp/cache"
database:
  backend: "sqlite"
  sqlite:
    path: "/tmp/gate.db"
`), 0o600))
	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "https://pypi.org", cfg.Upstreams.PyPI.Default)
	assert.Empty(t, cfg.Upstreams.PyPI.ExtraIndexes)
	assert.Equal(t, "https://registry.npmjs.org", cfg.Upstreams.NPM.Default)
}

func TestLoad_PyPIStructured_ParsesExtraIndexes(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
upstreams:
  pypi:
    default: "https://pypi.org"
    extra_indexes:
      - name: "hexaly"
        url: "https://pip.hexaly.com/hexaly/"
cache:
  backend: "local"
  local:
    path: "/tmp/cache"
database:
  backend: "sqlite"
  sqlite:
    path: "/tmp/gate.db"
`), 0o600))
	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "https://pypi.org", cfg.Upstreams.PyPI.Default)
	require.Len(t, cfg.Upstreams.PyPI.ExtraIndexes, 1)
	assert.Equal(t, "hexaly", cfg.Upstreams.PyPI.ExtraIndexes[0].Name)
	assert.Equal(t, "https://pip.hexaly.com/hexaly/", cfg.Upstreams.PyPI.ExtraIndexes[0].URL)
}

// Regression: overriding viper's DecodeHook drops its built-in comma-slice hook.
// We re-add mapstructure.StringToSliceHookFunc(","); this proves an existing
// []string config field still decodes from BOTH a YAML list and a comma env var.
func TestLoad_StringSliceHook_StillWorksAfterDecodeHookOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
upstreams:
  pypi: "https://pypi.org"
scanners:
  typosquat:
    combosquat_suffixes: ["-utils", "-helper"]
cache:
  backend: "local"
  local:
    path: "/tmp/cache"
database:
  backend: "sqlite"
  sqlite:
    path: "/tmp/gate.db"
`), 0o600))
	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"-utils", "-helper"}, cfg.Scanners.Typosquat.CombosquatSuffixes)

	// Comma env override into the same []string field still splits.
	t.Setenv("SGW_SCANNERS_TYPOSQUAT_COMBOSQUAT_SUFFIXES", "-x,-y,-z")
	cfg2, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"-x", "-y", "-z"}, cfg2.Scanners.Typosquat.CombosquatSuffixes)
}

func TestLoad_PyPIEnvOverride_PopulatesDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
upstreams:
  pypi: "https://pypi.org"
cache:
  backend: "local"
  local:
    path: "/tmp/cache"
database:
  backend: "sqlite"
  sqlite:
    path: "/tmp/gate.db"
`), 0o600))
	t.Setenv("SGW_UPSTREAMS_PYPI", "https://mirror.internal.example.com")
	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "https://mirror.internal.example.com", cfg.Upstreams.PyPI.Default)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestLoad_PyPI' -v`
Expected: FAIL to compile — `cfg.Upstreams.PyPI.Default undefined (type string has no field or method Default)`.

- [ ] **Step 3: Change `UpstreamsConfig` field types**

In `internal/config/config.go`, change the six non-Docker fields (currently `string`) to `UpstreamSet`. The struct becomes:

```go
type UpstreamsConfig struct {
	PyPI          UpstreamSet          `mapstructure:"pypi"`
	NPM           UpstreamSet          `mapstructure:"npm"`
	NuGet         UpstreamSet          `mapstructure:"nuget"`
	Docker        DockerUpstreamConfig `mapstructure:"docker"`
	Maven         UpstreamSet          `mapstructure:"maven"`
	MavenResolver MavenResolverConfig  `mapstructure:"maven_resolver"`
	RubyGems      UpstreamSet          `mapstructure:"rubygems"`
	GoMod         UpstreamSet          `mapstructure:"gomod"`
}
```

- [ ] **Step 4: Wire the decode hook + BindEnv into `Load`**

In `internal/config/config.go`, add the mapstructure import to the import block:

```go
	"github.com/go-viper/mapstructure/v2"
```

In `Load`, immediately after `v.AutomaticEnv()` (~line 592), bind the env keys explicitly (AutomaticEnv does not reliably populate a now-struct field from a scalar env var):

```go
	// Explicit env binding for upstreams that are now structured (UpstreamSet).
	// A scalar SGW_UPSTREAMS_<ECO> is decoded into UpstreamSet.Default via the
	// string-to-set decode hook below. AutomaticEnv alone does not populate a
	// nested-struct key from a scalar env var.
	for _, eco := range []string{"pypi", "npm", "nuget", "maven", "rubygems", "gomod"} {
		_ = v.BindEnv("upstreams."+eco, "SGW_UPSTREAMS_"+strings.ToUpper(eco))
	}
```

Then replace the final unmarshal (currently `if err := v.Unmarshal(&cfg); err != nil {` ~line 694) with a decode-hook-aware unmarshal that **preserves viper's two default hooks** (duration + comma-slice) and adds ours:

```go
	decodeOpt := viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
		stringToUpstreamSetHookFunc(),
	))
	if err := v.Unmarshal(&cfg, decodeOpt); err != nil {
		return nil, fmt.Errorf("config: unmarshalling: %w", err)
	}
```

- [ ] **Step 5: Update `main.go` to route through `DefaultOr` (no behaviour change)**

In `cmd/shieldoo-gate/main.go`, replace lines 496-501 (the `fallback(cfg.Upstreams.X, ...)` block) with:

```go
	// Resolve upstream URLs with sensible defaults.
	// Phase 1: each ecosystem still uses only the default URL (DefaultOr) — behaviour
	// is identical to the previous single-string config. Later phases consume the
	// full UpstreamSet (extra_indexes) per ecosystem.
	pypiUpstream := cfg.Upstreams.PyPI.DefaultOr("https://pypi.org")
	npmUpstream := cfg.Upstreams.NPM.DefaultOr("https://registry.npmjs.org")
	nugetUpstream := cfg.Upstreams.NuGet.DefaultOr("https://api.nuget.org")
	mavenUpstream := cfg.Upstreams.Maven.DefaultOr("https://repo1.maven.org/maven2")
	rubygemsUpstream := cfg.Upstreams.RubyGems.DefaultOr("https://rubygems.org")
	gomodUpstream := cfg.Upstreams.GoMod.DefaultOr("https://proxy.golang.org")
```

**Do NOT delete the `fallback`/`orDefault` helper** (`main.go:961-966`). It is still used by npm/nuget/maven/rubygems/gomod, which only migrate in Phases 5–7. Leaving it untouched here keeps the build green; it is removed in the final ecosystem phase once no caller remains.

- [ ] **Step 6: Run the full build + config tests**

Run: `go build ./... && go test ./internal/config/ -run 'TestLoad' -v`
Expected: build PASS; all `TestLoad*` tests PASS, including the pre-existing `TestLoad_FromYAML_ParsesAllSections` (bare-string `pypi:`/`npm:`/`nuget:` still decode via the hook) and the three new back-compat tests.

- [ ] **Step 7: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go cmd/shieldoo-gate/main.go
git commit -m "feat(config): UpstreamsConfig fields to UpstreamSet, back-compat decode hook + env bind"
```

---

## Task 3: Validate upstream sets at config load

**Files:**
- Modify: `internal/config/config_upstreams.go` (add validator)
- Modify: `internal/config/config.go` (`Validate` ~line 702-814 calls the validator)
- Test: `internal/config/config_upstreams_test.go`

- [ ] **Step 1: Write the failing validation tests**

Add to `internal/config/config_upstreams_test.go`:

```go
func TestValidateUpstreamSet_DefaultOnly_OK(t *testing.T) {
	require.NoError(t, validateUpstreamSet("pypi", UpstreamSet{Default: "https://pypi.org"}))
}

func TestValidateUpstreamSet_HTTPIndexURL_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{Name: "corp", URL: "http://insecure.example.com/"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestValidateUpstreamSet_UserinfoURL_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{Name: "corp", URL: "https://user:pass@example.com/"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "userinfo")
}

func TestValidateUpstreamSet_BadName_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{Name: "Corp_Index", URL: "https://example.com/"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestValidateUpstreamSet_DuplicateName_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{
			{Name: "corp", URL: "https://a.example.com/"},
			{Name: "corp", URL: "https://b.example.com/"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestValidateUpstreamSet_StarOnlyPattern_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{Name: "corp", URL: "https://example.com/", Packages: []string{"*"}}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern")
}

func TestValidateUpstreamSet_BadAuthType_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{
			Name: "corp", URL: "https://example.com/",
			Packages: []string{"corp-*"},
			Auth:     &UpstreamAuth{Type: "token", TokenEnv: "X"},
		}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth")
}

func TestValidateUpstreamSet_AuthMissingTokenEnv_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{
			Name: "corp", URL: "https://example.com/",
			Packages: []string{"corp-*"},
			Auth:     &UpstreamAuth{Type: "bearer", TokenEnv: ""},
		}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token_env")
}

func TestValidateUpstreamSet_ValidScopedAuthIndex_OK(t *testing.T) {
	require.NoError(t, validateUpstreamSet("pypi", UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []UpstreamIndex{{
			Name: "corp", URL: "https://pkgs.internal.example.com/simple/",
			FilesHost: "https://files.internal.example.com/",
			Packages:  []string{"mycompany-*", "acme-*"},
			Auth:      &UpstreamAuth{Type: "basic", TokenEnv: "SGW_CORP_INDEX_TOKEN"},
		}},
	}))
}

func TestValidateUpstreamSet_FilesHostHTTP_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{Name: "corp", URL: "https://example.com/", FilesHost: "http://files.example.com/"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "files_host")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestValidateUpstreamSet' -v`
Expected: FAIL to compile — `undefined: validateUpstreamSet`.

- [ ] **Step 3: Implement the validator**

Add to `internal/config/config_upstreams.go` (extend the import block with `fmt`, `net/url`, `path/filepath`, `regexp`, and `github.com/rs/zerolog/log`):

```go
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
			if err := validateHTTPSURL(where+".files_host", idx.FilesHost); err != nil {
				return err
			}
		}
		for j, pat := range idx.Packages {
			if pat == "" || pat == "*" {
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
```

- [ ] **Step 4: Call the validator from `Validate`**

In `internal/config/config.go`, inside `func (c *Config) Validate() error` (before the final `return nil` at ~line 814), add:

```go
	for eco, set := range map[string]UpstreamSet{
		"pypi":     c.Upstreams.PyPI,
		"npm":      c.Upstreams.NPM,
		"nuget":    c.Upstreams.NuGet,
		"maven":    c.Upstreams.Maven,
		"rubygems": c.Upstreams.RubyGems,
		"gomod":    c.Upstreams.GoMod,
	} {
		if err := validateUpstreamSet(eco, set); err != nil {
			return err
		}
	}
```

- [ ] **Step 5: Run validation tests + full config suite**

Run: `go test ./internal/config/ -v`
Expected: PASS (all new validator tests + pre-existing config tests).

- [ ] **Step 6: Full phase verification**

Run: `make build && make lint && make test`
Expected: build PASS, lint clean, all tests PASS. (No e2e for this phase — pure config, no behaviour change.)

- [ ] **Step 7: Commit**

```bash
git add internal/config/config_upstreams.go internal/config/config_upstreams_test.go internal/config/config.go
git commit -m "feat(config): validate upstream sets (https-only, scoping, auth) at load"
```

---

## Phase 1 done-when

- [ ] `UpstreamsConfig` exposes `UpstreamSet` for pypi/npm/nuget/maven/rubygems/gomod; Docker unchanged.
- [ ] Bare-string config and `SGW_UPSTREAMS_*` env vars still work (back-compat tests green).
- [ ] Structured config with `extra_indexes` parses; invalid sets fail at `Validate()` with clear errors.
- [ ] `main.go` builds and runs with identical single-upstream behaviour (via `DefaultOr`).
- [ ] `make build && make lint && make test` all green.
- [ ] No `docs/` change needed yet (config schema is documented in Phase 7); `config.example.yaml` left untouched until Phase 3 demonstrates the PyPI shape end-to-end.
