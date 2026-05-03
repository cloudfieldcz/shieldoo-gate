package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	Ports      PortsConfig      `mapstructure:"ports"`
	Upstreams  UpstreamsConfig  `mapstructure:"upstreams"`
	Cache      CacheConfig      `mapstructure:"cache"`
	Database   DatabaseConfig   `mapstructure:"database"`
	Scanners   ScannersConfig   `mapstructure:"scanners"`
	Policy     PolicyConfig     `mapstructure:"policy"`
	ThreatFeed ThreatFeedConfig `mapstructure:"threat_feed"`
	Rescan     RescanConfig     `mapstructure:"rescan"`
	Log        LogConfig        `mapstructure:"log"`
	Alerts     AlertsConfig     `mapstructure:"alerts"`
	Auth       AuthConfig       `mapstructure:"auth"`
	ProxyAuth  ProxyAuthConfig  `mapstructure:"proxy_auth"`
	PublicURLs PublicURLsConfig `mapstructure:"public_urls"`
	Projects   ProjectsConfig   `mapstructure:"projects"`
	SBOM       SBOMConfig       `mapstructure:"sbom"`
}

// ProjectsConfig controls project registry behavior.
// In lazy mode, unknown Basic auth labels auto-create projects (rate-limited, capped).
// In strict mode, unknown labels are rejected at auth time.
type ProjectsConfig struct {
	Mode             string   `mapstructure:"mode"`               // "lazy" | "strict" (default: "lazy")
	DefaultLabel     string   `mapstructure:"default_label"`      // fallback for empty username (default: "default")
	LabelRegex       string   `mapstructure:"label_regex"`        // optional custom validation regex
	MaxCount         int      `mapstructure:"max_count"`          // hard cap on total projects (default: 1000, 0 = unlimited)
	LazyCreateRate   int      `mapstructure:"lazy_create_rate"`   // new projects per hour per identity (default: 10)
	CacheSize        int      `mapstructure:"cache_size"`         // LRU cache entries (default: 512)
	CacheTTL         string   `mapstructure:"cache_ttl"`          // LRU entry TTL (default: "5m")
	UsageFlushPeriod string   `mapstructure:"usage_flush_period"` // debounced usage upsert interval (default: "30s")
	BootstrapLabels  []string `mapstructure:"bootstrap_labels"`   // labels guaranteed to exist on startup; idempotent. Required for strict mode pre-provisioning.
}

// SBOMConfig controls CycloneDX SBOM generation and storage.
type SBOMConfig struct {
	Enabled    bool   `mapstructure:"enabled"`     // default false
	Format     string `mapstructure:"format"`      // "cyclonedx-json" (only option in v1.2)
	AsyncWrite bool   `mapstructure:"async_write"` // write blob asynchronously, default true
	TTL        string `mapstructure:"ttl"`         // retention duration, default "30d"
}

// PublicURLsConfig holds the public-facing URLs for each ecosystem proxy.
// When set, the admin UI displays these instead of <host>:port placeholders.
type PublicURLsConfig struct {
	PyPI     string `mapstructure:"pypi"     json:"pypi,omitempty"`
	NPM      string `mapstructure:"npm"      json:"npm,omitempty"`
	NuGet    string `mapstructure:"nuget"    json:"nuget,omitempty"`
	Docker   string `mapstructure:"docker"   json:"docker,omitempty"`
	Maven    string `mapstructure:"maven"    json:"maven,omitempty"`
	RubyGems string `mapstructure:"rubygems" json:"rubygems,omitempty"`
	GoMod    string `mapstructure:"gomod"    json:"gomod,omitempty"`
}

// ProxyAuthConfig holds API key authentication configuration for proxy endpoints.
// When Enabled is false (default), proxy endpoints are open — backward compatible.
type ProxyAuthConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	GlobalTokenEnv string `mapstructure:"global_token_env"`
}

// AuthConfig holds OIDC authentication configuration for the admin API.
// When Enabled is false (default), the admin API is fully open — backward compatible.
type AuthConfig struct {
	Enabled        bool     `mapstructure:"enabled"`
	IssuerURL      string   `mapstructure:"issuer_url"`
	ClientID       string   `mapstructure:"client_id"`
	ClientSecretEnv string  `mapstructure:"client_secret_env"`
	RedirectURL    string   `mapstructure:"redirect_url"`
	Scopes         []string `mapstructure:"scopes"`
}

// RescanConfig controls the periodic artifact rescan scheduler.
type RescanConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	Interval      string `mapstructure:"interval"`       // scheduler tick interval, default "6h"
	BatchSize     int    `mapstructure:"batch_size"`      // max artifacts per tick, default 100
	MaxConcurrent int    `mapstructure:"max_concurrent"`  // concurrent scans, default 5
}

// knownEventTypes is the set of recognised event type strings for alert "on" filters.
var knownEventTypes = map[string]bool{
	"SERVED":           true,
	"BLOCKED":          true,
	"QUARANTINED":      true,
	"RELEASED":         true,
	"SCANNED":          true,
	"OVERRIDE_CREATED": true,
	"OVERRIDE_REVOKED": true,
	"TAG_MUTATED":      true,
	"RESCAN_QUEUED":          true,
	"ALLOWED_WITH_WARNING":   true,
	"LICENSE_BLOCKED":        true,
	"LICENSE_WARNED":         true,
	"LICENSE_CHECK_SKIPPED":  true,
	"PROJECT_NOT_FOUND":      true,
	"SBOM_GENERATED":         true,
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
}

type PortsConfig struct {
	PyPI   int `mapstructure:"pypi"`
	NPM    int `mapstructure:"npm"`
	NuGet  int `mapstructure:"nuget"`
	Docker int `mapstructure:"docker"`
	Maven    int `mapstructure:"maven"`
	RubyGems int `mapstructure:"rubygems"`
	GoMod    int `mapstructure:"gomod"`
	Admin    int `mapstructure:"admin"`
}

type UpstreamsConfig struct {
	PyPI          string               `mapstructure:"pypi"`
	NPM           string               `mapstructure:"npm"`
	NuGet         string               `mapstructure:"nuget"`
	Docker        DockerUpstreamConfig `mapstructure:"docker"`
	Maven         string               `mapstructure:"maven"`
	MavenResolver MavenResolverConfig  `mapstructure:"maven_resolver"`
	RubyGems      string               `mapstructure:"rubygems"`
	GoMod         string               `mapstructure:"gomod"`
}

// MavenResolverConfig controls the effective-POM parent chain resolver.
// When enabled (default), the resolver fetches standalone .pom files from
// the upstream Maven repository and walks the parent chain to discover
// licenses that are inherited rather than declared inline.
type MavenResolverConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	CacheSize       int    `mapstructure:"cache_size"`
	CacheTTL        string `mapstructure:"cache_ttl"`
	MaxDepth        int    `mapstructure:"max_depth"`
	FetchTimeout    string `mapstructure:"fetch_timeout"`
	ResolverTimeout string `mapstructure:"resolver_timeout"`
}

type DockerUpstreamConfig struct {
	DefaultRegistry   string                `mapstructure:"default_registry"`
	AllowedRegistries []DockerRegistryEntry `mapstructure:"allowed_registries"`
	Sync              DockerSyncConfig      `mapstructure:"sync"`
	Push              DockerPushConfig      `mapstructure:"push"`
}

type DockerRegistryEntry struct {
	Host string              `mapstructure:"host"`
	URL  string              `mapstructure:"url"`
	Auth *DockerRegistryAuth `mapstructure:"auth"`
}

// DockerRegistryAuth holds per-registry credentials.
// TokenEnv references an environment variable — credentials are NEVER stored in config plaintext.
type DockerRegistryAuth struct {
	Type     string `mapstructure:"type"`      // "bearer" or "basic"
	TokenEnv string `mapstructure:"token_env"` // env var name containing the token/password
}

type DockerSyncConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	Interval       string `mapstructure:"interval"`
	RescanInterval string `mapstructure:"rescan_interval"`
	MaxConcurrent  int    `mapstructure:"max_concurrent"`
}

type DockerPushConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type CacheConfig struct {
	Backend   string           `mapstructure:"backend"` // "local" (default), "s3", "azure_blob", or "gcs"
	Local     LocalCacheConfig `mapstructure:"local"`
	S3        S3CacheConfig    `mapstructure:"s3"`
	AzureBlob AzureBlobConfig  `mapstructure:"azure_blob"`
	GCS       GCSCacheConfig   `mapstructure:"gcs"`
	TTL       TTLConfig        `mapstructure:"ttl"`
}

type AzureBlobConfig struct {
	AccountName      string `mapstructure:"account_name"`
	ContainerName    string `mapstructure:"container_name"`
	ConnectionStrEnv string `mapstructure:"connection_string_env"` // env var name for connection string
	Prefix           string `mapstructure:"prefix"`
}

type GCSCacheConfig struct {
	Bucket          string `mapstructure:"bucket"`
	CredentialsFile string `mapstructure:"credentials_file"` // optional path to service account JSON
	Prefix          string `mapstructure:"prefix"`
}

type S3CacheConfig struct {
	Bucket         string `mapstructure:"bucket"`
	Region         string `mapstructure:"region"`
	Endpoint       string `mapstructure:"endpoint"`         // for MinIO / S3-compatible
	Prefix         string `mapstructure:"prefix"`           // optional key prefix
	ForcePathStyle bool   `mapstructure:"force_path_style"` // for MinIO
	AccessKeyEnv   string `mapstructure:"access_key_env"`   // env var name for access key
	SecretKeyEnv   string `mapstructure:"secret_key_env"`   // env var name for secret key
}

type LocalCacheConfig struct {
	Path      string `mapstructure:"path"`
	MaxSizeGB int64  `mapstructure:"max_size_gb"`
}

type TTLConfig struct {
	PyPI   string `mapstructure:"pypi"`
	NPM    string `mapstructure:"npm"`
	NuGet  string `mapstructure:"nuget"`
	Docker string `mapstructure:"docker"`
}

type DatabaseConfig struct {
	Backend  string         `mapstructure:"backend"`
	SQLite   SQLiteConfig   `mapstructure:"sqlite"`
	Postgres PostgresConfig `mapstructure:"postgres"`
}

type SQLiteConfig struct {
	Path string `mapstructure:"path"`
}

type PostgresConfig struct {
	DSN             string `mapstructure:"dsn"`
	MaxOpenConns    int    `mapstructure:"max_open_conns"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns"`
	ConnMaxLifetime string `mapstructure:"conn_max_lifetime"`
}

type ScannersConfig struct {
	Parallel  bool            `mapstructure:"parallel"`
	Timeout   string          `mapstructure:"timeout"`
	GuardDog  GuardDogConfig  `mapstructure:"guarddog"`
	Trivy     TrivyConfig     `mapstructure:"trivy"`
	OSV       OSVConfig       `mapstructure:"osv"`
	Sandbox   SandboxConfig   `mapstructure:"sandbox"`
	AI        AIConfig        `mapstructure:"ai"`
	Typosquat   TyposquatConfig   `mapstructure:"typosquat"`
	VersionDiff VersionDiffConfig `mapstructure:"version_diff"`
	Reputation  ReputationConfig  `mapstructure:"reputation"`
}

// AIConfig holds configuration for the AI (LLM-based) scanner.
// The scanner uses Azure OpenAI or OpenAI API to analyze install-time scripts.
type AIConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	Provider        string `mapstructure:"provider"`          // "azure_openai" (default) or "openai"
	Model           string `mapstructure:"model"`             // e.g. "gpt-5.4-mini"
	APIKeyEnv       string `mapstructure:"api_key_env"`       // env var name for API key
	Timeout         string `mapstructure:"timeout"`           // per-API call timeout, default "15s"
	MaxInputTokens  int    `mapstructure:"max_input_tokens"`  // max tokens sent to LLM, default 32000
	BridgeSocket    string `mapstructure:"bridge_socket"`     // scanner-bridge Unix socket path
	AzureEndpoint   string `mapstructure:"azure_endpoint"`    // Azure OpenAI endpoint URL
	AzureDeployment string `mapstructure:"azure_deployment"`  // Azure deployment name
}

// SandboxConfig holds configuration for the dynamic sandbox (gVisor) scanner.
// The sandbox scanner runs asynchronously — it does not block the download path.
type SandboxConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	RuntimeBinary string `mapstructure:"runtime_binary"` // default "runsc"
	Timeout       string `mapstructure:"timeout"`         // default "30s"
	NetworkPolicy string `mapstructure:"network_policy"`  // "none" or "monitor"
	MaxConcurrent int    `mapstructure:"max_concurrent"`  // default 2
}

// TyposquatConfig holds configuration for the built-in typosquatting detection scanner.
type TyposquatConfig struct {
	Enabled            bool     `mapstructure:"enabled"`
	TopPackagesCount   int      `mapstructure:"top_packages_count"`
	MaxEditDistance     int      `mapstructure:"max_edit_distance"`
	InternalNamespaces []string `mapstructure:"internal_namespaces"`
	CombosquatSuffixes []string `mapstructure:"combosquat_suffixes"`
	Allowlist          []string `mapstructure:"allowlist"`
	// PersistDedupWindowSeconds controls how long PersistTyposquatBlock will
	// suppress repeated DB writes for the same artifact ID. Bounds DB-write
	// growth under typosquat-name flooding without retaining audit_log
	// entries (which stay append-only per security invariant). Default 300
	// (5 minutes); 0 disables dedup.
	PersistDedupWindowSeconds int `mapstructure:"persist_dedup_window_seconds"`
}

// VersionDiffConfig holds configuration for the AI-driven version diff scanner.
// The scanner sends new + previous artifact paths to scanner-bridge over gRPC,
// where a Python module extracts diffs and calls the LLM (gpt-5.4-mini default).
//
// Mode "shadow" runs the scanner but ScanResult.Verdict is forced to CLEAN so
// the policy engine ignores it. Mode "active" passes the LLM verdict through.
type VersionDiffConfig struct {
	Enabled                 bool     `mapstructure:"enabled"`
	Mode                    string   `mapstructure:"mode"`                       // "shadow" | "active"
	MaxArtifactSizeMB       int      `mapstructure:"max_artifact_size_mb"`       // default 50
	MaxExtractedSizeMB      int      `mapstructure:"max_extracted_size_mb"`      // default 50
	MaxExtractedFiles       int      `mapstructure:"max_extracted_files"`        // default 5000
	ScannerTimeout          string   `mapstructure:"scanner_timeout"`            // default "55s" — must be < scanners.timeout
	BridgeSocket            string   `mapstructure:"bridge_socket"`              // shared with ai-scanner; empty = reuse guarddog socket
	Allowlist               []string `mapstructure:"allowlist"`
	MinConfidence           float32  `mapstructure:"min_confidence"`             // default 0.6 — SUSPICIOUS below this is downgraded to CLEAN with audit_log entry
	PerPackageRateLimit     int      `mapstructure:"per_package_rate_limit"`     // default 10 LLM calls/h/package; 0 = unlimited
	DailyCostLimitUSD       float64  `mapstructure:"daily_cost_limit_usd"`       // default 5.0; circuit breaker auto-disables on exceed
	CircuitBreakerThreshold int      `mapstructure:"circuit_breaker_threshold"`  // default 5 consecutive failures triggers 60 s pause
}

// ReputationConfig holds configuration for the maintainer/package reputation scanner.
// The scanner queries upstream registry APIs for metadata (maintainer history,
// publication patterns, download counts) and produces a risk score.
type ReputationConfig struct {
	Enabled      bool                 `mapstructure:"enabled"`
	CacheTTL     string               `mapstructure:"cache_ttl"`      // metadata cache TTL, default "24h"
	CacheTTLJitter string             `mapstructure:"cache_ttl_jitter"` // random jitter added to TTL, default "2h"
	Timeout      string               `mapstructure:"timeout"`        // per-request timeout, default "10s"
	RateLimit    int                  `mapstructure:"rate_limit"`     // max upstream API requests per minute per ecosystem, default 30
	RetentionDays int                 `mapstructure:"retention_days"` // delete stale entries older than this, default 30
	Thresholds   ReputationThresholds `mapstructure:"thresholds"`
	Signals      ReputationSignals    `mapstructure:"signals"`
}

// ReputationThresholds controls verdict thresholds for reputation risk scores.
type ReputationThresholds struct {
	Suspicious float64 `mapstructure:"suspicious"` // score >= this → SUSPICIOUS, default 0.5
	Malicious  float64 `mapstructure:"malicious"`  // score >= this → MALICIOUS, default 0.8
}

// ReputationSignals holds per-signal enable/weight configuration.
type ReputationSignals struct {
	// V1 signals
	PackageAge          SignalConfig `mapstructure:"package_age"`
	LowDownloads        SignalConfig `mapstructure:"low_downloads"`
	NoSourceRepo        SignalConfig `mapstructure:"no_source_repo"`
	DormantReactivation SignalConfig `mapstructure:"dormant_reactivation"`
	FewVersions         SignalConfig `mapstructure:"few_versions"`
	NoDescription       SignalConfig `mapstructure:"no_description"`
	VersionCountSpike   SignalConfig `mapstructure:"version_count_spike"`
	OwnershipChange     SignalConfig `mapstructure:"ownership_change"`
	// V2 signals (from feature spec)
	YankedVersions        SignalConfig `mapstructure:"yanked_versions"`
	UnusualVersioning     SignalConfig `mapstructure:"unusual_versioning"`
	MaintainerEmailDomain SignalConfig `mapstructure:"maintainer_email_domain"`
	FirstPublication      SignalConfig `mapstructure:"first_publication"`
	RepoMismatch          SignalConfig `mapstructure:"repo_mismatch"`
	ClassifierAnomaly     SignalConfig `mapstructure:"classifier_anomaly"`
}

// SignalConfig controls a single reputation signal.
type SignalConfig struct {
	Enabled bool    `mapstructure:"enabled"`
	Weight  float64 `mapstructure:"weight"`
}

type GuardDogConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	BridgeSocket string `mapstructure:"bridge_socket"`
}

type TrivyConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Binary   string `mapstructure:"binary"`
	CacheDir string `mapstructure:"cache_dir"`
}

type OSVConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	APIURL  string `mapstructure:"api_url"`
}

type PolicyConfig struct {
	Mode                        string              `mapstructure:"mode"`
	BlockIfVerdict              string              `mapstructure:"block_if_verdict"`
	QuarantineIfVerdict         string              `mapstructure:"quarantine_if_verdict"`
	MinimumConfidence           float32             `mapstructure:"minimum_confidence"`
	BehavioralMinimumConfidence float32             `mapstructure:"behavioral_minimum_confidence"`
	AITriage                    AITriageConfig      `mapstructure:"ai_triage"`
	Allowlist                   []string            `mapstructure:"allowlist"`
	TagMutability               TagMutabilityConfig `mapstructure:"tag_mutability"`
	Licenses                    LicensePolicyConfig `mapstructure:"licenses"`
}

// LicensePolicyConfig controls SPDX-based license policy enforcement.
// When Enabled is false, license evaluation is skipped entirely.
type LicensePolicyConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	Blocked       []string `mapstructure:"blocked"`        // SPDX ids to always block
	Warned        []string `mapstructure:"warned"`         // allow + warning
	Allowed       []string `mapstructure:"allowed"`        // whitelist mode if non-empty
	UnknownAction string   `mapstructure:"unknown_action"` // "allow" | "warn" | "block" (default: "allow")
	OnSBOMError   string   `mapstructure:"on_sbom_error"`  // "allow" | "warn" | "block" (default: "allow")
	OrSemantics   string   `mapstructure:"or_semantics"`   // "any_allowed" | "all_allowed" (default: "any_allowed")
}

// AITriageConfig holds configuration for AI-assisted triage in balanced mode.
type AITriageConfig struct {
	Enabled                 bool    `mapstructure:"enabled"`
	Timeout                 string  `mapstructure:"timeout"`
	MinConfidence           float32 `mapstructure:"min_confidence"`
	CacheTTL                string  `mapstructure:"cache_ttl"`
	RateLimit               int     `mapstructure:"rate_limit"`
	CircuitBreakerThreshold int     `mapstructure:"circuit_breaker_threshold"`
	CircuitBreakerCooldown  string  `mapstructure:"circuit_breaker_cooldown"`
}

// TagMutabilityConfig controls upstream digest change detection on cache hits.
type TagMutabilityConfig struct {
	Enabled         bool     `mapstructure:"enabled"`
	Action          string   `mapstructure:"action"`             // "quarantine" | "warn" | "block"
	ExcludeTags     []string `mapstructure:"exclude_tags"`       // e.g., ["latest", "dev", "nightly"]
	CheckOnCacheHit bool     `mapstructure:"check_on_cache_hit"` // default false; adds latency to cache hits
}

type ThreatFeedConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	URL             string `mapstructure:"url"`
	RefreshInterval string `mapstructure:"refresh_interval"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	File   string `mapstructure:"file"` // optional: also write logs to this file path
}

type AlertsConfig struct {
	Webhook WebhookAlertConfig `mapstructure:"webhook"`
	Slack   SlackAlertConfig   `mapstructure:"slack"`
	Email   EmailAlertConfig   `mapstructure:"email"`
}

type WebhookAlertConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	URL           string   `mapstructure:"url"`
	SecretEnv     string   `mapstructure:"secret_env"`
	AllowInsecure bool     `mapstructure:"allow_insecure"`
	On            []string `mapstructure:"on"`
}

type SlackAlertConfig struct {
	Enabled    bool     `mapstructure:"enabled"`
	WebhookEnv string   `mapstructure:"webhook_env"`
	On         []string `mapstructure:"on"`
}

type EmailAlertConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	Host          string   `mapstructure:"host"`
	Port          int      `mapstructure:"port"`
	From          string   `mapstructure:"from"`
	To            []string `mapstructure:"to"`
	UsernameEnv   string   `mapstructure:"username_env"`
	PasswordEnv   string   `mapstructure:"password_env"`
	UseTLS        bool     `mapstructure:"use_tls"`
	TLSSkipVerify bool     `mapstructure:"tls_skip_verify"`
	BatchInterval string   `mapstructure:"batch_interval"`
	On            []string `mapstructure:"on"`
}

// Load reads the YAML config file at path and applies any SGW_* environment overrides.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("SGW")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}

	// Set policy defaults before unmarshal so zero-value config is safe.
	v.SetDefault("policy.mode", "")
	v.SetDefault("policy.block_if_verdict", "MALICIOUS")
	v.SetDefault("policy.quarantine_if_verdict", "SUSPICIOUS")
	v.SetDefault("policy.minimum_confidence", 0.7)
	v.SetDefault("policy.ai_triage.enabled", false)
	v.SetDefault("policy.ai_triage.timeout", "5s")
	v.SetDefault("policy.ai_triage.min_confidence", 0.7)
	v.SetDefault("policy.ai_triage.cache_ttl", "168h")
	v.SetDefault("policy.ai_triage.rate_limit", 10)
	v.SetDefault("policy.ai_triage.circuit_breaker_threshold", 5)
	v.SetDefault("policy.ai_triage.circuit_breaker_cooldown", "60s")

	v.SetDefault("projects.mode", "lazy")
	v.SetDefault("projects.default_label", "default")
	v.SetDefault("projects.max_count", 1000)
	v.SetDefault("projects.lazy_create_rate", 10)
	v.SetDefault("projects.cache_size", 512)
	v.SetDefault("projects.cache_ttl", "5m")
	v.SetDefault("projects.usage_flush_period", "30s")

	v.SetDefault("sbom.enabled", false)
	v.SetDefault("sbom.format", "cyclonedx-json")
	v.SetDefault("sbom.async_write", true)
	v.SetDefault("sbom.ttl", "30d")

	v.SetDefault("upstreams.maven_resolver.enabled", true)
	v.SetDefault("upstreams.maven_resolver.cache_size", 4096)
	v.SetDefault("upstreams.maven_resolver.cache_ttl", "24h")
	v.SetDefault("upstreams.maven_resolver.max_depth", 5)
	v.SetDefault("upstreams.maven_resolver.fetch_timeout", "3s")
	v.SetDefault("upstreams.maven_resolver.resolver_timeout", "5s")

	v.SetDefault("policy.licenses.enabled", false)
	v.SetDefault("policy.licenses.unknown_action", "allow")
	v.SetDefault("policy.licenses.on_sbom_error", "allow")
	v.SetDefault("policy.licenses.or_semantics", "any_allowed")

	v.SetDefault("scanners.typosquat.enabled", true)
	v.SetDefault("scanners.typosquat.max_edit_distance", 2)
	v.SetDefault("scanners.typosquat.top_packages_count", 5000)
	v.SetDefault("scanners.typosquat.combosquat_suffixes", []string{"-utils", "-helper", "-lib", "-dev", "-tool", "-sdk"})

	v.SetDefault("scanners.version_diff.enabled", false)
	v.SetDefault("scanners.version_diff.mode", "shadow")
	v.SetDefault("scanners.version_diff.max_artifact_size_mb", 50)
	v.SetDefault("scanners.version_diff.max_extracted_size_mb", 50)
	v.SetDefault("scanners.version_diff.max_extracted_files", 5000)
	v.SetDefault("scanners.version_diff.scanner_timeout", "55s")
	v.SetDefault("scanners.version_diff.min_confidence", 0.6)
	v.SetDefault("scanners.version_diff.per_package_rate_limit", 10)
	v.SetDefault("scanners.version_diff.daily_cost_limit_usd", 5.0)
	v.SetDefault("scanners.version_diff.circuit_breaker_threshold", 5)

	v.SetDefault("scanners.reputation.enabled", false)
	v.SetDefault("scanners.reputation.cache_ttl", "24h")
	v.SetDefault("scanners.reputation.timeout", "10s")
	v.SetDefault("scanners.reputation.thresholds.suspicious", 0.5)
	v.SetDefault("scanners.reputation.thresholds.malicious", 0.8)
	v.SetDefault("scanners.reputation.signals.package_age.enabled", true)
	v.SetDefault("scanners.reputation.signals.package_age.weight", 0.3)
	v.SetDefault("scanners.reputation.signals.low_downloads.enabled", true)
	v.SetDefault("scanners.reputation.signals.low_downloads.weight", 0.2)
	v.SetDefault("scanners.reputation.signals.no_source_repo.enabled", true)
	v.SetDefault("scanners.reputation.signals.no_source_repo.weight", 0.3)
	v.SetDefault("scanners.reputation.signals.dormant_reactivation.enabled", true)
	v.SetDefault("scanners.reputation.signals.dormant_reactivation.weight", 0.7)
	v.SetDefault("scanners.reputation.signals.few_versions.enabled", true)
	v.SetDefault("scanners.reputation.signals.few_versions.weight", 0.15)
	v.SetDefault("scanners.reputation.signals.no_description.enabled", true)
	v.SetDefault("scanners.reputation.signals.no_description.weight", 0.1)
	v.SetDefault("scanners.reputation.signals.version_count_spike.enabled", true)
	v.SetDefault("scanners.reputation.signals.version_count_spike.weight", 0.4)
	v.SetDefault("scanners.reputation.signals.ownership_change.enabled", true)
	v.SetDefault("scanners.reputation.signals.ownership_change.weight", 0.8)
	v.SetDefault("scanners.reputation.signals.yanked_versions.enabled", true)
	v.SetDefault("scanners.reputation.signals.yanked_versions.weight", 0.6)
	v.SetDefault("scanners.reputation.signals.unusual_versioning.enabled", true)
	v.SetDefault("scanners.reputation.signals.unusual_versioning.weight", 0.2)
	v.SetDefault("scanners.reputation.signals.maintainer_email_domain.enabled", true)
	v.SetDefault("scanners.reputation.signals.maintainer_email_domain.weight", 0.15)
	v.SetDefault("scanners.reputation.signals.first_publication.enabled", true)
	v.SetDefault("scanners.reputation.signals.first_publication.weight", 0.25)
	v.SetDefault("scanners.reputation.signals.repo_mismatch.enabled", false)
	v.SetDefault("scanners.reputation.signals.repo_mismatch.weight", 0.4)
	v.SetDefault("scanners.reputation.signals.classifier_anomaly.enabled", false)
	v.SetDefault("scanners.reputation.signals.classifier_anomaly.weight", 0.15)
	v.SetDefault("scanners.reputation.cache_ttl_jitter", "2h")
	v.SetDefault("scanners.reputation.rate_limit", 30)
	v.SetDefault("scanners.reputation.retention_days", 30)

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshalling: %w", err)
	}

	return &cfg, nil
}

// Validate checks required configuration fields are populated.
func (c *Config) Validate() error {
	switch c.Cache.Backend {
	case "local", "":
		if c.Cache.Local.Path == "" {
			return fmt.Errorf("config: cache.local.path is required when backend is 'local'")
		}
	case "s3":
		if c.Cache.S3.Bucket == "" {
			return fmt.Errorf("config: cache.s3.bucket is required when backend is 's3'")
		}
		if c.Cache.S3.Region == "" && c.Cache.S3.Endpoint == "" {
			return fmt.Errorf("config: cache.s3.region is required when backend is 's3' and no endpoint is set")
		}
	case "azure_blob":
		if c.Cache.AzureBlob.ContainerName == "" {
			return fmt.Errorf("config: cache.azure_blob.container_name is required when backend is 'azure_blob'")
		}
		if c.Cache.AzureBlob.AccountName == "" && c.Cache.AzureBlob.ConnectionStrEnv == "" {
			return fmt.Errorf("config: cache.azure_blob.account_name or connection_string_env is required when backend is 'azure_blob'")
		}
	case "gcs":
		if c.Cache.GCS.Bucket == "" {
			return fmt.Errorf("config: cache.gcs.bucket is required when backend is 'gcs'")
		}
	default:
		return fmt.Errorf("config: unknown cache backend: %s", c.Cache.Backend)
	}
	switch c.Database.Backend {
	case "sqlite", "":
		if c.Database.SQLite.Path == "" {
			return fmt.Errorf("config: database.sqlite.path is required when backend is 'sqlite'")
		}
	case "postgres":
		if c.Database.Postgres.DSN == "" {
			return fmt.Errorf("config: database.postgres.dsn is required when backend is 'postgres'")
		}
	default:
		return fmt.Errorf("config: unknown database backend: %s", c.Database.Backend)
	}

	if err := c.validatePolicy(); err != nil {
		return err
	}

	if err := c.validateAlerts(); err != nil {
		return err
	}

	if err := c.validateRescan(); err != nil {
		return err
	}

	if err := c.validateAuth(); err != nil {
		return err
	}

	if err := c.validateProxyAuth(); err != nil {
		return err
	}

	if err := c.validateTyposquat(); err != nil {
		return err
	}

	if err := c.validateVersionDiff(); err != nil {
		return err
	}

	if err := c.validateReputation(); err != nil {
		return err
	}

	if err := c.validateProjects(); err != nil {
		return err
	}

	if err := c.validateLicenses(); err != nil {
		return err
	}

	if err := c.validateSBOM(); err != nil {
		return err
	}

	return nil
}

func (c *Config) validateProjects() error {
	switch c.Projects.Mode {
	case "", "lazy", "strict":
	default:
		return fmt.Errorf("config: projects.mode must be 'lazy' or 'strict', got %q", c.Projects.Mode)
	}
	if c.Projects.MaxCount < 0 {
		return fmt.Errorf("config: projects.max_count must be >= 0, got %d", c.Projects.MaxCount)
	}
	if c.Projects.LazyCreateRate < 0 {
		return fmt.Errorf("config: projects.lazy_create_rate must be >= 0, got %d", c.Projects.LazyCreateRate)
	}
	if c.Projects.CacheTTL != "" {
		if _, err := time.ParseDuration(c.Projects.CacheTTL); err != nil {
			return fmt.Errorf("config: projects.cache_ttl %q: %w", c.Projects.CacheTTL, err)
		}
	}
	if c.Projects.UsageFlushPeriod != "" {
		if _, err := time.ParseDuration(c.Projects.UsageFlushPeriod); err != nil {
			return fmt.Errorf("config: projects.usage_flush_period %q: %w", c.Projects.UsageFlushPeriod, err)
		}
	}
	return nil
}

func (c *Config) validateLicenses() error {
	lic := c.Policy.Licenses
	if !lic.Enabled {
		return nil
	}
	allowed := map[string]bool{"": true, "allow": true, "warn": true, "block": true}
	if !allowed[lic.UnknownAction] {
		return fmt.Errorf("config: policy.licenses.unknown_action must be 'allow'|'warn'|'block', got %q", lic.UnknownAction)
	}
	if !allowed[lic.OnSBOMError] {
		return fmt.Errorf("config: policy.licenses.on_sbom_error must be 'allow'|'warn'|'block', got %q", lic.OnSBOMError)
	}
	orOK := map[string]bool{"": true, "any_allowed": true, "all_allowed": true}
	if !orOK[lic.OrSemantics] {
		return fmt.Errorf("config: policy.licenses.or_semantics must be 'any_allowed'|'all_allowed', got %q", lic.OrSemantics)
	}
	return nil
}

func (c *Config) validateSBOM() error {
	if !c.SBOM.Enabled {
		return nil
	}
	if c.SBOM.Format != "" && c.SBOM.Format != "cyclonedx-json" {
		return fmt.Errorf("config: sbom.format must be 'cyclonedx-json', got %q", c.SBOM.Format)
	}
	if c.SBOM.TTL != "" {
		if _, err := parseTTL(c.SBOM.TTL); err != nil {
			return fmt.Errorf("config: sbom.ttl %q: %w", c.SBOM.TTL, err)
		}
	}
	return nil
}

// parseTTL supports "Nd" (days) and time.ParseDuration formats.
func parseTTL(s string) (time.Duration, error) {
	// Support "30d" style.
	if n := len(s); n > 1 && s[n-1] == 'd' {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil {
			return time.Duration(days) * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}

// validatePolicy checks policy configuration including mode and AI triage settings.
func (c *Config) validatePolicy() error {
	mode := c.Policy.Mode
	switch mode {
	case "", "strict", "balanced", "permissive":
		// valid
	default:
		return fmt.Errorf("config: unknown policy.mode %q (valid: strict, balanced, permissive)", mode)
	}

	// Startup warnings for mode interactions.
	if mode != "" && mode != "strict" {
		if c.Policy.QuarantineIfVerdict != "" && c.Policy.QuarantineIfVerdict != "SUSPICIOUS" {
			log.Warn().Str("mode", mode).Msg("config: policy.mode is set — policy.quarantine_if_verdict is ignored")
		}
	}

	if mode == "permissive" {
		log.Warn().Msg("config: permissive mode is active — SUSPICIOUS artifacts with MEDIUM severity will be served without review. This is NOT recommended for production.")
	}

	if mode == "balanced" && !c.Policy.AITriage.Enabled {
		log.Info().Msg("config: balanced mode with AI triage disabled — MEDIUM severity will be quarantined (degraded mode)")
	}

	// Validate AI triage config if enabled.
	if c.Policy.AITriage.Enabled {
		if c.Policy.AITriage.Timeout != "" {
			if _, err := time.ParseDuration(c.Policy.AITriage.Timeout); err != nil {
				return fmt.Errorf("config: policy.ai_triage.timeout %q is not a valid duration: %w", c.Policy.AITriage.Timeout, err)
			}
		}
		if c.Policy.AITriage.CacheTTL != "" {
			if _, err := time.ParseDuration(c.Policy.AITriage.CacheTTL); err != nil {
				return fmt.Errorf("config: policy.ai_triage.cache_ttl %q is not a valid duration: %w", c.Policy.AITriage.CacheTTL, err)
			}
		}
		if c.Policy.AITriage.CircuitBreakerCooldown != "" {
			if _, err := time.ParseDuration(c.Policy.AITriage.CircuitBreakerCooldown); err != nil {
				return fmt.Errorf("config: policy.ai_triage.circuit_breaker_cooldown %q is not a valid duration: %w", c.Policy.AITriage.CircuitBreakerCooldown, err)
			}
		}
		if c.Policy.AITriage.MinConfidence < 0 || c.Policy.AITriage.MinConfidence > 1 {
			return fmt.Errorf("config: policy.ai_triage.min_confidence must be between 0.0 and 1.0, got %f", c.Policy.AITriage.MinConfidence)
		}
		if c.Policy.AITriage.RateLimit < 0 {
			return fmt.Errorf("config: policy.ai_triage.rate_limit must be >= 0, got %d", c.Policy.AITriage.RateLimit)
		}
	}

	return nil
}

// validateAuth checks OIDC authentication configuration.
func (c *Config) validateAuth() error {
	if !c.Auth.Enabled {
		return nil
	}
	if c.Auth.IssuerURL == "" {
		return fmt.Errorf("config: auth.issuer_url is required when auth is enabled")
	}
	if c.Auth.ClientID == "" {
		return fmt.Errorf("config: auth.client_id is required when auth is enabled")
	}
	return nil
}

// validateRescan checks rescan scheduler configuration.
func (c *Config) validateRescan() error {
	if !c.Rescan.Enabled {
		return nil
	}
	if c.Rescan.Interval != "" {
		if _, err := time.ParseDuration(c.Rescan.Interval); err != nil {
			return fmt.Errorf("config: rescan.interval %q is not a valid duration: %w", c.Rescan.Interval, err)
		}
	}
	if c.Rescan.BatchSize < 0 {
		return fmt.Errorf("config: rescan.batch_size must be >= 0, got %d", c.Rescan.BatchSize)
	}
	if c.Rescan.MaxConcurrent < 0 {
		return fmt.Errorf("config: rescan.max_concurrent must be >= 0, got %d", c.Rescan.MaxConcurrent)
	}
	return nil
}

// validateProxyAuth checks proxy authentication configuration.
func (c *Config) validateProxyAuth() error {
	if !c.ProxyAuth.Enabled {
		return nil
	}

	// At least one auth method must be available.
	hasGlobalToken := c.ProxyAuth.GlobalTokenEnv != "" && os.Getenv(c.ProxyAuth.GlobalTokenEnv) != ""
	hasPATSupport := c.Auth.Enabled // PAT management requires OIDC-protected admin API

	if !hasGlobalToken && !hasPATSupport {
		return fmt.Errorf("config: proxy_auth is enabled but no authentication method is available — set global_token_env to a valid env var or enable auth (OIDC) for PAT support")
	}

	if c.ProxyAuth.GlobalTokenEnv != "" && os.Getenv(c.ProxyAuth.GlobalTokenEnv) == "" {
		log.Warn().Str("env_var", c.ProxyAuth.GlobalTokenEnv).Msg("config: proxy_auth.global_token_env references an unset environment variable")
	}

	return nil
}

// validateTyposquat checks typosquatting scanner configuration.
func (c *Config) validateTyposquat() error {
	tc := c.Scanners.Typosquat
	if !tc.Enabled {
		return nil
	}
	if tc.MaxEditDistance < 1 || tc.MaxEditDistance > 3 {
		return fmt.Errorf("config: scanners.typosquat.max_edit_distance must be 1-3, got %d", tc.MaxEditDistance)
	}
	if tc.TopPackagesCount > 10000 {
		return fmt.Errorf("config: scanners.typosquat.top_packages_count must be <= 10000, got %d", tc.TopPackagesCount)
	}
	if tc.PersistDedupWindowSeconds < 0 {
		return fmt.Errorf("config: scanners.typosquat.persist_dedup_window_seconds must be >= 0, got %d", tc.PersistDedupWindowSeconds)
	}
	return nil
}

// validateVersionDiff checks version diff scanner configuration.
func (c *Config) validateVersionDiff() error {
	vc := c.Scanners.VersionDiff
	if !vc.Enabled {
		return nil
	}
	if vc.Mode != "" && vc.Mode != "shadow" && vc.Mode != "active" {
		return fmt.Errorf("config: scanners.version_diff.mode must be 'shadow' or 'active', got %q", vc.Mode)
	}
	if vc.MaxArtifactSizeMB < 1 {
		return fmt.Errorf("config: scanners.version_diff.max_artifact_size_mb must be >= 1, got %d", vc.MaxArtifactSizeMB)
	}
	if vc.MaxExtractedSizeMB < 1 {
		return fmt.Errorf("config: scanners.version_diff.max_extracted_size_mb must be >= 1, got %d", vc.MaxExtractedSizeMB)
	}
	if vc.MaxExtractedFiles < 100 {
		return fmt.Errorf("config: scanners.version_diff.max_extracted_files must be >= 100, got %d", vc.MaxExtractedFiles)
	}
	if vc.ScannerTimeout != "" {
		if _, err := time.ParseDuration(vc.ScannerTimeout); err != nil {
			return fmt.Errorf("config: scanners.version_diff.scanner_timeout %q is not a valid duration: %w", vc.ScannerTimeout, err)
		}
	}
	if vc.MinConfidence < 0 || vc.MinConfidence > 1 {
		return fmt.Errorf("config: scanners.version_diff.min_confidence must be in [0,1], got %f", vc.MinConfidence)
	}
	if vc.PerPackageRateLimit < 0 {
		return fmt.Errorf("config: scanners.version_diff.per_package_rate_limit must be >= 0, got %d", vc.PerPackageRateLimit)
	}
	if vc.DailyCostLimitUSD < 0 {
		return fmt.Errorf("config: scanners.version_diff.daily_cost_limit_usd must be >= 0, got %f", vc.DailyCostLimitUSD)
	}
	if vc.CircuitBreakerThreshold < 0 {
		return fmt.Errorf("config: scanners.version_diff.circuit_breaker_threshold must be >= 0, got %d", vc.CircuitBreakerThreshold)
	}
	// bridge_socket is intentionally NOT validated here: an empty value is
	// allowed at config-load time and inherits scanners.guarddog.bridge_socket
	// in cmd/shieldoo-gate/main.go before NewVersionDiffScanner runs. The
	// constructor enforces non-empty.

	// Invariant: the engine outer cap (scanners.timeout) must accommodate the
	// inner version-diff scanner_timeout plus a 5s buffer; otherwise every
	// version-diff scan is killed by the outer cap before the LLM finishes.
	outer := 60 * time.Second
	if c.Scanners.Timeout != "" {
		if d, err := time.ParseDuration(c.Scanners.Timeout); err == nil {
			outer = d
		}
	}
	inner := 55 * time.Second
	if vc.ScannerTimeout != "" {
		if d, err := time.ParseDuration(vc.ScannerTimeout); err == nil {
			inner = d
		}
	}
	if outer < inner+5*time.Second {
		return fmt.Errorf("config: scanners.timeout (%s) must be >= scanners.version_diff.scanner_timeout (%s) + 5s buffer", outer, inner)
	}
	return nil
}

// validateReputation checks reputation scanner configuration.
func (c *Config) validateReputation() error {
	rc := c.Scanners.Reputation
	if !rc.Enabled {
		return nil
	}
	if rc.CacheTTL != "" {
		if _, err := time.ParseDuration(rc.CacheTTL); err != nil {
			return fmt.Errorf("config: scanners.reputation.cache_ttl %q is not a valid duration: %w", rc.CacheTTL, err)
		}
	}
	if rc.Timeout != "" {
		if _, err := time.ParseDuration(rc.Timeout); err != nil {
			return fmt.Errorf("config: scanners.reputation.timeout %q is not a valid duration: %w", rc.Timeout, err)
		}
	}
	if rc.Thresholds.Suspicious < 0 || rc.Thresholds.Suspicious > 1 {
		return fmt.Errorf("config: scanners.reputation.thresholds.suspicious must be 0.0-1.0, got %f", rc.Thresholds.Suspicious)
	}
	if rc.Thresholds.Malicious < 0 || rc.Thresholds.Malicious > 1 {
		return fmt.Errorf("config: scanners.reputation.thresholds.malicious must be 0.0-1.0, got %f", rc.Thresholds.Malicious)
	}
	if rc.Thresholds.Malicious <= rc.Thresholds.Suspicious {
		return fmt.Errorf("config: scanners.reputation.thresholds.malicious (%f) must be greater than suspicious (%f)", rc.Thresholds.Malicious, rc.Thresholds.Suspicious)
	}
	if rc.CacheTTLJitter != "" {
		if _, err := time.ParseDuration(rc.CacheTTLJitter); err != nil {
			return fmt.Errorf("config: scanners.reputation.cache_ttl_jitter %q is not a valid duration: %w", rc.CacheTTLJitter, err)
		}
	}
	if rc.RateLimit < 0 {
		return fmt.Errorf("config: scanners.reputation.rate_limit must be >= 0, got %d", rc.RateLimit)
	}
	if rc.RetentionDays < 0 {
		return fmt.Errorf("config: scanners.reputation.retention_days must be >= 0, got %d", rc.RetentionDays)
	}
	// Validate signal weights are in (0, 1].
	if err := validateSignalWeights(rc.Signals); err != nil {
		return err
	}
	return nil
}

// validateSignalWeights checks that all enabled signal weights are in the valid range (0, 1].
func validateSignalWeights(s ReputationSignals) error {
	signals := map[string]SignalConfig{
		"package_age": s.PackageAge, "low_downloads": s.LowDownloads,
		"no_source_repo": s.NoSourceRepo, "dormant_reactivation": s.DormantReactivation,
		"few_versions": s.FewVersions, "no_description": s.NoDescription,
		"version_count_spike": s.VersionCountSpike, "ownership_change": s.OwnershipChange,
		"yanked_versions": s.YankedVersions, "unusual_versioning": s.UnusualVersioning,
		"maintainer_email_domain": s.MaintainerEmailDomain, "first_publication": s.FirstPublication,
		"repo_mismatch": s.RepoMismatch, "classifier_anomaly": s.ClassifierAnomaly,
	}
	for name, cfg := range signals {
		if cfg.Enabled && (cfg.Weight <= 0 || cfg.Weight > 1.0) {
			return fmt.Errorf("config: scanners.reputation.signals.%s.weight must be in (0.0, 1.0], got %f", name, cfg.Weight)
		}
	}
	return nil
}

// validateAlerts checks alert channel configuration for required fields and logs
// warnings for missing environment variables (which may be set at runtime).
func (c *Config) validateAlerts() error {
	wh := c.Alerts.Webhook
	if wh.Enabled {
		if wh.URL == "" {
			return fmt.Errorf("config: alerts.webhook.url is required when webhook is enabled")
		}
		if !wh.AllowInsecure && !strings.HasPrefix(wh.URL, "https://") {
			return fmt.Errorf("config: alerts.webhook.url must use https:// (set allow_insecure to override)")
		}
	}
	warnUnknownEvents("alerts.webhook.on", wh.On)

	sl := c.Alerts.Slack
	if sl.Enabled {
		if sl.WebhookEnv == "" {
			return fmt.Errorf("config: alerts.slack.webhook_env is required when slack is enabled")
		}
		if os.Getenv(sl.WebhookEnv) == "" {
			log.Warn().Str("env_var", sl.WebhookEnv).Msg("config: alerts.slack.webhook_env references an unset environment variable")
		}
	}
	warnUnknownEvents("alerts.slack.on", sl.On)

	em := c.Alerts.Email
	if em.Enabled {
		if em.Host == "" || em.From == "" || len(em.To) == 0 {
			return fmt.Errorf("config: alerts.email requires host, from, and at least one to address when enabled")
		}
		if em.PasswordEnv != "" && os.Getenv(em.PasswordEnv) == "" {
			log.Warn().Str("env_var", em.PasswordEnv).Msg("config: alerts.email.password_env references an unset environment variable")
		}
	}
	warnUnknownEvents("alerts.email.on", em.On)

	return nil
}

// warnUnknownEvents logs a warning for any event type in the "on" list that is
// not a known EventType constant. Unknown values are allowed (forward-compatible)
// but may indicate a typo.
func warnUnknownEvents(field string, events []string) {
	for _, e := range events {
		if !knownEventTypes[e] {
			log.Warn().Str("field", field).Str("value", e).Msg("config: unknown event type in alert filter")
		}
	}
}
