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
	PyPI   string               `mapstructure:"pypi"`
	NPM    string               `mapstructure:"npm"`
	NuGet  string               `mapstructure:"nuget"`
	Docker DockerUpstreamConfig `mapstructure:"docker"`
	Maven    string               `mapstructure:"maven"`
	RubyGems string               `mapstructure:"rubygems"`
	GoMod    string               `mapstructure:"gomod"`
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
	Parallel bool           `mapstructure:"parallel"`
	Timeout  string         `mapstructure:"timeout"`
	GuardDog GuardDogConfig `mapstructure:"guarddog"`
	Trivy    TrivyConfig    `mapstructure:"trivy"`
	OSV      OSVConfig      `mapstructure:"osv"`
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
	BlockIfVerdict      string   `mapstructure:"block_if_verdict"`
	QuarantineIfVerdict string   `mapstructure:"quarantine_if_verdict"`
	MinimumConfidence   float32  `mapstructure:"minimum_confidence"`
	Allowlist           []string `mapstructure:"allowlist"`
}

type ThreatFeedConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	URL             string `mapstructure:"url"`
	RefreshInterval string `mapstructure:"refresh_interval"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
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

	if err := c.validateAlerts(); err != nil {
		return err
	}

	if err := c.validateRescan(); err != nil {
		return err
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
