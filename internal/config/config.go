package config

import (
	"fmt"
	"strings"

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
	Log        LogConfig        `mapstructure:"log"`
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
}

type PortsConfig struct {
	PyPI   int `mapstructure:"pypi"`
	NPM    int `mapstructure:"npm"`
	NuGet  int `mapstructure:"nuget"`
	Docker int `mapstructure:"docker"`
	Admin  int `mapstructure:"admin"`
}

type UpstreamsConfig struct {
	PyPI   string `mapstructure:"pypi"`
	NPM    string `mapstructure:"npm"`
	NuGet  string `mapstructure:"nuget"`
	Docker string `mapstructure:"docker"`
}

type CacheConfig struct {
	Backend string          `mapstructure:"backend"`
	Local   LocalCacheConfig `mapstructure:"local"`
	TTL     TTLConfig       `mapstructure:"ttl"`
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
	Backend string       `mapstructure:"backend"`
	SQLite  SQLiteConfig `mapstructure:"sqlite"`
}

type SQLiteConfig struct {
	Path string `mapstructure:"path"`
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
	if c.Cache.Backend == "local" && c.Cache.Local.Path == "" {
		return fmt.Errorf("config: cache.local.path is required when backend is 'local'")
	}
	if c.Database.Backend == "sqlite" && c.Database.SQLite.Path == "" {
		return fmt.Errorf("config: database.sqlite.path is required when backend is 'sqlite'")
	}
	return nil
}
