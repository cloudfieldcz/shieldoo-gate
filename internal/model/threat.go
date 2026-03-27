package model

import "time"

type ThreatFeedEntry struct {
	SHA256      string    `db:"sha256" json:"sha256"`
	Ecosystem   string    `db:"ecosystem" json:"ecosystem"`
	PackageName string    `db:"package_name" json:"package_name"`
	Version     string    `db:"version" json:"version,omitempty"`
	ReportedAt  time.Time `db:"reported_at" json:"reported_at"`
	SourceURL   string    `db:"source_url" json:"source_url,omitempty"`
	IoCsJSON    string    `db:"iocs_json" json:"iocs_json,omitempty"`
}
