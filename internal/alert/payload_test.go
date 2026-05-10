package alert

import (
	"testing"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestNewAlertPayload_PopulatesVulnScanColumns(t *testing.T) {
	cid, srid, iid := int64(42), int64(101), int64(7)
	entry := model.AuditEntry{
		EventType:    model.EventScanNewCritical,
		Reason:       "3 new CRITICAL CVE(s) on billing-api",
		Timestamp:    time.Date(2026, 5, 8, 10, 0, 0, 0, time.UTC),
		MetadataJSON: `{"new_critical":[{"cve":"CVE-2024-1","pkg":"x","version":"1.0"}]}`,
		ComponentID:  &cid,
		ScanRunID:    &srid,
		IgnoreID:     &iid,
	}
	p := NewAlertPayload(entry)

	assert.Equal(t, "scan.new_critical", p.EventType)
	assert.NotNil(t, p.ComponentID)
	assert.Equal(t, int64(42), *p.ComponentID)
	assert.NotNil(t, p.ScanRunID)
	assert.Equal(t, int64(101), *p.ScanRunID)
	assert.NotNil(t, p.IgnoreID)
	assert.Equal(t, int64(7), *p.IgnoreID)
	// Metadata JSON is parsed for renderers that need richer detail.
	meta, ok := p.Metadata.(map[string]any)
	assert.True(t, ok, "metadata must parse to map")
	if ok {
		assert.NotNil(t, meta["new_critical"])
	}
}

func TestEventTitle_VulnScanEventsHaveCuratedTitles(t *testing.T) {
	assert.Equal(t, "New CRITICAL CVEs detected", EventTitle(string(model.EventScanNewCritical)))
	assert.Equal(t, "New HIGH CVEs detected", EventTitle(string(model.EventScanNewHigh)))
	assert.Equal(t, "Vulnerability anomaly (3σ spike)", EventTitle(string(model.EventScanAnomaly)))
	assert.Equal(t, "Scan run failed", EventTitle(string(model.EventScanRunFailed)))
	assert.Equal(t, "CVE ignore created", EventTitle(string(model.EventIgnoreCreated)))
	assert.Equal(t, "CVE ignore revoked", EventTitle(string(model.EventIgnoreRevoked)))
	assert.Equal(t, "CVE ignore expired", EventTitle(string(model.EventIgnoreExpired)))
	assert.Equal(t, "Global super-token used", EventTitle(string(model.EventSuperTokenUsed)))
	// Legacy events keep their pre-existing wording so no dashboard regresses.
	assert.Equal(t, "Artifact Blocked", EventTitle(string(model.EventBlocked)))
	assert.Equal(t, "Artifact Quarantined", EventTitle(string(model.EventQuarantined)))
	// Unknown events fall back to a safe label.
	assert.Equal(t, "Security Event: SOMETHING_NEW", EventTitle("SOMETHING_NEW"))
}

func TestEventDescription_AppendsFKIdentifiers(t *testing.T) {
	cid, srid := int64(42), int64(101)
	p := AlertPayload{
		EventType:   string(model.EventScanNewCritical),
		Reason:      "3 new CRITICAL CVE(s) on billing-api",
		ComponentID: &cid,
		ScanRunID:   &srid,
	}
	got := EventDescription(p)
	assert.Equal(t, "3 new CRITICAL CVE(s) on billing-api — component=42, scan_run=101", got)

	// Ignore lifecycle: both ignore_id and component_id surface inline.
	iid, cid2 := int64(7), int64(99)
	p2 := AlertPayload{
		EventType:   string(model.EventIgnoreExpired),
		Reason:      "ignore expired for CVE-2024-1",
		IgnoreID:    &iid,
		ComponentID: &cid2,
	}
	got2 := EventDescription(p2)
	assert.Equal(t, "ignore expired for CVE-2024-1 — ignore=7, component=99", got2)

	// Legacy event types fall back to bare Reason.
	p3 := AlertPayload{EventType: string(model.EventBlocked), Reason: "verdict MALICIOUS"}
	assert.Equal(t, "verdict MALICIOUS", EventDescription(p3))
}
