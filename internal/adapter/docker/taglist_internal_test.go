package docker

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewriteTagListLink_RelativeUpstreamLink_RewrittenToClientName(t *testing.T) {
	got := rewriteTagListLink(`</v2/library/python/tags/list?n=2&last=3.9>; rel="next"`, "library/python", "python")
	assert.Equal(t, `</v2/python/tags/list?last=3.9&n=2>; rel="next"`, got)
}

func TestRewriteTagListLink_AbsoluteUpstreamLink_BecomesGateRelative(t *testing.T) {
	got := rewriteTagListLink(`<https://ghcr.io/v2/org/img/tags/list?n=5&last=v1>; rel="next"`, "org/img", "ghcr.io/org/img")
	assert.Equal(t, `</v2/ghcr.io/org/img/tags/list?last=v1&n=5>; rel="next"`, got)
}

func TestRewriteTagListLink_ForeignRepositoryPath_Dropped(t *testing.T) {
	// A link addressing a different repository must not be relayed — the client
	// would follow it through the gate and enumerate the wrong image.
	got := rewriteTagListLink(`</v2/library/other/tags/list?n=2>; rel="next"`, "library/python", "python")
	assert.Empty(t, got)
}

func TestRewriteTagListLink_NonTagListPath_Dropped(t *testing.T) {
	got := rewriteTagListLink(`</v2/library/python/manifests/latest>; rel="next"`, "library/python", "python")
	assert.Empty(t, got)
}

func TestRewriteTagListLink_MalformedHeader_Dropped(t *testing.T) {
	for _, link := range []string{
		"/v2/library/python/tags/list; rel=next",       // no angle brackets
		`rel="next"; </v2/library/python/tags/list>`,   // brackets not first
		"</v2/library/python/tags/list?%zz>; rel=next", // unparseable query
	} {
		assert.Empty(t, rewriteTagListLink(link, "library/python", "python"), "link=%s", link)
	}
}

func TestRewriteTagListLink_Empty_ReturnsEmpty(t *testing.T) {
	assert.Empty(t, rewriteTagListLink("", "library/python", "python"))
}

func TestRewriteTagListLink_MultipleLinks_KeepsOnlyMatching(t *testing.T) {
	got := rewriteTagListLink(
		`</v2/library/python/tags/list?n=1>; rel="next", </v2/evil/tags/list?n=1>; rel="prev"`,
		"library/python", "python")
	assert.Equal(t, `</v2/python/tags/list?n=1>; rel="next"`, got)
}

func TestRewriteTagListLink_NoQuery_OmitsQuestionMark(t *testing.T) {
	got := rewriteTagListLink(`</v2/library/python/tags/list>; rel="next"`, "library/python", "python")
	assert.Equal(t, `</v2/python/tags/list>; rel="next"`, got)
}

func TestSanitizeTagListQuery_Empty_ReturnsEmpty(t *testing.T) {
	q, err := sanitizeTagListQuery("")
	require.NoError(t, err)
	assert.Empty(t, q)
}

func TestSanitizeTagListQuery_PaginationParams_Normalised(t *testing.T) {
	q, err := sanitizeTagListQuery("n=10&last=3.9-slim")
	require.NoError(t, err)
	assert.Equal(t, "last=3.9-slim&n=10", q)
}

func TestSanitizeTagListQuery_UnknownParam_Dropped(t *testing.T) {
	// Only n/last reach the upstream. `ns=` in particular is meaningful to a
	// Distribution registry in pull-through-mirror mode and would escape the
	// allowlist decision the resolver just made.
	q, err := sanitizeTagListQuery("ns=evil.example.com&access_token=secret&n=5")
	require.NoError(t, err)
	assert.Equal(t, "n=5", q)
}

func TestSanitizeTagListQuery_InvalidN_ReturnsError(t *testing.T) {
	for _, raw := range []string{"n=abc", "n=-1", "n=99999999999999999999"} {
		_, err := sanitizeTagListQuery(raw)
		assert.Error(t, err, "query=%s", raw)
	}
}

func TestSanitizeTagListQuery_OverlongQuery_ReturnsError(t *testing.T) {
	long := "last=" + string(make([]byte, maxTagListQueryLen))
	_, err := sanitizeTagListQuery(long)
	assert.Error(t, err)
}

func TestSanitizeTagListQuery_MalformedQuery_ReturnsError(t *testing.T) {
	_, err := sanitizeTagListQuery("n=%zz")
	assert.Error(t, err)
}

func TestParseTagListPagination_Absent_ReturnsNoLimit(t *testing.T) {
	n, last, err := parseTagListPagination(url.Values{})
	require.NoError(t, err)
	assert.Equal(t, -1, n)
	assert.Empty(t, last)
}

func TestParseTagListPagination_ZeroN_ReturnsZero(t *testing.T) {
	n, _, err := parseTagListPagination(url.Values{"n": {"0"}})
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestParseTagListPagination_LastCursor_Returned(t *testing.T) {
	n, last, err := parseTagListPagination(url.Values{"n": {"3"}, "last": {"v1.0"}})
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, "v1.0", last)
}

func TestParseTagListPagination_NegativeN_ReturnsError(t *testing.T) {
	_, _, err := parseTagListPagination(url.Values{"n": {"-5"}})
	assert.Error(t, err)
}

func TestRewriteTagListLink_NonPaginationRel_Dropped(t *testing.T) {
	got := rewriteTagListLink(`</v2/library/python/tags/list?n=1>; rel="stylesheet"`, "library/python", "python")
	assert.Empty(t, got)
}

func TestRewriteTagListLink_UpstreamQueryParams_DroppedFromRewrite(t *testing.T) {
	// An upstream-chosen parameter must not be echoed back into the client's
	// next request to the gate (which would relay it upstream again).
	got := rewriteTagListLink(`</v2/library/python/tags/list?n=1&last=3.9&ns=evil.example.com>; rel="next"`,
		"library/python", "python")
	assert.Equal(t, `</v2/python/tags/list?last=3.9&n=1>; rel="next"`, got)
}

func TestRewriteTagListLink_UpstreamAttributeTail_NotRelayed(t *testing.T) {
	got := rewriteTagListLink(`</v2/library/python/tags/list?n=1>; rel="next"; title="upstream <script>"`,
		"library/python", "python")
	assert.Equal(t, `</v2/python/tags/list?n=1>; rel="next"`, got)
}

func TestRewriteTagListLink_OversizedHeader_Dropped(t *testing.T) {
	long := "</v2/library/python/tags/list?last=" + strings.Repeat("a", maxTagListLinkLen) + `>; rel="next"`
	assert.Empty(t, rewriteTagListLink(long, "library/python", "python"))
}

func TestRewriteTagListLink_TooManyParts_Dropped(t *testing.T) {
	link := strings.Repeat(`</v2/library/python/tags/list?n=1>; rel="next", `, 5)
	assert.Empty(t, rewriteTagListLink(link, "library/python", "python"))
}

func TestRewriteTagListLink_InvalidPageSizeInUpstreamQuery_Dropped(t *testing.T) {
	got := rewriteTagListLink(`</v2/library/python/tags/list?n=huge>; rel="next"`, "library/python", "python")
	assert.Empty(t, got)
}

func TestPaginationQuery_KeepsOnlyPaginationParams(t *testing.T) {
	q, err := paginationQuery(url.Values{"n": {"3"}, "last": {"v1"}, "ns": {"evil"}})
	require.NoError(t, err)
	assert.Equal(t, "last=v1&n=3", q)
}
