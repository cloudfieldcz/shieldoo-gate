package pypi

import "testing"

func TestParseFilename(t *testing.T) {
	cases := []struct {
		name        string
		filename    string
		wantName    string
		wantVersion string
	}{
		{
			name:        "wheel with underscore name returns canonical hyphen form",
			filename:    "strawberry_graphql-0.263.0-py3-none-any.whl",
			wantName:    "strawberry-graphql",
			wantVersion: "0.263.0",
		},
		{
			name:        "wheel with already-canonical name unchanged",
			filename:    "requests-2.32.3-py3-none-any.whl",
			wantName:    "requests",
			wantVersion: "2.32.3",
		},
		{
			name:        "wheel with mixed separators canonicalized",
			filename:    "Some.Package_X-1.0-py3-none-any.whl",
			wantName:    "some-package-x",
			wantVersion: "1.0",
		},
		{
			name:        "sdist tar.gz with underscore name",
			filename:    "python_dateutil-2.9.0.post0.tar.gz",
			wantName:    "python-dateutil",
			wantVersion: "2.9.0.post0",
		},
		{
			name:        "sdist zip with underscore name",
			filename:    "graphql_core-3.2.8.zip",
			wantName:    "graphql-core",
			wantVersion: "3.2.8",
		},
		{
			name:        "uppercase wheel name lowered",
			filename:    "Flask-3.0.0-py3-none-any.whl",
			wantName:    "flask",
			wantVersion: "3.0.0",
		},
		{
			name:        "unparseable filename falls back",
			filename:    "weird.file",
			wantName:    "weird.file",
			wantVersion: "unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotVersion := parseFilename(tc.filename)
			if gotName != tc.wantName {
				t.Errorf("parseFilename(%q) name = %q, want %q", tc.filename, gotName, tc.wantName)
			}
			if gotVersion != tc.wantVersion {
				t.Errorf("parseFilename(%q) version = %q, want %q", tc.filename, gotVersion, tc.wantVersion)
			}
		})
	}
}
