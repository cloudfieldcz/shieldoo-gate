package pypi

import "testing"

func TestCanonicalName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// PEP 503 spec examples.
		{"hyphen passthrough", "strawberry-graphql", "strawberry-graphql"},
		{"underscore to hyphen", "strawberry_graphql", "strawberry-graphql"},
		{"dot to hyphen", "zope.interface", "zope-interface"},
		{"mixed separators collapse", "Some__Weird.NAME", "some-weird-name"},
		{"uppercase to lower", "Flask", "flask"},
		{"already canonical", "requests", "requests"},
		{"trailing underscore", "foo_", "foo-"},
		{"leading underscore", "_foo", "-foo"},
		{"long collapse", "a..__--b", "a-b"},
		// Real-world packages from the strawberry-graphql dependency tree.
		{"python-dateutil", "python_dateutil", "python-dateutil"},
		{"graphql-core", "graphql_core", "graphql-core"},
		{"typing-extensions", "typing_extensions", "typing-extensions"},
		// Idempotence.
		{"idempotent on canonical", "strawberry-graphql", "strawberry-graphql"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CanonicalName(tc.in)
			if got != tc.want {
				t.Errorf("CanonicalName(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// Canonicalization must be a fixed point.
			if again := CanonicalName(got); again != got {
				t.Errorf("CanonicalName not idempotent: %q -> %q -> %q", tc.in, got, again)
			}
		})
	}
}
