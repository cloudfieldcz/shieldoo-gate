package scanner

import "testing"

func TestCanonicalPackageName_PyPI(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"strawberry-graphql", "strawberry-graphql"},
		{"strawberry_graphql", "strawberry-graphql"},
		{"zope.interface", "zope-interface"},
		{"Some__Weird.NAME", "some-weird-name"},
		{"Flask", "flask"},
		{"a..__--b", "a-b"},
	}
	for _, tc := range cases {
		got := CanonicalPackageName(EcosystemPyPI, tc.in)
		if got != tc.want {
			t.Errorf("CanonicalPackageName(PyPI, %q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalPackageName_OtherEcosystemsUnchanged(t *testing.T) {
	for _, eco := range []Ecosystem{EcosystemNPM, EcosystemDocker} {
		in := "Some_Weird.Name"
		got := CanonicalPackageName(eco, in)
		if got != in {
			t.Errorf("CanonicalPackageName(%s, %q) = %q, want unchanged %q", eco, in, got, in)
		}
	}
}
