package sbom

import "testing"

func TestBuildPURL(t *testing.T) {
	cases := []struct {
		name        string
		ecosystem   string
		artifact    string
		version     string
		sha256      string
		upstreamURL string
		want        string
	}{
		{
			name:      "pypi simple",
			ecosystem: "pypi", artifact: "requests", version: "2.31.0",
			want: "pkg:pypi/requests@2.31.0",
		},
		{
			name:      "pypi name with dot survives",
			ecosystem: "pypi", artifact: "ruamel.yaml", version: "0.17.21",
			want: "pkg:pypi/ruamel.yaml@0.17.21",
		},
		{
			name:      "npm plain",
			ecosystem: "npm", artifact: "lodash", version: "4.17.21",
			want: "pkg:npm/lodash@4.17.21",
		},
		{
			name:      "npm scoped",
			ecosystem: "npm", artifact: "@types/node", version: "20.10.0",
			want: "pkg:npm/%40types/node@20.10.0",
		},
		{
			name:      "maven group:artifact",
			ecosystem: "maven", artifact: "org.apache.commons:commons-lang3", version: "3.14.0",
			want: "pkg:maven/org.apache.commons/commons-lang3@3.14.0",
		},
		{
			name:      "maven multi-colon takes last as artifactId",
			ecosystem: "maven", artifact: "com.foo.bar:baz", version: "1.0",
			want: "pkg:maven/com.foo.bar/baz@1.0",
		},
		{
			name:      "maven malformed (no colon) returns empty",
			ecosystem: "maven", artifact: "no-colon-here", version: "1.0",
			want: "",
		},
		{
			name:      "nuget",
			ecosystem: "nuget", artifact: "Newtonsoft.Json", version: "13.0.3",
			want: "pkg:nuget/Newtonsoft.Json@13.0.3",
		},
		{
			name:      "rubygems",
			ecosystem: "rubygems", artifact: "rails", version: "7.1.2",
			want: "pkg:gem/rails@7.1.2",
		},
		{
			name:      "go module single segment",
			ecosystem: "go", artifact: "fmt", version: "v1.0.0",
			want: "pkg:golang/fmt@v1.0.0",
		},
		{
			name:      "go module three segments",
			ecosystem: "go", artifact: "github.com/user/repo", version: "v1.2.3",
			want: "pkg:golang/github.com/user/repo@v1.2.3",
		},
		{
			name:      "go module four segments (subpackage)",
			ecosystem: "go", artifact: "github.com/org/repo/sub/pkg", version: "v0.1.0",
			want: "pkg:golang/github.com/org/repo/sub/pkg@v0.1.0",
		},
		{
			name:      "docker with upstream url + sha256 + tag",
			ecosystem: "docker", artifact: "registry_1_docker_io_library_alpine",
			version: "3.20.10",
			sha256:  "abcdef1234567890",
			upstreamURL: "https://registry-1.docker.io/v2/library/alpine/manifests/3.20.10",
			want: "pkg:oci/alpine@sha256:abcdef1234567890?repository_url=registry-1.docker.io%2Flibrary%2Falpine&tag=3.20.10",
		},
		{
			name:      "docker pulled by digest (no tag qualifier)",
			ecosystem: "docker", artifact: "registry_1_docker_io_library_alpine",
			version: "sha256:abcdef1234567890",
			sha256:  "abcdef1234567890",
			upstreamURL: "https://registry-1.docker.io/v2/library/alpine/manifests/sha256:abcdef1234567890",
			want: "pkg:oci/alpine@sha256:abcdef1234567890?repository_url=registry-1.docker.io%2Flibrary%2Falpine",
		},
		{
			name:      "docker without sha256 → empty",
			ecosystem: "docker", artifact: "anything", version: "latest",
			want: "",
		},
		{
			name:      "docker fallback to safeName when upstream unparseable",
			ecosystem: "docker", artifact: "host_path_alpine",
			version: "3.20", sha256: "deadbeef",
			upstreamURL: "",
			want:        "pkg:oci/alpine@sha256:deadbeef?tag=3.20",
		},
		{
			name:      "unknown ecosystem returns empty",
			ecosystem: "cargo", artifact: "serde", version: "1.0.0",
			want: "",
		},
		{
			name:      "empty name returns empty",
			ecosystem: "pypi", artifact: "", version: "1.0",
			want: "",
		},
		{
			name:      "no version omits @ segment",
			ecosystem: "pypi", artifact: "requests",
			want: "pkg:pypi/requests",
		},
		{
			name:      "sha256 prefix stripped",
			ecosystem: "docker", artifact: "host_alpine",
			version: "3.20", sha256: "sha256:abc",
			upstreamURL: "https://r.io/v2/alpine/manifests/3.20",
			want:        "pkg:oci/alpine@sha256:abc?repository_url=r.io%2Falpine&tag=3.20",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildPURL(tc.ecosystem, tc.artifact, tc.version, tc.sha256, tc.upstreamURL)
			if got != tc.want {
				t.Errorf("BuildPURL(%q,%q,%q,%q,%q)\n  got:  %s\n  want: %s",
					tc.ecosystem, tc.artifact, tc.version, tc.sha256, tc.upstreamURL,
					got, tc.want)
			}
		})
	}
}
