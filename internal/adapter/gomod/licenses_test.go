package gomod

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mitLicense is the canonical MIT license text (abbreviated but enough for
// licensecheck to match with high confidence).
const mitLicense = `MIT License

Copyright (c) 2025 Example

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

const apache2License = `
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
`

// buildModuleZip writes a Go-module-style zip to a temp file and returns its
// path. Entries are keyed by their in-zip path (e.g. "example.com/m@v1.0.0/LICENSE").
func buildModuleZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "gomod-*.zip")
	require.NoError(t, err)
	defer f.Close()

	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return f.Name()
}

func TestExtractLicensesFromGoModuleZip_MIT(t *testing.T) {
	zipPath := buildModuleZip(t, map[string]string{
		"example.com/m@v1.0.0/LICENSE": mitLicense,
		"example.com/m@v1.0.0/go.mod":  "module example.com/m\n",
	})

	got := extractLicensesFromGoModuleZip(zipPath)

	assert.Equal(t, []string{"MIT"}, got)
}

func TestExtractLicensesFromGoModuleZip_Apache2(t *testing.T) {
	zipPath := buildModuleZip(t, map[string]string{
		"example.com/m@v1.0.0/LICENSE": apache2License,
	})

	got := extractLicensesFromGoModuleZip(zipPath)

	assert.Equal(t, []string{"Apache-2.0"}, got)
}

func TestExtractLicensesFromGoModuleZip_NoLicenseFile(t *testing.T) {
	zipPath := buildModuleZip(t, map[string]string{
		"example.com/m@v1.0.0/go.mod": "module example.com/m\n",
		"example.com/m@v1.0.0/main.go": "package m\n",
	})

	got := extractLicensesFromGoModuleZip(zipPath)

	assert.Nil(t, got)
}

func TestExtractLicensesFromGoModuleZip_UnknownText(t *testing.T) {
	zipPath := buildModuleZip(t, map[string]string{
		"example.com/m@v1.0.0/LICENSE": "All rights reserved. Do whatever you want but give me credit.\n",
	})

	got := extractLicensesFromGoModuleZip(zipPath)

	assert.Nil(t, got)
}

func TestExtractLicensesFromGoModuleZip_FilenameVariants(t *testing.T) {
	// COPYING, LICENSE.md, LICENCE (British spelling) all should be detected.
	cases := []string{
		"example.com/m@v1.0.0/COPYING",
		"example.com/m@v1.0.0/LICENSE.md",
		"example.com/m@v1.0.0/LICENCE",
		"example.com/m@v1.0.0/LICENSE.txt",
	}
	for _, name := range cases {
		t.Run(filepath.Base(name), func(t *testing.T) {
			zipPath := buildModuleZip(t, map[string]string{name: mitLicense})
			got := extractLicensesFromGoModuleZip(zipPath)
			assert.Equal(t, []string{"MIT"}, got)
		})
	}
}

func TestExtractLicensesFromGoModuleZip_DedupesAcrossFiles(t *testing.T) {
	zipPath := buildModuleZip(t, map[string]string{
		"example.com/m@v1.0.0/LICENSE":    mitLicense,
		"example.com/m@v1.0.0/LICENSE.md": mitLicense,
	})

	got := extractLicensesFromGoModuleZip(zipPath)

	assert.Equal(t, []string{"MIT"}, got)
}

func TestExtractLicensesFromGoModuleZip_MissingFile(t *testing.T) {
	got := extractLicensesFromGoModuleZip("/nonexistent/path.zip")
	assert.Nil(t, got)
}

func TestExtractLicensesFromGoModuleZip_SkipsDeepNestedLicenses(t *testing.T) {
	// Vendored-dep LICENSEs deep inside should be ignored — they're not the
	// module's own license.
	zipPath := buildModuleZip(t, map[string]string{
		"example.com/m@v1.0.0/vendor/thirdparty/pkg/LICENSE": mitLicense,
		"example.com/m@v1.0.0/go.mod": "module example.com/m\n",
	})

	got := extractLicensesFromGoModuleZip(zipPath)

	assert.Nil(t, got)
}

func TestExtractLicensesFromGoModuleZip_MultiSlashModulePath(t *testing.T) {
	// Real-world modules like github.com/rs/zerolog produce entries with
	// multiple slashes before the "@version/" segment. The detector must
	// identify the module root by the "@" marker, not by a fixed slash
	// count.
	zipPath := buildModuleZip(t, map[string]string{
		"github.com/rs/zerolog@v1.33.0/LICENSE":    mitLicense,
		"github.com/rs/zerolog@v1.33.0/go.mod":     "module github.com/rs/zerolog\n",
		"github.com/rs/zerolog@v1.33.0/log.go":     "package zerolog\n",
		"github.com/rs/zerolog@v1.33.0/sub/x.go":   "package sub\n",
	})

	got := extractLicensesFromGoModuleZip(zipPath)

	assert.Equal(t, []string{"MIT"}, got)
}
