package trivy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeNuSpec writes a nuspec (plus optional sibling files) into a temp dir
// and returns the nuspec path.
func writeNuSpec(t *testing.T, nuspec string, siblings map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.nuspec")
	require.NoError(t, os.WriteFile(path, []byte(nuspec), 0o600))
	for name, content := range siblings {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	return path
}

// hangfireLicenseMD mirrors the real LICENSE.md shipped in Hangfire.Core
// 1.8.23 — a multi-license file offering LGPL v3 or a commercial license.
const hangfireLicenseMD = `License
========

Copyright © 2013-2026 Hangfire OÜ.

Hangfire software is an open-source software that is multi-licensed under the terms of the licenses listed in this file.

LGPL v3 License
---------------

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

Commercial License
------------------

Subject to the purchase of a corresponding subscription, you may distribute Hangfire under the terms of commercial license.
`

const mitLicenseText = `MIT License

Copyright (c) 2024 Example

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
`

func TestParseNuSpec_DeprecatedLicenseURLPlaceholder_Dropped(t *testing.T) {
	path := writeNuSpec(t, `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Test</id>
    <licenseUrl>https://aka.ms/deprecateLicenseUrl</licenseUrl>
  </metadata>
</package>`, nil)

	assert.Empty(t, parseNuSpec(path))
}

func TestParseNuSpec_LicenseTypeExpression_ReturnsExpression(t *testing.T) {
	path := writeNuSpec(t, `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Test</id>
    <license type="expression">Apache-2.0 OR MIT</license>
    <licenseUrl>https://licenses.nuget.org/Apache-2.0%20OR%20MIT</licenseUrl>
  </metadata>
</package>`, nil)

	assert.Equal(t, []string{"Apache-2.0 OR MIT"}, parseNuSpec(path))
}

func TestParseNuSpec_LicenseTypeFile_ClassifiesReferencedFile(t *testing.T) {
	path := writeNuSpec(t, `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Hangfire.Core</id>
    <license type="file">LICENSE.md</license>
    <licenseUrl>https://aka.ms/deprecateLicenseUrl</licenseUrl>
  </metadata>
</package>`, map[string]string{"LICENSE.md": hangfireLicenseMD})

	got := parseNuSpec(path)
	assert.Equal(t, []string{"LGPL-3.0-only"}, got)
	assert.NotContains(t, got, "LICENSE.md")
	assert.NotContains(t, got, "https://aka.ms/deprecateLicenseUrl")
}

func TestParseNuSpec_LicenseTypeFileUnclassifiable_ReturnsEmpty(t *testing.T) {
	path := writeNuSpec(t, `<?xml version="1.0"?>
<package>
  <metadata>
    <license type="file">LICENSE.md</license>
  </metadata>
</package>`, map[string]string{"LICENSE.md": "You may do whatever you like with this code."})

	// Unrecognized license text must NOT leak the filename as a license id —
	// an empty result leaves the artifact "unknown" for the policy engine.
	assert.Empty(t, parseNuSpec(path))
}

func TestParseNuSpec_LicenseTypeFilePathTraversal_NotRead(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "pkg")
	require.NoError(t, os.Mkdir(sub, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "outside.md"), []byte(mitLicenseText), 0o600))
	path := filepath.Join(sub, "test.nuspec")
	require.NoError(t, os.WriteFile(path, []byte(`<?xml version="1.0"?>
<package>
  <metadata>
    <license type="file">../outside.md</license>
  </metadata>
</package>`), 0o600))

	assert.Empty(t, parseNuSpec(path))
}

func TestParseNuSpec_NuGetOrgLicenseURL_MapsToSPDXExpression(t *testing.T) {
	path := writeNuSpec(t, `<?xml version="1.0"?>
<package>
  <metadata>
    <licenseUrl>https://licenses.nuget.org/Apache-2.0%20OR%20MIT</licenseUrl>
  </metadata>
</package>`, nil)

	assert.Equal(t, []string{"Apache-2.0 OR MIT"}, parseNuSpec(path))
}

func TestParseNuSpec_LegacyLicenseURL_KeptVerbatim(t *testing.T) {
	path := writeNuSpec(t, `<?xml version="1.0"?>
<package>
  <metadata>
    <licenseUrl>https://raw.github.com/HangfireIO/Hangfire/master/LICENSE.md</licenseUrl>
  </metadata>
</package>`, nil)

	assert.Equal(t, []string{"https://raw.github.com/HangfireIO/Hangfire/master/LICENSE.md"}, parseNuSpec(path))
}

// gplV3Text mirrors the COPYING file Hangfire ships alongside LICENSE.md — the
// verbatim GNU GPL v3, which classifies as GPL-3.0-only on its own. The
// bundled-file fallback must NOT surface it when a higher-priority LICENSE.md
// resolves to the package's actual (LGPL) license.
const gplV3Text = `GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.`

func TestParseNuSpec_LegacyLicenseURLWithBundledFile_ClassifiesFile(t *testing.T) {
	// Mirrors Hangfire.Core 1.8.0: nuspec carries only a legacy GitHub
	// licenseUrl (unresolvable offline) but the package bundles LICENSE.md.
	path := writeNuSpec(t, `<?xml version="1.0"?>
<package>
  <metadata>
    <id>Hangfire.Core</id>
    <licenseUrl>https://raw.github.com/HangfireIO/Hangfire/master/LICENSE.md</licenseUrl>
  </metadata>
</package>`, map[string]string{"LICENSE.md": hangfireLicenseMD})

	got := parseNuSpec(path)
	assert.Equal(t, []string{"LGPL-3.0-only"}, got)
	assert.NotContains(t, got, "https://raw.github.com/HangfireIO/Hangfire/master/LICENSE.md")
}

func TestParseNuSpec_LegacyLicenseURLPrefersLICENSEmdOverCOPYING(t *testing.T) {
	// The package ships both LICENSE.md (LGPL summary) and COPYING (verbatim
	// GPL). The fallback must pick LICENSE.md and stop — never emit GPL-3.0.
	path := writeNuSpec(t, `<?xml version="1.0"?>
<package>
  <metadata>
    <licenseUrl>https://raw.github.com/HangfireIO/Hangfire/master/LICENSE.md</licenseUrl>
  </metadata>
</package>`, map[string]string{"LICENSE.md": hangfireLicenseMD, "COPYING": gplV3Text})

	got := parseNuSpec(path)
	assert.Equal(t, []string{"LGPL-3.0-only"}, got)
	assert.NotContains(t, got, "GPL-3.0-only")
}

func TestClassifyLicenseText_MIT_ReturnsMIT(t *testing.T) {
	assert.Equal(t, []string{"MIT"}, classifyLicenseText([]byte(mitLicenseText)))
}

func TestClassifyLicenseText_Apache2_ReturnsApache20(t *testing.T) {
	text := "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/\n\nTERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION"
	assert.Equal(t, []string{"Apache-2.0"}, classifyLicenseText([]byte(text)))
}

func TestClassifyLicenseText_HangfireMultiLicense_ReturnsLGPL30(t *testing.T) {
	assert.Equal(t, []string{"LGPL-3.0-only"}, classifyLicenseText([]byte(hangfireLicenseMD)))
}

func TestClassifyLicenseText_GPL3_NotConfusedWithLGPL(t *testing.T) {
	text := "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n\nThis program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version."
	assert.Equal(t, []string{"GPL-3.0-only"}, classifyLicenseText([]byte(text)))
}

func TestClassifyLicenseText_LGPL21_ReturnsLGPL21(t *testing.T) {
	text := "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1, February 1999\n\nThis library is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation; either version 2.1 of the License."
	assert.Equal(t, []string{"LGPL-2.1-only"}, classifyLicenseText([]byte(text)))
}

func TestClassifyLicenseText_BSD3Clause_ReturnsBSD3(t *testing.T) {
	text := "Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n1. Redistributions of source code must retain the above copyright notice.\n3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software."
	assert.Equal(t, []string{"BSD-3-Clause"}, classifyLicenseText([]byte(text)))
}

func TestClassifyLicenseText_LGPLv3Abbreviation_ReturnsLGPL30(t *testing.T) {
	// Mirrors Hangfire.PostgreSql's LICENSE.md, which never spells out the
	// full GNU phrase — only the LGPLv3 abbreviation and a gnu.org URL.
	text := "Hangfire.PostgreSql is an Open Source project licensed under the terms of the LGPLv3 license. Please see http://www.gnu.org/licenses/lgpl-3.0.html for license text or COPYING.LESSER file distributed with the source code."
	assert.Equal(t, []string{"LGPL-3.0-only"}, classifyLicenseText([]byte(text)))
}

func TestClassifyLicenseText_UnknownText_ReturnsEmpty(t *testing.T) {
	assert.Empty(t, classifyLicenseText([]byte("All rights reserved. Contact sales for licensing.")))
}

func TestNuGetLicenseURLToExpression_EncodedExpression_Decoded(t *testing.T) {
	got, ok := nugetLicenseURLToExpression("https://licenses.nuget.org/Apache-2.0%20OR%20MIT")
	require.True(t, ok)
	assert.Equal(t, "Apache-2.0 OR MIT", got)
}

func TestNuGetLicenseURLToExpression_NonNuGetHost_NotMapped(t *testing.T) {
	_, ok := nugetLicenseURLToExpression("https://raw.github.com/HangfireIO/Hangfire/master/LICENSE.md")
	assert.False(t, ok)
}
