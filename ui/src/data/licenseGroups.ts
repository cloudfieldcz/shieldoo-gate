// Curated license groups for the License Policy editor.
//
// Matching in the backend is by **canonical SPDX ID** (case-insensitive,
// whitespace-trimmed). There is no prefix/wildcard match — so when a user
// clicks "Block strong copyleft", the UI expands the group into every
// concrete SPDX ID that belongs to it, and those are what get saved.
//
// Keeping the expansion explicit means:
//   1. The admin can audit exactly which IDs are blocked.
//   2. The evaluator stays simple (set lookup, no pattern engine).
//   3. Adding a new dialect of GPL later requires an explicit update to
//      both this file and the user's saved policy — no silent broadening.

export interface LicenseGroup {
  id: string
  name: string
  tagline: string
  licenses: string[]
  /** Default bulk action recommended for enterprise policy. */
  defaultAction: 'block' | 'warn' | 'allow'
}

export const LICENSE_GROUPS: LicenseGroup[] = [
  {
    id: 'strong-copyleft',
    name: 'Strong copyleft (GPL)',
    tagline:
      'GNU General Public License family. Derivative works must be distributed under the same license. Usually incompatible with proprietary products.',
    licenses: [
      'GPL-2.0-only',
      'GPL-2.0-or-later',
      'GPL-3.0-only',
      'GPL-3.0-or-later',
    ],
    defaultAction: 'block',
  },
  {
    id: 'network-copyleft',
    name: 'Network copyleft (AGPL)',
    tagline:
      'AGPL closes the "network loophole" in GPL — serving modified software over a network triggers source-disclosure obligations. Hardest to comply with for SaaS.',
    licenses: ['AGPL-3.0-only', 'AGPL-3.0-or-later'],
    defaultAction: 'block',
  },
  {
    id: 'weak-copyleft',
    name: 'Weak / library copyleft (LGPL / MPL / EPL)',
    tagline:
      'Modifications to the library must be shared, but you can link against it from a proprietary codebase. Usually acceptable with care — many orgs warn instead of block.',
    licenses: [
      'LGPL-2.0-only',
      'LGPL-2.0-or-later',
      'LGPL-2.1-only',
      'LGPL-2.1-or-later',
      'LGPL-3.0-only',
      'LGPL-3.0-or-later',
      'MPL-1.1',
      'MPL-2.0',
      'EPL-1.0',
      'EPL-2.0',
    ],
    defaultAction: 'warn',
  },
  {
    id: 'permissive',
    name: 'Permissive (MIT / Apache / BSD / ISC)',
    tagline:
      'Minimal obligations (usually just attribution). The safest bucket for commercial use — most orgs allow these without review.',
    licenses: [
      'MIT',
      'Apache-2.0',
      'BSD-2-Clause',
      'BSD-3-Clause',
      'BSD-3-Clause-Clear',
      'ISC',
    ],
    defaultAction: 'allow',
  },
  {
    id: 'public-domain',
    name: 'Public domain / very permissive',
    tagline:
      'No meaningful restrictions. Treat as permissive unless you have unusual legal requirements.',
    licenses: ['CC0-1.0', 'Unlicense', '0BSD', 'WTFPL', 'CC-PDDC'],
    defaultAction: 'allow',
  },
  {
    id: 'creative-commons',
    name: 'Creative Commons',
    tagline:
      'CC licenses show up on docs, data, and media more than code. Some variants (NC, ND) are often unacceptable for commercial software bundles.',
    licenses: [
      'CC-BY-4.0',
      'CC-BY-SA-4.0',
      'CC-BY-NC-4.0',
      'CC-BY-NC-SA-4.0',
      'CC-BY-ND-4.0',
    ],
    defaultAction: 'warn',
  },
]

/** Flat set of all curated SPDX IDs — convenient for autocomplete. */
export const CURATED_SPDX_IDS: string[] = Array.from(
  new Set(LICENSE_GROUPS.flatMap((g) => g.licenses))
).sort()
