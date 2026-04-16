// Curated list of the ~100 most-common SPDX license identifiers. Used as the
// source for datalist-based autocomplete in the License Policy editor.
//
// The backend accepts any string (the evaluator just does a case-insensitive
// set lookup), so this list is only a UX hint — users can type any SPDX ID
// and the editor will flag unrecognized ones with a warning badge.
//
// Kept small on purpose: the full SPDX registry has >700 entries, most of
// which nobody in a corporate context ever writes.

export const COMMON_SPDX_IDS: string[] = [
  // Permissive
  'MIT',
  'MIT-0',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'BSD-3-Clause-Clear',
  'BSD-4-Clause',
  'ISC',
  'Zlib',
  'WTFPL',
  '0BSD',
  'Artistic-2.0',
  'BSL-1.0',
  'PostgreSQL',
  'Python-2.0',
  'PSF-2.0',
  'NCSA',

  // Weak / library copyleft
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
  'CDDL-1.0',
  'CDDL-1.1',

  // Strong copyleft
  'GPL-2.0-only',
  'GPL-2.0-or-later',
  'GPL-3.0-only',
  'GPL-3.0-or-later',

  // Network copyleft
  'AGPL-3.0-only',
  'AGPL-3.0-or-later',

  // Public domain / CC0
  'CC0-1.0',
  'Unlicense',
  'CC-PDDC',

  // Creative Commons
  'CC-BY-3.0',
  'CC-BY-4.0',
  'CC-BY-SA-3.0',
  'CC-BY-SA-4.0',
  'CC-BY-NC-3.0',
  'CC-BY-NC-4.0',
  'CC-BY-NC-SA-3.0',
  'CC-BY-NC-SA-4.0',
  'CC-BY-ND-3.0',
  'CC-BY-ND-4.0',
  'CC-BY-NC-ND-3.0',
  'CC-BY-NC-ND-4.0',

  // Misc / less common but show up in real SBOMs
  'OFL-1.1',
  'EUPL-1.1',
  'EUPL-1.2',
  'CECILL-2.1',
  'MS-PL',
  'MS-RL',
  'Ruby',
  'Vim',
  'X11',
  'OpenSSL',
  'BlueOak-1.0.0',
  'curl',
  'JSON',
  'IJG',
  'libpng-2.0',
  'TCL',
  'NTP',
]
