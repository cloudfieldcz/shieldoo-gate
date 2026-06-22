// ESLint flat config (ESLint 10) for the Shieldoo Gate admin UI.
// React 18 + TypeScript + Vite. Run via `npm run lint`.
//
// Rule baseline: @eslint/js + typescript-eslint `recommended`, plus the
// canonical Vite-React-TS hooks rules (rules-of-hooks = error,
// exhaustive-deps = warn). We deliberately do NOT use react-hooks v7's
// `recommended-latest`, whose newer `set-state-in-effect` rule flags the
// widely-accepted "reset pagination on filter change" pattern as an error;
// adopting it would be a separate, reviewed refactor.
import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  // Build output and vendored deps are never linted.
  { ignores: ['dist', 'node_modules'] },

  // Application source: browser-targeted React/TS.
  {
    files: ['src/**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
    },
  },

  // Playwright e2e specs run under Node, not the browser.
  {
    files: ['e2e/**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: globals.node,
    },
  },
)
