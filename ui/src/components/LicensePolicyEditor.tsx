import { useEffect, useMemo, useState } from 'react'
import { Ban, AlertTriangle, CheckCircle2, X, Info, Save } from 'lucide-react'
import type {
  LicenseAction,
  OrSemantics,
  LicensePolicyMode,
} from '../api/types'
import { LICENSE_GROUPS } from '../data/licenseGroups'
import { COMMON_SPDX_IDS } from '../data/spdxIds'

export interface LicensePolicyValue {
  mode?: LicensePolicyMode // project variant only
  enabled?: boolean // global variant only
  blocked: string[]
  warned: string[]
  allowed: string[]
  unknown_action: LicenseAction | ''
  on_sbom_error?: LicenseAction | '' // global only
  or_semantics?: OrSemantics // global only
}

export interface LicensePolicyEditorProps {
  variant: 'global' | 'project'
  value: LicensePolicyValue
  onSave: (next: LicensePolicyValue) => void
  saving?: boolean
  /** When true, the 'override' mode is disabled with a tooltip (lazy-mode guard). */
  modeOverrideDisabled?: boolean
  /** Small info banner rendered above the editor. */
  hint?: React.ReactNode
  /** Descriptive label for the current effective source. */
  sourceLabel?: string
}

type Bucket = 'blocked' | 'warned' | 'allowed'

const BUCKETS: { key: Bucket; label: string; action: LicenseAction; icon: JSX.Element; bg: string; text: string; hover: string; muted: string; ring: string }[] = [
  {
    key: 'blocked',
    label: 'Blocked',
    action: 'block',
    icon: <Ban className="w-4 h-4" />,
    bg: 'bg-red-50',
    text: 'text-red-800',
    hover: 'hover:bg-red-100',
    muted: 'bg-red-100',
    ring: 'ring-red-400',
  },
  {
    key: 'warned',
    label: 'Warned',
    action: 'warn',
    icon: <AlertTriangle className="w-4 h-4" />,
    bg: 'bg-amber-50',
    text: 'text-amber-800',
    hover: 'hover:bg-amber-100',
    muted: 'bg-amber-100',
    ring: 'ring-amber-400',
  },
  {
    key: 'allowed',
    label: 'Allowed (whitelist)',
    action: 'allow',
    icon: <CheckCircle2 className="w-4 h-4" />,
    bg: 'bg-green-50',
    text: 'text-green-800',
    hover: 'hover:bg-green-100',
    muted: 'bg-green-100',
    ring: 'ring-green-400',
  },
]

/** How many of `groupIds` are currently in `bucket`, and the all/some/none state. */
function bucketCoverage(value: LicensePolicyValue, groupIds: string[], bucket: Bucket): { count: number; state: 'all' | 'some' | 'none' } {
  const inBucket = new Set(value[bucket].map(lc))
  let hit = 0
  for (const id of groupIds) if (inBucket.has(lc(id))) hit++
  let state: 'all' | 'some' | 'none' = 'none'
  if (hit === groupIds.length && hit > 0) state = 'all'
  else if (hit > 0) state = 'some'
  return { count: hit, state }
}

/** Normalize for case-insensitive deduplication, but preserve user casing. */
function lc(s: string): string {
  return s.trim().toLowerCase()
}

function uniq(ids: string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const id of ids) {
    const k = lc(id)
    if (!k || seen.has(k)) continue
    seen.add(k)
    out.push(id.trim())
  }
  return out
}

/** Move a set of SPDX IDs into the target bucket; remove from the other two. */
function applyGroup(value: LicensePolicyValue, ids: string[], target: Bucket): LicensePolicyValue {
  const targets = new Set(ids.map(lc))
  const strip = (list: string[]) => list.filter((id) => !targets.has(lc(id)))
  const next: LicensePolicyValue = {
    ...value,
    blocked: strip(value.blocked),
    warned: strip(value.warned),
    allowed: strip(value.allowed),
  }
  next[target] = uniq([...next[target], ...ids])
  return next
}

function valuesEqual(a: LicensePolicyValue, b: LicensePolicyValue): boolean {
  return JSON.stringify(a) === JSON.stringify(b)
}

export default function LicensePolicyEditor({
  variant,
  value,
  onSave,
  saving,
  modeOverrideDisabled,
  hint,
  sourceLabel,
}: LicensePolicyEditorProps) {
  const [draft, setDraft] = useState<LicensePolicyValue>(value)
  const [addInput, setAddInput] = useState<Record<Bucket, string>>({
    blocked: '',
    warned: '',
    allowed: '',
  })

  useEffect(() => {
    setDraft(value)
  }, [value])

  const dirty = !valuesEqual(draft, value)

  const isActiveEditing = variant === 'global' || draft.mode === 'override'

  // Hide the list editor entirely when the project mode is inherit/disabled.
  const showListEditor = isActiveEditing

  // SPDX ID set for "recognized" badge styling.
  const knownSet = useMemo(
    () => new Set(COMMON_SPDX_IDS.map((s) => s.toLowerCase())),
    []
  )

  function addToBucket(bucket: Bucket, raw: string) {
    const val = raw.trim()
    if (!val) return
    const next = applyGroup(draft, [val], bucket)
    setDraft(next)
    setAddInput((s) => ({ ...s, [bucket]: '' }))
  }

  function removeFromBucket(bucket: Bucket, id: string) {
    setDraft((d) => ({
      ...d,
      [bucket]: d[bucket].filter((x) => lc(x) !== lc(id)),
    }))
  }

  function applyPreset(groupIds: string[], target: Bucket) {
    setDraft((d) => applyGroup(d, groupIds, target))
  }

  return (
    <div className="space-y-6">
      {hint && (
        <div className="flex items-start gap-2 p-3 rounded-md bg-blue-50 text-blue-900 text-sm border border-blue-200">
          <Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <div>{hint}</div>
        </div>
      )}

      {sourceLabel && (
        <div className="text-xs text-gray-500">
          <span className="font-medium">Effective source:</span> {sourceLabel}
        </div>
      )}

      {/* Project-only: mode selector */}
      {variant === 'project' && (
        <fieldset className="space-y-2">
          <legend className="text-sm font-semibold text-gray-900">Policy mode</legend>
          <div className="flex gap-4 flex-wrap">
            {(['inherit', 'override', 'disabled'] as LicensePolicyMode[]).map((m) => {
              const isOverride = m === 'override'
              const disabled = isOverride && !!modeOverrideDisabled
              return (
                <label
                  key={m}
                  title={disabled ? 'Override requires projects.mode=strict' : undefined}
                  className={`flex items-center gap-2 px-3 py-2 border rounded-md text-sm cursor-pointer ${
                    draft.mode === m
                      ? 'bg-blue-50 border-blue-400 text-blue-900'
                      : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                  } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
                >
                  <input
                    type="radio"
                    name="license-policy-mode"
                    value={m}
                    checked={draft.mode === m}
                    disabled={disabled}
                    onChange={() => setDraft({ ...draft, mode: m })}
                  />
                  <span className="capitalize">{m}</span>
                </label>
              )
            })}
          </div>
          <p className="text-xs text-gray-500">
            <strong>inherit</strong> uses the global policy · <strong>override</strong> replaces it (strict projects mode only) · <strong>disabled</strong> skips license checks for this project.
          </p>
        </fieldset>
      )}

      {/* Quick preset table: one click maps a license group to a bucket. */}
      {showListEditor && (
        <div className="border border-gray-200 rounded-md overflow-hidden">
          <div className="px-4 py-3 bg-gray-50 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-900">License groups</h3>
            <p className="text-xs text-gray-600 mt-0.5">
              Click a cell to assign every SPDX ID in the group to that bucket (removes from the other two). All matches are exact canonical SPDX identifiers — there is no wildcard matching.
            </p>
            <p className="text-xs text-gray-500 mt-1">
              <strong>Button state reflects the current policy</strong>, not a recommendation:
              solid = all IDs in that bucket, outline with <span className="font-mono">(n/m)</span> = some, plain = none.
              The small <span className="font-mono">suggest: …</span> badge next to each group name is only an enterprise-typical hint.
            </p>
          </div>
          <table className="w-full text-sm">
            <thead className="bg-gray-100 text-gray-600 text-xs uppercase tracking-wide">
              <tr>
                <th className="px-4 py-2 text-left font-medium">Group</th>
                <th className="px-2 py-2 text-center font-medium">Block</th>
                <th className="px-2 py-2 text-center font-medium">Warn</th>
                <th className="px-2 py-2 text-center font-medium">Allow</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {LICENSE_GROUPS.map((g) => (
                <tr key={g.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 align-top">
                    <div className="font-medium text-gray-900 flex items-center gap-2">
                      {g.name}
                      <span
                        className="text-[10px] uppercase tracking-wide font-semibold px-1.5 py-0.5 rounded bg-gray-100 text-gray-600"
                        title="Suggested default — not the current state. Click a button on the right to apply."
                      >
                        suggest: {g.defaultAction}
                      </span>
                    </div>
                    <div className="text-xs text-gray-500 mt-0.5 max-w-xl">{g.tagline}</div>
                    <div className="text-xs text-gray-400 mt-1">
                      {g.licenses.length} SPDX ID{g.licenses.length === 1 ? '' : 's'}:{' '}
                      <span className="font-mono">{g.licenses.join(', ')}</span>
                    </div>
                  </td>
                  {BUCKETS.map((b) => {
                    const cov = bucketCoverage(draft, g.licenses, b.key)
                    const base = 'inline-flex items-center gap-1 px-3 py-1.5 text-xs rounded-md border'
                    let style: string
                    let suffix = ''
                    if (cov.state === 'all') {
                      style = `${b.bg} ${b.text} border-current hover:brightness-95`
                    } else if (cov.state === 'some') {
                      style = `bg-white ${b.text} border-current ring-1 ${b.ring} hover:brightness-95`
                      suffix = ` (${cov.count}/${g.licenses.length})`
                    } else {
                      style = 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                    }
                    const title =
                      cov.state === 'all'
                        ? `All ${g.licenses.length} SPDX IDs of "${g.name}" are currently in the ${b.label} bucket. Click to re-apply (no-op here — already full).`
                        : cov.state === 'some'
                        ? `${cov.count} of ${g.licenses.length} SPDX IDs of "${g.name}" are in ${b.label}. Click to move the rest of the group into ${b.label} (and out of the other two buckets).`
                        : `Click to assign every SPDX ID in "${g.name}" to the ${b.label} bucket.`
                    return (
                      <td key={b.key} className="px-2 py-3 text-center align-top">
                        <button
                          type="button"
                          onClick={() => applyPreset(g.licenses, b.key)}
                          title={title}
                          className={`${base} ${style}`}
                        >
                          {b.icon}
                          {b.label.split(' ')[0]}
                          {suffix && <span className="ml-0.5 text-[10px] opacity-70 tabular-nums">{suffix}</span>}
                        </button>
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Bucket editors */}
      {showListEditor &&
        BUCKETS.map((b) => (
          <div key={b.key} className={`border border-gray-200 rounded-md overflow-hidden`}>
            <div className={`px-4 py-2 ${b.bg} ${b.text} flex items-center gap-2 border-b border-gray-200`}>
              {b.icon}
              <h3 className="text-sm font-semibold">{b.label}</h3>
              <span className="text-xs font-normal opacity-70 ml-1">
                ({draft[b.key].length} SPDX ID{draft[b.key].length === 1 ? '' : 's'})
              </span>
            </div>
            <div className="p-4 space-y-3">
              {/* Pills */}
              {draft[b.key].length === 0 ? (
                <p className="text-xs text-gray-400 italic">empty</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {draft[b.key].map((id) => {
                    const known = knownSet.has(id.toLowerCase())
                    return (
                      <span
                        key={id}
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono ${b.muted} ${b.text} border border-current border-opacity-20`}
                        title={known ? 'Recognized SPDX ID' : 'Not in the common SPDX list — will still match if Trivy emits it verbatim'}
                      >
                        {id}
                        {!known && <span className="text-[10px] font-sans opacity-60">?</span>}
                        <button
                          type="button"
                          onClick={() => removeFromBucket(b.key, id)}
                          className={`ml-0.5 rounded-full hover:bg-white hover:bg-opacity-50 p-0.5 ${b.hover}`}
                          aria-label={`Remove ${id}`}
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </span>
                    )
                  })}
                </div>
              )}

              {/* Add input */}
              <div className="flex gap-2">
                <input
                  type="text"
                  list="spdx-id-suggestions"
                  placeholder="Add SPDX ID, e.g. GPL-3.0-only"
                  value={addInput[b.key]}
                  onChange={(e) => setAddInput((s) => ({ ...s, [b.key]: e.target.value }))}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault()
                      addToBucket(b.key, addInput[b.key])
                    }
                  }}
                  className="flex-1 px-3 py-1.5 text-sm border border-gray-300 rounded-md font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                <button
                  type="button"
                  onClick={() => addToBucket(b.key, addInput[b.key])}
                  disabled={!addInput[b.key].trim()}
                  className="px-3 py-1.5 text-sm rounded-md bg-white border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Add
                </button>
              </div>
            </div>
          </div>
        ))}

      {/* Single shared <datalist> for all three inputs. */}
      <datalist id="spdx-id-suggestions">
        {COMMON_SPDX_IDS.map((id) => (
          <option key={id} value={id} />
        ))}
      </datalist>

      {/* Unknown / fallback actions */}
      {showListEditor && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <label className="text-sm space-y-1">
            <div className="font-medium text-gray-900">
              Unknown license
              <span className="block text-xs text-gray-500 font-normal">
                Action for licenses that don't match any SPDX ID in the lists above.
              </span>
            </div>
            <select
              value={draft.unknown_action || 'allow'}
              onChange={(e) => setDraft({ ...draft, unknown_action: e.target.value as LicenseAction })}
              className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-md bg-white"
            >
              <option value="allow">allow (pass silently)</option>
              <option value="warn">warn (allow + audit event)</option>
              <option value="block">block (reject 403)</option>
            </select>
          </label>

          {variant === 'global' && (
            <>
              <label className="text-sm space-y-1">
                <div className="font-medium text-gray-900">
                  Missing SBOM
                  <span className="block text-xs text-gray-500 font-normal">
                    Action when no SBOM is available (rare — only pre-v1.2 artifacts or Trivy outages).
                  </span>
                </div>
                <select
                  value={draft.on_sbom_error || 'allow'}
                  onChange={(e) => setDraft({ ...draft, on_sbom_error: e.target.value as LicenseAction })}
                  className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-md bg-white"
                >
                  <option value="allow">allow</option>
                  <option value="warn">warn</option>
                  <option value="block">block (risky — turns scanner outage into a 403 storm)</option>
                </select>
              </label>

              <label className="text-sm space-y-1">
                <div className="font-medium text-gray-900">
                  OR expression semantics
                  <span className="block text-xs text-gray-500 font-normal">
                    How to evaluate <span className="font-mono">MIT OR Apache-2.0</span>: any operand allowed, or all?
                  </span>
                </div>
                <select
                  value={draft.or_semantics || 'any_allowed'}
                  onChange={(e) => setDraft({ ...draft, or_semantics: e.target.value as OrSemantics })}
                  className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-md bg-white"
                >
                  <option value="any_allowed">any_allowed (default, permissive)</option>
                  <option value="all_allowed">all_allowed (strict)</option>
                </select>
              </label>
            </>
          )}
        </div>
      )}

      {/* Save bar */}
      <div className="flex items-center justify-end gap-3 pt-2 border-t border-gray-200">
        <button
          type="button"
          onClick={() => setDraft(value)}
          disabled={!dirty || saving}
          className="px-3 py-2 text-sm rounded-md bg-white border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
        >
          Revert
        </button>
        <button
          type="button"
          onClick={() => onSave(draft)}
          disabled={!dirty || saving}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm rounded-md bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
        >
          <Save className="w-4 h-4" />
          {saving ? 'Saving…' : 'Save policy'}
        </button>
      </div>
    </div>
  )
}
