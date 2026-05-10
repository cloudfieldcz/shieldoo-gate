import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { X, AlertTriangle } from 'lucide-react'
import { vulnApi, type Component } from '../../api/vulnerabilities'

type Props = {
  component: Component
  onClose: () => void
  onSaved: () => void
}

/**
 * Per-component edit modal — display_name, description, repo_url, ai_enabled, enabled.
 * PATCH /api/v1/vulnerabilities/components/{id}.
 *
 * `name`, `ecosystem`, `project_id` are immutable in the UI (they identify the
 * component). repo_url is informational; ai_enabled gates the AI surfaces for
 * this component only; enabled=false skips scheduled rescans.
 */
export default function ComponentEditModal({ component, onClose, onSaved }: Props) {
  const [displayName, setDisplayName] = useState(component.display_name ?? '')
  const [description, setDescription] = useState(component.description ?? '')
  const [repoURL, setRepoURL] = useState(component.repo_url ?? '')
  const [aiEnabled, setAIEnabled] = useState(component.ai_enabled)
  const [enabled, setEnabled] = useState(component.enabled)
  const [error, setError] = useState('')

  const mut = useMutation({
    mutationFn: () =>
      vulnApi.update(component.id, {
        display_name: displayName,
        description,
        repo_url: repoURL,
        ai_enabled: aiEnabled,
        enabled,
      }),
    onSuccess: () => onSaved(),
    onError: (e) => setError(extractError(e)),
  })

  const repoTrimmed = repoURL.trim()
  const repoLooksValid = repoTrimmed === '' || /^https?:\/\//i.test(repoTrimmed)

  const handleSave = () => {
    if (!repoLooksValid) {
      setError('Repo URL must start with http:// or https://')
      return
    }
    setError('')
    mut.mutate()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-white rounded-xl shadow-2xl max-w-lg w-full mx-4 max-h-[90vh] overflow-auto">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <h3 className="text-base font-semibold">Edit component</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          {/* Identity (read-only) */}
          <div className="grid grid-cols-2 gap-3 text-xs text-gray-500 -mb-2">
            <div>
              <div className="uppercase tracking-wide mb-0.5">Name</div>
              <div className="font-mono text-gray-800">{component.name}</div>
            </div>
            <div>
              <div className="uppercase tracking-wide mb-0.5">Ecosystem</div>
              <div className="font-mono text-gray-800">{component.ecosystem || '—'}</div>
            </div>
          </div>

          <Field
            label="Display name"
            help="Human-readable label shown in lists. Falls back to the component name when empty."
          >
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              maxLength={255}
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </Field>

          <Field label="Description" help="Free-form, shown under the component header.">
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </Field>

          <Field label="Repository URL" help="Optional. Linked from the component header. http:// or https:// only.">
            <input
              type="url"
              value={repoURL}
              onChange={(e) => setRepoURL(e.target.value)}
              placeholder="https://github.com/org/repo"
              className={`w-full px-3 py-2 text-sm border rounded-lg focus:outline-none focus:ring-2 ${
                repoLooksValid
                  ? 'border-gray-300 focus:ring-blue-500'
                  : 'border-red-300 focus:ring-red-500'
              }`}
            />
          </Field>

          <ToggleRow
            label="AI surfaces"
            help="Anomaly detection + AI fix-path + ignore-reason drafter for this component."
            checked={aiEnabled}
            onChange={setAIEnabled}
          />

          <ToggleRow
            label="Active"
            help="Disabled components are skipped by the scheduled rescan; existing data is preserved."
            checked={enabled}
            onChange={setEnabled}
          />

          {error && (
            <div className="flex items-start gap-2 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg p-3">
              <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 px-5 py-4 border-t border-gray-200 bg-gray-50">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 rounded-lg"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={mut.isPending || !repoLooksValid}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            {mut.isPending ? 'Saving…' : 'Save changes'}
          </button>
        </div>
      </div>
    </div>
  )
}

function Field({ label, help, children }: { label: string; help?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium text-gray-700 mb-1">{label}</label>
      {children}
      {help && <p className="mt-1 text-xs text-gray-500">{help}</p>}
    </div>
  )
}

function ToggleRow({
  label,
  help,
  checked,
  onChange,
}: {
  label: string
  help: string
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <label className="flex items-start gap-3 cursor-pointer">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
      />
      <div className="flex-1">
        <div className="text-sm text-gray-800 font-medium">{label}</div>
        <div className="text-xs text-gray-500">{help}</div>
      </div>
    </label>
  )
}

function extractError(e: unknown): string {
  const resp = (e as { response?: { data?: { error?: string; message?: string } } })?.response
  return resp?.data?.error ?? resp?.data?.message ?? 'Failed to save changes.'
}
