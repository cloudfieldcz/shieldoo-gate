import { useState } from 'react'
import { X } from 'lucide-react'
import type {
  ProjectArtifact,
  ProjectOverrideKind,
  ProjectOverrideRequest,
  ProjectOverrideScope,
} from '../api/types'

interface Props {
  artifact: ProjectArtifact
  kind: ProjectOverrideKind
  saving: boolean
  onCancel: () => void
  onSubmit: (req: ProjectOverrideRequest) => void
}

export default function OverrideModal({ artifact, kind, saving, onCancel, onSubmit }: Props) {
  const allowVersionToggle = !!artifact.version
  const [scope, setScope] = useState<ProjectOverrideScope>(
    allowVersionToggle ? 'version' : 'package'
  )
  const [reason, setReason] = useState('')
  const [expiresAt, setExpiresAt] = useState('')

  const title = kind === 'allow' ? 'Whitelist package' : 'Blacklist package'
  const verb = kind === 'allow' ? 'Whitelist' : 'Blacklist'
  const tone =
    kind === 'allow'
      ? 'bg-green-600 hover:bg-green-700 focus-visible:ring-green-500'
      : 'bg-red-600 hover:bg-red-700 focus-visible:ring-red-500'

  function handleSubmit() {
    if (!reason.trim()) return
    onSubmit({
      ecosystem: artifact.ecosystem,
      name: artifact.name,
      version: scope === 'version' ? artifact.version ?? '' : '',
      scope,
      kind,
      reason: reason.trim(),
      expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined,
    })
  }

  return (
    <div
      className="fixed inset-0 z-40 bg-black/40 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="override-modal-title"
    >
      <div className="bg-white rounded-lg shadow-xl max-w-lg w-full">
        <div className="flex items-start justify-between border-b border-gray-200 px-5 py-3">
          <div>
            <h2 id="override-modal-title" className="text-base font-semibold text-gray-900">
              {title}
            </h2>
            <p className="text-xs text-gray-500 mt-0.5 font-mono">
              {artifact.ecosystem}:{artifact.name}
              {artifact.version ? `:${artifact.version}` : ''}
            </p>
          </div>
          <button
            type="button"
            onClick={onCancel}
            disabled={saving}
            className="text-gray-400 hover:text-gray-700 disabled:opacity-50"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Scope</label>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={!allowVersionToggle}
                onClick={() => setScope('version')}
                className={`flex-1 px-3 py-2 text-xs rounded border ${
                  scope === 'version'
                    ? 'bg-blue-50 border-blue-400 text-blue-800'
                    : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                } disabled:opacity-40 disabled:cursor-not-allowed`}
                title={
                  allowVersionToggle
                    ? 'Apply only to this exact version'
                    : 'No version available — package scope only'
                }
              >
                This version{artifact.version ? ` (${artifact.version})` : ''}
              </button>
              <button
                type="button"
                onClick={() => setScope('package')}
                className={`flex-1 px-3 py-2 text-xs rounded border ${
                  scope === 'package'
                    ? 'bg-blue-50 border-blue-400 text-blue-800'
                    : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                }`}
              >
                Any version
              </button>
            </div>
          </div>

          <div>
            <label htmlFor="override-reason" className="block text-xs font-medium text-gray-700 mb-1">
              Reason <span className="text-red-600">*</span>
            </label>
            <textarea
              id="override-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              required
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder={
                kind === 'allow'
                  ? 'e.g. approved by legal — needed for analytics service'
                  : 'e.g. CVE-XXXX, replaced by internal fork'
              }
            />
            <p className="text-[11px] text-gray-500 mt-1">
              Stored in the audit log so future operators can trace the decision.
            </p>
          </div>

          <div>
            <label htmlFor="override-expiry" className="block text-xs font-medium text-gray-700 mb-1">
              Expires (optional)
            </label>
            <input
              id="override-expiry"
              type="date"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
              className="px-3 py-2 text-sm border border-gray-300 rounded focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
            <p className="text-[11px] text-gray-500 mt-1">
              After this date the override is no longer applied (the row stays for audit).
            </p>
          </div>
        </div>

        <div className="flex justify-end gap-2 border-t border-gray-200 px-5 py-3">
          <button
            type="button"
            onClick={onCancel}
            disabled={saving}
            className="px-3 py-1.5 text-sm rounded border border-gray-300 bg-white text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSubmit}
            disabled={saving || !reason.trim()}
            className={`px-3 py-1.5 text-sm rounded text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-1 disabled:opacity-50 ${tone}`}
          >
            {saving ? 'Saving…' : verb}
          </button>
        </div>
      </div>
    </div>
  )
}
