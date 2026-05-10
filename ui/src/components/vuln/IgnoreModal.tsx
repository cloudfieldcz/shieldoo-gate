import { useState } from 'react'
import { vulnApi, aiApi, type ScanFinding } from '../../api/vulnerabilities'

type Props = {
  componentID: number
  componentRepoURL?: string
  finding: ScanFinding
  scanRunID: number
  aiEnabled: boolean
  onClose: () => void
  onCreated: () => void
  // initial values when restoring an expired ignore — pre-fills the reason and
  // surfaces an "Restoring expired ignore" header. Optional.
  initialReason?: string
  restoreFromExpired?: boolean
}

const expiryOptions = [
  { label: 'In 30 days', days: 30 },
  { label: 'In 90 days', days: 90, default: true },
  { label: 'In 180 days', days: 180 },
  { label: 'Never (not recommended)', days: 0 },
]

export default function IgnoreModal({
  componentID,
  componentRepoURL,
  finding,
  scanRunID,
  aiEnabled,
  onClose,
  onCreated,
  initialReason,
  restoreFromExpired,
}: Props) {
  const [reason, setReason] = useState(initialReason ?? '')
  const [expiryDays, setExpiryDays] = useState<number>(90)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [draft, setDraft] = useState<string | null>(null)
  const [draftLoading, setDraftLoading] = useState(false)
  const [aiDraftAccepted, setAiDraftAccepted] = useState(false)

  const supportsDraft = aiEnabled && !!componentRepoURL

  const handleDraft = async () => {
    setDraftLoading(true)
    try {
      const r = await aiApi.draft({
        component_id: componentID,
        cve_id: finding.cve_id,
        package_name: finding.package_name,
        package_version: finding.package_version,
      })
      setDraft(r.reason)
    } catch (e) {
      setError('AI draft unavailable')
    } finally {
      setDraftLoading(false)
    }
  }

  const handleSubmit = async () => {
    if (!reason.trim() || reason.length > 1000) {
      setError('Reason is required (max 1000 chars)')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      let expiresAt: string | null = null
      if (expiryDays > 0) {
        const d = new Date()
        d.setDate(d.getDate() + expiryDays)
        expiresAt = d.toISOString()
      }
      await vulnApi.createIgnore(componentID, {
        cve_id: finding.cve_id,
        package_name: finding.package_name,
        package_version: finding.package_version,
        reason,
        expires_at: expiresAt,
        ai_draft_accepted: aiDraftAccepted,
        against_run_id: scanRunID,
      })
      onCreated()
    } catch (e: any) {
      setError(e?.response?.data?.error ?? 'Failed to create ignore')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-white rounded-lg shadow-2xl w-full max-w-2xl">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold">
            {restoreFromExpired ? 'Restore' : 'Ignore'} {finding.cve_id} on {finding.package_name}@{finding.package_version}
          </h2>
          {restoreFromExpired && (
            <p className="mt-1 text-xs text-amber-700">
              This ignore expired and was auto-revoked. Submitting will create a fresh ignore — the previous reason has been pre-filled for you to review.
            </p>
          )}
        </div>
        <div className="px-6 py-4 space-y-4 max-h-[70vh] overflow-auto">
          <div className="rounded border border-gray-200 bg-gray-50 p-3 text-sm">
            <div className="text-gray-600 mb-1">{finding.summary || 'No summary available'}</div>
            {finding.fixed_version && (
              <div className="text-green-700">Fixed in: {finding.fixed_version}</div>
            )}
          </div>

          {supportsDraft && (
            <div className="rounded border border-purple-200 bg-gradient-to-br from-indigo-50 to-violet-50 p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-purple-700 uppercase tracking-wider">AI-DRAFTED FROM CODE CONTEXT</span>
                <button
                  type="button"
                  onClick={handleDraft}
                  disabled={draftLoading}
                  className="text-xs text-purple-700 hover:underline disabled:opacity-50"
                >
                  {draft ? 'Regenerate' : 'Draft reason'}
                </button>
              </div>
              {draft ? (
                <>
                  <p className="italic text-sm text-gray-700">{draft}</p>
                  <button
                    type="button"
                    onClick={() => { setReason(draft); setAiDraftAccepted(true) }}
                    className="mt-2 px-3 py-1 text-xs bg-purple-600 text-white rounded hover:bg-purple-700"
                  >
                    Use this draft
                  </button>
                </>
              ) : (
                <p className="text-xs text-gray-500">Click "Draft reason" to ask the AI to inspect the linked repo for call-sites.</p>
              )}
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Reason</label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={1000}
              rows={5}
              placeholder="Why is this acceptable? (e.g. 'Not exploitable in our usage — function never called'.)"
              className="w-full rounded border border-gray-300 px-3 py-2 text-sm"
            />
            <div className="text-xs text-gray-500 mt-1">{reason.length}/1000</div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Expires</label>
            <div className="space-y-1">
              {expiryOptions.map((opt) => (
                <label key={opt.label} className="flex items-center gap-2 text-sm">
                  <input
                    type="radio"
                    name="expiry"
                    checked={expiryDays === opt.days}
                    onChange={() => setExpiryDays(opt.days)}
                  />
                  {opt.label}
                </label>
              ))}
            </div>
          </div>

          {error && <div className="text-sm text-red-600">{error}</div>}
        </div>
        <div className="px-6 py-4 border-t border-gray-200 flex justify-end gap-2">
          <button onClick={onClose} className="px-4 py-2 text-sm rounded border border-gray-300 hover:bg-gray-50">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={submitting || !reason.trim()}
            className="px-4 py-2 text-sm rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {submitting ? 'Saving…' : 'Ignore'}
          </button>
        </div>
      </div>
    </div>
  )
}
