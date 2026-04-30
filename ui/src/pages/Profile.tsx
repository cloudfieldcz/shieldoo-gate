import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { userApi, apiKeysApi, configApi } from '../api/client'
import { Key, Plus, Copy, Check, Trash2, AlertTriangle } from 'lucide-react'
import type { APIKey, PublicURLs } from '../api/types'

export default function Profile() {
  const queryClient = useQueryClient()

  const { data: user } = useQuery({
    queryKey: ['userinfo'],
    queryFn: userApi.me,
    staleTime: Infinity,
  })

  const keysQuery = useQuery({
    queryKey: ['api-keys'],
    queryFn: apiKeysApi.list,
    staleTime: 2 * 60 * 1000,
    retry: (count, error) => {
      // Don't retry on 404 (proxy_auth disabled).
      if ((error as { response?: { status: number } })?.response?.status === 404) return false
      return count < 2
    },
  })

  const { data: publicURLs } = useQuery({
    queryKey: ['public-urls'],
    queryFn: configApi.publicURLs,
    staleTime: Infinity,
  })

  const apiKeysAvailable = !keysQuery.isError || (keysQuery.error as { response?: { status: number } })?.response?.status !== 404

  return (
    <div className="p-8 space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Profile</h1>
        <p className="text-sm text-gray-500 mt-1">Your account and API key management.</p>
      </div>

      {/* User info */}
      {user && (
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
          <h2 className="text-base font-semibold text-gray-900 mb-4">Account</h2>
          <dl className="space-y-3">
            {[
              ['Email', user.email],
              ['Name', user.name || '—'],
              ['Subject', user.sub],
            ].map(([label, value]) => (
              <div key={label} className="flex gap-4 text-sm">
                <dt className="w-20 text-gray-500 flex-shrink-0">{label}</dt>
                <dd className="text-gray-900 font-mono">{value}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}

      {/* API Keys */}
      {apiKeysAvailable ? (
        <APIKeysSection keys={keysQuery.data ?? []} isLoading={keysQuery.isLoading} queryClient={queryClient} />
      ) : (
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-5">
          <p className="text-sm text-blue-800">
            API key management is not enabled in this deployment. Set{' '}
            <code className="font-mono bg-blue-100 px-1 rounded">proxy_auth.enabled: true</code> in config to enable.
          </p>
        </div>
      )}

      {/* Usage instructions */}
      {apiKeysAvailable && <UsageInstructions urls={publicURLs} />}
    </div>
  )
}

// --- API Keys Section ---

function APIKeysSection({
  keys,
  isLoading,
  queryClient,
}: {
  keys: APIKey[]
  isLoading: boolean
  queryClient: ReturnType<typeof useQueryClient>
}) {
  const [showCreate, setShowCreate] = useState(false)
  const [newToken, setNewToken] = useState<string | null>(null)
  const [newKeyName, setNewKeyName] = useState('')
  const [nameError, setNameError] = useState('')

  const createMutation = useMutation({
    mutationFn: (name: string) => apiKeysApi.create(name),
    onSuccess: (data) => {
      setNewToken(data.token)
      setShowCreate(false)
      setNewKeyName('')
      setNameError('')
      queryClient.invalidateQueries({ queryKey: ['api-keys'] })
    },
  })

  const handleCreate = () => {
    const trimmed = newKeyName.trim()
    if (!trimmed) {
      setNameError('Name is required')
      return
    }
    if (trimmed.length > 255) {
      setNameError('Name too long (max 255 characters)')
      return
    }
    setNameError('')
    createMutation.mutate(trimmed)
  }

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold text-gray-900">API Keys</h2>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1.5 text-sm font-medium text-blue-600 hover:text-blue-700"
        >
          <Plus className="w-4 h-4" />
          Create Key
        </button>
      </div>

      <p className="text-xs text-gray-500 -mt-2">
        Proxy requests authenticate with HTTP Basic Auth: a <strong>project label</strong> as username and the token as password.
        The key <em>name</em> below is for your own bookkeeping (shown in this list, not in requests).
      </p>

      {/* Create form */}
      {showCreate && (
        <div className="flex items-start gap-2">
          <div className="flex-1">
            <input
              type="text"
              value={newKeyName}
              onChange={(e) => { setNewKeyName(e.target.value); setNameError('') }}
              onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
              placeholder="Key name (e.g. ci-pipeline)"
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              autoFocus
              maxLength={255}
            />
            {nameError && <p className="text-xs text-red-500 mt-1">{nameError}</p>}
            {createMutation.isError && <p className="text-xs text-red-500 mt-1">Failed to create key.</p>}
          </div>
          <button
            onClick={handleCreate}
            disabled={createMutation.isPending}
            className="px-3 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            {createMutation.isPending ? 'Creating...' : 'Create'}
          </button>
          <button
            onClick={() => { setShowCreate(false); setNewKeyName(''); setNameError('') }}
            className="px-3 py-2 text-sm text-gray-500 hover:text-gray-700"
          >
            Cancel
          </button>
        </div>
      )}

      {/* Token display modal */}
      {newToken && (
        <TokenModal token={newToken} onClose={() => setNewToken(null)} />
      )}

      {/* Keys table */}
      {isLoading ? (
        <p className="text-sm text-gray-400">Loading keys...</p>
      ) : keys.length === 0 ? (
        <p className="text-sm text-gray-500">No API keys yet. Create one to authenticate proxy requests.</p>
      ) : (
        <KeysTable keys={keys} queryClient={queryClient} />
      )}
    </div>
  )
}

// --- Token Modal (non-dismissible) ---

function TokenModal({ token, onClose }: { token: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(token)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-white rounded-xl shadow-2xl p-6 max-w-lg w-full mx-4 space-y-4">
        <div className="flex items-center gap-2 text-amber-600">
          <AlertTriangle className="w-5 h-5" />
          <h3 className="text-base font-semibold">Save Your API Key</h3>
        </div>
        <p className="text-sm text-gray-600">
          Make sure you have copied the token. You will not be able to see it again.
        </p>
        <div className="flex items-center gap-2 bg-gray-50 border border-gray-200 rounded-lg px-3 py-2">
          <code className="flex-1 text-sm font-mono text-gray-900 break-all select-all">{token}</code>
          <button
            onClick={handleCopy}
            className="flex-shrink-0 p-1.5 text-gray-500 hover:text-blue-600 rounded"
            title="Copy to clipboard"
          >
            {copied ? <Check className="w-4 h-4 text-green-600" /> : <Copy className="w-4 h-4" />}
          </button>
        </div>
        <div className="text-xs text-gray-600 bg-blue-50 border border-blue-200 rounded-lg p-3 space-y-1">
          <p className="font-medium text-gray-900">How to use:</p>
          <p>
            HTTP Basic Auth — <code className="px-1 bg-white border rounded">PROJECT</code> in the username field, the token in the password field.
          </p>
          <p>
            <strong>What to put in <code className="px-1 bg-white border rounded">PROJECT</code>:</strong> any label from <code className="px-1 bg-white border rounded">[a-z0-9][a-z0-9_-]{'{0,63}'}</code> (your team, service, or pipeline name). Shieldoo Gate uses it to segment audit events and per-project artifact usage. If you don't need segmentation, use <code className="px-1 bg-white border rounded">default</code>. Full examples are in the <em>Usage</em> section below.
          </p>
        </div>
        <button
          onClick={onClose}
          className="w-full px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700"
        >
          I have copied this token
        </button>
      </div>
    </div>
  )
}

// --- Keys Table ---

function KeysTable({
  keys,
  queryClient,
}: {
  keys: APIKey[]
  queryClient: ReturnType<typeof useQueryClient>
}) {
  const [confirmRevoke, setConfirmRevoke] = useState<APIKey | null>(null)

  const revokeMutation = useMutation({
    mutationFn: (id: number) => apiKeysApi.revoke(id),
    onSuccess: () => {
      setConfirmRevoke(null)
      queryClient.invalidateQueries({ queryKey: ['api-keys'] })
    },
  })

  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 text-left text-gray-500">
              <th className="pb-2 font-medium">Name</th>
              <th className="pb-2 font-medium">Created</th>
              <th className="pb-2 font-medium">Last Used</th>
              <th className="pb-2 font-medium">Status</th>
              <th className="pb-2 font-medium"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {keys.map((key) => (
              <tr key={key.id} className={key.enabled ? '' : 'opacity-50'}>
                <td className="py-2.5 font-mono flex items-center gap-2">
                  <Key className="w-3.5 h-3.5 text-gray-400" />
                  {key.name}
                </td>
                <td className="py-2.5 text-gray-500">{formatDate(key.created_at)}</td>
                <td className="py-2.5 text-gray-500">{key.last_used_at ? formatDate(key.last_used_at) : 'Never'}</td>
                <td className="py-2.5">
                  {key.enabled ? (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-50 text-green-700">Active</span>
                  ) : (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-500">Revoked</span>
                  )}
                </td>
                <td className="py-2.5 text-right">
                  {key.enabled && (
                    <button
                      onClick={() => setConfirmRevoke(key)}
                      className="text-red-500 hover:text-red-700 p-1"
                      title="Revoke key"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Revoke confirmation */}
      {confirmRevoke && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white rounded-xl shadow-2xl p-6 max-w-md w-full mx-4 space-y-4">
            <div className="flex items-center gap-2 text-red-600">
              <AlertTriangle className="w-5 h-5" />
              <h3 className="text-base font-semibold">Revoke API Key</h3>
            </div>
            <p className="text-sm text-gray-600">
              Are you sure you want to revoke <strong>{confirmRevoke.name}</strong>? This action cannot be undone.
              Any systems using this token will lose access immediately.
            </p>
            {revokeMutation.isError && <p className="text-sm text-red-500">Failed to revoke key.</p>}
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setConfirmRevoke(null)}
                className="px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 rounded-lg"
              >
                Cancel
              </button>
              <button
                onClick={() => revokeMutation.mutate(confirmRevoke.id)}
                disabled={revokeMutation.isPending}
                className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 disabled:opacity-50"
              >
                {revokeMutation.isPending ? 'Revoking...' : 'Revoke'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

// --- Usage Instructions ---

function UsageInstructions({ urls }: { urls?: PublicURLs }) {
  const pypi = urls?.pypi || 'http://<host>:5000'
  const npm = urls?.npm || '<host>:4873'
  const docker = urls?.docker || '<host>:5002'
  const nuget = urls?.nuget || 'http://<host>:5001'
  const gomod = urls?.gomod || 'http://<host>:8087'
  const rubygems = urls?.rubygems || 'http://<host>:8086'
  const maven = urls?.maven || 'http://<host>:8085'

  // Strip protocol for npm/docker where needed
  const npmHost = npm.replace(/^https?:\/\//, '')
  const dockerHost = docker.replace(/^https?:\/\//, '')
  const scheme = pypi.startsWith('https') ? 'https' : 'http'

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 space-y-3">
      <h2 className="text-base font-semibold text-gray-900">Usage</h2>
      <p className="text-sm text-gray-600">
        All ecosystems use <strong>HTTP Basic Auth</strong> (<code className="px-1 bg-gray-100 rounded">PROJECT:TOKEN</code>).
        The <strong>username is interpreted as a project label</strong> — it's
        used to segment audit events, track per-project artifact usage, and
        apply per-project license policy. Pick whatever name fits your team
        or service.
      </p>
      <div className="text-sm text-gray-600 space-y-1 bg-blue-50 border border-blue-200 rounded-lg p-3">
        <p><strong>What to put in the username?</strong></p>
        <ul className="list-disc pl-5 space-y-1">
          <li><code className="px-1 bg-white border rounded">myteam</code>, <code className="px-1 bg-white border rounded">backend-svc</code>, <code className="px-1 bg-white border rounded">data-pipeline</code> — any lowercase label <code className="px-1 bg-white border rounded">[a-z0-9][a-z0-9_-]{'{0,63}'}</code>. Mixed case (<code className="px-1 bg-white border rounded">MyTeam</code>) is auto-lowercased.</li>
          <li><code className="px-1 bg-white border rounded">default</code> or leave empty — if you don't need per-project segmentation, everything lands under the <code className="px-1 bg-white border rounded">default</code> project.</li>
          <li>In <strong>lazy</strong> mode (default), a new label auto-creates a project. In <strong>strict</strong> mode, an admin must create the project first at <code className="px-1 bg-white border rounded">/projects</code>, otherwise the request is rejected (403).</li>
        </ul>
      </div>
      <p className="text-sm text-gray-600">
        The examples below use <code className="px-1 bg-gray-100 rounded">$USER</code> (your shell user) as the project label — replace it with any label you prefer (e.g. <code className="px-1 bg-gray-100 rounded">default</code>, <code className="px-1 bg-gray-100 rounded">myteam</code>). The token goes in the password field; we recommend keeping it in an environment variable.
      </p>
      <pre className="bg-gray-50 border border-gray-200 rounded-lg p-4 text-xs font-mono text-gray-800 overflow-x-auto whitespace-pre">
{`# Set once
export SGW_TOKEN="your-token-here"
# Use your username, a team label, or 'default' — see the note above.
PROJECT=\${USER:-default}

# PyPI — pip
pip install --index-url ${scheme}://\${PROJECT}:\${SGW_TOKEN}@${pypi.replace(/^https?:\/\//, '')}/simple/ <package>

# PyPI — uv
UV_DEFAULT_INDEX=${scheme}://\${PROJECT}:\${SGW_TOKEN}@${pypi.replace(/^https?:\/\//, '')}/simple/ uv pip install <package>

# PyPI — pipenv
PIPENV_PYPI_MIRROR=${scheme}://\${PROJECT}:\${SGW_TOKEN}@${pypi.replace(/^https?:\/\//, '')}/simple/ pipenv install <package>

# npm (credentials must be base64-encoded)
npm config set registry ${npm}/
npm config set //${npmHost}/:_auth $(printf "\${PROJECT}:\${SGW_TOKEN}" | base64)

# Docker
echo \${SGW_TOKEN} | docker login ${dockerHost} -u \${PROJECT} --password-stdin

# NuGet
dotnet nuget add source ${nuget}/v3/index.json -n shieldoo -u \${PROJECT} -p \${SGW_TOKEN} --store-password-in-clear-text

# Go modules
GOPROXY=${gomod.replace(/^https?:\/\//, `${scheme}://\${PROJECT}:\${SGW_TOKEN}@`)} go get <module>

# Maven (Java) — add to ~/.m2/settings.xml
# <server><id>shieldoo</id><username>\${PROJECT}</username><password>\${SGW_TOKEN}</password></server>
# <mirror><id>shieldoo</id><url>${maven}/repository/</url><mirrorOf>central</mirrorOf></mirror>

# RubyGems
gem sources --add ${rubygems.replace(/^https?:\/\//, `${scheme}://\${PROJECT}:\${SGW_TOKEN}@`)}/`}
      </pre>
    </div>
  )
}

// --- Helpers ---

function formatDate(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}
