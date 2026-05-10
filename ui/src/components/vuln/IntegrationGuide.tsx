import { useState } from 'react'

type Props = {
  projectLabel: string
  componentName: string
}

export default function IntegrationGuide({ projectLabel, componentName }: Props) {
  const [tab, setTab] = useState<'gha' | 'gitlab' | 'curl'>('gha')

  const examples: Record<typeof tab, string> = {
    gha: `# .github/workflows/scan.yml
- name: Generate SBOM
  run: trivy fs --format cyclonedx --output sbom.json .
- name: Push to Shieldoo Gate
  env:
    SHIELDOO_TOKEN: \${{ secrets.SHIELDOO_TOKEN }}
  run: |
    curl -fsS -X POST \\
      -H "Authorization: Bearer <token>" \\
      -H "Content-Type: application/vnd.cyclonedx+json" \\
      --data-binary @sbom.json \\
      https://shieldoo.example.com/api/v1/projects/${projectLabel}/components/${componentName}/scans`,
    gitlab: `# .gitlab-ci.yml
scan:
  image: aquasec/trivy:latest
  script:
    - trivy fs --format cyclonedx --output sbom.json .
    - >
      curl -fsS -X POST
      -H "Authorization: Bearer <token>"
      -H "Content-Type: application/vnd.cyclonedx+json"
      --data-binary @sbom.json
      https://shieldoo.example.com/api/v1/projects/${projectLabel}/components/${componentName}/scans`,
    curl: `# Generic
trivy fs --format cyclonedx --output sbom.json .
curl -fsS -X POST \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/vnd.cyclonedx+json" \\
  --data-binary @sbom.json \\
  https://shieldoo.example.com/api/v1/projects/${projectLabel}/components/${componentName}/scans`,
  }

  return (
    <div className="rounded-lg border border-gray-200 bg-white">
      <div className="flex items-center gap-1 px-3 pt-3">
        {(['gha', 'gitlab', 'curl'] as const).map((id) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`px-3 py-1.5 text-sm rounded ${tab === id ? 'bg-blue-600 text-white' : 'text-gray-600 hover:bg-gray-100'}`}
          >
            {id === 'gha' ? 'GitHub Actions' : id === 'gitlab' ? 'GitLab CI' : 'Generic curl'}
          </button>
        ))}
      </div>
      <pre className="text-xs leading-relaxed bg-gray-900 text-gray-100 m-3 rounded-md p-4 overflow-auto max-h-96">
        {examples[tab]}
      </pre>
      <div className="px-4 py-3 border-t border-gray-200 text-xs text-gray-600">
        Need a token? <a href="/profile?scope=scan:upload" className="text-blue-600 underline">Create scan token</a>
      </div>
    </div>
  )
}
