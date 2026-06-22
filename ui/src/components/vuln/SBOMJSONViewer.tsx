// Strictly text-only SBOM viewer. Never uses dangerouslySetInnerHTML — protects against
// stored-XSS in the description / summary fields uploaded by CI.
type Props = { sbom: unknown }

export default function SBOMJSONViewer({ sbom }: Props) {
  let pretty: string
  try {
    pretty = JSON.stringify(sbom, null, 2)
  } catch {
    pretty = String(sbom)
  }
  return (
    <pre className="text-xs leading-relaxed bg-gray-900 text-gray-100 rounded-md p-4 overflow-auto max-h-[600px]">
      {pretty}
    </pre>
  )
}
