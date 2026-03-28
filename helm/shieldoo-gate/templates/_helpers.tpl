{{/*
Expand the name of the chart.
*/}}
{{- define "shieldoo-gate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "shieldoo-gate.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "shieldoo-gate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "shieldoo-gate.labels" -}}
helm.sh/chart: {{ include "shieldoo-gate.chart" . }}
{{ include "shieldoo-gate.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "shieldoo-gate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "shieldoo-gate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "shieldoo-gate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "shieldoo-gate.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the secret name to use for credentials.
*/}}
{{- define "shieldoo-gate.secretName" -}}
{{- if .Values.existingSecret }}
{{- .Values.existingSecret }}
{{- else }}
{{- include "shieldoo-gate.fullname" . }}-secrets
{{- end }}
{{- end }}

{{/*
Return the main container image reference.
*/}}
{{- define "shieldoo-gate.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/*
Return the scanner bridge container image reference.
*/}}
{{- define "shieldoo-gate.scannerBridgeImage" -}}
{{- printf "%s:%s" .Values.scannerBridge.image.repository (default .Chart.AppVersion .Values.scannerBridge.image.tag) }}
{{- end }}

{{/*
HA validation: block SQLite with replicaCount > 1.
*/}}
{{- define "shieldoo-gate.validateHA" -}}
{{- if and (gt (int .Values.replicaCount) 1) (eq .Values.database.backend "sqlite") }}
  {{- fail "replicaCount > 1 requires database.backend=postgres (SQLite is single-writer)" }}
{{- end }}
{{- if and (gt (int .Values.replicaCount) 1) (eq .Values.cache.backend "local") }}
  {{- fail "replicaCount > 1 requires cache.backend=s3|azure_blob|gcs (local cache is not shared)" }}
{{- end }}
{{- end }}
