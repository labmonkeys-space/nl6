{{/*
Copyright 2026 Ronny Trommer <ronny@no42.org>
SPDX-License-Identifier: Apache-2.0
*/}}

{{/* Chart name, optionally overridden. */}}
{{- define "nl6-minion.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "nl6-minion.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "nl6-minion.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "nl6-minion.labels" -}}
helm.sh/chart: {{ include "nl6-minion.chart" . }}
{{ include "nl6-minion.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "nl6-minion.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nl6-minion.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* ServiceAccount name. */}}
{{- define "nl6-minion.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "nl6-minion.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding Minion credentials. */}}
{{- define "nl6-minion.credentialsSecret" -}}
{{- if .Values.minion.credentials.existingSecret -}}
{{- .Values.minion.credentials.existingSecret -}}
{{- else -}}
{{- printf "%s-credentials" (include "nl6-minion.fullname" .) -}}
{{- end -}}
{{- end -}}
