{{/*
Expand the name of the chart.
*/}}
{{- define "squawk.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "squawk.fullname" -}}
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
{{- define "squawk.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "squawk.labels" -}}
helm.sh/chart: {{ include "squawk.chart" . }}
{{ include "squawk.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "squawk.selectorLabels" -}}
app.kubernetes.io/name: {{ include "squawk.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
DNS Server labels
*/}}
{{- define "squawk.dnsServer.labels" -}}
{{ include "squawk.labels" . }}
app.kubernetes.io/component: dns-server
{{- end }}

{{/*
DNS Server selector labels
*/}}
{{- define "squawk.dnsServer.selectorLabels" -}}
{{ include "squawk.selectorLabels" . }}
app.kubernetes.io/component: dns-server
{{- end }}

{{/*
Manager labels
*/}}
{{- define "squawk.manager.labels" -}}
{{ include "squawk.labels" . }}
app.kubernetes.io/component: manager
{{- end }}

{{/*
Manager selector labels
*/}}
{{- define "squawk.manager.selectorLabels" -}}
{{ include "squawk.selectorLabels" . }}
app.kubernetes.io/component: manager
{{- end }}

{{/*
Frontend labels
*/}}
{{- define "squawk.frontend.labels" -}}
{{ include "squawk.labels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
Frontend selector labels
*/}}
{{- define "squawk.frontend.selectorLabels" -}}
{{ include "squawk.selectorLabels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
DNS Agent labels
*/}}
{{- define "squawk.dnsAgent.labels" -}}
{{ include "squawk.labels" . }}
app.kubernetes.io/component: dns-agent
{{- end }}

{{/*
DNS Agent selector labels
*/}}
{{- define "squawk.dnsAgent.selectorLabels" -}}
{{ include "squawk.selectorLabels" . }}
app.kubernetes.io/component: dns-agent
{{- end }}

{{/*
DHCP Server labels
*/}}
{{- define "squawk.dhcpServer.labels" -}}
{{ include "squawk.labels" . }}
app.kubernetes.io/component: dhcp-server
{{- end }}

{{/*
DHCP Server selector labels
*/}}
{{- define "squawk.dhcpServer.selectorLabels" -}}
{{ include "squawk.selectorLabels" . }}
app.kubernetes.io/component: dhcp-server
{{- end }}

{{/*
NTP Server labels
*/}}
{{- define "squawk.ntpServer.labels" -}}
{{ include "squawk.labels" . }}
app.kubernetes.io/component: ntp-server
{{- end }}

{{/*
NTP Server selector labels
*/}}
{{- define "squawk.ntpServer.selectorLabels" -}}
{{ include "squawk.selectorLabels" . }}
app.kubernetes.io/component: ntp-server
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "squawk.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "squawk.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Get the namespace
*/}}
{{- define "squawk.namespace" -}}
{{- if and .Values.namespace .Values.namespace.create }}
{{- .Values.namespace.name }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
Create database URL
*/}}
{{- define "squawk.databaseUrl" -}}
{{- if .Values.externalDatabase.enabled }}
{{- printf "postgresql://%s:%s@%s:%v/%s" .Values.externalDatabase.user .Values.externalDatabase.password .Values.externalDatabase.host (.Values.externalDatabase.port | int) .Values.externalDatabase.database }}
{{- else if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:%s@%s-postgresql:5432/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "squawk.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- "" }}
{{- end }}
{{- end }}

{{/*
Create cache URL
*/}}
{{- define "squawk.cacheUrl" -}}
{{- if .Values.externalCache.enabled }}
{{- printf "redis://%s:%v" .Values.externalCache.host (.Values.externalCache.port | int) }}
{{- else if .Values.valkey.enabled }}
{{- printf "redis://%s-valkey:6379" (include "squawk.fullname" .) }}
{{- else }}
{{- "" }}
{{- end }}
{{- end }}

{{/*
Get the image registry
*/}}
{{- define "squawk.imageRegistry" -}}
{{- .Values.global.imageRegistry | default "ghcr.io" }}
{{- end }}

{{/*
DNS Server image
*/}}
{{- define "squawk.dnsServer.image" -}}
{{- printf "%s/%s:%s" (include "squawk.imageRegistry" .) .Values.dnsServer.image.repository .Values.dnsServer.image.tag }}
{{- end }}

{{/*
Manager image
*/}}
{{- define "squawk.manager.image" -}}
{{- printf "%s/%s:%s" (include "squawk.imageRegistry" .) .Values.manager.image.repository .Values.manager.image.tag }}
{{- end }}

{{/*
Frontend image
*/}}
{{- define "squawk.frontend.image" -}}
{{- printf "%s/%s:%s" (include "squawk.imageRegistry" .) .Values.frontend.image.repository .Values.frontend.image.tag }}
{{- end }}

{{/*
DNS Agent image
*/}}
{{- define "squawk.dnsAgent.image" -}}
{{- printf "%s/%s:%s" (include "squawk.imageRegistry" .) .Values.dnsAgent.image.repository .Values.dnsAgent.image.tag }}
{{- end }}

{{/*
Flask API labels
*/}}
{{- define "squawk.flaskApi.labels" -}}
{{ include "squawk.labels" . }}
app.kubernetes.io/component: flask-api
{{- end }}

{{/*
Flask API selector labels
*/}}
{{- define "squawk.flaskApi.selectorLabels" -}}
{{ include "squawk.selectorLabels" . }}
app.kubernetes.io/component: flask-api
{{- end }}

{{/*
DNS WebUI labels
*/}}
{{- define "squawk.dnsWebui.labels" -}}
{{ include "squawk.labels" . }}
app.kubernetes.io/component: dns-webui
{{- end }}

{{/*
DNS WebUI selector labels
*/}}
{{- define "squawk.dnsWebui.selectorLabels" -}}
{{ include "squawk.selectorLabels" . }}
app.kubernetes.io/component: dns-webui
{{- end }}

{{/*
DNS Client labels
*/}}
{{- define "squawk.dnsClient.labels" -}}
{{ include "squawk.labels" . }}
app.kubernetes.io/component: squawk-client
{{- end }}

{{/*
DNS Client selector labels
*/}}
{{- define "squawk.dnsClient.selectorLabels" -}}
{{ include "squawk.selectorLabels" . }}
app.kubernetes.io/component: squawk-client
{{- end }}

{{/*
JWT keys secret name (asymmetric signing/verification keys)
*/}}
{{- define "squawk.jwt.secretName" -}}
{{- .Values.jwt.secretName | default "squawk-jwt-keys" }}
{{- end }}
