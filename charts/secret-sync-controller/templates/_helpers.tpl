{{- define "secret-sync-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "secret-sync-controller.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "secret-sync-controller.name" . -}}
{{- end -}}
{{- end -}}

{{- define "secret-sync-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "secret-sync-controller.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
