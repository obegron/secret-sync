{{- define "vcluster-secret-sync-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vcluster-secret-sync-controller.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "vcluster-secret-sync-controller.name" . -}}
{{- end -}}
{{- end -}}

{{- define "vcluster-secret-sync-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "vcluster-secret-sync-controller.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
