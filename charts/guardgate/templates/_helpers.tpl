{{/* Nhãn chung cho mọi object */}}
{{- define "guardgate.labels" -}}
app.kubernetes.io/part-of: guardgate
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end }}

{{/* Nhãn chọn pod của một component; NetworkPolicy cũng dựa vào nhãn này. Gọi với (dict "name" .. "root" $) */}}
{{- define "guardgate.selectorLabels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end }}

{{/* Ảnh ứng dụng: <registry>/guardgate-<app>:<tag>[@<digest>]. Bắt buộc có tag, cấm "latest". */}}
{{- define "guardgate.image" -}}
{{- $tag := required "image.tag is required" .root.Values.image.tag -}}
{{- if eq $tag "latest" }}{{ fail "image.tag must not be \"latest\" (pin a commit SHA)" }}{{ end -}}
{{- $img := printf "%s/guardgate-%s:%s" .root.Values.image.registry .name $tag -}}
{{- if .app.digest }}{{ $img = printf "%s@%s" $img .app.digest }}{{ end -}}
{{- $img -}}
{{- end }}
