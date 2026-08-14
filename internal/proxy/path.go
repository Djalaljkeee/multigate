package proxy

import "strings"

// splitSubPath достаёт shortUuid и необязательный суффикс формата из пути
// запроса. Поддерживаются формы:
//
//	/{shortUuid}
//	/sub/{shortUuid}
//	/api/sub/{shortUuid}
//	/api/sub/{shortUuid}/clash
//	/{shortUuid}/singbox
//
// Суффикс - это всё, что идёт в пути после shortUuid (например "clash" или
// "singbox"). Если распознать shortUuid не удалось, обе строки пустые.
func splitSubPath(p string) (shortUUID, suffix string) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", ""
	}
	parts := strings.Split(p, "/")

	i := 0
	switch {
	case parts[0] == "api" && len(parts) > 1 && parts[1] == "sub":
		i = 2
	case parts[0] == "sub":
		i = 1
	}
	if i >= len(parts) {
		return "", ""
	}
	shortUUID = parts[i]
	if i+1 < len(parts) {
		suffix = strings.Join(parts[i+1:], "/")
	}
	return shortUUID, suffix
}

// firstSegment отдаёт первый элемент суффикса пути ("clash/x" -> "clash").
func firstSegment(suffix string) string {
	if idx := strings.IndexByte(suffix, '/'); idx >= 0 {
		return suffix[:idx]
	}
	return suffix
}
