package proxy

import (
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// formatFromSuffix переводит суффикс пути (например "clash" из
// /api/sub/{uuid}/clash) в формат ответа. Пустой или неизвестный суффикс
// даёт model.FormatUnknown.
func formatFromSuffix(suffix string) model.Format {
	switch strings.ToLower(firstSegment(suffix)) {
	case "clash", "clash-meta", "meta":
		return model.FormatClash
	case "singbox", "sing-box":
		return model.FormatSingBox
	case "base64", "v2ray", "xray", "outline":
		return model.FormatBase64
	default:
		return model.FormatUnknown
	}
}

// guessFormat решает, в каком формате готовить тело-заглушку для
// заблокированного или истёкшего клиента. Порядок предпочтения:
//  1. явный суффикс пути (/clash, /singbox) - клиент попросил конкретно;
//  2. формат, который уже назвал апстрим (актуально для режима panel,
//     когда SubResponse.Format известен из настоящего ответа);
//  3. эвристика по ядру клиента, определённому пакетом ua.
func guessFormat(suffix string, c model.Client, upstreamFormat model.Format) model.Format {
	if f := formatFromSuffix(suffix); f != model.FormatUnknown {
		return f
	}
	if upstreamFormat != "" && upstreamFormat != model.FormatUnknown {
		return upstreamFormat
	}
	switch c.Core {
	case model.CoreMihomo:
		return model.FormatClash
	case model.CoreSingBox:
		return model.FormatSingBox
	default:
		return model.FormatBase64
	}
}
