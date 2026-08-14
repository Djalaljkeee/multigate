// Package subfmt читает и пишет тело подписки в разных форматах: base64
// (список ссылок в base64, основной формат панели Remnawave), plain (тот
// же список без кодирования), clash (YAML для mihomo) и singbox (JSON).
//
// Задача пакета: уметь добавить в существующее тело подписки лишние узлы
// (например, выданный из пула конфиг WireGuard или бонусную ноду), не
// разломав всё остальное, что в этом теле уже было. Поэтому clash и
// singbox разбираются настоящими парсерами (yaml.v3 и encoding/json), а не
// регулярками: чужой конфиг может содержать что угодно кроме proxies и
// outbounds, например dns, rules, route, experimental, и всё это должно
// доехать до клиента как было.
package subfmt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"gopkg.in/yaml.v3"
)

// Entry: один узел подписки в виде, не зависящем от формата тела.
// Ровно одно из URI/WG обычно заполнено: URI для обычных прокси-ссылок
// (vless://, vmess://, trojan://, ss:// и так далее), WG для узла
// WireGuard/AmneziaWG, у которого вместо ссылки целый INI-конфиг.
type Entry struct {
	Name string // имя узла
	URI  string // готовая ссылка vless:// или другая
	WG   string // содержимое конфига WireGuard/AmneziaWG, если узел такой
}

// Detect определяет формат тела подписки по содержимому и Content-Type.
// Содержимое в приоритете: Content-Type у панелей и мирроров часто врёт
// или просто text/plain для всего подряд, а по факту в base64 бывает и
// стандартный алфавит, и URL-safe, и без выравнивания "=", так что решает
// именно попытка разобрать тело, а не заголовок.
func Detect(body []byte, contentType string) model.Format {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return model.FormatUnknown
	}
	ct := strings.ToLower(contentType)

	switch trimmed[0] {
	case '{':
		var doc map[string]any
		if err := json.Unmarshal(trimmed, &doc); err == nil {
			if _, ok := doc["outbounds"]; ok {
				return model.FormatSingBox
			}
			return model.FormatJSON
		}
	case '<':
		return model.FormatHTML
	}
	if strings.Contains(ct, "html") {
		return model.FormatHTML
	}

	// Clash: настоящий YAML-парсер, а не угадывание по словам "proxies" в
	// сыром тексте, так не спутаем с посторонним YAML, где такого ключа
	// нет вовсе.
	var y map[string]any
	if err := yaml.Unmarshal(trimmed, &y); err == nil {
		if _, ok := y["proxies"]; ok {
			return model.FormatClash
		}
		if _, ok := y["proxy-groups"]; ok {
			return model.FormatClash
		}
	}

	// base64: пробуем распаковать всеми четырьмя алфавитами. Настоящий
	// список ссылок plain-формата всегда содержит символы вне любого
	// base64-алфавита (уже в "vless://uuid@host" есть ":", "@", "?", "&"),
	// поэтому декодирование на нём просто не пройдёт и мы корректно
	// свалимся в ветку plain ниже.
	if data, err := decodeBase64Flexible(string(trimmed)); err == nil && len(data) > 0 {
		return model.FormatBase64
	}

	if utf8.Valid(trimmed) {
		return model.FormatPlain
	}
	return model.FormatUnknown
}

// Decode разбирает тело подписки формата f в список узлов.
func Decode(body []byte, f model.Format) ([]Entry, error) {
	switch f {
	case model.FormatBase64:
		return decodeBase64(body)
	case model.FormatPlain:
		return decodePlain(body)
	case model.FormatClash:
		return decodeClash(body)
	case model.FormatSingBox:
		return decodeSingbox(body)
	default:
		return nil, fmt.Errorf("subfmt: формат %q для Decode не поддержан", f)
	}
}

// Encode собирает тело подписки формата f с нуля из списка узлов.
// Используется, когда сливать не с чем: например, у пользователя ещё нет
// собственного clash-конфига, а отдать нужно.
func Encode(entries []Entry, f model.Format) ([]byte, error) {
	switch f {
	case model.FormatBase64:
		return encodeBase64(entries)
	case model.FormatPlain:
		return encodePlain(entries)
	case model.FormatClash:
		return encodeClash(entries)
	case model.FormatSingBox:
		return encodeSingbox(entries)
	default:
		return nil, fmt.Errorf("subfmt: формат %q для Encode не поддержан", f)
	}
}

// Append дописывает extra в существующее тело body формата f.
//
// Контракт нарочно однозначный: если body не разобрать (формат не тот, что
// заявлен, либо содержимое побилось), Append возвращает body БЕЗ ИЗМЕНЕНИЙ
// и ошибку. Никогда не пустое тело и не молчаливую потерю подписки.
// Решение, что делать дальше (отдать как есть, залогировать, отказаться
// от довеска), остаётся за вызывающей стороной.
func Append(body []byte, f model.Format, extra []Entry) ([]byte, error) {
	if len(extra) == 0 {
		return body, nil
	}
	switch f {
	case model.FormatBase64:
		return appendViaEntries(body, extra, decodeBase64, encodeBase64)
	case model.FormatPlain:
		return appendViaEntries(body, extra, decodePlain, encodePlain)
	case model.FormatClash:
		return appendClash(body, extra)
	case model.FormatSingBox:
		return appendSingbox(body, extra)
	default:
		return body, fmt.Errorf("subfmt: формат %q для Append не поддержан", f)
	}
}

// Merge сливает secondary в primary: узлы secondary дописываются в узлы
// primary, а их имена, в существующие группы (proxy-groups у clash,
// селекторы и urltest у singbox). Остальная структура primary (dns, rules,
// route и всё, о чём этот пакет не знает) остаётся как есть: для clash и
// singbox слияние идёт на уровне самих узлов конфигов, без превращения их
// в промежуточные ссылки и обратно. Это и есть самый надёжный способ
// ничего не сломать в чужом файле.
//
// Тот же принцип, что у Append: если primary не разобрать, возвращается
// primary без изменений и ошибка. Если не разобрать secondary, в body
// уходит primary (пересобранный для единообразия) и ошибка про secondary:
// пользователь всё равно получит рабочую подписку, просто без довеска.
func Merge(primary, secondary []byte, f model.Format) ([]byte, error) {
	switch f {
	case model.FormatBase64:
		return mergeViaEntries(primary, secondary, decodeBase64, encodeBase64)
	case model.FormatPlain:
		return mergeViaEntries(primary, secondary, decodePlain, encodePlain)
	case model.FormatClash:
		return mergeClash(primary, secondary)
	case model.FormatSingBox:
		return mergeSingbox(primary, secondary)
	default:
		return primary, fmt.Errorf("subfmt: формат %q для Merge не поддержан", f)
	}
}

// firstNonEmpty отдаёт первое непустое значение: удобно для полей, у
// которых в разных форматах разные имена одного и того же смысла
// (например "sni" и устаревший алиас "peer").
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
