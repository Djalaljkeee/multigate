package subfmt

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// decodeBase64Flexible декодирует base64 в любом из четырёх алфавитов,
// которые реально встречаются в подписках: обычный и URL-safe, с
// выравниванием "=" и без него. Панели и клиенты не сговаривались об одном
// варианте, поэтому пробуем по очереди и берём первый, который подошёл.
func decodeBase64Flexible(s string) ([]byte, error) {
	stripped := stripWhitespace(s)
	if stripped == "" {
		return nil, fmt.Errorf("subfmt: пустая base64-строка")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		data, err := enc.DecodeString(stripped)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("subfmt: не декодировать base64: %w", lastErr)
}

// stripWhitespace убирает пробелы и переносы строк: некоторые серверы
// отдают base64 с разбивкой по 76 символов в строке (старая MIME-традиция).
func stripWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// linesDecode разбирает текст plain-формата: одна ссылка на строку.
// Понимает и \n, и \r\n. Пустые строки пропускаются, мусорные строки без
// распознаваемой ссылки всё равно становятся Entry: пусть решает
// вызывающая сторона, а не пакет молча теряет их.
func linesDecode(text string) []Entry {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	var entries []Entry
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		entries = append(entries, Entry{URI: line, Name: nameFromURI(line)})
	}
	return entries
}

// linesEncode собирает текст plain-формата из узлов.
//
// Узлы без URI (например WireGuard-лизы, у которых Entry.WG заполнен, а
// URI пуст) молча пропускаются: base64/plain, это списки готовых ссылок,
// у них нет способа выразить целый INI-конфиг WireGuard одной строкой без
// выдумывания нестандартной схемы, которую ни один реальный клиент не
// поймёт. Ядра, понимающие WireGuard (mihomo, sing-box, см.
// model.Client.SupportsWireGuard), в любом случае получают его через
// clash или singbox формат, а не через base64/plain.
func linesEncode(entries []Entry) string {
	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.URI == "" {
			continue
		}
		lines = append(lines, withFragmentName(e.URI, e.Name))
	}
	return strings.Join(lines, "\n")
}

// nameFromURI вытаскивает имя узла из фрагмента ссылки: так подписи имён
// принято передавать в vless://.../#Имя и подобных ссылках.
func nameFromURI(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || u.Fragment == "" {
		return ""
	}
	return u.Fragment
}

// withFragmentName проставляет у ссылки фрагмент-имя, не трогая остальное.
// Если ссылку не разобрать (не похожа на URI вовсе), возвращаем её как
// есть: лучше оставить строку без переименования, чем испортить её попыткой правки.
func withFragmentName(uri, name string) string {
	if name == "" {
		return uri
	}
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	u.Fragment = name
	return u.String()
}

func decodeBase64(body []byte) ([]Entry, error) {
	data, err := decodeBase64Flexible(string(body))
	if err != nil {
		return nil, fmt.Errorf("subfmt: тело не в base64: %w", err)
	}
	return linesDecode(string(data)), nil
}

func encodeBase64(entries []Entry) ([]byte, error) {
	text := linesEncode(entries)
	return []byte(base64.StdEncoding.EncodeToString([]byte(text))), nil
}

func decodePlain(body []byte) ([]Entry, error) {
	return linesDecode(string(body)), nil
}

func encodePlain(entries []Entry) ([]byte, error) {
	return []byte(linesEncode(entries)), nil
}

// appendViaEntries: общая реализация Append для форматов, у которых узел
// это просто ссылка (base64, plain). Разбираем тело, докидываем extra с
// разруливанием дубликатов имён, собираем обратно.
func appendViaEntries(body []byte, extra []Entry,
	decode func([]byte) ([]Entry, error), encode func([]Entry) ([]byte, error)) ([]byte, error) {
	existing, err := decode(body)
	if err != nil {
		return body, err
	}
	combined := append(existing, dedupeEntries(namesOf(existing), extra)...)
	out, err := encode(combined)
	if err != nil {
		return body, err
	}
	return out, nil
}

// mergeViaEntries: общая реализация Merge для base64/plain. У этих
// форматов узел и есть просто ссылка, поэтому слияние двух тел, это
// слияние двух списков ссылок с разруливанием дублей по имени.
func mergeViaEntries(primary, secondary []byte,
	decode func([]byte) ([]Entry, error), encode func([]Entry) ([]byte, error)) ([]byte, error) {
	existing, err := decode(primary)
	if err != nil {
		return primary, err
	}
	extra, err := decode(secondary)
	if err != nil {
		// Первичное тело разобралось нормально: отдаём его (пересобранным
		// для единообразия), а вторичное отражаем только как ошибку в возврате.
		out, encErr := encode(existing)
		if encErr != nil {
			return primary, encErr
		}
		return out, fmt.Errorf("subfmt: вторичное тело не разобралось: %w", err)
	}
	combined := append(existing, dedupeEntries(namesOf(existing), extra)...)
	return encode(combined)
}
