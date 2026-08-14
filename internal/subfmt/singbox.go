package subfmt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// decodeSingbox разбирает sing-box JSON в список узлов из "outbounds".
func decodeSingbox(body []byte) ([]Entry, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("subfmt: не разобрать sing-box json: %w", err)
	}
	outbounds, _ := doc["outbounds"].([]any)

	entries := make([]Entry, 0, len(outbounds))
	for _, raw := range outbounds {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		entries = append(entries, singboxNodeToEntry(m))
	}
	return entries, nil
}

// singboxNodeToEntry превращает один outbound в Entry. Как и у clash, тип,
// не входящий в число поддержанных для конвертации, всё равно даёт запись
// с именем, просто без URI/WG, чтобы не занижать число узлов молча.
func singboxNodeToEntry(m map[string]any) Entry {
	name, _ := m["tag"].(string)
	e := Entry{Name: name}

	typ, _ := m["type"].(string)
	if strings.EqualFold(typ, "wireguard") {
		if cfg, err := singboxOutboundToWG(m); err == nil {
			e.WG = buildWireGuardINI(cfg)
		}
		return e
	}
	if link, err := singboxOutboundToLink(m); err == nil {
		if uri, err := buildLinkURI(link); err == nil {
			e.URI = uri
		}
	}
	return e
}

// encodeSingbox собирает sing-box JSON с нуля: минимальный документ с
// outbounds и одним селектором на все узлы. Используется, когда сливать
// не с чем.
func encodeSingbox(entries []Entry) ([]byte, error) {
	outbounds := make([]any, 0, len(entries))
	tags := make([]string, 0, len(entries))
	for _, e := range entries {
		node, ok := entryToSingboxOutbound(e)
		if !ok {
			continue
		}
		outbounds = append(outbounds, node)
		if t, _ := node["tag"].(string); t != "" {
			tags = append(tags, t)
		}
	}
	outbounds = append(outbounds, map[string]any{
		"type": "selector", "tag": "PROXY", "outbounds": toAnySlice(tags),
	})
	doc := map[string]any{"outbounds": outbounds}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("subfmt: не собрать sing-box json: %w", err)
	}
	return out, nil
}

// entryToSingboxOutbound конвертирует Entry в outbound sing-box. ok=false
// значит нечем выразить (пустые URI/WG или неподдержанная схема ссылки),
// узел пропускается, а не роняет всю операцию.
func entryToSingboxOutbound(e Entry) (map[string]any, bool) {
	if e.WG != "" {
		cfg, err := parseWireGuardINI(e.WG)
		if err != nil {
			return nil, false
		}
		return wgToSingboxOutbound(firstNonEmpty(e.Name, "wireguard"), cfg), true
	}
	if e.URI != "" {
		link, err := parseLink(e.URI)
		if err != nil {
			return nil, false
		}
		tag := firstNonEmpty(e.Name, link.Name, link.Server)
		return linkToSingboxOutbound(tag, link), true
	}
	return nil, false
}

// appendSingbox дописывает extra в outbounds существующего sing-box тела
// и в outbounds всех селекторов/urltest-групп.
func appendSingbox(body []byte, extra []Entry) ([]byte, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return encodeSingbox(extra)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body, fmt.Errorf("subfmt: не разобрать sing-box json: %w", err)
	}
	outbounds, _ := doc["outbounds"].([]any)

	used := usedNames(existingSingboxTags(outbounds))
	var addedTags []string
	for _, e := range extra {
		e.Name = dedupeName(firstNonEmpty(e.Name, "node"), used)
		node, ok := entryToSingboxOutbound(e)
		if !ok {
			continue
		}
		node["tag"] = e.Name
		outbounds = append(outbounds, node)
		addedTags = append(addedTags, e.Name)
	}
	doc["outbounds"] = outbounds

	if len(addedTags) > 0 {
		addTagsToSingboxGroups(outbounds, addedTags)
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return body, fmt.Errorf("subfmt: не собрать sing-box json: %w", err)
	}
	return out, nil
}

// mergeSingbox сливает secondary в primary на уровне самих JSON-объектов
// outbounds, без перегона через ссылки. Объекты secondary попадают в
// outbounds primary как есть (с переименованием tag при конфликте), а их
// tag добавляются в outbounds у существующих селекторов и urltest-групп
// primary. Остальные поля документа (log, dns, route, experimental)
// primary не трогаются.
func mergeSingbox(primary, secondary []byte) ([]byte, error) {
	if len(bytes.TrimSpace(primary)) == 0 {
		return normalizeSingbox(secondary)
	}

	var pDoc map[string]any
	if err := json.Unmarshal(primary, &pDoc); err != nil {
		return primary, fmt.Errorf("subfmt: не разобрать первичный sing-box json: %w", err)
	}
	var sDoc map[string]any
	if err := json.Unmarshal(secondary, &sDoc); err != nil {
		out, encErr := json.MarshalIndent(pDoc, "", "  ")
		if encErr != nil {
			return primary, fmt.Errorf("subfmt: не разобрать вторичный sing-box json (%v) и не пересобрать первичный: %w", err, encErr)
		}
		return out, fmt.Errorf("subfmt: не разобрать вторичный sing-box json: %w", err)
	}

	pOutbounds, _ := pDoc["outbounds"].([]any)
	sOutbounds, _ := sDoc["outbounds"].([]any)

	used := usedNames(existingSingboxTags(pOutbounds))
	var addedTags []string
	for _, raw := range sOutbounds {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		// Свои селекторы/urltest-группы secondary не копируем: их список
		// outbounds ссылается на теги secondary, а после разруливания
		// коллизий имён эти теги в объединённом документе могут не
		// совпадать с исходными, и скопированная группа тихо указывала бы
		// не на тот узел. Группы primary расширяются новыми тегами ниже
		// через addTagsToSingboxGroups, а собственные группы secondary
		// просто теряют смысл вне её документа.
		typ, _ := m["type"].(string)
		if typ == "selector" || typ == "urltest" {
			continue
		}
		origTag, _ := m["tag"].(string)
		newTag := dedupeName(firstNonEmpty(origTag, "node"), used)
		if newTag != origTag {
			m["tag"] = newTag
		}
		pOutbounds = append(pOutbounds, m)
		addedTags = append(addedTags, newTag)
	}
	pDoc["outbounds"] = pOutbounds

	if len(addedTags) > 0 {
		addTagsToSingboxGroups(pOutbounds, addedTags)
	}

	out, err := json.MarshalIndent(pDoc, "", "  ")
	if err != nil {
		return primary, fmt.Errorf("subfmt: не собрать sing-box json после слияния: %w", err)
	}
	return out, nil
}

// normalizeSingbox парсит и пересобирает тело: как и у clash, используется
// в Merge, когда primary пустое, результат обязан быть валидным JSON.
func normalizeSingbox(body []byte) ([]byte, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return []byte{}, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body, fmt.Errorf("subfmt: не разобрать sing-box json: %w", err)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return body, fmt.Errorf("subfmt: не собрать sing-box json: %w", err)
	}
	return out, nil
}

// existingSingboxTags собирает tag всех существующих outbounds: нужно для
// поиска конфликтов имён при добавлении новых.
func existingSingboxTags(outbounds []any) []string {
	tags := make([]string, 0, len(outbounds))
	for _, raw := range outbounds {
		if m, ok := raw.(map[string]any); ok {
			if t, ok := m["tag"].(string); ok && t != "" {
				tags = append(tags, t)
			}
		}
	}
	return tags
}

// addTagsToSingboxGroups добавляет tag новых узлов в outbounds каждого
// существующего селектора (type=selector) и urltest-группы (type=urltest).
func addTagsToSingboxGroups(outbounds []any, tags []string) {
	for _, raw := range outbounds {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := m["type"].(string)
		if typ != "selector" && typ != "urltest" {
			continue
		}
		list, _ := m["outbounds"].([]any)
		for _, t := range tags {
			list = append(list, t)
		}
		m["outbounds"] = list
	}
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
