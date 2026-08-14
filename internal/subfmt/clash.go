package subfmt

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// decodeClash разбирает clash YAML в список узлов из "proxies".
func decodeClash(body []byte) ([]Entry, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("subfmt: не разобрать clash yaml: %w", err)
	}
	root := documentRoot(&doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("subfmt: clash yaml без корневой мапы")
	}

	proxies := mapValue(root, "proxies")
	if proxies == nil {
		return []Entry{}, nil
	}
	if proxies.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("subfmt: поле proxies в clash yaml не список")
	}

	entries := make([]Entry, 0, len(proxies.Content))
	for _, node := range proxies.Content {
		entries = append(entries, clashNodeToEntry(node))
	}
	return entries, nil
}

// clashNodeToEntry превращает один узел proxies в Entry. Если тип прокси
// не из числа поддержанных для конвертации, узел всё равно попадает в
// результат: с именем, но пустыми URI/WG, так Decode не занижает
// количество узлов молча.
func clashNodeToEntry(node *yaml.Node) Entry {
	var m map[string]any
	if err := node.Decode(&m); err != nil {
		return Entry{}
	}
	name, _ := m["name"].(string)
	e := Entry{Name: name}

	typ, _ := m["type"].(string)
	if strings.EqualFold(typ, "wireguard") {
		if cfg, err := clashProxyToWG(m); err == nil {
			e.WG = buildWireGuardINI(cfg)
		}
		return e
	}
	if link, err := clashProxyToLink(m); err == nil {
		if uri, err := buildLinkURI(link); err == nil {
			e.URI = uri
		}
	}
	return e
}

// encodeClash собирает clash YAML с нуля: минимальный документ с proxies и
// одной select-группой на все узлы. Используется, когда сливать не с чем.
func encodeClash(entries []Entry) ([]byte, error) {
	proxies := make([]any, 0, len(entries))
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		node, ok := entryToClashProxy(e)
		if !ok {
			continue
		}
		proxies = append(proxies, node)
		if n, _ := node["name"].(string); n != "" {
			names = append(names, n)
		}
	}
	doc := map[string]any{
		"proxies": proxies,
		"proxy-groups": []any{
			map[string]any{"name": "PROXY", "type": "select", "proxies": names},
		},
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("subfmt: не собрать clash yaml: %w", err)
	}
	return out, nil
}

// entryToClashProxy конвертирует Entry в узел clash-прокси. Возвращает
// ok=false для узлов, которые для clash выразить нечем (пустые URI/WG или
// схема ссылки не из поддержанных): такой узел молча пропускается, а не
// роняет всю операцию.
func entryToClashProxy(e Entry) (map[string]any, bool) {
	if e.WG != "" {
		cfg, err := parseWireGuardINI(e.WG)
		if err != nil {
			return nil, false
		}
		return wgToClashProxy(firstNonEmpty(e.Name, "wireguard"), cfg), true
	}
	if e.URI != "" {
		link, err := parseLink(e.URI)
		if err != nil {
			return nil, false
		}
		name := firstNonEmpty(e.Name, link.Name, link.Server)
		return linkToClashProxy(name, link), true
	}
	return nil, false
}

// appendClash дописывает extra в proxies существующего clash-тела и в
// proxies всех существующих proxy-groups. Пустое тело: частный случай,
// сливать не с чем, собираем документ с нуля.
func appendClash(body []byte, extra []Entry) ([]byte, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return encodeClash(extra)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return body, fmt.Errorf("subfmt: не разобрать clash yaml: %w", err)
	}
	root := documentRoot(&doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return body, fmt.Errorf("subfmt: clash yaml без корневой мапы")
	}

	proxiesNode := mapValue(root, "proxies")
	if proxiesNode == nil {
		proxiesNode = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		setMapValue(root, "proxies", proxiesNode)
	} else if proxiesNode.Kind != yaml.SequenceNode {
		return body, fmt.Errorf("subfmt: поле proxies в clash yaml не список")
	}

	used := usedNames(existingClashNames(proxiesNode))
	var addedNames []string
	for _, e := range extra {
		e.Name = dedupeName(firstNonEmpty(e.Name, "node"), used)
		node, ok := entryToClashProxy(e)
		if !ok {
			continue
		}
		node["name"] = e.Name
		var yn yaml.Node
		if err := yn.Encode(node); err != nil {
			continue
		}
		proxiesNode.Content = append(proxiesNode.Content, &yn)
		addedNames = append(addedNames, e.Name)
	}
	if len(addedNames) > 0 {
		addNamesToClashGroups(root, addedNames)
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return body, fmt.Errorf("subfmt: не собрать clash yaml: %w", err)
	}
	return out, nil
}

// mergeClash сливает secondary в primary на уровне самих YAML-узлов, без
// перегона через промежуточные ссылки: узлы secondary копируются в proxies
// primary как есть (только имя при конфликте меняется), а их имена
// добавляются в proxy-groups primary. Остальная структура primary
// (dns/rules/route и что угодно ещё) не трогается вовсе.
func mergeClash(primary, secondary []byte) ([]byte, error) {
	if len(bytes.TrimSpace(primary)) == 0 {
		return normalizeClash(secondary)
	}

	var pDoc yaml.Node
	if err := yaml.Unmarshal(primary, &pDoc); err != nil {
		return primary, fmt.Errorf("subfmt: не разобрать первичный clash yaml: %w", err)
	}
	pRoot := documentRoot(&pDoc)
	if pRoot == nil || pRoot.Kind != yaml.MappingNode {
		return primary, fmt.Errorf("subfmt: первичный clash yaml без корневой мапы")
	}

	var sDoc yaml.Node
	if err := yaml.Unmarshal(secondary, &sDoc); err != nil {
		out, encErr := yaml.Marshal(&pDoc)
		if encErr != nil {
			return primary, fmt.Errorf("subfmt: не разобрать вторичный clash yaml (%v) и не пересобрать первичный: %w", err, encErr)
		}
		return out, fmt.Errorf("subfmt: не разобрать вторичный clash yaml: %w", err)
	}
	sRoot := documentRoot(&sDoc)
	sProxies := mapValue(sRoot, "proxies")

	pProxiesNode := mapValue(pRoot, "proxies")
	if pProxiesNode == nil {
		pProxiesNode = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		setMapValue(pRoot, "proxies", pProxiesNode)
	}

	used := usedNames(existingClashNames(pProxiesNode))
	var addedNames []string
	if sProxies != nil {
		for _, item := range sProxies.Content {
			clone := deepCopyNode(item)
			origName := ""
			if v := mapValue(clone, "name"); v != nil {
				origName = v.Value
			}
			newName := dedupeName(firstNonEmpty(origName, "node"), used)
			if newName != origName {
				setClashName(clone, newName)
			}
			pProxiesNode.Content = append(pProxiesNode.Content, clone)
			addedNames = append(addedNames, newName)
		}
	}
	if len(addedNames) > 0 {
		addNamesToClashGroups(pRoot, addedNames)
	}

	out, err := yaml.Marshal(&pDoc)
	if err != nil {
		return primary, fmt.Errorf("subfmt: не собрать clash yaml после слияния: %w", err)
	}
	return out, nil
}

// normalizeClash парсит и пересобирает тело: используется, когда у Merge
// первичное тело пустое, результат должен быть гарантированно валидным
// yaml, а не просто эхом чужого тела как есть.
func normalizeClash(body []byte) ([]byte, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return []byte{}, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return body, fmt.Errorf("subfmt: не разобрать clash yaml: %w", err)
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return body, fmt.Errorf("subfmt: не собрать clash yaml: %w", err)
	}
	return out, nil
}

// documentRoot достаёт корневую мапу из DocumentNode, который получается
// при Unmarshal в *yaml.Node.
func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	return doc
}

// mapValue ищет значение по ключу в MappingNode. Content мапы: плоский
// список [ключ1, значение1, ключ2, значение2, ...], как это устроено в yaml.v3.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// setMapValue дописывает в мапу новую пару ключ/значение.
func setMapValue(m *yaml.Node, key string, value *yaml.Node) {
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	m.Content = append(m.Content, keyNode, value)
}

// existingClashNames собирает имена уже существующих proxies: нужно для
// поиска конфликтов имён при добавлении новых.
func existingClashNames(seq *yaml.Node) []string {
	if seq == nil {
		return nil
	}
	names := make([]string, 0, len(seq.Content))
	for _, item := range seq.Content {
		if v := mapValue(item, "name"); v != nil {
			names = append(names, v.Value)
		}
	}
	return names
}

// addNamesToClashGroups добавляет имена новых узлов в proxies каждой
// существующей proxy-group: и у select, и у url-test групп поле называется
// одинаково, поэтому отдельно по типу группы не ветвимся.
func addNamesToClashGroups(root *yaml.Node, names []string) {
	groups := mapValue(root, "proxy-groups")
	if groups == nil || groups.Kind != yaml.SequenceNode {
		return
	}
	for _, group := range groups.Content {
		list := mapValue(group, "proxies")
		if list == nil || list.Kind != yaml.SequenceNode {
			continue
		}
		for _, name := range names {
			list.Content = append(list.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name})
		}
	}
}

// setClashName проставляет/добавляет поле name у узла прокси.
func setClashName(node *yaml.Node, name string) {
	if v := mapValue(node, "name"); v != nil {
		v.Value = name
		v.Tag = "!!str"
		return
	}
	setMapValue(node, "name", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name})
}

// deepCopyNode копирует поддерево узла: узлы secondary нельзя вплетать в
// дерево primary напрямую, у них разное происхождение (Alias/Anchor и
// метаданные вроде Line/Column ссылаются на другой документ).
func deepCopyNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	cp := *n
	if n.Content != nil {
		cp.Content = make([]*yaml.Node, len(n.Content))
		for i, c := range n.Content {
			cp.Content[i] = deepCopyNode(c)
		}
	}
	return &cp
}
