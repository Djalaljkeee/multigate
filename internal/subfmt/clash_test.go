package subfmt

import (
	"strings"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"gopkg.in/yaml.v3"
)

const clashPrimary = `port: 7890
socks-port: 7891
mode: rule
log-level: info
proxies:
  - name: old-node
    type: vless
    server: 1.1.1.1
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    network: tcp
    tls: true
    servername: example.com
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - old-node
  - name: Auto
    type: url-test
    proxies:
      - old-node
rules:
  - MATCH,PROXY
`

const clashSecondary = `proxies:
  - name: old-node
    type: trojan
    server: 2.2.2.2
    port: 8443
    password: secondarypass
  - name: fresh-node
    type: vless
    server: 3.3.3.3
    port: 443
    uuid: 22222222-2222-2222-2222-222222222222
proxy-groups:
  - name: SomethingElse
    type: select
    proxies:
      - old-node
`

func TestDecodeClash(t *testing.T) {
	entries, err := Decode([]byte(clashPrimary), model.FormatClash)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.Name != "old-node" {
		t.Errorf("Name = %q", e.Name)
	}
	if !strings.HasPrefix(e.URI, "vless://11111111-1111-1111-1111-111111111111@1.1.1.1:443?") {
		t.Errorf("URI = %q", e.URI)
	}
	if !strings.Contains(e.URI, "sni=example.com") {
		t.Errorf("URI не содержит sni: %q", e.URI)
	}
}

func TestAppendClash_PreservesRestOfDocument(t *testing.T) {
	extra := []Entry{
		{Name: "old-node", URI: "vless://33333333-3333-3333-3333-333333333333@4.4.4.4:443?security=tls#old-node"},
		{Name: "brand-new", URI: "trojan://passpass@5.5.5.5:443#brand-new"},
	}
	out, err := Append([]byte(clashPrimary), model.FormatClash, extra)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("результат Append: невалидный yaml: %v\n%s", err, out)
	}

	// Остальные поля документа не тронуты.
	if toInt(doc["port"]) != 7890 || doc["mode"] != "rule" || doc["log-level"] != "info" {
		t.Errorf("верхнеуровневые поля документа изменились: %+v", doc)
	}
	rules, _ := doc["rules"].([]any)
	if len(rules) != 1 || rules[0] != "MATCH,PROXY" {
		t.Errorf("rules изменились: %+v", doc["rules"])
	}

	proxies, _ := doc["proxies"].([]any)
	if len(proxies) != 3 {
		t.Fatalf("len(proxies) = %d, want 3 (1 исходный + 2 добавленных): %+v", len(proxies), proxies)
	}
	names := clashProxyNames(t, proxies)
	if names[0] != "old-node" {
		t.Errorf("исходный узел переименовался: %v", names)
	}
	if !containsStr(names, "brand-new") {
		t.Errorf("новый узел без коллизии не добавился как есть: %v", names)
	}
	renamed := findRenamed(names, "old-node")
	if renamed == "" {
		t.Errorf("узел с коллизией имени не переименован: %v", names)
	}

	// Имена новых узлов добавлены в ОБЕ существующие proxy-groups.
	groups, _ := doc["proxy-groups"].([]any)
	if len(groups) != 2 {
		t.Fatalf("len(proxy-groups) = %d, want 2", len(groups))
	}
	for _, g := range groups {
		gm := g.(map[string]any)
		groupProxies := clashProxyNames(t, gm["proxies"].([]any))
		if !containsStr(groupProxies, "brand-new") {
			t.Errorf("группа %v не получила новый узел brand-new: %v", gm["name"], groupProxies)
		}
		if findRenamed(groupProxies, "old-node") == "" {
			t.Errorf("группа %v не получила переименованный узел old-node: %v", gm["name"], groupProxies)
		}
	}
}

func TestAppendClash_EmptyBody_BuildsFromScratch(t *testing.T) {
	extra := []Entry{{Name: "n1", URI: "vless://uuid@host:443#n1"}}
	out, err := Append(nil, model.FormatClash, extra)
	if err != nil {
		t.Fatalf("Append(пустое тело): %v", err)
	}
	entries, err := Decode(out, model.FormatClash)
	if err != nil {
		t.Fatalf("Decode(результат): %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "n1" {
		t.Errorf("entries = %+v", entries)
	}
}

func TestMergeClash(t *testing.T) {
	out, err := Merge([]byte(clashPrimary), []byte(clashSecondary), model.FormatClash)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("результат Merge: невалидный yaml: %v\n%s", err, out)
	}

	// Верхнеуровневые поля primary (единственного источника структуры) на месте.
	if toInt(doc["port"]) != 7890 || toInt(doc["socks-port"]) != 7891 {
		t.Errorf("поля primary потерялись: %+v", doc)
	}
	// Верхнеуровневых полей secondary (их тут и не было: только proxies/proxy-groups) быть не должно.
	if _, ok := doc["rules"]; !ok {
		t.Error("rules из primary потерялись")
	}

	proxies, _ := doc["proxies"].([]any)
	if len(proxies) != 3 {
		t.Fatalf("len(proxies) = %d, want 3 (1 primary + 2 secondary): %+v", len(proxies), proxies)
	}
	names := clashProxyNames(t, proxies)
	if names[0] != "old-node" {
		t.Errorf("исходный узел primary переименовался: %v", names)
	}
	// secondary.old-node должен переименоваться (коллизия с primary.old-node).
	if findRenamed(names, "old-node") == "" {
		t.Errorf("узел secondary с коллизией имени не переименован: %v", names)
	}
	if !containsStr(names, "fresh-node") {
		t.Errorf("уникальный узел secondary потерялся: %v", names)
	}

	// В proxy-groups secondary (SomethingElse) нас не интересуют: обновляются
	// только существующие группы PRIMARY.
	groups, _ := doc["proxy-groups"].([]any)
	if len(groups) != 2 {
		t.Fatalf("len(proxy-groups) = %d, want 2 (группы secondary не копируются)", len(groups))
	}
	for _, g := range groups {
		gm := g.(map[string]any)
		groupProxies := clashProxyNames(t, gm["proxies"].([]any))
		if !containsStr(groupProxies, "fresh-node") {
			t.Errorf("группа %v не получила fresh-node: %v", gm["name"], groupProxies)
		}
	}
}

func TestMergeClash_EmptyPrimary_UsesSecondary(t *testing.T) {
	out, err := Merge(nil, []byte(clashSecondary), model.FormatClash)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("результат: невалидный yaml: %v\n%s", err, out)
	}
	proxies, _ := doc["proxies"].([]any)
	if len(proxies) != 2 {
		t.Errorf("len(proxies) = %d, want 2 (proxies secondary как есть)", len(proxies))
	}
}

func TestMergeClash_BothEmpty(t *testing.T) {
	out, err := Merge(nil, nil, model.FormatClash)
	if err != nil {
		t.Fatalf("Merge(пусто, пусто): %v", err)
	}
	if len(out) != 0 {
		t.Errorf("out = %q, want пусто", out)
	}
}

func TestAppendClash_NoExistingProxiesKey(t *testing.T) {
	// У документа в принципе нет proxies: только служебные поля. Append
	// обязан завести ключ proxies сам, а не споткнуться об его отсутствие.
	body := []byte("mode: rule\nlog-level: info\n")
	extra := []Entry{{Name: "n1", URI: "vless://uuid@host:443#n1"}}

	out, err := Append(body, model.FormatClash, extra)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("результат: невалидный yaml: %v\n%s", err, out)
	}
	if doc["mode"] != "rule" {
		t.Errorf("исходное поле mode потерялось: %+v", doc)
	}
	proxies, _ := doc["proxies"].([]any)
	if len(proxies) != 1 {
		t.Fatalf("len(proxies) = %d, want 1: %+v", len(proxies), proxies)
	}
}

func TestMergeClash_UnparsablePrimary_ReturnsOriginal(t *testing.T) {
	garbage := []byte("не yaml: [не закрытая скобка")
	out, err := Merge(garbage, []byte(clashSecondary), model.FormatClash)
	if err == nil {
		t.Fatal("ожидалась ошибка на нераспознанном primary")
	}
	if string(out) != string(garbage) {
		t.Errorf("primary изменился при ошибке разбора: было %q, стало %q", garbage, out)
	}
}

func TestAppendClash_WireGuardNode(t *testing.T) {
	extra := []Entry{{Name: "wg-lease", WG: sampleWGConfig}}
	out, err := Append([]byte(clashPrimary), model.FormatClash, extra)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("невалидный yaml: %v", err)
	}
	proxies, _ := doc["proxies"].([]any)
	var wgNode map[string]any
	for _, raw := range proxies {
		m := raw.(map[string]any)
		if m["name"] == "wg-lease" {
			wgNode = m
		}
	}
	if wgNode == nil {
		t.Fatalf("узел wg-lease не найден среди proxies: %+v", proxies)
	}
	if wgNode["type"] != "wireguard" {
		t.Errorf("type = %v, want wireguard", wgNode["type"])
	}

	// Он же должен корректно вернуться назад через Decode с заполненным WG.
	entries, err := Decode(out, model.FormatClash)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var wgEntry *Entry
	for i := range entries {
		if entries[i].Name == "wg-lease" {
			wgEntry = &entries[i]
		}
	}
	if wgEntry == nil {
		t.Fatal("wg-lease не найден после Decode")
	}
	if wgEntry.WG == "" || !strings.Contains(wgEntry.WG, "PrivateKey") {
		t.Errorf("WG не восстановился: %q", wgEntry.WG)
	}
}

// --- вспомогательное для тестов ---

func clashProxyNames(t *testing.T, items []any) []string {
	t.Helper()
	names := make([]string, 0, len(items))
	for _, raw := range items {
		switch v := raw.(type) {
		case map[string]any:
			names = append(names, v["name"].(string))
		case string:
			names = append(names, v)
		default:
			t.Fatalf("неожиданный элемент списка: %#v", raw)
		}
	}
	return names
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// findRenamed ищет в списке имя вида "base (N)": результат переименования
// при коллизии: и возвращает его, если нашёл.
func findRenamed(list []string, base string) string {
	for _, v := range list {
		if v != base && strings.HasPrefix(v, base+" (") {
			return v
		}
	}
	return ""
}
