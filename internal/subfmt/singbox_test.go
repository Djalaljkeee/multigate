package subfmt

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

const singboxPrimary = `{
  "log": {"level": "info"},
  "dns": {"servers": [{"address": "1.1.1.1"}]},
  "outbounds": [
    {
      "type": "vless",
      "tag": "old-node",
      "server": "1.1.1.1",
      "server_port": 443,
      "uuid": "11111111-1111-1111-1111-111111111111",
      "tls": {"enabled": true, "server_name": "example.com"}
    },
    {"type": "selector", "tag": "PROXY", "outbounds": ["old-node"]},
    {"type": "urltest", "tag": "Auto", "outbounds": ["old-node"]}
  ]
}`

const singboxSecondary = `{
  "outbounds": [
    {"type": "trojan", "tag": "old-node", "server": "2.2.2.2", "server_port": 8443, "password": "secondarypass"},
    {"type": "vless", "tag": "fresh-node", "server": "3.3.3.3", "server_port": 443, "uuid": "22222222-2222-2222-2222-222222222222"},
    {"type": "selector", "tag": "SomethingElse", "outbounds": ["old-node"]}
  ]
}`

func TestDecodeSingbox(t *testing.T) {
	entries, err := Decode([]byte(singboxPrimary), model.FormatSingBox)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// В outbounds три объекта: vless-узел + селектор + urltest. Селектор и
	// urltest: не прокси-узлы (у них нет server/uuid), поэтому попадают в
	// результат с именем, но пустыми URI/WG.
	if len(entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3: %+v", len(entries), entries)
	}
	node := entries[0]
	if node.Name != "old-node" {
		t.Errorf("Name = %q", node.Name)
	}
	if !strings.HasPrefix(node.URI, "vless://11111111-1111-1111-1111-111111111111@1.1.1.1:443?") {
		t.Errorf("URI = %q", node.URI)
	}
	if !strings.Contains(node.URI, "sni=example.com") {
		t.Errorf("URI не содержит sni: %q", node.URI)
	}
	if entries[1].Name != "PROXY" || entries[1].URI != "" {
		t.Errorf("селектор должен остаться без URI: %+v", entries[1])
	}
}

func TestAppendSingbox_PreservesRestOfDocument(t *testing.T) {
	extra := []Entry{
		{Name: "old-node", URI: "vless://33333333-3333-3333-3333-333333333333@4.4.4.4:443?security=tls#old-node"},
		{Name: "brand-new", URI: "trojan://passpass@5.5.5.5:443#brand-new"},
	}
	out, err := Append([]byte(singboxPrimary), model.FormatSingBox, extra)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("результат Append: невалидный json: %v\n%s", err, out)
	}
	if _, ok := doc["log"]; !ok {
		t.Error("поле log потерялось")
	}
	if _, ok := doc["dns"]; !ok {
		t.Error("поле dns потерялось")
	}

	outbounds, _ := doc["outbounds"].([]any)
	tags := singboxOutboundTags(t, outbounds)
	// 1 исходный узел + 2 группы (selector/urltest) + 2 добавленных узла.
	if len(tags) != 5 {
		t.Fatalf("len(outbounds) = %d, want 5: %v", len(tags), tags)
	}
	if !containsStr(tags, "brand-new") {
		t.Errorf("новый узел не добавился: %v", tags)
	}
	if findRenamed(tags, "old-node") == "" {
		t.Errorf("узел с коллизией имени не переименован: %v", tags)
	}

	for _, raw := range outbounds {
		m := raw.(map[string]any)
		typ, _ := m["type"].(string)
		if typ != "selector" && typ != "urltest" {
			continue
		}
		groupOut := stringSliceOf(t, m["outbounds"])
		if !containsStr(groupOut, "brand-new") {
			t.Errorf("группа %v (%s) не получила brand-new: %v", m["tag"], typ, groupOut)
		}
		if findRenamed(groupOut, "old-node") == "" {
			t.Errorf("группа %v (%s) не получила переименованный old-node: %v", m["tag"], typ, groupOut)
		}
	}
}

func TestAppendSingbox_EmptyBody_BuildsFromScratch(t *testing.T) {
	extra := []Entry{{Name: "n1", URI: "vless://uuid@host:443#n1"}}
	out, err := Append(nil, model.FormatSingBox, extra)
	if err != nil {
		t.Fatalf("Append(пустое тело): %v", err)
	}
	entries, err := Decode(out, model.FormatSingBox)
	if err != nil {
		t.Fatalf("Decode(результат): %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name == "n1" {
			found = true
		}
	}
	if !found {
		t.Errorf("entries = %+v", entries)
	}
}

func TestMergeSingbox_EmptyPrimary_UsesSecondary(t *testing.T) {
	out, err := Merge(nil, []byte(singboxSecondary), model.FormatSingBox)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("результат: невалидный json: %v\n%s", err, out)
	}
	outbounds, _ := doc["outbounds"].([]any)
	if len(outbounds) != 3 {
		t.Errorf("len(outbounds) = %d, want 3 (outbounds secondary как есть)", len(outbounds))
	}
}

func TestMergeSingbox_BothEmpty(t *testing.T) {
	out, err := Merge(nil, nil, model.FormatSingBox)
	if err != nil {
		t.Fatalf("Merge(пусто, пусто): %v", err)
	}
	if len(out) != 0 {
		t.Errorf("out = %q, want пусто", out)
	}
}

func TestMergeSingbox(t *testing.T) {
	out, err := Merge([]byte(singboxPrimary), []byte(singboxSecondary), model.FormatSingBox)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("результат Merge: невалидный json: %v\n%s", err, out)
	}
	if _, ok := doc["log"]; !ok {
		t.Error("поле log из primary потерялось")
	}

	outbounds, _ := doc["outbounds"].([]any)
	tags := singboxOutboundTags(t, outbounds)
	// primary: old-node + PROXY + Auto (3) ; secondary: old-node(renamed) + fresh-node (2, группа SomethingElse не копируется)
	if len(tags) != 5 {
		t.Fatalf("len(outbounds) = %d, want 5: %v", len(tags), tags)
	}
	if !containsStr(tags, "fresh-node") {
		t.Errorf("уникальный узел secondary потерялся: %v", tags)
	}
	if findRenamed(tags, "old-node") == "" {
		t.Errorf("узел secondary с коллизией имени не переименован: %v", tags)
	}
	if containsStr(tags, "SomethingElse") {
		t.Errorf("группа secondary не должна была скопироваться: %v", tags)
	}

	for _, raw := range outbounds {
		m := raw.(map[string]any)
		typ, _ := m["type"].(string)
		if typ != "selector" && typ != "urltest" {
			continue
		}
		groupOut := stringSliceOf(t, m["outbounds"])
		if !containsStr(groupOut, "fresh-node") {
			t.Errorf("группа %v (%s) не получила fresh-node: %v", m["tag"], typ, groupOut)
		}
	}
}

func TestMergeSingbox_UnparsablePrimary_ReturnsOriginal(t *testing.T) {
	garbage := []byte("{не json")
	out, err := Merge(garbage, []byte(singboxSecondary), model.FormatSingBox)
	if err == nil {
		t.Fatal("ожидалась ошибка на нераспознанном primary")
	}
	if string(out) != string(garbage) {
		t.Errorf("primary изменился при ошибке разбора: было %q, стало %q", garbage, out)
	}
}

func TestAppendSingbox_WireGuardNode(t *testing.T) {
	extra := []Entry{{Name: "wg-lease", WG: sampleWGConfig}}
	out, err := Append([]byte(singboxPrimary), model.FormatSingBox, extra)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	entries, err := Decode(out, model.FormatSingBox)
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
		t.Fatalf("wg-lease не найден: %+v", entries)
	}
	if wgEntry.WG == "" || !strings.Contains(wgEntry.WG, "PrivateKey") {
		t.Errorf("WG не восстановился: %q", wgEntry.WG)
	}
}

func singboxOutboundTags(t *testing.T, outbounds []any) []string {
	t.Helper()
	tags := make([]string, 0, len(outbounds))
	for _, raw := range outbounds {
		m, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("outbound не объект: %#v", raw)
		}
		tag, _ := m["tag"].(string)
		tags = append(tags, tag)
	}
	return tags
}

func stringSliceOf(t *testing.T, v any) []string {
	t.Helper()
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("не список: %#v", v)
	}
	out := make([]string, 0, len(arr))
	for _, raw := range arr {
		s, ok := raw.(string)
		if !ok {
			t.Fatalf("элемент не строка: %#v", raw)
		}
		out = append(out, s)
	}
	return out
}
