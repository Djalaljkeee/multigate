package subfmt

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

func TestDecodePlain(t *testing.T) {
	body := "vless://uuid1@host1:443?security=tls#node-one\n\n" +
		"  \n" + // пустая строка с пробелами: должна быть пропущена
		"trojan://pass@host2:443#node-two\r\n"

	entries, err := Decode([]byte(body), model.FormatPlain)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2: %+v", len(entries), entries)
	}
	if entries[0].Name != "node-one" || entries[1].Name != "node-two" {
		t.Errorf("имена не разобрались: %+v", entries)
	}
}

func TestBase64RoundTrip(t *testing.T) {
	entries := []Entry{
		{Name: "n1", URI: "vless://uuid1@host1:443?security=tls#old"},
		{Name: "n2", URI: "trojan://pass@host2:443#old2"},
	}
	body, err := Encode(entries, model.FormatBase64)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Тело обязано быть валидным стандартным base64: основной формат.
	if _, err := base64.StdEncoding.DecodeString(string(body)); err != nil {
		t.Errorf("Encode(base64) выдал невалидный стандартный base64: %v", err)
	}

	back, err := Decode(body, model.FormatBase64)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(back) != 2 || back[0].Name != "n1" || back[1].Name != "n2" {
		t.Errorf("после round-trip получили %+v", back)
	}
}

func TestDecodeBase64_AllAlphabets(t *testing.T) {
	text := "vless://uuid@host:443#node"
	variants := map[string]string{
		"std":         base64.StdEncoding.EncodeToString([]byte(text)),
		"raw-std":     base64.RawStdEncoding.EncodeToString([]byte(text)),
		"url":         base64.URLEncoding.EncodeToString([]byte(text)),
		"raw-url":     base64.RawURLEncoding.EncodeToString([]byte(text)),
		"с пробелами": " " + base64.StdEncoding.EncodeToString([]byte(text)) + "\n",
	}
	for name, encoded := range variants {
		t.Run(name, func(t *testing.T) {
			entries, err := Decode([]byte(encoded), model.FormatBase64)
			if err != nil {
				t.Fatalf("Decode(%s): %v", name, err)
			}
			if len(entries) != 1 || entries[0].Name != "node" {
				t.Errorf("Decode(%s) = %+v", name, entries)
			}
		})
	}
}

func TestAppend_Base64_DedupesNameCollision(t *testing.T) {
	primary := []Entry{{Name: "node", URI: "vless://aaaa@host1:443#node"}}
	body, err := Encode(primary, model.FormatBase64)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	extra := []Entry{{Name: "node", URI: "vless://bbbb@host2:443#node"}}
	out, err := Append(body, model.FormatBase64, extra)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	entries, err := Decode(out, model.FormatBase64)
	if err != nil {
		t.Fatalf("Decode(out): %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2: %+v", len(entries), entries)
	}
	if entries[0].Name != "node" {
		t.Errorf("первый узел переименовался: %q", entries[0].Name)
	}
	if entries[1].Name == "node" {
		t.Error("второй узел не переименован при коллизии имени")
	}
	if !strings.Contains(entries[1].Name, "node") {
		t.Errorf("переименованное имя потеряло связь с оригиналом: %q", entries[1].Name)
	}
}

func TestAppend_UnparsableBody_ReturnsOriginalAndError(t *testing.T) {
	// Тело заявлено как base64, но реально не декодируется ни одним алфавитом
	// (двоеточие вне base64-алфавита).
	garbage := []byte("это точно: не base64 вообще!!!")
	extra := []Entry{{Name: "n", URI: "vless://uuid@host:443#n"}}

	out, err := Append(garbage, model.FormatBase64, extra)
	if err == nil {
		t.Fatal("ожидалась ошибка на нераспознанном теле")
	}
	if string(out) != string(garbage) {
		t.Errorf("тело изменилось при ошибке разбора: было %q, стало %q", garbage, out)
	}
}

func TestAppend_EmptyExtra_ReturnsBodyUnchanged(t *testing.T) {
	body := []byte("любое тело, даже мусорное: не важно")
	out, err := Append(body, model.FormatBase64, nil)
	if err != nil {
		t.Fatalf("Append с пустым extra не должен ошибаться: %v", err)
	}
	if string(out) != string(body) {
		t.Errorf("тело изменилось без единого extra: было %q, стало %q", body, out)
	}
}

func TestMerge_PlainDedup(t *testing.T) {
	primary := []byte("vless://aaaa@host1:443#shared\ntrojan://bbbb@host2:443#unique1")
	secondary := []byte("vless://cccc@host3:443#shared\ntrojan://dddd@host4:443#unique2")

	out, err := Merge(primary, secondary, model.FormatPlain)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	entries, err := Decode(out, model.FormatPlain)
	if err != nil {
		t.Fatalf("Decode(merged): %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("len(entries) = %d, want 4: %+v", len(entries), entries)
	}
	names := namesOf(entries)
	seen := map[string]int{}
	for _, n := range names {
		seen[n]++
	}
	if seen["shared"] != 1 {
		t.Errorf("исходный shared должен остаться один: %v", names)
	}
	foundRenamed := false
	for _, n := range names {
		if n != "shared" && strings.HasPrefix(n, "shared") {
			foundRenamed = true
		}
	}
	if !foundRenamed {
		t.Errorf("не нашли переименованный дубликат shared: %v", names)
	}
}

func TestDetect_And_Decode_Consistent(t *testing.T) {
	// Sanity: то, что Detect назвал base64/plain, Decode тем же форматом
	// обязан разобрать без ошибки: иначе связка форматов в проекте не сходится.
	body := []byte(base64.StdEncoding.EncodeToString([]byte("vless://uuid@host:443#a\ntrojan://p@host2:443#b")))
	f := Detect(body, "")
	if f != model.FormatBase64 {
		t.Fatalf("Detect = %q, want base64", f)
	}
	if _, err := Decode(body, f); err != nil {
		t.Fatalf("Decode после Detect: %v", err)
	}
}
