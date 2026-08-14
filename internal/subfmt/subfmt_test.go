package subfmt

import (
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

func TestDecode_UnsupportedFormat(t *testing.T) {
	if _, err := Decode([]byte("что угодно"), model.FormatHTML); err == nil {
		t.Error("ожидалась ошибка для неподдержанного формата в Decode")
	}
}

func TestEncode_UnsupportedFormat(t *testing.T) {
	if _, err := Encode(nil, model.FormatJSON); err == nil {
		t.Error("ожидалась ошибка для неподдержанного формата в Encode")
	}
}

// TestEncode_AllFormats: сборка "с нуля" через единую точку входа Encode,
// в отличие от прочих тестов, которые в основном идут через Append(nil, ...).
func TestEncode_AllFormats(t *testing.T) {
	entries := []Entry{
		{Name: "n1", URI: "vless://11111111-1111-1111-1111-111111111111@host1:443?security=tls#n1"},
		{Name: "n2", URI: "trojan://pass@host2:443#n2"},
	}
	for _, f := range []model.Format{model.FormatBase64, model.FormatPlain, model.FormatClash, model.FormatSingBox} {
		t.Run(string(f), func(t *testing.T) {
			body, err := Encode(entries, f)
			if err != nil {
				t.Fatalf("Encode(%s): %v", f, err)
			}
			if len(body) == 0 {
				t.Fatalf("Encode(%s) вернул пустое тело", f)
			}
			if got := Detect(body, ""); got != f {
				t.Errorf("Detect(Encode(%s)) = %q, себя не узнал", f, got)
			}
			back, err := Decode(body, f)
			if err != nil {
				t.Fatalf("Decode(Encode(%s)): %v", f, err)
			}
			// У singbox своя добавленная группа-селектор "PROXY" тоже живёт
			// в outbounds, поэтому там узлов на один больше: сравниваем не
			// точное число, а что оба исходных имени нашлись среди decoded.
			gotNames := namesOf(back)
			for _, e := range entries {
				if !containsStr(gotNames, e.Name) {
					t.Errorf("Decode(Encode(%s)) потерял узел %q: %v", f, e.Name, gotNames)
				}
			}
		})
	}
}

func TestAppend_UnsupportedFormat_ReturnsBodyAndError(t *testing.T) {
	body := []byte("исходное тело")
	out, err := Append(body, model.FormatUnknown, []Entry{{Name: "x", URI: "vless://u@h:1#x"}})
	if err == nil {
		t.Error("ожидалась ошибка для неподдержанного формата в Append")
	}
	if string(out) != string(body) {
		t.Errorf("тело изменилось: было %q, стало %q", body, out)
	}
}

func TestMerge_UnsupportedFormat_ReturnsPrimaryAndError(t *testing.T) {
	primary := []byte("исходное тело")
	out, err := Merge(primary, []byte("что-то ещё"), model.FormatUnknown)
	if err == nil {
		t.Error("ожидалась ошибка для неподдержанного формата в Merge")
	}
	if string(out) != string(primary) {
		t.Errorf("primary изменился: было %q, стало %q", primary, out)
	}
}
