package subfmt

import (
	"encoding/base64"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

const sampleClashYAML = `port: 7890
mode: rule
proxies:
  - name: node1
    type: vless
    server: 1.1.1.1
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - node1
rules:
  - MATCH,PROXY
`

const sampleSingboxJSON = `{
  "log": {"level": "info"},
  "outbounds": [
    {"type": "vless", "tag": "node1", "server": "1.1.1.1", "server_port": 443, "uuid": "11111111-1111-1111-1111-111111111111"}
  ]
}`

func TestDetect(t *testing.T) {
	plainLinks := "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#node1\n" +
		"trojan://pass@example.com:443?sni=example.com#node2"

	cases := []struct {
		name        string
		body        []byte
		contentType string
		want        model.Format
	}{
		{"пусто", []byte(""), "", model.FormatUnknown},
		{"только пробелы", []byte("   \n\t "), "", model.FormatUnknown},
		{"clash yaml", []byte(sampleClashYAML), "", model.FormatClash},
		{"clash yaml с content-type yaml", []byte(sampleClashYAML), "application/yaml", model.FormatClash},
		{"singbox json", []byte(sampleSingboxJSON), "", model.FormatSingBox},
		{"singbox json с content-type json", []byte(sampleSingboxJSON), "application/json", model.FormatSingBox},
		{"обычный json без outbounds: не singbox", []byte(`{"status":"ok","count":3}`), "", model.FormatJSON},
		{"html по содержимому", []byte("<!DOCTYPE html><html><body>hi</body></html>"), "", model.FormatHTML},
		{"html по content-type", []byte("не совсем html текст"), "text/html; charset=utf-8", model.FormatHTML},
		{"plain список ссылок", []byte(plainLinks), "text/plain", model.FormatPlain},
		{
			"base64 стандартный с выравниванием",
			[]byte(base64.StdEncoding.EncodeToString([]byte(plainLinks))),
			"text/plain", model.FormatBase64,
		},
		{
			"base64 url-safe без выравнивания",
			[]byte(base64.RawURLEncoding.EncodeToString([]byte(plainLinks))),
			"text/plain", model.FormatBase64,
		},
		{
			"base64 с переносами строк (mime-стиль по 76 символов)",
			[]byte(wrap76(base64.StdEncoding.EncodeToString([]byte(plainLinks)))),
			"", model.FormatBase64,
		},
		{"бинарный мусор: unknown", []byte{0xff, 0xfe, 0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}, "", model.FormatUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect(tc.body, tc.contentType)
			if got != tc.want {
				t.Errorf("Detect(...) = %q, want %q", got, tc.want)
			}
		})
	}
}

// wrap76 режет строку по 76 символов переносами: типичное mime-оформление
// base64, которое иногда встречается в реальных ответах.
func wrap76(s string) string {
	var out []byte
	for i := 0; i < len(s); i += 76 {
		end := i + 76
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end]...)
		out = append(out, '\n')
	}
	return string(out)
}
