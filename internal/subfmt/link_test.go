package subfmt

import (
	"reflect"
	"testing"
)

func TestParseLink(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want proxyLink
	}{
		{
			name: "vless reality vision",
			uri: "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&" +
				"security=reality&sni=www.example.com&fp=chrome&pbk=pubkey123&sid=ab12&type=tcp&" +
				"flow=xtls-rprx-vision#My%20Node",
			want: proxyLink{
				Scheme: "vless", Name: "My Node", Server: "example.com", Port: 443,
				UUID: "11111111-1111-1111-1111-111111111111", Encryption: "none",
				Network: "tcp", Security: "reality", SNI: "www.example.com",
				Fingerprint: "chrome", PublicKey: "pubkey123", ShortID: "ab12",
				Flow: "xtls-rprx-vision",
			},
		},
		{
			name: "vless ws tls",
			uri: "vless://22222222-2222-2222-2222-222222222222@1.2.3.4:8443?security=tls&" +
				"type=ws&host=cdn.example.com&path=%2Fws&sni=cdn.example.com#ws-node",
			want: proxyLink{
				Scheme: "vless", Name: "ws-node", Server: "1.2.3.4", Port: 8443,
				UUID: "22222222-2222-2222-2222-222222222222", Security: "tls",
				Network: "ws", Host: "cdn.example.com", Path: "/ws", SNI: "cdn.example.com",
			},
		},
		{
			name: "trojan",
			uri:  "trojan://secretpass@trojan.example.com:443?sni=trojan.example.com#trojan-node",
			want: proxyLink{
				Scheme: "trojan", Name: "trojan-node", Server: "trojan.example.com", Port: 443,
				Password: "secretpass", Network: "tcp", Security: "none", SNI: "trojan.example.com",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLink(tc.uri)
			if err != nil {
				t.Fatalf("parseLink(%q) error: %v", tc.uri, err)
			}
			if *got != tc.want {
				t.Errorf("parseLink(%q) =\n%+v\nwant\n%+v", tc.uri, *got, tc.want)
			}
		})
	}
}

func TestParseVmessLink(t *testing.T) {
	// {"v":"2","ps":"vmess-node","add":"vm.example.com","port":"443","id":"33333333-3333-3333-3333-333333333333","aid":"0","scy":"auto","net":"ws","type":"none","host":"vm.example.com","path":"/vm","tls":"tls","sni":"vm.example.com"}
	uri := "vmess://eyJ2IjoiMiIsInBzIjoidm1lc3Mtbm9kZSIsImFkZCI6InZtLmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMzMzMzMzMzMtMzMzMy0zMzMzLTMzMzMtMzMzMzMzMzMzMzMzIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIiwiaG9zdCI6InZtLmV4YW1wbGUuY29tIiwicGF0aCI6Ii92bSIsInRscyI6InRscyIsInNuaSI6InZtLmV4YW1wbGUuY29tIn0="

	got, err := parseVmessLink(uri)
	if err != nil {
		t.Fatalf("parseVmessLink error: %v", err)
	}
	want := &proxyLink{
		Scheme: "vmess", Name: "vmess-node", Server: "vm.example.com", Port: 443,
		UUID: "33333333-3333-3333-3333-333333333333", Method: "auto", Network: "ws",
		Host: "vm.example.com", Path: "/vm", HeaderType: "none", SNI: "vm.example.com",
		Security: "tls",
	}
	if *got != *want {
		t.Errorf("parseVmessLink =\n%+v\nwant\n%+v", *got, *want)
	}
}

func TestParseSSLink_SIP002(t *testing.T) {
	// method=chacha20-ietf-poly1305, password=secret -> base64url(method:password)
	// без выравнивания: Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ
	uri := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@ss.example.com:8388#ss-node"

	got, err := parseSSLink(uri)
	if err != nil {
		t.Fatalf("parseSSLink error: %v", err)
	}
	if got.Method != "chacha20-ietf-poly1305" || got.Password != "secret" ||
		got.Server != "ss.example.com" || got.Port != 8388 || got.Name != "ss-node" {
		t.Errorf("parseSSLink = %+v", *got)
	}
}

// TestLinkRoundTrip проверяет parse -> build -> parse: структура должна
// восстановиться один в один, даже если конкретная строка ссылки на выходе
// не побайтово совпадает с исходной (другой порядок query-параметров: это
// нормально, реальные клиенты по порядку их не различают).
func TestLinkRoundTrip(t *testing.T) {
	uris := []string{
		"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&sni=a.com&fp=chrome&pbk=pk&sid=sid&flow=xtls-rprx-vision&type=tcp#node1",
		"vless://22222222-2222-2222-2222-222222222222@1.2.3.4:8443?security=tls&type=ws&host=cdn.com&path=%2Fws#node2",
		"trojan://pass123@trojan.example.com:443?sni=trojan.example.com&type=grpc&serviceName=grpcsvc#node3",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@ss.example.com:8388#node4",
	}
	for _, uri := range uris {
		t.Run(uri, func(t *testing.T) {
			p1, err := parseLink(uri)
			if err != nil {
				t.Fatalf("parseLink: %v", err)
			}
			rebuilt, err := buildLinkURI(p1)
			if err != nil {
				t.Fatalf("buildLinkURI: %v", err)
			}
			p2, err := parseLink(rebuilt)
			if err != nil {
				t.Fatalf("parseLink(rebuilt=%q): %v", rebuilt, err)
			}
			if !reflect.DeepEqual(p1, p2) {
				t.Errorf("после пересборки структура изменилась:\nбыло:  %+v\nстало: %+v\nпересобранная ссылка: %s", *p1, *p2, rebuilt)
			}
		})
	}
}

func TestParseSSLink_Legacy(t *testing.T) {
	// Легаси-форма: base64("метод:пароль@host:port") целиком, без userinfo в URL.
	// base64("chacha20-ietf-poly1305:secret@ss.example.com:8388")
	uri := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXRAc3MuZXhhbXBsZS5jb206ODM4OA==#legacy-node"

	got, err := parseSSLink(uri)
	if err != nil {
		t.Fatalf("parseSSLink: %v", err)
	}
	if got.Method != "chacha20-ietf-poly1305" || got.Password != "secret" ||
		got.Server != "ss.example.com" || got.Port != 8388 || got.Name != "legacy-node" {
		t.Errorf("parseSSLink(легаси) = %+v", *got)
	}
}

func TestParseSSLink_Errors(t *testing.T) {
	cases := []string{
		"ss://",
		"ss://не-base64-и-нет-userinfo",
		"ss://" + "aGVsbG8=", // валидный base64, но без ":" внутри: не метод:пароль
	}
	for _, c := range cases {
		if _, err := parseSSLink(c); err == nil {
			t.Errorf("parseSSLink(%q) должен был вернуть ошибку", c)
		}
	}
}

func TestParseLink_UnknownScheme(t *testing.T) {
	if _, err := parseLink("hysteria2://pass@host:443#node"); err == nil {
		t.Error("ожидалась ошибка для неподдержанной схемы, получили nil")
	}
}

func TestParseLink_Garbage(t *testing.T) {
	cases := []string{"", "not a uri at all", "vless://", "http://no-userinfo-vless-would-still-parse-but-not-vless-scheme.com"}
	for _, c := range cases {
		if _, err := parseLink(c); err == nil {
			t.Errorf("parseLink(%q) должен был вернуть ошибку", c)
		}
	}
}
