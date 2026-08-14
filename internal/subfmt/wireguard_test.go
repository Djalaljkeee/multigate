package subfmt

import (
	"reflect"
	"testing"
)

const sampleWGConfig = `[Interface]
PrivateKey = cHJpdmF0ZWtleWJhc2U2NGZha2UxMjM0NTY3ODkwMTI=
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1420
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 10
S2 = 20
H1 = 111111
H2 = 222222
H3 = 333333
H4 = 444444

[Peer]
PublicKey = cHVibGlja2V5YmFzZTY0ZmFrZTEyMzQ1Njc4OTAxMg==
PresharedKey = cHNrYmFzZTY0ZmFrZQ==
Endpoint = wg.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
`

func TestParseWireGuardINI(t *testing.T) {
	cfg, err := parseWireGuardINI(sampleWGConfig)
	if err != nil {
		t.Fatalf("parseWireGuardINI: %v", err)
	}
	if cfg.PrivateKey != "cHJpdmF0ZWtleWJhc2U2NGZha2UxMjM0NTY3ODkwMTI=" {
		t.Errorf("PrivateKey = %q", cfg.PrivateKey)
	}
	if len(cfg.Address) != 2 || cfg.Address[0] != "10.0.0.2/32" || cfg.Address[1] != "fd00::2/128" {
		t.Errorf("Address = %v", cfg.Address)
	}
	if len(cfg.DNS) != 2 {
		t.Errorf("DNS = %v", cfg.DNS)
	}
	if cfg.MTU != 1420 {
		t.Errorf("MTU = %d", cfg.MTU)
	}
	if cfg.Jc != 5 || cfg.Jmin != 50 || cfg.Jmax != 1000 || cfg.S1 != 10 || cfg.S2 != 20 ||
		cfg.H1 != 111111 || cfg.H2 != 222222 || cfg.H3 != 333333 || cfg.H4 != 444444 {
		t.Errorf("amnezia-параметры разобраны неверно: %+v", cfg)
	}
	if cfg.PeerPublicKey != "cHVibGlja2V5YmFzZTY0ZmFrZTEyMzQ1Njc4OTAxMg==" {
		t.Errorf("PeerPublicKey = %q", cfg.PeerPublicKey)
	}
	if cfg.PresharedKey != "cHNrYmFzZTY0ZmFrZQ==" {
		t.Errorf("PresharedKey = %q", cfg.PresharedKey)
	}
	if cfg.Endpoint != "wg.example.com:51820" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
	if len(cfg.AllowedIPs) != 2 {
		t.Errorf("AllowedIPs = %v", cfg.AllowedIPs)
	}
}

func TestParseWireGuardINI_Garbage(t *testing.T) {
	cases := []string{"", "не конфиг вообще", "[Interface]\nAddress = 10.0.0.2/32\n"}
	for _, c := range cases {
		if _, err := parseWireGuardINI(c); err == nil {
			t.Errorf("parseWireGuardINI(%q) должен был вернуть ошибку (нет ключей)", c)
		}
	}
}

func TestWireGuardINIRoundTrip(t *testing.T) {
	cfg1, err := parseWireGuardINI(sampleWGConfig)
	if err != nil {
		t.Fatalf("parseWireGuardINI: %v", err)
	}
	rebuilt := buildWireGuardINI(cfg1)
	cfg2, err := parseWireGuardINI(rebuilt)
	if err != nil {
		t.Fatalf("parseWireGuardINI(rebuilt): %v\n--- rebuilt ---\n%s", err, rebuilt)
	}
	if !reflect.DeepEqual(cfg1, cfg2) {
		t.Errorf("после пересборки конфиг изменился:\nбыло:  %+v\nстало: %+v", *cfg1, *cfg2)
	}
}

func TestWGClashProxyRoundTrip(t *testing.T) {
	cfg1, err := parseWireGuardINI(sampleWGConfig)
	if err != nil {
		t.Fatalf("parseWireGuardINI: %v", err)
	}
	node := wgToClashProxy("wg-node", cfg1)
	if node["type"] != "wireguard" || node["name"] != "wg-node" {
		t.Fatalf("node = %+v", node)
	}
	if node["server"] != "wg.example.com" || node["port"] != 51820 {
		t.Errorf("server/port = %v/%v", node["server"], node["port"])
	}
	amn, ok := node["amnezia-wg-option"].(map[string]any)
	if !ok {
		t.Fatal("amnezia-wg-option отсутствует, хотя Jc/Jmin/... заданы")
	}
	if amn["jc"] != 5 {
		t.Errorf("amnezia jc = %v", amn["jc"])
	}

	cfg2, err := clashProxyToWG(node)
	if err != nil {
		t.Fatalf("clashProxyToWG: %v", err)
	}
	if cfg2.Endpoint != cfg1.Endpoint || cfg2.PrivateKey != cfg1.PrivateKey || cfg2.PeerPublicKey != cfg1.PeerPublicKey {
		t.Errorf("после round-trip через clash-прокси конфиг разошёлся:\nбыло:  %+v\nстало: %+v", *cfg1, *cfg2)
	}
	if cfg2.Jc != cfg1.Jc || cfg2.H4 != cfg1.H4 {
		t.Errorf("amnezia-параметры не восстановились: %+v", *cfg2)
	}
}

func TestWGSingboxOutboundRoundTrip(t *testing.T) {
	cfg1, err := parseWireGuardINI(sampleWGConfig)
	if err != nil {
		t.Fatalf("parseWireGuardINI: %v", err)
	}
	node := wgToSingboxOutbound("wg-node", cfg1)
	if node["type"] != "wireguard" || node["tag"] != "wg-node" {
		t.Fatalf("node = %+v", node)
	}
	if node["server"] != "wg.example.com" || node["server_port"] != 51820 {
		t.Errorf("server/server_port = %v/%v", node["server"], node["server_port"])
	}

	cfg2, err := singboxOutboundToWG(node)
	if err != nil {
		t.Fatalf("singboxOutboundToWG: %v", err)
	}
	if cfg2.Endpoint != cfg1.Endpoint || cfg2.PrivateKey != cfg1.PrivateKey || cfg2.PeerPublicKey != cfg1.PeerPublicKey {
		t.Errorf("после round-trip через singbox outbound конфиг разошёлся:\nбыло:  %+v\nстало: %+v", *cfg1, *cfg2)
	}
}
