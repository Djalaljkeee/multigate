package subfmt

import "testing"

// TestLinkToClashProxy_AllSchemes проверяет конвертацию каждой поддержанной
// схемы в clash-прокси и обратно: round-trip через сам clash-узел, а не
// только через промежуточную ссылку.
func TestLinkToClashProxy_AllSchemes(t *testing.T) {
	cases := []struct {
		name string
		link *proxyLink
	}{
		{"vless reality", &proxyLink{
			Scheme: "vless", Name: "n1", Server: "1.1.1.1", Port: 443,
			UUID: "uuid-1", Flow: "xtls-rprx-vision", Network: "tcp", Security: "reality",
			SNI: "example.com", Fingerprint: "chrome", PublicKey: "pbk", ShortID: "sid",
		}},
		{"vless ws tls", &proxyLink{
			Scheme: "vless", Name: "n2", Server: "1.1.1.1", Port: 443,
			UUID: "uuid-2", Network: "ws", Security: "tls", SNI: "example.com",
			Host: "cdn.example.com", Path: "/ws",
		}},
		{"vless grpc", &proxyLink{
			Scheme: "vless", Name: "n3", Server: "1.1.1.1", Port: 443,
			UUID: "uuid-3", Network: "grpc", Security: "tls", ServiceName: "svc",
		}},
		{"vmess", &proxyLink{
			Scheme: "vmess", Name: "n4", Server: "1.1.1.1", Port: 443,
			UUID: "uuid-4", Method: "auto", Network: "tcp", Security: "none",
		}},
		{"trojan", &proxyLink{
			Scheme: "trojan", Name: "n5", Server: "1.1.1.1", Port: 443,
			Password: "pass", Network: "tcp", Security: "tls", SNI: "example.com",
			AllowInsecure: true,
		}},
		{"ss", &proxyLink{
			Scheme: "ss", Name: "n6", Server: "1.1.1.1", Port: 8388,
			Method: "chacha20-ietf-poly1305", Password: "secret",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := linkToClashProxy(tc.link.Name, tc.link)
			if node["type"] != tc.link.Scheme {
				t.Fatalf("type = %v, want %v", node["type"], tc.link.Scheme)
			}
			back, err := clashProxyToLink(node)
			if err != nil {
				t.Fatalf("clashProxyToLink: %v", err)
			}
			assertLinkCoreFieldsEqual(t, tc.link, back)
		})
	}
}

// TestLinkToSingboxOutbound_AllSchemes: то же самое для sing-box.
func TestLinkToSingboxOutbound_AllSchemes(t *testing.T) {
	cases := []struct {
		name string
		link *proxyLink
	}{
		{"vless reality", &proxyLink{
			Scheme: "vless", Name: "n1", Server: "1.1.1.1", Port: 443,
			UUID: "uuid-1", Flow: "xtls-rprx-vision", Network: "tcp", Security: "reality",
			SNI: "example.com", Fingerprint: "chrome", PublicKey: "pbk", ShortID: "sid",
		}},
		{"vless ws tls insecure", &proxyLink{
			Scheme: "vless", Name: "n2", Server: "1.1.1.1", Port: 443,
			UUID: "uuid-2", Network: "ws", Security: "tls", SNI: "example.com",
			Host: "cdn.example.com", Path: "/ws", AllowInsecure: true,
		}},
		{"vless grpc", &proxyLink{
			Scheme: "vless", Name: "n3", Server: "1.1.1.1", Port: 443,
			UUID: "uuid-3", Network: "grpc", Security: "tls", ServiceName: "svc",
		}},
		{"vmess", &proxyLink{
			Scheme: "vmess", Name: "n4", Server: "1.1.1.1", Port: 443,
			UUID: "uuid-4", Method: "auto", Network: "tcp", Security: "none",
		}},
		{"trojan", &proxyLink{
			Scheme: "trojan", Name: "n5", Server: "1.1.1.1", Port: 443,
			Password: "pass", Network: "tcp", Security: "tls", SNI: "example.com",
		}},
		{"ss", &proxyLink{
			Scheme: "ss", Name: "n6", Server: "1.1.1.1", Port: 8388,
			Method: "chacha20-ietf-poly1305", Password: "secret",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := linkToSingboxOutbound(tc.link.Name, tc.link)
			back, err := singboxOutboundToLink(node)
			if err != nil {
				t.Fatalf("singboxOutboundToLink: %v", err)
			}
			assertLinkCoreFieldsEqual(t, tc.link, back)
		})
	}
}

// TestBuildVmessLink_RoundTrip проверяет сборку vmess-ссылки из proxyLink и
// разбор обратно: путь, которым идёт Decode(clash/singbox) для узлов vmess.
func TestBuildVmessLink_RoundTrip(t *testing.T) {
	p1 := &proxyLink{
		Scheme: "vmess", Name: "vmess-node", Server: "vm.example.com", Port: 443,
		UUID: "33333333-3333-3333-3333-333333333333", Method: "auto", Network: "ws",
		Host: "vm.example.com", Path: "/vm", Security: "tls", SNI: "vm.example.com",
	}
	uri, err := buildLinkURI(p1)
	if err != nil {
		t.Fatalf("buildLinkURI: %v", err)
	}
	p2, err := parseLink(uri)
	if err != nil {
		t.Fatalf("parseLink(%q): %v", uri, err)
	}
	if p2.Server != p1.Server || p2.Port != p1.Port || p2.UUID != p1.UUID ||
		p2.Network != p1.Network || p2.Host != p1.Host || p2.Path != p1.Path || p2.Security != p1.Security {
		t.Errorf("после round-trip vmess-ссылка разошлась:\nбыло:  %+v\nстало: %+v", *p1, *p2)
	}
}

// assertLinkCoreFieldsEqual сравнивает поля, которые обязаны пережить
// конвертацию в нативный узел (clash/singbox) и обратно. AllowInsecure для
// clash сознательно не проверяем у схем, где skip-cert-verify не пишется.
func assertLinkCoreFieldsEqual(t *testing.T, want, got *proxyLink) {
	t.Helper()
	if got.Scheme != want.Scheme {
		t.Errorf("Scheme = %q, want %q", got.Scheme, want.Scheme)
	}
	if got.Server != want.Server || got.Port != want.Port {
		t.Errorf("Server/Port = %s:%d, want %s:%d", got.Server, got.Port, want.Server, want.Port)
	}
	switch want.Scheme {
	case "vless":
		if got.UUID != want.UUID || got.Flow != want.Flow {
			t.Errorf("UUID/Flow = %q/%q, want %q/%q", got.UUID, got.Flow, want.UUID, want.Flow)
		}
	case "vmess":
		if got.UUID != want.UUID {
			t.Errorf("UUID = %q, want %q", got.UUID, want.UUID)
		}
	case "trojan":
		if got.Password != want.Password {
			t.Errorf("Password = %q, want %q", got.Password, want.Password)
		}
	case "ss":
		if got.Method != want.Method || got.Password != want.Password {
			t.Errorf("Method/Password = %q/%q, want %q/%q", got.Method, got.Password, want.Method, want.Password)
		}
		return
	}
	if got.Network != firstNonEmpty(want.Network, "tcp") {
		t.Errorf("Network = %q, want %q", got.Network, want.Network)
	}
	if want.Security == "tls" || want.Security == "reality" {
		if got.Security != want.Security {
			t.Errorf("Security = %q, want %q", got.Security, want.Security)
		}
		if got.SNI != want.SNI {
			t.Errorf("SNI = %q, want %q", got.SNI, want.SNI)
		}
	}
	if want.Security == "reality" {
		if got.PublicKey != want.PublicKey || got.ShortID != want.ShortID {
			t.Errorf("PublicKey/ShortID = %q/%q, want %q/%q", got.PublicKey, got.ShortID, want.PublicKey, want.ShortID)
		}
	}
	switch want.Network {
	case "ws":
		if got.Host != want.Host || got.Path != want.Path {
			t.Errorf("Host/Path = %q/%q, want %q/%q", got.Host, got.Path, want.Host, want.Path)
		}
	case "grpc":
		if got.ServiceName != want.ServiceName {
			t.Errorf("ServiceName = %q, want %q", got.ServiceName, want.ServiceName)
		}
	}
}
