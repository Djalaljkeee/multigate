package subfmt

import "fmt"

// linkToClashProxy собирает clash-прокси (map, который потом кодируется в
// yaml.Node через node.Encode) из общей proxyLink. Схема полей взята из
// собственной документации mihomo для соответствующих типов прокси.
func linkToClashProxy(name string, p *proxyLink) map[string]any {
	m := map[string]any{
		"name":   name,
		"type":   p.Scheme,
		"server": p.Server,
		"port":   p.Port,
		"udp":    true,
	}

	switch p.Scheme {
	case "vless":
		m["uuid"] = p.UUID
		if p.Flow != "" {
			m["flow"] = p.Flow
		}
	case "vmess":
		m["uuid"] = p.UUID
		m["alterId"] = 0
		m["cipher"] = firstNonEmpty(p.Method, "auto")
	case "trojan":
		m["password"] = p.Password
	case "ss":
		m["cipher"] = p.Method
		m["password"] = p.Password
		return m // у shadowsocks нет tls/транспортных опций ниже
	}

	if p.Network != "" && p.Network != "tcp" {
		m["network"] = p.Network
	}
	if p.Security == "tls" || p.Security == "reality" {
		m["tls"] = true
		if p.SNI != "" {
			m["servername"] = p.SNI
		}
		if p.Fingerprint != "" {
			m["client-fingerprint"] = p.Fingerprint
		}
		if p.AllowInsecure {
			m["skip-cert-verify"] = true
		}
	}
	if p.Security == "reality" {
		reality := map[string]any{}
		if p.PublicKey != "" {
			reality["public-key"] = p.PublicKey
		}
		if p.ShortID != "" {
			reality["short-id"] = p.ShortID
		}
		if len(reality) > 0 {
			m["reality-opts"] = reality
		}
	}

	switch p.Network {
	case "ws":
		opts := map[string]any{}
		if p.Path != "" {
			opts["path"] = p.Path
		}
		if p.Host != "" {
			opts["headers"] = map[string]any{"Host": p.Host}
		}
		if len(opts) > 0 {
			m["ws-opts"] = opts
		}
	case "grpc":
		if p.ServiceName != "" {
			m["grpc-opts"] = map[string]any{"grpc-service-name": p.ServiceName}
		}
	case "h2":
		opts := map[string]any{}
		if p.Path != "" {
			opts["path"] = p.Path
		}
		if p.Host != "" {
			opts["host"] = []string{p.Host}
		}
		if len(opts) > 0 {
			m["h2-opts"] = opts
		}
	}
	return m
}

// clashProxyToLink: обратное к linkToClashProxy, для Decode.
func clashProxyToLink(m map[string]any) (*proxyLink, error) {
	typ, _ := m["type"].(string)
	switch typ {
	case "vless", "vmess", "trojan", "ss":
	default:
		return nil, fmt.Errorf("subfmt: тип clash-прокси %q пока не поддержан для конвертации в ссылку", typ)
	}

	p := &proxyLink{Scheme: typ}
	p.Name, _ = m["name"].(string)
	p.Server, _ = m["server"].(string)
	p.Port = toInt(m["port"])

	switch typ {
	case "vless":
		p.UUID, _ = m["uuid"].(string)
		p.Flow, _ = m["flow"].(string)
	case "vmess":
		p.UUID, _ = m["uuid"].(string)
		p.Method, _ = m["cipher"].(string)
	case "trojan":
		p.Password, _ = m["password"].(string)
	case "ss":
		p.Method, _ = m["cipher"].(string)
		p.Password, _ = m["password"].(string)
		return p, nil
	}

	p.Network = firstNonEmpty(stringField(m, "network"), "tcp")
	p.Security = "none"
	if tls, _ := m["tls"].(bool); tls {
		p.Security = "tls"
	}
	p.SNI = stringField(m, "servername")
	p.Fingerprint = stringField(m, "client-fingerprint")
	if skip, _ := m["skip-cert-verify"].(bool); skip {
		p.AllowInsecure = true
	}
	if ro, ok := m["reality-opts"].(map[string]any); ok {
		p.Security = "reality"
		p.PublicKey = stringField(ro, "public-key")
		p.ShortID = stringField(ro, "short-id")
	}

	switch p.Network {
	case "ws":
		if wo, ok := m["ws-opts"].(map[string]any); ok {
			p.Path = stringField(wo, "path")
			if h, ok := wo["headers"].(map[string]any); ok {
				p.Host = stringField(h, "Host")
			}
		}
	case "grpc":
		if grpcOpts, ok := m["grpc-opts"].(map[string]any); ok {
			p.ServiceName = stringField(grpcOpts, "grpc-service-name")
		}
	case "h2":
		if ho, ok := m["h2-opts"].(map[string]any); ok {
			p.Path = stringField(ho, "path")
		}
	}
	return p, nil
}

// stringField читает строковое поле из мапы, не паникуя, если его нет или
// оно другого типа.
func stringField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}
