package subfmt

import "fmt"

// linkToSingboxOutbound собирает outbound sing-box из общей proxyLink.
// Схема полей взята из официальной документации sing-box для
// соответствующих типов outbound (значимо версионно: пример собран под
// линейку 1.9-1.11, где wireguard ещё outbound, а не endpoint, при
// обновлении sing-box стоит перепроверить).
func linkToSingboxOutbound(tag string, p *proxyLink) map[string]any {
	m := map[string]any{
		"type":        p.Scheme,
		"tag":         tag,
		"server":      p.Server,
		"server_port": p.Port,
	}

	switch p.Scheme {
	case "vless":
		m["uuid"] = p.UUID
		if p.Flow != "" {
			m["flow"] = p.Flow
		}
	case "vmess":
		m["uuid"] = p.UUID
		m["security"] = firstNonEmpty(p.Method, "auto")
		m["alter_id"] = 0
	case "trojan":
		m["password"] = p.Password
	case "ss":
		m["type"] = "shadowsocks"
		m["method"] = p.Method
		m["password"] = p.Password
		return m // у shadowsocks нет tls/transport ниже
	}

	if p.Security == "tls" || p.Security == "reality" {
		tls := map[string]any{"enabled": true}
		if p.SNI != "" {
			tls["server_name"] = p.SNI
		}
		if p.AllowInsecure {
			tls["insecure"] = true
		}
		if p.Fingerprint != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": p.Fingerprint}
		}
		if p.Security == "reality" {
			reality := map[string]any{"enabled": true}
			if p.PublicKey != "" {
				reality["public_key"] = p.PublicKey
			}
			if p.ShortID != "" {
				reality["short_id"] = p.ShortID
			}
			tls["reality"] = reality
		}
		m["tls"] = tls
	}

	if p.Network != "" && p.Network != "tcp" {
		transport := map[string]any{"type": p.Network}
		switch p.Network {
		case "ws":
			if p.Path != "" {
				transport["path"] = p.Path
			}
			if p.Host != "" {
				transport["headers"] = map[string]any{"Host": p.Host}
			}
		case "grpc":
			if p.ServiceName != "" {
				transport["service_name"] = p.ServiceName
			}
		case "h2":
			if p.Path != "" {
				transport["path"] = p.Path
			}
			if p.Host != "" {
				transport["host"] = []string{p.Host}
			}
		}
		m["transport"] = transport
	}
	return m
}

// singboxOutboundToLink: обратное к linkToSingboxOutbound, для Decode.
func singboxOutboundToLink(m map[string]any) (*proxyLink, error) {
	typ, _ := m["type"].(string)
	scheme := typ
	if typ == "shadowsocks" {
		scheme = "ss"
	}
	switch scheme {
	case "vless", "vmess", "trojan", "ss":
	default:
		return nil, fmt.Errorf("subfmt: тип sing-box outbound %q пока не поддержан для конвертации в ссылку", typ)
	}

	p := &proxyLink{Scheme: scheme}
	p.Name, _ = m["tag"].(string)
	p.Server, _ = m["server"].(string)
	p.Port = toInt(m["server_port"])

	switch scheme {
	case "vless":
		p.UUID, _ = m["uuid"].(string)
		p.Flow, _ = m["flow"].(string)
	case "vmess":
		p.UUID, _ = m["uuid"].(string)
		p.Method, _ = m["security"].(string)
	case "trojan":
		p.Password, _ = m["password"].(string)
	case "ss":
		p.Method, _ = m["method"].(string)
		p.Password, _ = m["password"].(string)
		return p, nil
	}

	p.Network = "tcp"
	p.Security = "none"
	if tls, ok := m["tls"].(map[string]any); ok {
		if enabled, _ := tls["enabled"].(bool); enabled {
			p.Security = "tls"
			p.SNI = stringField(tls, "server_name")
			if insecure, _ := tls["insecure"].(bool); insecure {
				p.AllowInsecure = true
			}
			if utls, ok := tls["utls"].(map[string]any); ok {
				p.Fingerprint = stringField(utls, "fingerprint")
			}
			if reality, ok := tls["reality"].(map[string]any); ok {
				if enabled, _ := reality["enabled"].(bool); enabled {
					p.Security = "reality"
					p.PublicKey = stringField(reality, "public_key")
					p.ShortID = stringField(reality, "short_id")
				}
			}
		}
	}
	if transport, ok := m["transport"].(map[string]any); ok {
		if t := stringField(transport, "type"); t != "" {
			p.Network = t
		}
		switch p.Network {
		case "ws":
			p.Path = stringField(transport, "path")
			if h, ok := transport["headers"].(map[string]any); ok {
				p.Host = stringField(h, "Host")
			}
		case "grpc":
			p.ServiceName = stringField(transport, "service_name")
		case "h2":
			p.Path = stringField(transport, "path")
		}
	}
	return p, nil
}
