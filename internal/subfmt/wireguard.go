package subfmt

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// wgConfig: общие поля конфига WireGuard/AmneziaWG вне зависимости от
// того, куда его дальше конвертируют (clash или singbox). Jc..H4, это
// параметры обфускации AmneziaWG (см. amneziawg-go); нулевое значение
// поля означает "не задано", а не "ноль", так задаются они и в самом
// INI-конфиге.
type wgConfig struct {
	PrivateKey string
	Address    []string // может быть несколько: v4 и v6
	DNS        []string
	MTU        int

	PeerPublicKey string
	PresharedKey  string
	Endpoint      string // host:port
	AllowedIPs    []string

	Jc, Jmin, Jmax int
	S1, S2         int
	H1, H2, H3, H4 int
}

// parseWireGuardINI разбирает конфиг WireGuard/AmneziaWG в формате обычного
// INI ([Interface]/[Peer], "Ключ = значение"). Разбор построчный и терпимый
// к мусору: незнакомые ключи и секции просто игнорируются, а не роняют разбор.
func parseWireGuardINI(text string) (*wgConfig, error) {
	cfg := &wgConfig{}
	section := ""
	sawAnyKey := false

	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		sawAnyKey = true

		switch section {
		case "interface":
			applyInterfaceKey(cfg, key, val)
		case "peer":
			applyPeerKey(cfg, key, val)
		}
	}

	if !sawAnyKey || cfg.PrivateKey == "" || cfg.PeerPublicKey == "" {
		return nil, fmt.Errorf("subfmt: не похоже на конфиг WireGuard: нет PrivateKey/PublicKey")
	}
	return cfg, nil
}

func applyInterfaceKey(cfg *wgConfig, key, val string) {
	switch key {
	case "privatekey":
		cfg.PrivateKey = val
	case "address":
		cfg.Address = splitTrim(val, ",")
	case "dns":
		cfg.DNS = splitTrim(val, ",")
	case "mtu":
		cfg.MTU, _ = strconv.Atoi(val)
	case "jc":
		cfg.Jc, _ = strconv.Atoi(val)
	case "jmin":
		cfg.Jmin, _ = strconv.Atoi(val)
	case "jmax":
		cfg.Jmax, _ = strconv.Atoi(val)
	case "s1":
		cfg.S1, _ = strconv.Atoi(val)
	case "s2":
		cfg.S2, _ = strconv.Atoi(val)
	case "h1":
		cfg.H1, _ = strconv.Atoi(val)
	case "h2":
		cfg.H2, _ = strconv.Atoi(val)
	case "h3":
		cfg.H3, _ = strconv.Atoi(val)
	case "h4":
		cfg.H4, _ = strconv.Atoi(val)
	}
}

func applyPeerKey(cfg *wgConfig, key, val string) {
	switch key {
	case "publickey":
		cfg.PeerPublicKey = val
	case "presharedkey":
		cfg.PresharedKey = val
	case "endpoint":
		cfg.Endpoint = val
	case "allowedips":
		cfg.AllowedIPs = splitTrim(val, ",")
	}
}

// buildWireGuardINI собирает конфиг обратно в текстовый INI-вид: нужен,
// когда WireGuard-узел приехал в теле подписки (clash/singbox) и его нужно
// показать в Entry.WG в исходном для этого пакета виде.
func buildWireGuardINI(cfg *wgConfig) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	writeStrIfSet(&b, "PrivateKey", cfg.PrivateKey)
	if len(cfg.Address) > 0 {
		fmt.Fprintf(&b, "Address = %s\n", strings.Join(cfg.Address, ", "))
	}
	if len(cfg.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(cfg.DNS, ", "))
	}
	writeIntIfSet(&b, "MTU", cfg.MTU)
	writeIntIfSet(&b, "Jc", cfg.Jc)
	writeIntIfSet(&b, "Jmin", cfg.Jmin)
	writeIntIfSet(&b, "Jmax", cfg.Jmax)
	writeIntIfSet(&b, "S1", cfg.S1)
	writeIntIfSet(&b, "S2", cfg.S2)
	writeIntIfSet(&b, "H1", cfg.H1)
	writeIntIfSet(&b, "H2", cfg.H2)
	writeIntIfSet(&b, "H3", cfg.H3)
	writeIntIfSet(&b, "H4", cfg.H4)

	b.WriteString("\n[Peer]\n")
	writeStrIfSet(&b, "PublicKey", cfg.PeerPublicKey)
	writeStrIfSet(&b, "PresharedKey", cfg.PresharedKey)
	writeStrIfSet(&b, "Endpoint", cfg.Endpoint)
	if len(cfg.AllowedIPs) > 0 {
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(cfg.AllowedIPs, ", "))
	}
	return b.String()
}

func writeStrIfSet(b *strings.Builder, key, val string) {
	if val != "" {
		fmt.Fprintf(b, "%s = %s\n", key, val)
	}
}

func writeIntIfSet(b *strings.Builder, key string, val int) {
	if val != 0 {
		fmt.Fprintf(b, "%s = %d\n", key, val)
	}
}

func splitTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hasAmnezia(cfg *wgConfig) bool {
	return cfg.Jc != 0 || cfg.Jmin != 0 || cfg.Jmax != 0 || cfg.S1 != 0 || cfg.S2 != 0 ||
		cfg.H1 != 0 || cfg.H2 != 0 || cfg.H3 != 0 || cfg.H4 != 0
}

// splitHostPort разбирает "host:port" из Endpoint конфига WireGuard:
// clash и singbox хотят сервер и порт отдельными полями.
func splitHostPort(hostport string) (host string, port int, ok bool) {
	h, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, false
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, false
	}
	return h, p, true
}

// firstAddrByFamily ищет в списке адресов первый подходящей семьи
// (по наличию ":" в адресе, если отбросить маску подсети через "/").
func firstAddrByFamily(addrs []string, v6 bool) string {
	for _, a := range addrs {
		bare, _, _ := strings.Cut(a, "/")
		isV6 := strings.Contains(bare, ":")
		if isV6 == v6 {
			return a
		}
	}
	return ""
}

// wgToClashProxy собирает clash-прокси типа wireguard. Формат полей взят
// из документации mihomo (AmneziaWG-обфускация вынесена в отдельный
// amnezia-wg-option: так это описано в её собственной wiki на момент
// написания; при обновлении mihomo стоит перепроверить точные имена полей).
func wgToClashProxy(name string, cfg *wgConfig) map[string]any {
	m := map[string]any{
		"name":        name,
		"type":        "wireguard",
		"private-key": cfg.PrivateKey,
		"public-key":  cfg.PeerPublicKey,
		"udp":         true,
	}
	if host, port, ok := splitHostPort(cfg.Endpoint); ok {
		m["server"] = host
		m["port"] = port
	}
	if v4 := firstAddrByFamily(cfg.Address, false); v4 != "" {
		m["ip"] = v4
	}
	if v6 := firstAddrByFamily(cfg.Address, true); v6 != "" {
		m["ipv6"] = v6
	}
	if cfg.PresharedKey != "" {
		m["preshared-key"] = cfg.PresharedKey
	}
	if cfg.MTU > 0 {
		m["mtu"] = cfg.MTU
	}
	if len(cfg.DNS) > 0 {
		m["dns"] = cfg.DNS
	}
	if hasAmnezia(cfg) {
		m["amnezia-wg-option"] = map[string]any{
			"jc": cfg.Jc, "jmin": cfg.Jmin, "jmax": cfg.Jmax,
			"s1": cfg.S1, "s2": cfg.S2,
			"h1": cfg.H1, "h2": cfg.H2, "h3": cfg.H3, "h4": cfg.H4,
		}
	}
	return m
}

// clashProxyToWG: обратное к wgToClashProxy, для Decode.
func clashProxyToWG(m map[string]any) (*wgConfig, error) {
	cfg := &wgConfig{}
	cfg.PrivateKey, _ = m["private-key"].(string)
	cfg.PeerPublicKey, _ = m["public-key"].(string)
	if cfg.PrivateKey == "" || cfg.PeerPublicKey == "" {
		return nil, fmt.Errorf("subfmt: в clash-прокси типа wireguard нет ключей")
	}
	cfg.PresharedKey, _ = m["preshared-key"].(string)

	server, _ := m["server"].(string)
	if server != "" {
		cfg.Endpoint = net.JoinHostPort(server, strconv.Itoa(toInt(m["port"])))
	}
	if ip, ok := m["ip"].(string); ok && ip != "" {
		cfg.Address = append(cfg.Address, ip)
	}
	if ip6, ok := m["ipv6"].(string); ok && ip6 != "" {
		cfg.Address = append(cfg.Address, ip6)
	}
	cfg.MTU = toInt(m["mtu"])
	if dns, ok := m["dns"].([]any); ok {
		for _, d := range dns {
			if s, ok := d.(string); ok {
				cfg.DNS = append(cfg.DNS, s)
			}
		}
	}
	if opt, ok := m["amnezia-wg-option"].(map[string]any); ok {
		cfg.Jc, cfg.Jmin, cfg.Jmax = toInt(opt["jc"]), toInt(opt["jmin"]), toInt(opt["jmax"])
		cfg.S1, cfg.S2 = toInt(opt["s1"]), toInt(opt["s2"])
		cfg.H1, cfg.H2, cfg.H3, cfg.H4 = toInt(opt["h1"]), toInt(opt["h2"]), toInt(opt["h3"]), toInt(opt["h4"])
	}
	return cfg, nil
}

// wgToSingboxOutbound собирает outbound типа wireguard по официальной схеме
// sing-box. Amnezia-обфускацию сюда сознательно не добавляем: ванильный
// sing-box такие поля не поддерживает (это фича форков мihomo/Amnezia),
// а писать их "на всякий случай" в стандартный outbound рискованнее, чем
// просто не выдать эту часть конфига для sing-box-клиентов.
func wgToSingboxOutbound(tag string, cfg *wgConfig) map[string]any {
	m := map[string]any{
		"type":            "wireguard",
		"tag":             tag,
		"private_key":     cfg.PrivateKey,
		"peer_public_key": cfg.PeerPublicKey,
	}
	if host, port, ok := splitHostPort(cfg.Endpoint); ok {
		m["server"] = host
		m["server_port"] = port
	}
	if len(cfg.Address) > 0 {
		m["local_address"] = cfg.Address
	}
	if cfg.PresharedKey != "" {
		m["pre_shared_key"] = cfg.PresharedKey
	}
	if cfg.MTU > 0 {
		m["mtu"] = cfg.MTU
	}
	return m
}

// singboxOutboundToWG: обратное к wgToSingboxOutbound, для Decode.
func singboxOutboundToWG(m map[string]any) (*wgConfig, error) {
	cfg := &wgConfig{}
	cfg.PrivateKey, _ = m["private_key"].(string)
	cfg.PeerPublicKey, _ = m["peer_public_key"].(string)
	if cfg.PrivateKey == "" || cfg.PeerPublicKey == "" {
		return nil, fmt.Errorf("subfmt: в sing-box outbound типа wireguard нет ключей")
	}
	cfg.PresharedKey, _ = m["pre_shared_key"].(string)

	server, _ := m["server"].(string)
	if server != "" {
		cfg.Endpoint = net.JoinHostPort(server, strconv.Itoa(toInt(m["server_port"])))
	}
	if addrs, ok := m["local_address"].([]any); ok {
		for _, a := range addrs {
			if s, ok := a.(string); ok {
				cfg.Address = append(cfg.Address, s)
			}
		}
	}
	cfg.MTU = toInt(m["mtu"])
	return cfg, nil
}
