package subfmt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// proxyLink: общие поля прокси-ссылки (vless://, vmess://, trojan://,
// ss://), в одном виде вне зависимости от схемы. Используется, чтобы
// перекладывать узел, пришедший ссылкой, в структуру clash или singbox
// (Append) и обратно, при разборе их узлов (Decode).
//
// Полей ровно столько, сколько нужно для самых ходовых схем и транспортов
// в экосистеме Xray: TLS/Reality, ws/grpc/h2. Экзотика вроде ssr, snell,
// hysteria2, tuic сюда сознательно не включена: для неизвестной схемы
// parseLink просто возвращает ошибку, и вызывающий код пропускает такой
// узел, не роняя остальную подписку.
type proxyLink struct {
	Scheme string // vless | vmess | trojan | ss
	Name   string

	Server string
	Port   int

	UUID     string // vless/vmess id
	Password string // trojan password / ss password
	Method   string // ss cipher, vmess security (scy)

	Flow       string // vless flow, напр. xtls-rprx-vision
	Encryption string // vless encryption, обычно "none"

	Network  string // tcp | ws | grpc | h2 (пусто трактуется как tcp)
	Security string // none | tls | reality

	SNI           string
	Fingerprint   string // fp, отпечаток TLS-клиента (uTLS)
	ALPN          string
	AllowInsecure bool

	PublicKey string // reality pbk
	ShortID   string // reality sid
	SpiderX   string // reality spx

	Host        string // Host-заголовок для ws/h2
	Path        string // путь для ws/h2
	ServiceName string // grpc serviceName
	HeaderType  string // vmess headerType, обычно none
}

// parseLink разбирает ссылку в proxyLink. Схема, которую не понимаем,
// это не паника и не потеря остального тела, а просто ошибка, которую
// вызывающий код (Append) трактует как "этот узел пропускаем".
func parseLink(raw string) (*proxyLink, error) {
	raw = strings.TrimSpace(raw)
	scheme, _, ok := strings.Cut(raw, "://")
	if !ok {
		return nil, fmt.Errorf("subfmt: %q не похоже на ссылку вида scheme://...", raw)
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return parseGenericLink(raw, "vless")
	case "trojan":
		return parseGenericLink(raw, "trojan")
	case "vmess":
		return parseVmessLink(raw)
	case "ss":
		return parseSSLink(raw)
	default:
		return nil, fmt.Errorf("subfmt: схема %q пока не поддержана для конвертации", scheme)
	}
}

// parseGenericLink разбирает vless:// и trojan://: у обеих одна и та же
// форма scheme://идентификатор@host:port?параметры#имя, различается только
// то, что лежит в userinfo (uuid у vless, пароль у trojan).
func parseGenericLink(raw, scheme string) (*proxyLink, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("subfmt: не разобрать %s-ссылку: %w", scheme, err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("subfmt: в %s-ссылке нет адреса сервера", scheme)
	}
	port, _ := strconv.Atoi(u.Port())

	p := &proxyLink{Scheme: scheme, Server: host, Port: port, Name: u.Fragment}
	switch scheme {
	case "vless":
		p.UUID = u.User.Username()
	case "trojan":
		p.Password = u.User.Username()
	}

	q := u.Query()
	p.Flow = q.Get("flow")
	p.Encryption = q.Get("encryption")
	p.Network = firstNonEmpty(q.Get("type"), "tcp")
	p.Security = firstNonEmpty(q.Get("security"), "none")
	p.SNI = firstNonEmpty(q.Get("sni"), q.Get("peer"))
	p.Fingerprint = q.Get("fp")
	p.ALPN = q.Get("alpn")
	p.PublicKey = q.Get("pbk")
	p.ShortID = q.Get("sid")
	p.SpiderX = q.Get("spx")
	p.Host = q.Get("host")
	p.Path = q.Get("path")
	p.ServiceName = q.Get("serviceName")
	p.HeaderType = q.Get("headerType")
	p.AllowInsecure = q.Get("allowInsecure") == "1" || strings.EqualFold(q.Get("allowInsecure"), "true")
	return p, nil
}

// vmessJSON: payload vmess-ссылки (v2rayN/v2ray формат): vmess://base64(json).
// Port и Aid объявлены как any: у разных генераторов встречаются то числом,
// то строкой, а падать из-за этого не хочется, см. toInt.
type vmessJSON struct {
	V    string `json:"v,omitempty"`
	PS   string `json:"ps,omitempty"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	Aid  any    `json:"aid,omitempty"`
	Scy  string `json:"scy,omitempty"`
	Net  string `json:"net,omitempty"`
	Type string `json:"type,omitempty"`
	Host string `json:"host,omitempty"`
	Path string `json:"path,omitempty"`
	TLS  string `json:"tls,omitempty"`
	SNI  string `json:"sni,omitempty"`
	FP   string `json:"fp,omitempty"`
	ALPN string `json:"alpn,omitempty"`
}

func parseVmessLink(raw string) (*proxyLink, error) {
	payload := strings.TrimPrefix(raw, "vmess://")
	payload = strings.TrimPrefix(payload, "VMESS://")
	// У части генераторов после base64-блока через "#" добавлено имя,
	// не часть стандарта (имя и так есть в JSON как "ps"), но встречается.
	payload, frag, hasFrag := strings.Cut(payload, "#")

	data, err := decodeBase64Flexible(payload)
	if err != nil {
		return nil, fmt.Errorf("subfmt: не разобрать vmess-ссылку: %w", err)
	}
	var v vmessJSON
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("subfmt: содержимое vmess-ссылки не JSON: %w", err)
	}

	name := v.PS
	if hasFrag {
		if unescaped, err := url.QueryUnescape(frag); err == nil {
			name = unescaped
		} else {
			name = frag
		}
	}

	p := &proxyLink{
		Scheme:      "vmess",
		Name:        name,
		Server:      v.Add,
		Port:        toInt(v.Port),
		UUID:        v.ID,
		Method:      firstNonEmpty(v.Scy, "auto"),
		Network:     firstNonEmpty(v.Net, "tcp"),
		Host:        v.Host,
		Path:        v.Path,
		HeaderType:  v.Type,
		SNI:         v.SNI,
		Fingerprint: v.FP,
		ALPN:        v.ALPN,
		Security:    "none",
	}
	if strings.EqualFold(v.TLS, "tls") || strings.EqualFold(v.TLS, "reality") {
		p.Security = strings.ToLower(v.TLS)
	}
	return p, nil
}

// parseSSLink разбирает ss:// в обеих распространённых формах: SIP002
// (userinfo это base64("метод:пароль"), адрес открытым текстом) и старую
// легаси-форму, где base64 закодирована целиком строка "метод:пароль@host:port".
func parseSSLink(raw string) (*proxyLink, error) {
	if u, err := url.Parse(raw); err == nil && u.Host != "" && u.User != nil {
		if method, password, ok := decodeSSUserinfo(u.User.String()); ok {
			port, _ := strconv.Atoi(u.Port())
			return &proxyLink{
				Scheme: "ss", Name: u.Fragment,
				Server: u.Hostname(), Port: port,
				Method: method, Password: password,
			}, nil
		}
	}

	body := strings.TrimPrefix(raw, "ss://")
	body = strings.TrimPrefix(body, "SS://")
	body, frag, _ := strings.Cut(body, "#")
	data, err := decodeBase64Flexible(body)
	if err != nil {
		return nil, fmt.Errorf("subfmt: не разобрать ss-ссылку: %w", err)
	}
	method, rest, ok := strings.Cut(string(data), ":")
	if !ok {
		return nil, fmt.Errorf("subfmt: в ss-ссылке нет пароля")
	}
	password, hostport, ok := strings.Cut(rest, "@")
	if !ok {
		return nil, fmt.Errorf("subfmt: в ss-ссылке нет адреса сервера")
	}
	host, portStr, ok := strings.Cut(hostport, ":")
	if !ok {
		return nil, fmt.Errorf("subfmt: в ss-ссылке нет порта")
	}
	port, _ := strconv.Atoi(portStr)

	name := frag
	if unescaped, err := url.QueryUnescape(frag); err == nil {
		name = unescaped
	}
	return &proxyLink{Scheme: "ss", Name: name, Server: host, Port: port, Method: method, Password: password}, nil
}

// decodeSSUserinfo раскодирует userinfo ss://-ссылки: обычно это
// base64("метод:пароль") без выравнивания (так рекомендует SIP002), но
// встречается и открытым текстом.
func decodeSSUserinfo(userinfo string) (method, password string, ok bool) {
	if data, err := decodeBase64Flexible(userinfo); err == nil {
		if m, p, found := strings.Cut(string(data), ":"); found {
			return m, p, true
		}
	}
	if m, p, found := strings.Cut(userinfo, ":"); found {
		return m, p, true
	}
	return "", "", false
}

// buildLinkURI собирает ссылку обратно из proxyLink: обратная операция
// к parseLink, нужна при разборе clash/singbox узлов в Entry.URI (Decode).
func buildLinkURI(p *proxyLink) (string, error) {
	switch p.Scheme {
	case "vless", "trojan":
		return buildGenericLink(p), nil
	case "vmess":
		return buildVmessLink(p)
	case "ss":
		return buildSSLink(p), nil
	default:
		return "", fmt.Errorf("subfmt: схема %q не поддержана для сборки ссылки", p.Scheme)
	}
}

func buildGenericLink(p *proxyLink) string {
	u := &url.URL{Scheme: p.Scheme, Host: net.JoinHostPort(p.Server, strconv.Itoa(p.Port))}
	switch p.Scheme {
	case "vless":
		u.User = url.User(p.UUID)
	case "trojan":
		u.User = url.User(p.Password)
	}

	q := url.Values{}
	setIfNotEmpty(q, "flow", p.Flow)
	setIfNotEmpty(q, "encryption", p.Encryption)
	if p.Network != "" && p.Network != "tcp" {
		q.Set("type", p.Network)
	}
	setIfNotEmpty(q, "security", p.Security)
	setIfNotEmpty(q, "sni", p.SNI)
	setIfNotEmpty(q, "fp", p.Fingerprint)
	setIfNotEmpty(q, "alpn", p.ALPN)
	setIfNotEmpty(q, "pbk", p.PublicKey)
	setIfNotEmpty(q, "sid", p.ShortID)
	setIfNotEmpty(q, "spx", p.SpiderX)
	setIfNotEmpty(q, "host", p.Host)
	setIfNotEmpty(q, "path", p.Path)
	setIfNotEmpty(q, "serviceName", p.ServiceName)
	setIfNotEmpty(q, "headerType", p.HeaderType)
	if p.AllowInsecure {
		q.Set("allowInsecure", "1")
	}
	u.RawQuery = q.Encode()
	u.Fragment = p.Name
	return u.String()
}

func buildVmessLink(p *proxyLink) (string, error) {
	v := vmessJSON{
		V: "2", PS: p.Name, Add: p.Server, Port: strconv.Itoa(p.Port),
		ID: p.UUID, Aid: "0", Scy: firstNonEmpty(p.Method, "auto"),
		Net: firstNonEmpty(p.Network, "tcp"), Type: p.HeaderType,
		Host: p.Host, Path: p.Path, SNI: p.SNI, FP: p.Fingerprint, ALPN: p.ALPN,
	}
	if p.Security == "tls" || p.Security == "reality" {
		v.TLS = "tls"
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("subfmt: не собрать vmess JSON: %w", err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(data), nil
}

func buildSSLink(p *proxyLink) string {
	// SIP002 отдельно рекомендует base64url без выравнивания для userinfo:
	// тогда в самой ссылке не нужно процентное экранирование "+"/"/".
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(p.Method + ":" + p.Password))
	u := &url.URL{
		Scheme: "ss",
		User:   url.User(userinfo),
		Host:   net.JoinHostPort(p.Server, strconv.Itoa(p.Port)),
	}
	u.Fragment = p.Name
	return u.String()
}

func setIfNotEmpty(q url.Values, key, val string) {
	if val != "" {
		q.Set(key, val)
	}
}

// toInt приводит к int значение, которое в JSON или YAML могло приехать
// и числом, и строкой: это реальный разнобой между генераторами ссылок.
func toInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
	}
}
