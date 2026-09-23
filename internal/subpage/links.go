package subpage

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html/template"
	"regexp"
	"strings"
	"sync"
)

// Публичные ключи Happ для зашифрованных ссылок happ://crypt3/ и
// happ://crypt4/. Взяты из страницы подписки Remnawave: Happ расшифровывает
// такую ссылку своим закрытым ключом, и адрес подписки не светится открытым
// текстом ни в истории браузера, ни в скриншоте.
var (
	//go:embed keys/happ_v3.pem
	happV3PEM []byte
	//go:embed keys/happ_v4.pem
	happV4PEM []byte
)

var happKeys = map[string]struct {
	pem    []byte
	prefix string
}{
	"v3": {happV3PEM, "happ://crypt3/"},
	"v4": {happV4PEM, "happ://crypt4/"},
}

var (
	parsedKeysOnce sync.Once
	parsedKeys     map[string]*rsa.PublicKey
)

func happKey(version string) (*rsa.PublicKey, string, error) {
	parsedKeysOnce.Do(func() {
		parsedKeys = map[string]*rsa.PublicKey{}
		for v, k := range happKeys {
			block, _ := pem.Decode(k.pem)
			if block == nil {
				continue
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				continue
			}
			if rsaPub, ok := pub.(*rsa.PublicKey); ok {
				parsedKeys[v] = rsaPub
			}
		}
	})
	pub, ok := parsedKeys[version]
	if !ok {
		return nil, "", fmt.Errorf("subpage: нет ключа Happ %s", version)
	}
	return pub, happKeys[version].prefix, nil
}

// HappCryptoLink шифрует адрес подписки ключом Happ так же, как это делает
// JSEncrypt на странице Remnawave: RSA PKCS#1 v1.5, результат в base64.
func HappCryptoLink(subURL, version string) (string, error) {
	pub, prefix, err := happKey(version)
	if err != nil {
		return "", err
	}
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(subURL))
	if err != nil {
		return "", fmt.Errorf("subpage: зашифровать ссылку Happ: %w", err)
	}
	return prefix + base64.StdEncoding.EncodeToString(ct), nil
}

var placeholderRe = regexp.MustCompile(`\{\{(\w+)\}\}`)

// fillLink подставляет в ссылку кнопки значения шаблонов страницы
// Remnawave: {{SUBSCRIPTION_LINK}}, {{USERNAME}}, {{HAPP_CRYPT3_LINK}},
// {{HAPP_CRYPT4_LINK}}. Неизвестные шаблоны остаются как есть.
func fillLink(link string, info linkData) string {
	return placeholderRe.ReplaceAllStringFunc(link, func(m string) string {
		switch placeholderRe.FindStringSubmatch(m)[1] {
		case "SUBSCRIPTION_LINK":
			return info.SubURL
		case "USERNAME":
			return info.Username
		case "HAPP_CRYPT3_LINK":
			if l, err := HappCryptoLink(info.SubURL, "v3"); err == nil {
				return l
			}
			return "unknown"
		case "HAPP_CRYPT4_LINK":
			if l, err := HappCryptoLink(info.SubURL, "v4"); err == nil {
				return l
			}
			return "unknown"
		}
		return m
	})
}

type linkData struct {
	SubURL   string
	Username string
}

// safeURL помечает ссылку кнопки как доверенную для href. html/template
// иначе заменил бы схемы приложений (incy://, happ://) на заглушку.
// Ссылки задаёт администратор в панели, но исполняемые схемы всё равно
// не пропускаем: страница открывается по ссылке, которую пересылают.
func safeURL(link string) template.URL {
	l := strings.ToLower(strings.TrimSpace(link))
	for _, bad := range []string{"javascript:", "data:", "vbscript:", "file:"} {
		if strings.HasPrefix(l, bad) {
			return "#"
		}
	}
	return template.URL(strings.TrimSpace(link))
}
