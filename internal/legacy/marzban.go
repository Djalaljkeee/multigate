// Package legacy распознаёт ссылки подписки, выданные ещё панелью Marzban.
//
// После переезда с Marzban на Remnawave у клиентов в приложениях остаются
// старые ссылки вида /sub/<токен Marzban>. Панель Remnawave такой токен не
// знает и отвечает 404, а страница подписки Remnawave умеет их понимать
// (MARZBAN_LEGACY_LINK_ENABLED): проверяет подпись токена секретом Marzban,
// достаёт из него имя пользователя и дальше работает с его текущим shortUuid.
// Этот пакет повторяет ту же проверку, чтобы прослойка могла встать на место
// страницы подписки, не отрезав таких клиентов.
//
// Поддерживаются обе формы токена Marzban:
//   - классическая: base64url("<username>,<unix-время>") + 10 символов подписи,
//     где подпись = base64url(sha256(<base64-часть> + <секрет>))[:10];
//   - JWT (HS256) с полями sub = имя пользователя и access = "subscription".
package legacy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// sigLen: длина подписи в конце классического токена.
const sigLen = 10

// Token: то, что удалось достать из проверенного токена Marzban.
type Token struct {
	Username  string
	CreatedAt time.Time
}

// ParseKeys разбирает настройку с секретами Marzban: несколько ключей через
// запятую (после смены секрета в Marzban старые ссылки подписаны прежним).
func ParseKeys(raw string) []string {
	var keys []string
	for _, k := range strings.Split(raw, ",") {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}
	return keys
}

// Decode проверяет token каждым ключом из keys и возвращает имя пользователя,
// если подпись сошлась хотя бы с одним. Без ключей не делает ничего:
// непроверенному токену доверять нельзя, иначе любой, кто знает формат,
// получил бы подписку любого пользователя по одному лишь имени.
func Decode(token string, keys []string) (Token, bool) {
	if len(keys) == 0 || len(token) < sigLen {
		return Token{}, false
	}
	for _, key := range keys {
		if t, ok := decodeJWT(token, key); ok {
			return t, true
		}
		if t, ok := decodeClassic(token, key); ok {
			return t, true
		}
	}
	return Token{}, false
}

func decodeClassic(token, key string) (Token, bool) {
	body, sig := token[:len(token)-sigLen], token[len(token)-sigLen:]
	if body == "" {
		return Token{}, false
	}
	sum := sha256.Sum256([]byte(body + key))
	want := base64.RawURLEncoding.EncodeToString(sum[:])[:sigLen]
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return Token{}, false
	}

	decoded, ok := decodeBase64Loose(body)
	if !ok {
		return Token{}, false
	}
	parts := strings.Split(decoded, ",")
	if len(parts) < 2 {
		return Token{}, false
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil {
		return Token{}, false
	}
	return Token{Username: SanitizeUsername(parts[0]), CreatedAt: time.Unix(ts, 0)}, true
}

// jwtClaims: поля токена Marzban в форме JWT, которые нам нужны.
type jwtClaims struct {
	Sub    string `json:"sub"`
	Access string `json:"access"`
	Iat    int64  `json:"iat"`
}

func decodeJWT(token, key string) (Token, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Token{}, false
	}

	var header struct {
		Alg string `json:"alg"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &header) != nil || header.Alg != "HS256" {
		return Token{}, false
	}

	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return Token{}, false
	}

	var c jwtClaims
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(pb, &c) != nil {
		return Token{}, false
	}
	if c.Access != "subscription" || strings.TrimSpace(c.Sub) == "" {
		return Token{}, false
	}
	return Token{Username: SanitizeUsername(c.Sub), CreatedAt: time.Unix(c.Iat, 0)}, true
}

// decodeBase64Loose декодирует base64 в любом из распространённых вариантов:
// Node, которым пользуется страница подписки, принимает и url-алфавит,
// и стандартный, с выравниванием и без. Токены выдавал Marzban (Python),
// но повторяем ту же терпимость, чтобы не отрезать ни одну старую ссылку.
func decodeBase64Loose(s string) (string, bool) {
	trimmed := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(trimmed); err == nil {
			return string(b), true
		}
	}
	return "", false
}

// SanitizeUsername приводит имя пользователя Marzban к виду, в котором
// его завела в Remnawave миграция: всё, кроме латиницы, цифр, «_» и «-»,
// заменяется на «_», а слишком короткое имя добивается «_» до 6 символов.
// Правило взято один в один из страницы подписки Remnawave.
func SanitizeUsername(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if n := len(out); n < 6 {
		out += strings.Repeat("_", 6-n)
	}
	return out
}
