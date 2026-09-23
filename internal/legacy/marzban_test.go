package legacy

import (
	"testing"
	"time"
)

// Векторы посчитаны независимо (Python, по алгоритму страницы подписки
// Remnawave) с ключом testKey. Классический токен повторяет форму настоящей
// ссылки клиента: 33 символа, base64 от "us_321,<время>" и 10 символов подписи.
const (
	testKey      = "test-secret-1"
	classicToken = "dXNfMzIxLDE3NDIzODQzOTczBxt2KEkzn"
	jwtToken     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c183NyIsImFjY2VzcyI6InN1YnNjcmlwdGlvbiIsImlhdCI6MTcwMDAwMDAwMH0.AbjwF1aqFT9CxjX4X9g2dj3aAKQVeKQKUVTj4r_pLAA"
	jwtAPIToken  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c183NyIsImFjY2VzcyI6ImFwaSIsImlhdCI6MTcwMDAwMDAwMH0.SsgT_HJNwGPAjAw3C4xUQtpdWyMLZUI4onCPFfcyttU"
)

func TestDecodeClassic(t *testing.T) {
	got, ok := Decode(classicToken, []string{testKey})
	if !ok {
		t.Fatal("классический токен не распознан")
	}
	if got.Username != "us_321" {
		t.Fatalf("username = %q, ждали us_321", got.Username)
	}
	if want := time.Unix(1742384397, 0); !got.CreatedAt.Equal(want) {
		t.Fatalf("createdAt = %v, ждали %v", got.CreatedAt, want)
	}
}

func TestDecodeTriesEveryKey(t *testing.T) {
	// Секрет в Marzban меняли: старые ссылки подписаны прежним ключом.
	if _, ok := Decode(classicToken, []string{"new-secret", testKey}); !ok {
		t.Fatal("токен, подписанный вторым ключом, не распознан")
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]struct {
		token string
		keys  []string
	}{
		"чужой ключ":            {classicToken, []string{"other"}},
		"без ключей":            {classicToken, nil},
		"испорченная подпись":   {classicToken[:len(classicToken)-1] + "x", []string{testKey}},
		"испорченное тело":      {"e" + classicToken[1:], []string{testKey}},
		"shortUuid Remnawave":   {"B8Eog9aZk2LmQx7T", []string{testKey}},
		"слишком короткий":      {"abc", []string{testKey}},
		"JWT не для подписки":   {jwtAPIToken, []string{testKey}},
		"JWT с чужим ключом":    {jwtToken, []string{"other"}},
		"JWT с порченой частью": {jwtToken[:len(jwtToken)-2] + "xx", []string{testKey}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got, ok := Decode(tc.token, tc.keys); ok {
				t.Fatalf("токен принят, а не должен: %+v", got)
			}
		})
	}
}

func TestDecodeJWT(t *testing.T) {
	got, ok := Decode(jwtToken, []string{testKey})
	if !ok {
		t.Fatal("JWT не распознан")
	}
	// Короткое имя добивается до 6 символов, как при миграции в Remnawave.
	if got.Username != "us_77_" {
		t.Fatalf("username = %q, ждали us_77_", got.Username)
	}
}

func TestSanitizeUsername(t *testing.T) {
	cases := map[string]string{
		"us_321":     "us_321",
		"ivan.petr":  "ivan_petr",
		"a":          "a_____",
		"пётр":       "______",
		"user@mail1": "user_mail1",
	}
	for in, want := range cases {
		if got := SanitizeUsername(in); got != want {
			t.Errorf("SanitizeUsername(%q) = %q, ждали %q", in, got, want)
		}
	}
}

func TestParseKeys(t *testing.T) {
	got := ParseKeys(" a , ,b,")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("ParseKeys = %q", got)
	}
}
