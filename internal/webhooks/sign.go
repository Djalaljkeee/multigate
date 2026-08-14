package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// signatureHeader: заголовок, в котором панель передаёт подпись тела.
const signatureHeader = "x-remnawave-signature"

// computeSignature считает HMAC-SHA256 тела события под конкретный секрет.
// Используется и для проверки входящего вебхука, и для подписи исходящей
// рассылки, в обоих случаях под СВОЙ секрет стороны, которой подпись
// адресована.
func computeSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// validSignature сверяет заголовок подписи с посчитанной по секрету.
// Значение заголовка допускается как в чистом hex, так и с префиксом
// "sha256=": так подписывают часть систем вебхуков, и это не мешает
// проверке.
//
// Сравнение только через hmac.Equal. Обычное сравнение строк "==" в Go
// возвращает false на первом несовпавшем байте, и время сравнения выдаёт
// длину совпавшего префикса. Этого достаточно, чтобы подобрать подпись
// побайтово через замер времени ответа.
func validSignature(secret string, body []byte, header string) bool {
	got := strings.TrimSpace(header)
	got = strings.TrimPrefix(got, "sha256=")
	if got == "" || secret == "" {
		return false
	}
	want := computeSignature(secret, body)
	return hmac.Equal([]byte(got), []byte(want))
}
