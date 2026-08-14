package ua

import "strings"

// botTokens: явные признаки автоматизированных клиентов и утилит, не
// браузер и не клиент подписки, а скрипт, консольная утилита или сканер.
// Проверяем раньше браузерных признаков, потому что часть ботов дописывает
// в UA "Mozilla/5.0", притворяясь браузером (классика для поисковых ботов
// и security-сканеров).
var botTokens = []string{
	"curl/", "wget/", "python-requests", "python-urllib", "go-http-client",
	"okhttp", "postmanruntime", "insomnia", "httpie", "libwww-perl",
	"bot", "spider", "crawler", "scrapy", "headlesschrome", "phantomjs",
	"axios/", "node-fetch",
}

// browserTokens: признаки настоящего браузера. Проверяются ПОСЛЕ известных
// имён клиентов подписки (см. IsBrowser): некоторые клиенты сами дописывают
// в UA "Mozilla/5.0" или элементы WebKit для совместимости с CDN и WAF
// перед своим настоящим именем, и если проверять браузерные признаки
// раньше, такой клиент ошибочно определится как браузер.
var browserTokens = []string{
	"chrome/", "chromium/", "firefox/", "safari/", "edg/", "edge/",
	"yabrowser/", "opr/", "opera/", "msie ", "trident/", "gecko/",
}

// IsBrowser отличает запрос обычного браузера (или бота/утилиты вроде curl)
// от запроса клиента подписки. Пустой UA браузером не считается: по нему
// вообще ничего не известно, а решение "не браузер" безопаснее для вызывающей
// стороны (не отдаст человеку сырой base64 вместо страницы).
func IsBrowser(userAgent string) bool {
	ua := strings.TrimSpace(userAgent)
	if ua == "" {
		return false
	}

	// Сначала известные имена клиентов подписки: они в приоритете, даже
	// если сам UA замаскирован под браузер.
	if _, _, ok := matchApp(ua); ok {
		return false
	}

	low := strings.ToLower(ua)
	for _, tok := range botTokens {
		if strings.Contains(low, tok) {
			return false
		}
	}
	for _, tok := range browserTokens {
		if strings.Contains(low, tok) {
			return true
		}
	}
	// Голый "Mozilla/5.0" без прочих браузерных признаков и без имени
	// известного клиента или бота тоже считаем браузером: это старый
	// или редкий браузер/WebView, но точно не клиент подписки.
	return strings.Contains(low, "mozilla/")
}
