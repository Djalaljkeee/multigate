// Package ua разбирает User-Agent и заголовки запроса подписки, чтобы понять,
// кто именно пришёл за конфигом: какое приложение, какой версии, на каком
// ядре и на какой платформе, и чем это устройство отличить от других.
// От результата зависит, какой формат подписки отдавать (пакет subfmt)
// и как считать устройства пользователя против лимита HWID в панели.
package ua

import (
	"net/http"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// Заголовки, которыми клиент подписки может сообщить о себе явно.
// Их значениям доверяем больше, чем догадкам по User-Agent: раз клиент
// потрудился их прислать, значит знает о себе больше, чем видно по UA.
const (
	headerHWID        = "x-hwid"
	headerDeviceID    = "x-device-id"
	headerDeviceOS    = "x-device-os"
	headerVerOS       = "x-ver-os"
	headerDeviceModel = "x-device-model"
	headerAppVersion  = "x-app-version"
)

// Parse собирает Client из строки User-Agent и заголовков устройства запроса.
// Это основной способ вызова пакета из обработчика подписки: там есть
// полный *http.Request, а не только заголовок UA.
func Parse(r *http.Request) model.Client {
	c := parseCore(r.UserAgent())

	// Заголовки устройства перекрывают то, что удалось вытащить из UA:
	// если клиент прислал их сам, это точнее любой догадки по строке UA.
	if v := strings.TrimSpace(r.Header.Get(headerDeviceOS)); v != "" {
		if p := normalizePlatform(v); p != model.PlatformUnknown {
			c.Platform = p
		}
	}
	if v := strings.TrimSpace(r.Header.Get(headerVerOS)); v != "" {
		c.OSVersion = v
	}
	if v := strings.TrimSpace(r.Header.Get(headerDeviceModel)); v != "" {
		c.Device = v
	}
	if v := strings.TrimSpace(r.Header.Get(headerAppVersion)); v != "" {
		c.AppVersion = v
	}

	hwid := strings.TrimSpace(r.Header.Get(headerHWID))
	if hwid == "" {
		hwid = strings.TrimSpace(r.Header.Get(headerDeviceID))
	}
	if hwid != "" {
		c.HWID = hwid
		c.HWIDSource = "header"
		return c
	}

	// Настоящего HWID клиент не прислал (типично для v2rayNG, Clash и
	// большинства десктопных клиентов). Считаем синтетический идентификатор
	// по уже дополненным заголовками полям: так он точнее, чем если бы
	// строился только по сырому UA.
	if id, ok := syntheticHWID(c); ok {
		c.HWID = id
		c.HWIDSource = "ua"
	}
	return c
}

// ParseUA разбирает только строку User-Agent, без заголовков запроса.
// Заголовков здесь в принципе нет, поэтому HWID (если получится) всегда
// синтетический, посчитанный по UA.
func ParseUA(userAgent string) model.Client {
	c := parseCore(userAgent)
	if id, ok := syntheticHWID(c); ok {
		c.HWID = id
		c.HWIDSource = "ua"
	}
	return c
}

// parseCore разбирает UA во все поля Client, кроме HWID. Вынесено отдельно,
// потому что Parse(r) сначала накладывает на эти поля заголовки устройства
// и только потом решает, откуда взять HWID: приоритет источников иначе не
// собрать корректно.
func parseCore(userAgent string) model.Client {
	c := model.Client{UserAgent: userAgent}

	ua := strings.TrimSpace(userAgent)
	if ua == "" {
		// Пустой UA: ничего не известно, но поля должны быть заполнены
		// явно, а не оставлены нулевыми пустыми строками.
		c.Core = model.CoreUnknown
		c.Platform = model.PlatformUnknown
		return c
	}

	if rule, version, ok := matchApp(ua); ok {
		c.App = rule.app
		c.Core = rule.core
		c.AppVersion = version
	} else {
		c.Core = model.CoreUnknown
	}

	c.Platform, c.OSVersion, c.Device = detectPlatform(ua)
	c.IsBrowser = IsBrowser(ua)
	return c
}
