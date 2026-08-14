package proxy

import (
	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/subfmt"
)

// stubBody собирает валидное, но пустое тело подписки под конкретный
// формат. Используется для decision=blocked и decision=expired: клиент
// должен получить корректно распознаваемый ответ (список из нуля серверов),
// а не мусор, иначе часть приложений подписки покажет ошибку сети вместо
// понятного сообщения из profile-title.
//
// base64/plain собираются через subfmt.Encode(nil, ...): для пустого списка
// узлов это гарантированно та же самая пустая строка, что была бы и без
// него (base64/plain нуля байт всегда валиден и не ошибается), но теперь
// пакет subfmt действительно используется, а не дублируется руками.
//
// clash/singbox НАРОЧНО остаются собственными литералами, а не
// subfmt.Encode(nil, ...): для пустого списка узлов subfmt строит
// непустой, но бесполезный документ - select/selector-группу без единого
// outbound (у clash к тому же без секции rules вовсе). Часть клиентов на
// таком конфиге либо не поднимется, либо трактует "нет маршрута" как
// "блокировать весь трафик" вместо "пропускать напрямую". Для
// заблокированного или истёкшего пользователя такой регресс недопустим,
// поэтому здесь используется заведомо безопасный хардкод: пустой список
// прокси плюс явный fallback (MATCH,DIRECT у clash, outbound типа direct у
// singbox), проверенный на реальных клиентах.
func stubBody(format model.Format) (body []byte, contentType string) {
	switch format {
	case model.FormatClash:
		return []byte("proxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n"),
			"text/yaml; charset=utf-8"
	case model.FormatSingBox:
		return []byte(`{"outbounds":[{"type":"direct","tag":"direct"}]}`),
			"application/json; charset=utf-8"
	case model.FormatBase64, model.FormatPlain:
		empty, _ := subfmt.Encode(nil, format) // для nil-списка узлов эти два формата не ошибаются никогда
		return empty, "text/plain; charset=utf-8"
	default:
		// json/unknown: subfmt их не поддерживает (Encode вернул бы
		// ошибку), да они тут и не нужны - пустая строка тоже безопасный
		// пустой ответ, decision=blocked/expired этими форматами не просят.
		return []byte{}, "text/plain; charset=utf-8"
	}
}
