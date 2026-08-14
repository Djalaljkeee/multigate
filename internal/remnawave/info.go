package remnawave

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// metaResponse: то немногое из /api/system/metadata, что нужно клиенту.
// Панель отдаёт больше полей, но версия остаётся единственным, от чего зависит
// поведение пакета.
type metaResponse struct {
	Version string `json:"version"`
}

// Info возвращает версию и достижимость панели. Результат кэшируется на 5
// минут: определение версии стоит нескольких запросов, а сама версия панели
// в проде не меняется чаще, чем раз в релиз.
//
// Ошибка связи не считается фатальной для вызывающего кода: вместо голого
// error здесь возвращается PanelInfo{Reachable: false, Err: "..."}, чтобы
// админка могла показать причину, а решение "что делать дальше" осталось
// за вызывающим. Сама функция возвращает error только если входной ctx уже
// отменён.
func (c *Client) Info(ctx context.Context) (model.PanelInfo, error) {
	if err := ctx.Err(); err != nil {
		return model.PanelInfo{}, err
	}

	if info, ok := c.cachedInfo(); ok {
		return info, nil
	}

	// Ждём здесь, а не запускаем detectVersion сразу: без этого замка сотня
	// одновременных запросов подписки, заставших остывший кэш, отправит
	// в панель сотню одинаковых проверок версии разом.
	c.updating.Lock()
	defer c.updating.Unlock()
	if info, ok := c.cachedInfo(); ok {
		return info, nil
	}

	info := c.detectVersion(ctx)

	c.infoMu.Lock()
	c.info = info
	c.infoMu.Unlock()

	return info, nil
}

func (c *Client) cachedInfo() (model.PanelInfo, bool) {
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	if c.info.CheckedAt.IsZero() || time.Since(c.info.CheckedAt) >= infoCacheTTL {
		return model.PanelInfo{}, false
	}
	return c.info, true
}

// ensureMajor определяет старшую версию панели: только от неё зависит,
// как собирать идентификатор пользователя в запросах (UpdateUser,
// DeleteDevice). Использует тот же кэш, что и Info().
func (c *Client) ensureMajor(ctx context.Context) (int, error) {
	info, err := c.Info(ctx)
	if err != nil {
		return 0, err
	}
	if !info.Reachable {
		msg := info.Err
		if msg == "" {
			msg = "панель недоступна"
		}
		return 0, fmt.Errorf("remnawave: не определить версию панели: %s", msg)
	}
	if info.Major == 0 {
		return 0, errors.New("remnawave: панель ответила, но версия осталась неизвестна")
	}
	return info.Major, nil
}

// detectVersion выясняет версию панели. Порядок попыток:
//  1. GET /api/system/metadata (с токеном): основной путь, есть в 2.7.4+.
//  2. Если ответ 401/403 (токен не тот, но панель точно жива), подтверждаем
//     достижимость публичным GET /api/auth/status, версию в этом случае
//     узнать не можем, но хотя бы не путаем "неверный токен" с "панель легла".
//  3. Если metadata просто недоступна маршрутом (старая панель, 404, либо
//     сеть ответила ошибкой), определяем старшую версию по форме первого
//     пользователя в /api/users: числовой id есть только в 3.x.
func (c *Client) detectVersion(ctx context.Context) model.PanelInfo {
	now := time.Now()

	var meta metaResponse
	_, metaErr := c.getJSON(ctx, "/api/system/metadata", nil, true, &meta)
	if metaErr == nil && strings.TrimSpace(meta.Version) != "" {
		info := model.PanelInfo{
			Version:   meta.Version,
			Major:     majorFromVersion(meta.Version),
			Reachable: true,
			CheckedAt: now,
		}
		if info.Major >= 3 {
			// Маршрут появился в 3.2.0. На определение старшей версии он не
			// влияет (она уже видна по строке version), но так мы держим его
			// "прогретым" и увидим явную поломку конфигурации в журнале.
			if _, err := c.getJSON(ctx, "/api/system/configuration", nil, true, nil); err != nil {
				c.log.DebugContext(ctx, "remnawave: /api/system/configuration недоступен", "err", err)
			}
		}
		return info
	}

	if metaErr != nil && errors.Is(metaErr, ErrUnauthorized) {
		if _, err := c.getJSON(ctx, "/api/auth/status", nil, false, nil); err == nil {
			// Панель ответила на публичный маршрут без токена, значит она жива,
			// проблема именно в токене. Версию узнать нечем, оставляем 0.
			return model.PanelInfo{Reachable: true, CheckedAt: now, Err: metaErr.Error()}
		}
	}

	major, usersErr := c.detectMajorFromUsers(ctx)
	if usersErr == nil {
		return model.PanelInfo{Major: major, Reachable: true, CheckedAt: now}
	}

	errText := usersErr.Error()
	if metaErr != nil {
		errText = metaErr.Error()
	}
	return model.PanelInfo{Reachable: false, CheckedAt: now, Err: errText}
}

// majorFromVersion достаёт старшую цифру версии из строки вида "3.2.2".
// Пустая или нечисловая строка даёт 0: «не определено».
func majorFromVersion(v string) int {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '.'); i > 0 {
		v = v[:i]
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}
