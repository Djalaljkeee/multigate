package proxy

import (
	"context"
	"net/http"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// afterExpiry пробует грейс для истёкшей подписки и, если он применился,
// перезабирает подписку у апстрима заново.
//
// Тело и заголовки в up сняты ДО грейса и всё ещё отражают старое
// состояние пользователя (старый сквад, старый expire) - грейс меняет их
// прямо в панели (см. пакет grace), поэтому единственный способ отдать
// клиенту рабочую подписку, это забрать её ещё раз. Если грейс выключен,
// не положен пользователю, панель недоступна или сам грейс не удался, up
// возвращается без изменений: finalize следом сам обнаружит истёкший срок
// и отдаст заглушку - ровно то поведение, которое было бы и без этой
// функции. Ошибка на любом из шагов только уходит в журнал процесса,
// подписка не должна ломаться из-за проблем с грейсом.
func (h *Handler) afterExpiry(ctx context.Context, mode model.Mode, shortUUID, suffix string, r *http.Request, ip string, up upstream) upstream {
	if h.deps.Grace == nil || h.deps.Panel == nil {
		return up
	}
	if !h.deps.Store.GetBool(ctx, store.KeyGraceEnabled) {
		return up
	}
	if !parseUserInfo(up.header.Get("Subscription-Userinfo")).IsExpired(time.Now()) {
		return up
	}

	// Грейс - это ещё 2-3 похода в панель (пользователь, обновление
	// сквада/срока, повторная подписка) поверх уже потраченного бюджета на
	// первый fetch, поэтому берём отдельный таймаут от родительского
	// контекста запроса, а не остаток контекста первого fetch: иначе на
	// небыстрой панели грейс почти никогда не успевал бы выполниться целиком.
	timeout := h.deps.Store.GetDuration(ctx, store.KeyUpstreamTimeout, 15*time.Second)
	gctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pu, err := h.deps.Panel.UserByShortUUID(gctx, shortUUID)
	if err != nil {
		h.deps.Logger.Warn("proxy: грейс недоступен, панель не отвечает на запрос пользователя",
			"short_uuid", shortUUID, "err", err)
		return up
	}

	applied, err := h.deps.Grace.Maybe(gctx, pu)
	if err != nil {
		// Осторожно: грейс пишет в живую панель клиента. Ошибка здесь не
		// должна портить выдачу - клиент получит обычную заглушку истёкшей
		// подписки, как будто грейса нет вовсе.
		h.deps.Logger.Warn("proxy: грейс не применился, отдаю заглушку истёкшей подписки",
			"short_uuid", shortUUID, "err", err)
		return up
	}
	if !applied {
		return up
	}

	var (
		fresh upstream
		ferr  error
	)
	switch mode {
	case model.ModePanel:
		fresh, ferr = h.fetchPanel(gctx, shortUUID, suffix, r.Header)
	default:
		fresh, ferr = h.fetchMirror(gctx, r, ip)
	}
	if ferr != nil {
		h.deps.Logger.Warn("proxy: грейс применился, но повторно забрать подписку не удалось",
			"short_uuid", shortUUID, "err", ferr)
		return up
	}
	return fresh
}
