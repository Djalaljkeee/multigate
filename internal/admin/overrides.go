package admin

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// overridesPageData: данные вкладки «Блокировки».
type overridesPageData struct {
	pageBase
	Overrides []model.Override
	Error     string
}

// handleOverridesList показывает все локальные блокировки.
func (h *Handler) handleOverridesList(w http.ResponseWriter, r *http.Request, s *session) {
	list, err := h.store.ListOverrides(r.Context())
	if err != nil {
		h.log.Error("admin: не прочитать блокировки", "err", err)
		h.renderError(w, r, s, http.StatusInternalServerError, "Не удалось прочитать список блокировок")
		return
	}
	h.render(w, http.StatusOK, "overrides.html", overridesPageData{
		pageBase:  h.newPageBase(r, s, "Блокировки", "overrides"),
		Overrides: list,
	})
}

// handleOverrideAdd создаёт локальную блокировку по пользователю или устройству.
// Форма используется и на вкладке «Блокировки», и с карточки пользователя,
// в обоих случаях после сохранения возвращаемся туда, откуда пришли.
func (h *Handler) handleOverrideAdd(w http.ResponseWriter, r *http.Request, s *session) {
	returnTo := safeNext(r.PostFormValue("return"), h.base)
	if returnTo == fallbackNext(h.base) {
		returnTo = h.path("/overrides")
	}

	shortUUID := strings.TrimSpace(r.PostFormValue("short_uuid"))
	hwid := strings.TrimSpace(r.PostFormValue("hwid"))
	action := r.PostFormValue("action")
	reason := strings.TrimSpace(r.PostFormValue("reason"))

	if shortUUID == "" && hwid == "" {
		h.redirectWithFlash(w, r, s, "err", "Укажите shortUuid или HWID, иначе непонятно, кого блокировать", returnTo)
		return
	}
	if action != "allow" {
		action = "block"
	}

	_, err := h.store.AddOverride(r.Context(), model.Override{
		ShortUUID: shortUUID,
		HWID:      hwid,
		Action:    action,
		Reason:    reason,
		CreatedBy: s.user,
	})
	if err != nil {
		h.log.Error("admin: не добавить блокировку", "err", err)
		h.redirectWithFlash(w, r, s, "err", "Не удалось сохранить блокировку", returnTo)
		return
	}

	h.log.Info("admin: блокировка добавлена", "shortUUID", shortUUID, "hwid", hwid, "action", action, "by", s.user)
	h.redirectWithFlash(w, r, s, "ok", "Блокировка сохранена", returnTo)
}

// handleOverrideDelete снимает блокировку.
func (h *Handler) handleOverrideDelete(w http.ResponseWriter, r *http.Request, s *session) {
	returnTo := safeNext(r.PostFormValue("return"), h.base)
	if returnTo == fallbackNext(h.base) {
		returnTo = h.path("/overrides")
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		h.redirectWithFlash(w, r, s, "err", "Некорректный идентификатор блокировки", returnTo)
		return
	}

	if err := h.store.DeleteOverride(r.Context(), id); err != nil {
		h.log.Error("admin: не удалить блокировку", "id", id, "err", err)
		h.redirectWithFlash(w, r, s, "err", "Не удалось снять блокировку", returnTo)
		return
	}

	h.log.Info("admin: блокировка снята", "id", id, "by", s.user)
	h.redirectWithFlash(w, r, s, "ok", "Блокировка снята", returnTo)
}
