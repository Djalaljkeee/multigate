package admin

import (
	"net/http"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// reqLogPageData: данные вкладки «Журнал запросов».
type reqLogPageData struct {
	pageBase
	Filter   store.ReqLogFilter
	SinceStr string
	UntilStr string
	Rows     []model.RequestLog
	Total    int
	Pager    pagination
	ReturnTo string
}

// handleReqLog отдаёт журнал запросов с фильтрами и постраничным выводом.
func (h *Handler) handleReqLog(w http.ResponseWriter, r *http.Request, s *session) {
	q := r.URL.Query()
	page := parsePage(r)
	since := parseLocalDateTime(q.Get("since"))
	until := parseLocalDateTime(q.Get("until"))

	f := store.ReqLogFilter{
		ShortUUID: strings.TrimSpace(q.Get("short_uuid")),
		HWID:      strings.TrimSpace(q.Get("hwid")),
		IP:        strings.TrimSpace(q.Get("ip")),
		App:       strings.TrimSpace(q.Get("app")),
		Decision:  strings.TrimSpace(q.Get("decision")),
		Search:    strings.TrimSpace(q.Get("q")),
		Since:     since,
		Until:     until,
		Limit:     pageSize,
		Offset:    (page - 1) * pageSize,
	}

	rows, total, err := h.store.ListRequestLog(r.Context(), f)
	if err != nil {
		h.log.Error("admin: не прочитать журнал запросов", "err", err)
		h.renderError(w, r, s, http.StatusInternalServerError, "Не удалось прочитать журнал запросов")
		return
	}

	data := reqLogPageData{
		pageBase: h.newPageBase(r, s, "Журнал запросов", "reqlog"),
		Filter:   f,
		SinceStr: formatLocalDateTime(since),
		UntilStr: formatLocalDateTime(until),
		Rows:     rows,
		Total:    total,
		Pager:    newPagination(r, page, total),
		ReturnTo: currentURL(r),
	}
	h.render(w, http.StatusOK, "reqlog.html", data)
}

// handleReqLogBlock: быстрые кнопки «заблокировать устройство/пользователя»
// прямо из строки журнала. Действие всегда «block»: снятие блокировки
// делается осознанно, с вкладки «Блокировки».
func (h *Handler) handleReqLogBlock(w http.ResponseWriter, r *http.Request, s *session) {
	kind := r.PostFormValue("kind")
	value := strings.TrimSpace(r.PostFormValue("value"))
	returnTo := safeNext(r.PostFormValue("return"), h.base)

	if value == "" {
		h.redirectWithFlash(w, r, s, "err", "Не указано, что блокировать", returnTo)
		return
	}

	o := model.Override{
		Action:    "block",
		Reason:    "добавлено из журнала запросов",
		CreatedBy: s.user,
	}
	switch kind {
	case "device":
		o.HWID = value
	case "user":
		o.ShortUUID = value
	default:
		h.redirectWithFlash(w, r, s, "err", "Неизвестный тип блокировки", returnTo)
		return
	}

	if _, err := h.store.AddOverride(r.Context(), o); err != nil {
		h.log.Error("admin: не добавить блокировку из журнала", "err", err)
		h.redirectWithFlash(w, r, s, "err", "Не удалось сохранить блокировку", returnTo)
		return
	}

	h.log.Info("admin: блокировка добавлена из журнала", "kind", kind, "value", value, "by", s.user)
	h.redirectWithFlash(w, r, s, "ok", "Блокировка добавлена", returnTo)
}
