package admin

import (
	"net/http"
	"sort"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// appCount: строка разбивки запросов по приложениям.
type appCount struct {
	App   string
	Count int
}

// overviewPageData: данные вкладки «Обзор».
type overviewPageData struct {
	pageBase
	PanelInfo    model.PanelInfo
	PanelCallErr string // ошибка самого вызова Panel.Info, отдельно от PanelInfo.Err
	Requests24h  int64
	TopApps      []appCount
	DBBytes      int64
	LogDrops     int64
}

// handleOverview: сводка состояния прослойки на одном экране.
func (h *Handler) handleOverview(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	data := overviewPageData{
		pageBase: h.newPageBase(r, s, "Обзор", "overview"),
	}

	if h.panel != nil {
		info, err := h.panel.Info(ctx)
		if err != nil {
			data.PanelCallErr = err.Error()
		}
		data.PanelInfo = info
	}

	since := time.Now().Add(-24 * time.Hour)
	if n, err := h.store.CountRequests(ctx, since); err != nil {
		h.log.Warn("admin: не посчитать запросы за сутки", "err", err)
	} else {
		data.Requests24h = n
	}

	if top, err := h.store.TopClients(ctx, since, 12); err != nil {
		h.log.Warn("admin: не посчитать разбивку по приложениям", "err", err)
	} else {
		data.TopApps = sortAppCounts(top)
	}

	if st, err := h.store.Stats(ctx); err != nil {
		h.log.Warn("admin: не получить статистику базы", "err", err)
	} else {
		data.DBBytes = st["db_bytes"]
	}

	data.LogDrops = h.reqLog.Drops()

	h.render(w, http.StatusOK, "overview.html", data)
}

// sortAppCounts переводит карту в срез, отсортированный по убыванию
// количества запросов: карты в Go не гарантируют порядок обхода,
// а таблице на странице нужен стабильный вид при каждом обновлении.
func sortAppCounts(m map[string]int) []appCount {
	out := make([]appCount, 0, len(m))
	for app, n := range m {
		out = append(out, appCount{App: app, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].App < out[j].App
	})
	return out
}
