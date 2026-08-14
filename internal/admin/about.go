package admin

import (
	"fmt"
	"net/http"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/version"
)

// tableCount: число строк в одной таблице базы, для списка на вкладке «О системе».
type tableCount struct {
	Table string
	Rows  int64
}

// aboutPageData: данные вкладки «О системе».
type aboutPageData struct {
	pageBase
	Full         string // version.Full()
	Uptime       string
	Dialect      string
	DBBytes      int64
	Tables       []tableCount
	PanelInfo    model.PanelInfo
	PanelCallErr string
	PanelStats   map[string]any
}

// таблицы, по которым отдельно показываем число строк на вкладке «О системе».
// Порядок фиксированный, чтобы список не прыгал между обновлениями.
var aboutTables = []string{"request_log", "webhook_log", "overrides", "grace_users", "wg_leases", "chat_messages"}

// handleAbout: версия сборки, аптайм, состояние базы и панели.
func (h *Handler) handleAbout(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	data := aboutPageData{
		pageBase: h.newPageBase(r, s, "О системе", "about"),
		Full:     version.Full(),
		Uptime:   formatUptime(time.Since(h.startedAt)),
		Dialect:  string(h.store.Dialect()),
	}

	if st, err := h.store.Stats(ctx); err != nil {
		h.log.Warn("admin: не получить статистику базы", "err", err)
	} else {
		data.DBBytes = st["db_bytes"]
		for _, t := range aboutTables {
			data.Tables = append(data.Tables, tableCount{Table: t, Rows: st[t]})
		}
	}

	if h.panel != nil {
		info, err := h.panel.Info(ctx)
		if err != nil {
			data.PanelCallErr = err.Error()
		}
		data.PanelInfo = info
		if stats, err := h.panel.SystemStats(ctx); err != nil {
			h.log.Warn("admin: не получить статистику панели", "err", err)
		} else {
			data.PanelStats = stats
		}
	}

	h.render(w, http.StatusOK, "about.html", data)
}

// formatUptime переводит длительность в короткую строку вида "3д 04:12:05".
func formatUptime(d time.Duration) string {
	d = d.Round(time.Second)
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	d -= minutes * time.Minute
	seconds := d / time.Second

	if days > 0 {
		return fmt.Sprintf("%dд %02d:%02d:%02d", days, hours, minutes, seconds)
	}
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}
