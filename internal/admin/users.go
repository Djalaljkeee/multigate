package admin

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// panelUnavailableMsg: единая формулировка для всех мест, где нужен Panel,
// а он либо не настроен, либо не отвечает.
const panelUnavailableMsg = "Панель не подключена или недоступна. Проверьте адрес и токен на вкладке «Настройки»."

// usersListPageData: данные вкладки «Пользователи».
type usersListPageData struct {
	pageBase
	Search   string
	Users    []model.PanelUser
	Total    int
	Pager    pagination
	PanelErr string
}

// handleUsersList отдаёт список пользователей панели с поиском и пагинацией.
// Панель может отсутствовать или не отвечать: тогда экран остаётся рабочим
// и просто показывает причину, почему списка нет.
func (h *Handler) handleUsersList(w http.ResponseWriter, r *http.Request, s *session) {
	page := parsePage(r)
	data := usersListPageData{
		pageBase: h.newPageBase(r, s, "Пользователи", "users"),
		Search:   strings.TrimSpace(r.URL.Query().Get("q")),
	}
	if h.panel == nil {
		data.PanelErr = panelUnavailableMsg
		data.Pager = newPagination(r, page, 0)
		h.render(w, http.StatusOK, "users_list.html", data)
		return
	}

	offset := (page - 1) * pageSize
	users, total, err := h.panel.ListUsers(r.Context(), offset, pageSize, data.Search)
	if err != nil {
		h.log.Warn("admin: не получить список пользователей панели", "err", err)
		data.PanelErr = "Не удалось получить список пользователей: " + err.Error()
		data.Pager = newPagination(r, page, 0)
		h.render(w, http.StatusOK, "users_list.html", data)
		return
	}

	data.Users = users
	data.Total = total
	data.Pager = newPagination(r, page, total)
	h.render(w, http.StatusOK, "users_list.html", data)
}

// userCardPageData: данные карточки пользователя.
type userCardPageData struct {
	pageBase
	ShortUUID    string
	User         model.PanelUser
	SquadNames   []string
	Devices      []model.Device
	DevicesErr   string
	PanelErr     string
	UserBlocked  bool
	BlockID      int64
	BlockReason  string
	BlockedHWIDs map[string]model.Override // hwid -> блокировка, для пометки в списке устройств
	ReturnTo     string
}

// handleUserCard показывает карточку одного пользователя: данные из панели,
// его устройства и локальные блокировки прослойки.
func (h *Handler) handleUserCard(w http.ResponseWriter, r *http.Request, s *session) {
	shortUUID := r.PathValue("shortUUID")
	data := userCardPageData{
		pageBase:  h.newPageBase(r, s, "Пользователь", "users"),
		ShortUUID: shortUUID,
		ReturnTo:  currentURL(r),
	}
	if h.panel == nil {
		data.PanelErr = panelUnavailableMsg
		h.render(w, http.StatusOK, "user_card.html", data)
		return
	}

	ctx := r.Context()
	user, err := h.panel.UserByShortUUID(ctx, shortUUID)
	if err != nil {
		h.log.Warn("admin: не получить пользователя панели", "shortUUID", shortUUID, "err", err)
		data.PanelErr = "Не удалось получить пользователя: " + err.Error()
		h.render(w, http.StatusOK, "user_card.html", data)
		return
	}
	data.User = user

	if len(user.Squads) > 0 {
		if squads, err := h.panel.Squads(ctx); err != nil {
			h.log.Warn("admin: не получить список сквадов", "err", err)
		} else {
			data.SquadNames = squadNames(user.Squads, squads)
		}
	}

	if devices, err := h.panel.Devices(ctx, user.Ref); err != nil {
		h.log.Warn("admin: не получить устройства пользователя", "shortUUID", shortUUID, "err", err)
		data.DevicesErr = "Не удалось получить устройства: " + err.Error()
	} else {
		data.Devices = devices
	}

	if o, ok := h.store.FindOverride(ctx, shortUUID, ""); ok {
		data.UserBlocked = true
		data.BlockID = o.ID
		data.BlockReason = o.Reason
	}
	if all, err := h.store.ListOverrides(ctx); err == nil {
		data.BlockedHWIDs = make(map[string]model.Override)
		for _, o := range all {
			if o.HWID != "" && (o.ShortUUID == "" || o.ShortUUID == shortUUID) {
				data.BlockedHWIDs[o.HWID] = o
			}
		}
	}

	h.render(w, http.StatusOK, "user_card.html", data)
}

// squadNames сопоставляет uuid сквадов пользователя с их именами.
// Сквады, которых нет в общем списке (например, удалённые), остаются
// в выдаче как есть: это заметнее, чем молча их пропустить.
func squadNames(uuids []string, all []model.Squad) []string {
	names := make(map[string]string, len(all))
	for _, sq := range all {
		names[sq.UUID] = sq.Name
	}
	out := make([]string, 0, len(uuids))
	for _, u := range uuids {
		if n, ok := names[u]; ok {
			out = append(out, n)
		} else {
			out = append(out, u)
		}
	}
	return out
}

// handleDeviceDelete удаляет устройство пользователя из реестра HWID панели.
func (h *Handler) handleDeviceDelete(w http.ResponseWriter, r *http.Request, s *session) {
	shortUUID := r.PathValue("shortUUID")
	hwid := r.PathValue("hwid")
	cardURL := h.path("/users/" + url.PathEscape(shortUUID))

	if h.panel == nil {
		h.redirectWithFlash(w, r, s, "err", panelUnavailableMsg, cardURL)
		return
	}

	ctx := r.Context()
	user, err := h.panel.UserByShortUUID(ctx, shortUUID)
	if err != nil {
		h.log.Warn("admin: не получить пользователя перед удалением устройства", "shortUUID", shortUUID, "err", err)
		h.redirectWithFlash(w, r, s, "err", "Не удалось найти пользователя: "+err.Error(), cardURL)
		return
	}

	if err := h.panel.DeleteDevice(ctx, user.Ref, hwid); err != nil {
		h.log.Warn("admin: не удалить устройство", "shortUUID", shortUUID, "hwid", hwid, "err", err)
		h.redirectWithFlash(w, r, s, "err", "Не удалось удалить устройство: "+err.Error(), cardURL)
		return
	}

	h.log.Info("admin: устройство удалено", "shortUUID", shortUUID, "hwid", hwid, "by", s.user)
	h.redirectWithFlash(w, r, s, "ok", "Устройство удалено", cardURL)
}
