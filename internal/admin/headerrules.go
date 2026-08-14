package admin

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// headerRulesListData: данные вкладки «Правила заголовков».
type headerRulesListData struct {
	pageBase
	Rules []model.HeaderRule
}

// handleHeaderRulesList показывает все правила подмены заголовков.
func (h *Handler) handleHeaderRulesList(w http.ResponseWriter, r *http.Request, s *session) {
	rules, err := h.listHeaderRules(r.Context())
	if err != nil {
		h.log.Error("admin: не прочитать правила заголовков", "err", err)
		h.renderError(w, r, s, http.StatusInternalServerError, "Не удалось прочитать правила заголовков")
		return
	}
	h.render(w, http.StatusOK, "headerrules_list.html", headerRulesListData{
		pageBase: h.newPageBase(r, s, "Правила заголовков", "headerrules"),
		Rules:    rules,
	})
}

// headerRuleFormData: данные формы создания/правки правила.
type headerRuleFormData struct {
	pageBase
	Editing bool
	ID      int64
	Form    headerRuleForm
	Error   string
}

// headerRuleForm: текстовое представление правила для полей формы.
// SetHeader и DelHeader в модели: map и slice, в форме это построчный текст:
// так проще редактировать руками, чем городить JSON-редактор на голом JS.
type headerRuleForm struct {
	Name     string
	Enabled  bool
	Priority int
	MatchApp string
	MatchOS  string
	MatchUA  string
	UARegex  bool
	SetLines string
	DelLines string
}

// handleHeaderRuleNewForm показывает форму создания нового правила.
func (h *Handler) handleHeaderRuleNewForm(w http.ResponseWriter, r *http.Request, s *session) {
	h.render(w, http.StatusOK, "headerrules_form.html", headerRuleFormData{
		pageBase: h.newPageBase(r, s, "Новое правило заголовков", "headerrules"),
		Form:     headerRuleForm{Enabled: true, Priority: 100},
	})
}

// handleHeaderRuleCreate сохраняет новое правило.
func (h *Handler) handleHeaderRuleCreate(w http.ResponseWriter, r *http.Request, s *session) {
	form, rule, errMsg := parseHeaderRuleForm(r)
	if errMsg != "" {
		h.render(w, http.StatusUnprocessableEntity, "headerrules_form.html", headerRuleFormData{
			pageBase: h.newPageBase(r, s, "Новое правило заголовков", "headerrules"),
			Form:     form,
			Error:    errMsg,
		})
		return
	}

	id, err := h.createHeaderRule(r.Context(), rule)
	if err != nil {
		h.log.Error("admin: не создать правило заголовков", "err", err)
		h.render(w, http.StatusInternalServerError, "headerrules_form.html", headerRuleFormData{
			pageBase: h.newPageBase(r, s, "Новое правило заголовков", "headerrules"),
			Form:     form,
			Error:    "Не удалось сохранить правило",
		})
		return
	}

	h.log.Info("admin: правило заголовков создано", "id", id, "name", rule.Name, "by", s.user)
	h.redirectWithFlash(w, r, s, "ok", "Правило создано", h.path("/headerrules"))
}

// handleHeaderRuleEditForm показывает форму правки существующего правила.
func (h *Handler) handleHeaderRuleEditForm(w http.ResponseWriter, r *http.Request, s *session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		h.renderError(w, r, s, http.StatusBadRequest, "Некорректный идентификатор правила")
		return
	}
	rule, err := h.getHeaderRule(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		h.renderError(w, r, s, http.StatusNotFound, "Такого правила нет")
		return
	}
	if err != nil {
		h.log.Error("admin: не прочитать правило заголовков", "id", id, "err", err)
		h.renderError(w, r, s, http.StatusInternalServerError, "Не удалось прочитать правило")
		return
	}

	h.render(w, http.StatusOK, "headerrules_form.html", headerRuleFormData{
		pageBase: h.newPageBase(r, s, "Правка правила заголовков", "headerrules"),
		Editing:  true,
		ID:       rule.ID,
		Form:     headerRuleToForm(rule),
	})
}

// handleHeaderRuleUpdate сохраняет изменения существующего правила.
func (h *Handler) handleHeaderRuleUpdate(w http.ResponseWriter, r *http.Request, s *session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		h.renderError(w, r, s, http.StatusBadRequest, "Некорректный идентификатор правила")
		return
	}

	form, rule, errMsg := parseHeaderRuleForm(r)
	rule.ID = id
	if errMsg != "" {
		h.render(w, http.StatusUnprocessableEntity, "headerrules_form.html", headerRuleFormData{
			pageBase: h.newPageBase(r, s, "Правка правила заголовков", "headerrules"),
			Editing:  true,
			ID:       id,
			Form:     form,
			Error:    errMsg,
		})
		return
	}

	if err := h.updateHeaderRule(r.Context(), rule); err != nil {
		h.log.Error("admin: не сохранить правило заголовков", "id", id, "err", err)
		h.render(w, http.StatusInternalServerError, "headerrules_form.html", headerRuleFormData{
			pageBase: h.newPageBase(r, s, "Правка правила заголовков", "headerrules"),
			Editing:  true,
			ID:       id,
			Form:     form,
			Error:    "Не удалось сохранить правило",
		})
		return
	}

	h.log.Info("admin: правило заголовков изменено", "id", id, "by", s.user)
	h.redirectWithFlash(w, r, s, "ok", "Правило сохранено", h.path("/headerrules"))
}

// handleHeaderRuleDelete удаляет правило.
func (h *Handler) handleHeaderRuleDelete(w http.ResponseWriter, r *http.Request, s *session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		h.redirectWithFlash(w, r, s, "err", "Некорректный идентификатор правила", h.path("/headerrules"))
		return
	}
	if err := h.deleteHeaderRule(r.Context(), id); err != nil {
		h.log.Error("admin: не удалить правило заголовков", "id", id, "err", err)
		h.redirectWithFlash(w, r, s, "err", "Не удалось удалить правило", h.path("/headerrules"))
		return
	}
	h.log.Info("admin: правило заголовков удалено", "id", id, "by", s.user)
	h.redirectWithFlash(w, r, s, "ok", "Правило удалено", h.path("/headerrules"))
}

// parseHeaderRuleForm читает форму и одновременно проверяет её: возвращает
// текстовое представление (чтобы вернуть в форму при ошибке), саму модель
// и текст ошибки (пустой, если всё разобралось).
func parseHeaderRuleForm(r *http.Request) (headerRuleForm, model.HeaderRule, string) {
	priority, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("priority")))
	form := headerRuleForm{
		Name:     strings.TrimSpace(r.PostFormValue("name")),
		Enabled:  r.PostFormValue("enabled") != "",
		Priority: priority,
		MatchApp: strings.TrimSpace(r.PostFormValue("match_app")),
		MatchOS:  strings.TrimSpace(r.PostFormValue("match_os")),
		MatchUA:  strings.TrimSpace(r.PostFormValue("match_ua")),
		UARegex:  r.PostFormValue("ua_regex") != "",
		SetLines: r.PostFormValue("set_headers"),
		DelLines: r.PostFormValue("del_headers"),
	}

	if form.Name == "" {
		return form, model.HeaderRule{}, "Укажите название правила"
	}

	setHeader, err := parseHeaderSetLines(form.SetLines)
	if err != nil {
		return form, model.HeaderRule{}, err.Error()
	}
	delHeader := parseHeaderDelLines(form.DelLines)
	if len(setHeader) == 0 && len(delHeader) == 0 {
		return form, model.HeaderRule{}, "Укажите хотя бы один заголовок для замены или удаления"
	}

	rule := model.HeaderRule{
		Name:      form.Name,
		Enabled:   form.Enabled,
		Priority:  form.Priority,
		MatchApp:  form.MatchApp,
		MatchOS:   form.MatchOS,
		MatchUA:   form.MatchUA,
		UARegex:   form.UARegex,
		SetHeader: setHeader,
		DelHeader: delHeader,
	}
	return form, rule, ""
}

// parseHeaderSetLines разбирает построчный ввод "Имя: значение" в карту.
func parseHeaderSetLines(text string) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, errors.New("строка «" + line + "» не в формате «Заголовок: значение»")
		}
		out[name] = strings.TrimSpace(value)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// parseHeaderDelLines разбирает построчный ввод имён заголовков на удаление.
func parseHeaderDelLines(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// headerRuleToForm: обратное преобразование для формы правки: карта и срез
// заголовков сериализуются обратно в построчный текст.
func headerRuleToForm(r model.HeaderRule) headerRuleForm {
	keys := make([]string, 0, len(r.SetHeader))
	for k := range r.SetHeader {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var setLines strings.Builder
	for _, k := range keys {
		if setLines.Len() > 0 {
			setLines.WriteByte('\n')
		}
		setLines.WriteString(k + ": " + r.SetHeader[k])
	}

	return headerRuleForm{
		Name:     r.Name,
		Enabled:  r.Enabled,
		Priority: r.Priority,
		MatchApp: r.MatchApp,
		MatchOS:  r.MatchOS,
		MatchUA:  r.MatchUA,
		UARegex:  r.UARegex,
		SetLines: setLines.String(),
		DelLines: strings.Join(r.DelHeader, "\n"),
	}
}
