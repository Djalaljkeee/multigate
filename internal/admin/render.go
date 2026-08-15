package admin

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/brand"
	"github.com/qwe8nxtroud/multigate/internal/store"
	"github.com/qwe8nxtroud/multigate/web"
)

// pageBase: поля, общие для всех страниц админки: шапка, меню, CSRF.
// Конкретные страницы встраивают эту структуру и добавляют свои данные;
// html/template видит встроенные поля как обычные (promoted fields).
type pageBase struct {
	Title         string // заголовок вкладки браузера и <h1>
	Active        string // ключ пункта меню, который нужно подсветить
	Base          string // BasePath админки, для ссылок в шаблоне
	CSRF          string
	Flash         *flashMsg
	Mode          string // режим работы (mirror/panel), для индикатора в шапке
	PanelSet      bool   // панель вообще настроена (Deps.Panel != nil)
	Authenticated bool   // показывать общий каркас с меню (иначе форма по центру, как на входе)
}

// templateSet держит по одному скомпилированному дереву шаблонов на страницу.
// Раздельная компиляция нужна потому, что каждая страница определяет блок
// с одинаковым именем "content": если парсить всё одним деревом, поздний
// файл перезапишет более ранний. Так каждая страница получает свою пару
// layout.html + <страница>.html и не мешает соседям.
type templateSet struct {
	pages map[string]*template.Template
}

// pages: файлы шаблонов страниц (без layout.html, он общий для всех).
var pageFiles = []string{
	"login.html",
	"setup.html",
	"overview.html",
	"reqlog.html",
	"users_list.html",
	"user_card.html",
	"overrides.html",
	"headerrules_list.html",
	"headerrules_form.html",
	"settings.html",
	"about.html",
	"error.html",
}

func funcMap() template.FuncMap {
	return template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"fmtTime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Local().Format("02.01.2006 15:04:05")
		},
		"fmtBytes": fmtBytes,
		"yesno": func(b bool) string {
			if b {
				return "да"
			}
			return "нет"
		},
		"decisionRU": decisionRU,
		// decisionOptions отдаёт список решений для выпадающего списка фильтра:
		// в шаблонах Go нет литерала для среза, только встроенный slice()
		// для среза УЖЕ существующего значения, поэтому список строится в коде.
		"decisionOptions": func() []string {
			return []string{"normal", "blocked", "expired", "notfound", "decoy", "error"}
		},
		"statusClass": func(status int) string {
			switch {
			case status >= 500:
				return "st-err"
			case status >= 400:
				return "st-warn"
			case status >= 200:
				return "st-ok"
			default:
				return ""
			}
		},
		"dict": tplDict,
		// brand отдаёт шаблону атрибуцию автора и список продуктов из одного
		// источника (пакет brand), чтобы футер и страница «О системе» не
		// держали свои копии текста и ссылок.
		"brand": brand.Get,
	}
}

// tplDict собирает map[string]any из чередующихся ключ/значение: удобно,
// когда partial-шаблону нужно больше одного параметра.
func tplDict(pairs ...any) (map[string]any, error) {
	if len(pairs)%2 != 0 {
		return nil, fmt.Errorf("admin: dict ожидает чётное число аргументов")
	}
	out := make(map[string]any, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		key, ok := pairs[i].(string)
		if !ok {
			return nil, fmt.Errorf("admin: ключ dict должен быть строкой")
		}
		out[key] = pairs[i+1]
	}
	return out, nil
}

// fmtBytes переводит число байт в короткую человекочитаемую строку.
// Свой велосипед вместо go-humanize: пакет ничего не тянет и не стоит
// заводить внешнюю зависимость ради одной функции форматирования.
func fmtBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d Б", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	units := []string{"КБ", "МБ", "ГБ", "ТБ", "ПБ"}
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), units[exp])
}

// decisionRU переводит значения model.Decision в понятную подпись таблицы.
func decisionRU(d string) string {
	switch d {
	case "normal":
		return "выдана"
	case "blocked":
		return "заблокирован"
	case "expired":
		return "истёк срок"
	case "notfound":
		return "не найден"
	case "decoy":
		return "маскировка"
	case "error":
		return "сбой апстрима"
	default:
		return d
	}
}

// parseTemplates компилирует каждую страницу вместе с общим layout.html.
func parseTemplates() (*templateSet, error) {
	sub, err := fs.Sub(web.TemplatesFS, "templates")
	if err != nil {
		return nil, fmt.Errorf("admin: не открыть каталог шаблонов: %w", err)
	}

	ts := &templateSet{pages: make(map[string]*template.Template, len(pageFiles))}
	for _, name := range pageFiles {
		// common.html несёт переиспользуемые куски (пагинация и т.п.) и подключается
		// к каждой странице так же, как layout.html: отдельным файлом, а не через
		// один общий ParseFS по всей директории: иначе все страницы, определяющие
		// {{define "content"}}, перезаписывали бы друг друга в одном дереве.
		t, err := template.New("layout.html").Funcs(funcMap()).ParseFS(sub, "layout.html", "common.html", name)
		if err != nil {
			return nil, fmt.Errorf("admin: не разобрать шаблон %s: %w", name, err)
		}
		ts.pages[name] = t
	}
	return ts, nil
}

// render рисует страницу целиком в буфер и только потом пишет её в ответ:
// так ошибка на середине шаблона не уходит клиенту вперемешку с кодом 200.
func (h *Handler) render(w http.ResponseWriter, status int, page string, data any) {
	t, ok := h.tmpl.pages[page]
	if !ok {
		h.log.Error("admin: неизвестный шаблон страницы", slog.String("page", page))
		http.Error(w, "внутренняя ошибка шаблона", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", data); err != nil {
		h.log.Error("admin: ошибка рендера шаблона", slog.String("page", page), slog.Any("err", err))
		http.Error(w, "внутренняя ошибка шаблона", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// errorPageData: данные страницы «что-то пошло не так».
type errorPageData struct {
	pageBase
	Code    int
	Message string
}

// renderError показывает страницу ошибки внутри общего оформления вместо
// голого http.Error: администратор не должен видеть текст без вёрстки.
func (h *Handler) renderError(w http.ResponseWriter, r *http.Request, s *session, code int, msg string) {
	h.render(w, code, "error.html", errorPageData{
		pageBase: h.newPageBase(r, s, "Ошибка", ""),
		Code:     code,
		Message:  msg,
	})
}

// newPageBase собирает общие поля шапки для конкретной страницы.
func (h *Handler) newPageBase(r *http.Request, s *session, title, active string) pageBase {
	pb := pageBase{
		Title:    title,
		Active:   active,
		Base:     h.base,
		Mode:     h.store.Get(r.Context(), store.KeyMode),
		PanelSet: h.panel != nil,
	}
	if s != nil {
		pb.CSRF = s.csrf
		pb.Flash = h.sessions.takeFlash(s.id)
		pb.Authenticated = s.authenticated()
	}
	return pb
}

// redirectWithFlash выставляет одноразовое сообщение в сессию и уводит
// клиента на указанный путь. Используется после обработки POST-форм,
// чтобы обновление страницы не отправляло форму повторно.
func (h *Handler) redirectWithFlash(w http.ResponseWriter, r *http.Request, s *session, kind, text, to string) {
	if s != nil {
		h.sessions.setFlash(s.id, kind, text)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}
