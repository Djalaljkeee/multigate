// Package landing отдаёт страницу-маскировку тем, кто пришёл на адрес
// подписки браузером, а не клиентом. Смысл: домен прослойки не должен
// выглядеть как сервис подписок при случайном заходе, сканировании портов
// или автоматическом аудите доменов.
//
// Решение "показывать маскировку или нет" (model.DecisionDecoy) принимает
// вызывающий код на основе разбора User-Agent, этот пакет только рендерит
// уже выбранную страницу и ничего не знает про клиентов подписки.
//
// Все темы встроены в бинарник через embed.FS: ни одной внешней ссылки,
// шрифта или скрипта. Продукт ставят и на серверы без выхода в интернет.
package landing

import (
	"embed"
	"net/http"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

//go:embed themes/*.html
var themesFS embed.FS

// defaultTheme используется, если настройка пуста или ссылается на
// несуществующую тему. Пустая страница ничем не рискует: её нельзя
// перепутать вообще ни с чем.
const defaultTheme = "blank"

// themeFiles сопоставляет имя темы (значение store.KeyDecoyTheme) файлу
// внутри встроенной ФС.
var themeFiles = map[string]string{
	"blank":       "themes/blank.html",
	"maintenance": "themes/maintenance.html",
	"parking":     "themes/parking.html",
}

// robotsTxt запрещает индексацию целиком. У прослойки нет содержимого,
// которое имело бы смысл индексировать, а попадание адреса подписки
// в поисковую выдачу само по себе риск.
const robotsTxt = "User-agent: *\nDisallow: /\n"

// New отдаёт обработчик страницы-маскировки. Тема читается из настройки
// store.KeyDecoyTheme на каждый запрос, поэтому смена оформления в
// админке действует сразу, без перезапуска процесса.
func New(db *store.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ставим на любой ответ этого обработчика, включая сам robots.txt:
		// лишним точно не будет.
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Cache-Control", "no-store")

		if strings.HasSuffix(r.URL.Path, "/robots.txt") {
			serveRobots(w)
			return
		}
		servePage(w, r, db)
	})
}

func serveRobots(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(robotsTxt))
}

func servePage(w http.ResponseWriter, r *http.Request, db *store.DB) {
	theme := defaultTheme
	if db != nil {
		if v := strings.TrimSpace(db.Get(r.Context(), store.KeyDecoyTheme)); v != "" {
			theme = v
		}
	}
	path, ok := themeFiles[theme]
	if !ok {
		// Неизвестное значение настройки (опечатка, старая версия темы):
		// молча откатываемся на дефолт, а не отдаём ошибку. Страница,
		// которая иногда 500-тит, куда подозрительнее любой заглушки.
		path = themeFiles[defaultTheme]
	}

	body, err := themesFS.ReadFile(path)
	if err != nil {
		// Сюда можно попасть только если themeFiles рассинхронизировался со
		// встроенными файлами: это ошибка сборки пакета, а не запроса.
		// Пустой ответ безопаснее любого текста с намёком на причину.
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
