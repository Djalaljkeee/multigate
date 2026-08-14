package admin

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/qwe8nxtroud/multigate/internal/rules"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// TestSetupWizard проверяет мастер первичной настройки целиком: до него
// админка отправляет на /setup, форма сохраняет логин/пароль/режим и сама
// открывает сессию, а повторный заход на мастер после этого уже недоступен.
func TestSetupWizard(t *testing.T) {
	db := newTestStore(t)
	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	_, body := getBody(t, c, srv.URL+"/admin/setup")
	csrf := extractCSRF(t, body)

	resp, err := c.PostForm(srv.URL+"/admin/setup", url.Values{
		"username":         {"root"},
		"password":         {"first-run-password"},
		"password_confirm": {"first-run-password"},
		"mode":             {"mirror"},
		"mirror_target":    {"panel.example.com"},
		"domain":           {"sub.example.com"},
		"csrf":             {csrf},
	})
	if err != nil {
		t.Fatalf("POST /setup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ожидали 200 после перехода по редиректу мастера, получили %d", resp.StatusCode)
	}

	if got := db.Get(context.Background(), store.KeyInstalled); got != "1" {
		t.Fatalf("после мастера installed должен быть 1, а не %q", got)
	}
	if got := db.Get(context.Background(), store.KeyAdminUser); got != "root" {
		t.Fatalf("логин администратора не сохранился: %q", got)
	}
	if hash := db.Get(context.Background(), store.KeyAdminHash); hash == "" || hash == "first-run-password" {
		t.Fatalf("пароль должен храниться хешем, а не как есть: %q", hash)
	}

	// Мастер сам вошёл в систему: страницы админки уже доступны без нового логина.
	resp2, body2 := getBody(t, c, srv.URL+"/admin/overview")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("после мастера обзор должен быть доступен сразу, получили %d", resp2.StatusCode)
	}
	if !strings.Contains(body2, "Обзор") {
		t.Fatalf("страница обзора не похожа на себя")
	}

	// Повторный заход на мастер больше не работает: настройка уже пройдена.
	// Проверяем именно первый прыжок: дальше клиент и так залогинен, и
	// /login сам увёл бы его на /overview вторым редиректом, это отдельная
	// логика и не то, что здесь проверяется.
	noRedir := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	respSetup, err := noRedir.Get(srv.URL + "/admin/setup")
	if err != nil {
		t.Fatalf("GET /setup повторно: %v", err)
	}
	defer respSetup.Body.Close()
	if respSetup.StatusCode != http.StatusSeeOther {
		t.Fatalf("ожидали 303 на повторный мастер, получили %d", respSetup.StatusCode)
	}
	if loc := respSetup.Header.Get("Location"); !strings.HasSuffix(loc, "/admin/login") {
		t.Fatalf("повторный мастер должен уводить на /login, получили Location %q", loc)
	}
}

// TestHeaderRulesCRUD проверяет собственный слой доступа к таблице
// header_rules (в store для неё пока нет готовых методов, см. headerrules_store.go):
// создание, чтение списка, правку и удаление через настоящий HTTP-путь форм.
func TestHeaderRulesCRUD(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")
	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	_, lbody := getBody(t, c, srv.URL+"/admin/login")
	csrf := extractCSRF(t, lbody)
	resp, err := c.PostForm(srv.URL+"/admin/login", url.Values{
		"username": {"admin"}, "password": {"correct-horse-battery"}, "csrf": {csrf},
	})
	if err != nil {
		t.Fatalf("вход: %v", err)
	}
	resp.Body.Close()

	// Создание правила.
	_, formBody := getBody(t, c, srv.URL+"/admin/headerrules/new")
	csrf = extractCSRF(t, formBody)
	resp, err = c.PostForm(srv.URL+"/admin/headerrules/new", url.Values{
		"name":        {"скрыть сервер"},
		"enabled":     {"on"},
		"priority":    {"50"},
		"match_app":   {"Happ"},
		"set_headers": {"Server: nginx\nX-Powered-By: "},
		"del_headers": {"X-Debug"},
		"csrf":        {csrf},
	})
	if err != nil {
		t.Fatalf("создание правила: %v", err)
	}
	resp.Body.Close()

	rules, err := h.listHeaderRules(context.Background())
	if err != nil {
		t.Fatalf("listHeaderRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("ожидали одно правило, получили %d", len(rules))
	}
	r := rules[0]
	if r.Name != "скрыть сервер" || !r.Enabled || r.Priority != 50 {
		t.Fatalf("правило сохранилось некорректно: %+v", r)
	}
	if r.SetHeader["Server"] != "nginx" {
		t.Fatalf("SetHeader не сохранился: %+v", r.SetHeader)
	}
	if len(r.DelHeader) != 1 || r.DelHeader[0] != "X-Debug" {
		t.Fatalf("DelHeader не сохранился: %+v", r.DelHeader)
	}

	// Список должен отдавать созданное правило и через HTTP.
	_, listBody := getBody(t, c, srv.URL+"/admin/headerrules")
	if !strings.Contains(listBody, "скрыть сервер") {
		t.Fatalf("список правил не показывает созданное правило")
	}

	// Правка.
	editURL := srv.URL + "/admin/headerrules/" + strconv.FormatInt(r.ID, 10)
	_, editBody := getBody(t, c, editURL)
	csrf = extractCSRF(t, editBody)
	resp, err = c.PostForm(editURL, url.Values{
		"name":        {"скрыть сервер v2"},
		"enabled":     {"on"},
		"priority":    {"10"},
		"set_headers": {"Server: nginx"},
		"csrf":        {csrf},
	})
	if err != nil {
		t.Fatalf("правка правила: %v", err)
	}
	resp.Body.Close()

	updated, err := h.getHeaderRule(context.Background(), r.ID)
	if err != nil {
		t.Fatalf("getHeaderRule: %v", err)
	}
	if updated.Name != "скрыть сервер v2" || updated.Priority != 10 {
		t.Fatalf("правка не применилась: %+v", updated)
	}

	// Удаление.
	_, delListBody := getBody(t, c, srv.URL+"/admin/headerrules")
	csrf = extractCSRF(t, delListBody)
	resp, err = c.PostForm(srv.URL+"/admin/headerrules/"+strconv.FormatInt(r.ID, 10)+"/delete", url.Values{"csrf": {csrf}})
	if err != nil {
		t.Fatalf("удаление правила: %v", err)
	}
	resp.Body.Close()

	rules, err = h.listHeaderRules(context.Background())
	if err != nil {
		t.Fatalf("listHeaderRules после удаления: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("после удаления правил не должно остаться, а их %d", len(rules))
	}
}

// TestSetupClosedWhenAdminHashExistsWithoutInstalledFlag проверяет вторую
// линию обороны мастера настройки: если в базе уже есть хеш пароля
// администратора, мастер обязан быть закрыт (редирект на вход), даже когда
// флаг store.KeyInstalled почему-то не выставлен: например, его сбросили
// вручную в базе. Без этой проверки сброс одного флага заново открывает
// мастер на уже сконфигурированном инстансе.
func TestSetupClosedWhenAdminHashExistsWithoutInstalledFlag(t *testing.T) {
	db := newTestStore(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("existing-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if err := db.SetMany(context.Background(), map[string]string{
		store.KeyAdminUser: "root",
		store.KeyAdminHash: string(hash),
		// store.KeyInstalled нарочно не ставим: это и есть проверяемый сценарий.
	}); err != nil {
		t.Fatalf("SetMany: %v", err)
	}

	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := noRedirectClient()
	resp, _ := getBody(t, c, srv.URL+"/admin/setup")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("ожидали 303 на /setup при уже заданном хеше пароля, получили %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "/admin/login") {
		t.Fatalf("ожидали редирект на /admin/login, получили %q", loc)
	}

	// Прямая попытка отправить форму мастера (например, зная csrf со страницы
	// входа) тоже не должна перезаписать администратора.
	jar, _ := cookiejar.New(nil)
	c2 := &http.Client{Jar: jar}
	_, lbody := getBody(t, c2, srv.URL+"/admin/login")
	csrf := extractCSRF(t, lbody)
	resp2, err := c2.PostForm(srv.URL+"/admin/setup", url.Values{
		"username":         {"attacker"},
		"password":         {"attacker-password"},
		"password_confirm": {"attacker-password"},
		"mode":             {"mirror"},
		"mirror_target":    {"evil.example.com"},
		"csrf":             {csrf},
	})
	if err != nil {
		t.Fatalf("POST /setup: %v", err)
	}
	resp2.Body.Close()

	if got := db.Get(context.Background(), store.KeyAdminUser); got != "root" {
		t.Fatalf("администратора перезаписали через открытый мастер настройки: %q", got)
	}
}

// TestHeaderRuleSaveInvalidatesRulesCache проверяет, что после сохранения
// или удаления правила через админку пакет rules (тот же, которым на
// каждом ответе подписки пользуется прокси) видит изменение сразу, а не
// спустя время, пока не протухнет его собственный 30-секундный кэш.
func TestHeaderRuleSaveInvalidatesRulesCache(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")
	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	before, err := rules.Load(context.Background(), db)
	if err != nil {
		t.Fatalf("rules.Load до создания: %v", err)
	}
	if len(before) != 0 {
		t.Fatalf("ожидали пустой список правил до создания, получили %d", len(before))
	}

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	_, lbody := getBody(t, c, srv.URL+"/admin/login")
	csrf := extractCSRF(t, lbody)
	resp, err := c.PostForm(srv.URL+"/admin/login", url.Values{
		"username": {"admin"}, "password": {"correct-horse-battery"}, "csrf": {csrf},
	})
	if err != nil {
		t.Fatalf("вход: %v", err)
	}
	resp.Body.Close()

	_, formBody := getBody(t, c, srv.URL+"/admin/headerrules/new")
	csrf = extractCSRF(t, formBody)
	resp, err = c.PostForm(srv.URL+"/admin/headerrules/new", url.Values{
		"name":        {"тест сброса кэша"},
		"enabled":     {"on"},
		"priority":    {"10"},
		"set_headers": {"Server: nginx"},
		"csrf":        {csrf},
	})
	if err != nil {
		t.Fatalf("создание правила: %v", err)
	}
	resp.Body.Close()

	after, err := rules.Load(context.Background(), db)
	if err != nil {
		t.Fatalf("rules.Load после создания: %v", err)
	}
	if len(after) != 1 {
		t.Fatalf("правило, созданное через админку, не видно пакету rules сразу после сохранения (кэш не сброшен): %d правил", len(after))
	}
	id := after[0].ID

	_, listBody := getBody(t, c, srv.URL+"/admin/headerrules")
	csrf = extractCSRF(t, listBody)
	resp, err = c.PostForm(srv.URL+"/admin/headerrules/"+strconv.FormatInt(id, 10)+"/delete", url.Values{"csrf": {csrf}})
	if err != nil {
		t.Fatalf("удаление правила: %v", err)
	}
	resp.Body.Close()

	afterDelete, err := rules.Load(context.Background(), db)
	if err != nil {
		t.Fatalf("rules.Load после удаления: %v", err)
	}
	if len(afterDelete) != 0 {
		t.Fatalf("правило осталось видно пакету rules после удаления через админку (кэш не сброшен): %d правил", len(afterDelete))
	}
}
