package remnawave

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestRawUser_ToPanelUser_V2UsesUUIDAsRef(t *testing.T) {
	raw := rawUser{
		UUID:      "11111111-1111-1111-1111-111111111111",
		ShortUUID: "short1",
		Username:  "vasya",
		Status:    "ACTIVE",
	}
	u := raw.toPanelUser(2)
	if u.Ref != raw.UUID {
		t.Fatalf("на 2.x Ref должен быть uuid: got %q", u.Ref)
	}
	if u.UUID != raw.UUID || u.ShortUUID != raw.ShortUUID || u.Username != raw.Username {
		t.Fatalf("поля не перенеслись: %+v", u)
	}
	if !u.IsActive() {
		t.Fatal("статус ACTIVE должен считаться активным")
	}
}

func TestRawUser_ToPanelUser_V3UsesIDAsRef(t *testing.T) {
	raw := rawUser{
		ID:        json.Number("42"),
		UUID:      "11111111-1111-1111-1111-111111111111",
		ShortUUID: "short1",
		Username:  "vasya",
	}
	u := raw.toPanelUser(3)
	if u.Ref != "42" {
		t.Fatalf("на 3.x Ref должен быть числовой id строкой: got %q", u.Ref)
	}
	// UUID заполняется в любом случае, если панель его прислала: пригодится
	// для отображения в админке даже когда обращаться нужно по id.
	if u.UUID != raw.UUID {
		t.Fatalf("UUID должен сохраниться даже когда Ref = id: got %q", u.UUID)
	}
}

func TestRawUser_ToPanelUser_V3WithoutIDFallsBackToUUID(t *testing.T) {
	// Оборонительный случай: если панель заявила себя как 3.x, но конкретный
	// ответ id не содержит, не должны падать в пустой Ref.
	raw := rawUser{UUID: "uuid-only"}
	u := raw.toPanelUser(3)
	if u.Ref != "uuid-only" {
		t.Fatalf("без id ожидал откат на uuid: got %q", u.Ref)
	}
}

func TestRawUser_ToPanelUser_SquadsAndExpire(t *testing.T) {
	raw := rawUser{
		ExpireAt:     json.RawMessage(`"2026-01-01T00:00:00Z"`),
		ActiveSquads: []squadRef{{UUID: "sq-1"}, {UUID: "sq-2"}},
	}
	u := raw.toPanelUser(2)
	if len(u.Squads) != 2 || u.Squads[0] != "sq-1" || u.Squads[1] != "sq-2" {
		t.Fatalf("сквады не перенеслись: %+v", u.Squads)
	}
	if u.ExpireAt.IsZero() {
		t.Fatal("ExpireAt не должен быть нулевым")
	}

	raw2 := rawUser{Squads: []squadRef{{UUID: "sq-legacy"}}}
	u2 := raw2.toPanelUser(2)
	if len(u2.Squads) != 1 || u2.Squads[0] != "sq-legacy" {
		t.Fatalf("запасное поле internalSquads не сработало: %+v", u2.Squads)
	}
}

func TestParseTime_Formats(t *testing.T) {
	cases := []json.RawMessage{
		json.RawMessage(`"2026-01-01T00:00:00Z"`),
		json.RawMessage(`1767225600`),    // unix-секунды
		json.RawMessage(`1767225600000`), // unix-миллисекунды
	}
	for _, raw := range cases {
		if got := parseTime(raw); got.IsZero() {
			t.Errorf("parseTime(%s) вернул нулевое время", raw)
		}
	}
	if got := parseTime(json.RawMessage(`null`)); !got.IsZero() {
		t.Errorf("parseTime(null) должен быть нулевым, got %v", got)
	}
	if got := parseTime(json.RawMessage(`""`)); !got.IsZero() {
		t.Errorf(`parseTime("") должен быть нулевым, got %v`, got)
	}
	if got := parseTime(nil); !got.IsZero() {
		t.Errorf("parseTime(nil) должен быть нулевым, got %v", got)
	}
}

func TestParseUsersPage_ObjectAndArray(t *testing.T) {
	page, err := parseUsersPage(json.RawMessage(`{"users":[{"username":"a"}],"total":7}`))
	if err != nil {
		t.Fatalf("object form: %v", err)
	}
	if page.Total != 7 || len(page.Users) != 1 {
		t.Fatalf("object form: %+v", page)
	}

	page2, err := parseUsersPage(json.RawMessage(`[{"username":"a"},{"username":"b"}]`))
	if err != nil {
		t.Fatalf("array form: %v", err)
	}
	if len(page2.Users) != 2 {
		t.Fatalf("array form: %+v", page2)
	}

	page3, err := parseUsersPage(json.RawMessage(`{"users":[],"total":0}`))
	if err != nil {
		t.Fatalf("empty page form: %v", err)
	}
	if len(page3.Users) != 0 {
		t.Fatalf("empty page form: %+v", page3)
	}
}

// TestListUsers_V2_QueryAndRef проверяет, что ListUsers шлёт offset/limit/search
// в query и на панели 2.x выставляет Ref = uuid.
func TestListUsers_V2_QueryAndRef(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata": jsonOK(`{"response":{"version":"2.7.4"}}`),
		"/api/users": func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if q.Get("offset") != "10" || q.Get("limit") != "20" || q.Get("search") != "vasya" {
				t.Errorf("неожиданные query-параметры: %v", q)
			}
			jsonOK(`{"users":[{"uuid":"u-1","username":"vasya"}],"total":1}`)(w, r)
		},
	})
	c := newTestClient(t, ts.URL)

	users, total, err := c.ListUsers(context.Background(), 10, 20, "vasya")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if total != 1 || len(users) != 1 {
		t.Fatalf("неожиданный результат: users=%+v total=%d", users, total)
	}
	if users[0].Ref != "u-1" {
		t.Fatalf("на 2.x Ref должен быть uuid: got %q", users[0].Ref)
	}
}

// TestListUsers_V3_Ref проверяет, что на панели 3.x Ref становится строковым id.
func TestListUsers_V3_Ref(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata":      jsonOK(`{"response":{"version":"3.2.2"}}`),
		"/api/system/configuration": jsonOK(`{"response":{}}`),
		"/api/users":                jsonOK(`{"users":[{"id":7,"username":"vasya"}],"total":1}`),
	})
	c := newTestClient(t, ts.URL)

	users, _, err := c.ListUsers(context.Background(), 0, 100, "")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Ref != "7" {
		t.Fatalf("на 3.x Ref должен быть \"7\": %+v", users)
	}
}

// TestUpdateUser_V2SendsUUIDField проверяет тело PATCH на панели 2.x.
func TestUpdateUser_V2SendsUUIDField(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata": jsonOK(`{"response":{"version":"2.7.4"}}`),
		"/api/users": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPatch {
				t.Errorf("ожидал PATCH, got %s", r.Method)
			}
			body := decodeBody(t, r)
			if body["uuid"] != "u-1" {
				t.Errorf("ожидал uuid=u-1 в теле: %v", body)
			}
			if _, hasID := body["id"]; hasID {
				t.Errorf("на 2.x поле id в теле лишнее: %v", body)
			}
			if body["status"] != "DISABLED" {
				t.Errorf("исходное поле патча потерялось: %v", body)
			}
			jsonOK(`{"response":{}}`)(w, r)
		},
	})
	c := newTestClient(t, ts.URL)

	if err := c.UpdateUser(context.Background(), "u-1", map[string]any{"status": "DISABLED"}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
}

// TestUpdateUser_TranslatesSquadsAlias проверяет контракт с internal/grace:
// абстрактный ключ "squads" (см. grace.PatchSquads) должен превратиться
// в activeInternalSquads, так же, как называется поле в GET-ответе панели.
func TestUpdateUser_TranslatesSquadsAlias(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata": jsonOK(`{"response":{"version":"2.7.4"}}`),
		"/api/users": func(w http.ResponseWriter, r *http.Request) {
			body := decodeBody(t, r)
			squads, ok := body["activeInternalSquads"].([]any)
			if !ok || len(squads) != 1 || squads[0] != "grace-squad" {
				t.Errorf("ожидал activeInternalSquads=[grace-squad] в теле: %v", body)
			}
			if _, hasRaw := body["squads"]; hasRaw {
				t.Errorf("абстрактный ключ squads не должен уйти панели как есть: %v", body)
			}
			jsonOK(`{"response":{}}`)(w, r)
		},
	})
	c := newTestClient(t, ts.URL)

	patch := map[string]any{"squads": []string{"grace-squad"}}
	if err := c.UpdateUser(context.Background(), "u-1", patch); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
}

// TestUpdateUser_V3SendsIDField проверяет тело PATCH на панели 3.x: поле id,
// причём числом, а не строкой.
func TestUpdateUser_V3SendsIDField(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata":      jsonOK(`{"response":{"version":"3.2.2"}}`),
		"/api/system/configuration": jsonOK(`{"response":{}}`),
		"/api/users": func(w http.ResponseWriter, r *http.Request) {
			body := decodeBody(t, r)
			idVal, ok := body["id"].(float64)
			if !ok || idVal != 42 {
				t.Errorf("ожидал числовой id=42 в теле: %v", body)
			}
			if _, hasUUID := body["uuid"]; hasUUID {
				t.Errorf("на 3.x поле uuid в теле лишнее: %v", body)
			}
			jsonOK(`{"response":{}}`)(w, r)
		},
	})
	c := newTestClient(t, ts.URL)

	if err := c.UpdateUser(context.Background(), "42", map[string]any{"status": "DISABLED"}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
}

func TestUpdateUser_V3RejectsNonNumericRef(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata":      jsonOK(`{"response":{"version":"3.2.2"}}`),
		"/api/system/configuration": jsonOK(`{"response":{}}`),
	})
	c := newTestClient(t, ts.URL)

	err := c.UpdateUser(context.Background(), "not-a-number", map[string]any{"status": "ACTIVE"})
	if err == nil {
		t.Fatal("ожидал ошибку: на 3.x ref обязан быть числом")
	}
}

func TestUserByShortUUID_NotFound(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata":      jsonOK(`{"response":{"version":"3.2.2"}}`),
		"/api/system/configuration": jsonOK(`{"response":{}}`),
		"/api/users/by-short-uuid/does-not-exist": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"User not found"}`))
		},
	})
	c := newTestClient(t, ts.URL)

	_, err := c.UserByShortUUID(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ожидал ErrNotFound, got %v", err)
	}
}

func TestResetTraffic_HitsExpectedPath(t *testing.T) {
	var gotPath, gotMethod string
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/users/u-1/actions/reset-traffic": func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotMethod = r.Method
			jsonOK(`{"response":{}}`)(w, r)
		},
	})
	c := newTestClient(t, ts.URL)

	if err := c.ResetTraffic(context.Background(), "u-1"); err != nil {
		t.Fatalf("ResetTraffic: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("ожидал POST, got %s", gotMethod)
	}
	if gotPath != "/api/users/u-1/actions/reset-traffic" {
		t.Fatalf("неожиданный путь: %s", gotPath)
	}
}

// decodeBody читает и разбирает JSON-тело запроса как map: тестам удобно
// проверять отдельные поля, не привязываясь к точной DTO панели.
func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("читать тело запроса: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("разобрать тело запроса %s: %v", data, err)
	}
	return out
}
