package rules

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "rules_test.db")
	db, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return db
}

func TestApply_EmptyConditionsMatchAny(t *testing.T) {
	rs := []model.HeaderRule{
		{ID: 1, Enabled: true, SetHeader: map[string]string{"X-Test": "1"}},
	}
	h := http.Header{}
	Apply(rs, model.Client{App: "AnyApp"}, h)
	if got := h.Get("X-Test"); got != "1" {
		t.Fatalf("ожидали X-Test=1, получили %q", got)
	}
}

func TestApply_DisabledRuleSkipped(t *testing.T) {
	rs := []model.HeaderRule{
		{ID: 1, Enabled: false, SetHeader: map[string]string{"X-Test": "1"}},
	}
	h := http.Header{}
	Apply(rs, model.Client{App: "AnyApp"}, h)
	if h.Get("X-Test") != "" {
		t.Fatal("выключенное правило не должно применяться")
	}
}

func TestApply_MatchAppAndOS(t *testing.T) {
	rule := model.HeaderRule{
		ID: 1, Enabled: true,
		MatchApp:  "Happ",
		MatchOS:   "ios",
		SetHeader: map[string]string{"X-Test": "matched"},
	}

	h := http.Header{}
	Apply([]model.HeaderRule{rule}, model.Client{App: "Happ", Platform: model.PlatformIOS}, h)
	if h.Get("X-Test") != "matched" {
		t.Fatal("правило должно было сработать при совпадении app+os")
	}

	h2 := http.Header{}
	Apply([]model.HeaderRule{rule}, model.Client{App: "v2rayNG", Platform: model.PlatformIOS}, h2)
	if h2.Get("X-Test") != "" {
		t.Fatal("правило не должно сработать при другом приложении")
	}

	h3 := http.Header{}
	Apply([]model.HeaderRule{rule}, model.Client{App: "Happ", Platform: model.PlatformAndroid}, h3)
	if h3.Get("X-Test") != "" {
		t.Fatal("правило не должно сработать при другой платформе")
	}
}

func TestApply_PriorityHigherWins(t *testing.T) {
	low := model.HeaderRule{ID: 1, Enabled: true, Priority: 10, SetHeader: map[string]string{"X-Title": "low"}}
	high := model.HeaderRule{ID: 2, Enabled: true, Priority: 100, SetHeader: map[string]string{"X-Title": "high"}}

	h := http.Header{}
	// Порядок в списке специально перемешан - Apply обязана сама сортировать.
	Apply([]model.HeaderRule{high, low}, model.Client{}, h)
	if got := h.Get("X-Title"); got != "high" {
		t.Fatalf("ожидали, что победит правило с большим приоритетом, получили %q", got)
	}
}

func TestApply_DelThenSetSameHeader(t *testing.T) {
	rule := model.HeaderRule{
		ID: 1, Enabled: true,
		DelHeader: []string{"X-Title"},
		SetHeader: map[string]string{"X-Title": "new"},
	}
	h := http.Header{"X-Title": []string{"old"}}
	Apply([]model.HeaderRule{rule}, model.Client{}, h)
	if got := h.Get("X-Title"); got != "new" {
		t.Fatalf("set_headers должен побеждать del_headers для одного заголовка, получили %q", got)
	}
}

func TestApply_UASubstringCaseInsensitive(t *testing.T) {
	rule := model.HeaderRule{ID: 1, Enabled: true, MatchUA: "clash", SetHeader: map[string]string{"X-Test": "1"}}
	h := http.Header{}
	Apply([]model.HeaderRule{rule}, model.Client{UserAgent: "ClashMetaForAndroid/1.0"}, h)
	if h.Get("X-Test") != "1" {
		t.Fatal("подстрока должна совпадать без учёта регистра")
	}
}

func TestApply_UARegex(t *testing.T) {
	rule := model.HeaderRule{
		ID: 1, Enabled: true, UARegex: true,
		MatchUA:   `^v2rayNG/\d+\.\d+`,
		SetHeader: map[string]string{"X-Test": "1"},
	}

	h := http.Header{}
	Apply([]model.HeaderRule{rule}, model.Client{UserAgent: "v2rayNG/1.8.0"}, h)
	if h.Get("X-Test") != "1" {
		t.Fatal("регулярное выражение должно было совпасть")
	}

	h2 := http.Header{}
	Apply([]model.HeaderRule{rule}, model.Client{UserAgent: "Happ/1.0"}, h2)
	if h2.Get("X-Test") != "" {
		t.Fatal("регулярное выражение не должно было совпасть")
	}
}

func TestApply_InvalidRegexDoesNotPanic(t *testing.T) {
	rule := model.HeaderRule{
		ID: 1, Enabled: true, UARegex: true,
		MatchUA:   `(unclosed`,
		SetHeader: map[string]string{"X-Test": "1"},
	}
	h := http.Header{}
	Apply([]model.HeaderRule{rule}, model.Client{UserAgent: "anything"}, h)
	if h.Get("X-Test") != "" {
		t.Fatal("правило с невалидным регулярным выражением не должно ничего применять")
	}
}

func TestSaveLoadDelete(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	id, err := Save(ctx, db, model.HeaderRule{
		Name:      "test",
		Enabled:   true,
		Priority:  50,
		MatchApp:  "Happ",
		SetHeader: map[string]string{"Profile-Title": "MultiGate"},
		DelHeader: []string{"ETag"},
	})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if id == 0 {
		t.Fatal("ожидали ненулевой id")
	}

	list, err := Load(ctx, db)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ожидали одно правило, получили %d", len(list))
	}
	got := list[0]
	if got.Name != "test" || got.MatchApp != "Happ" || got.SetHeader["Profile-Title"] != "MultiGate" {
		t.Fatalf("правило прочиталось неверно: %+v", got)
	}
	if len(got.DelHeader) != 1 || got.DelHeader[0] != "ETag" {
		t.Fatalf("del_headers прочитались неверно: %+v", got.DelHeader)
	}

	// Обновление существующего правила должно сразу быть видно через Load,
	// несмотря на TTL кэша: Save обязан сбрасывать кэш.
	got.Priority = 77
	if _, err := Save(ctx, db, got); err != nil {
		t.Fatalf("Save (update): %v", err)
	}
	list2, err := Load(ctx, db)
	if err != nil {
		t.Fatalf("Load после обновления: %v", err)
	}
	if len(list2) != 1 || list2[0].Priority != 77 {
		t.Fatalf("обновление приоритета не подхватилось: %+v", list2)
	}

	if err := Delete(ctx, db, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	list3, err := Load(ctx, db)
	if err != nil {
		t.Fatalf("Load после удаления: %v", err)
	}
	if len(list3) != 0 {
		t.Fatalf("ожидали пустой список после удаления, получили %d", len(list3))
	}
}

func TestLoad_SeparateCachePerDB(t *testing.T) {
	db1 := openTestDB(t)
	db2 := openTestDB(t)
	ctx := context.Background()

	if _, err := Save(ctx, db1, model.HeaderRule{Name: "only-in-db1", Enabled: true}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	list1, err := Load(ctx, db1)
	if err != nil || len(list1) != 1 {
		t.Fatalf("Load(db1): list=%v err=%v", list1, err)
	}
	list2, err := Load(ctx, db2)
	if err != nil || len(list2) != 0 {
		t.Fatalf("Load(db2) не должен видеть правила другой базы: list=%v err=%v", list2, err)
	}
}
