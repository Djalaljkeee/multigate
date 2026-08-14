package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// newTestDB поднимает базу во временном каталоге теста.
func newTestDB(t *testing.T) *DB {
	t.Helper()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "test.db")
	db, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("не открыть базу: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("миграции: %v", err)
	}
	return db
}

func TestMigrateIdempotent(t *testing.T) {
	db := newTestDB(t)
	// Повторный прогон миграций обязан быть безопасным: он случается
	// при каждом старте сервиса и при откате на предыдущую версию бинарника.
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("повторные миграции упали: %v", err)
	}
}

func TestSettingsDefaultsAndSet(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if got := db.Get(ctx, KeyMode); got != "mirror" {
		t.Errorf("режим по умолчанию: получили %q, ждали mirror", got)
	}
	// Грейс трогает живую панель, поэтому обязан быть выключен на чистой установке.
	if db.GetBool(ctx, KeyGraceEnabled) {
		t.Error("грейс включён по умолчанию, а не должен")
	}
	if got := db.GetInt(ctx, KeyLogKeepDays, 0); got != 14 {
		t.Errorf("срок хранения журнала: получили %d, ждали 14", got)
	}

	if err := db.Set(ctx, KeyMode, "panel"); err != nil {
		t.Fatalf("запись настройки: %v", err)
	}
	if got := db.Get(ctx, KeyMode); got != "panel" {
		t.Errorf("после записи режим %q, ждали panel", got)
	}

	if err := db.SetMany(ctx, map[string]string{
		KeyPanelURL:   "http://remnawave:3000",
		KeyCacheTTL:   "30",
		KeyLogEnabled: "0",
	}); err != nil {
		t.Fatalf("пакетная запись: %v", err)
	}
	if got := db.GetDuration(ctx, KeyCacheTTL, 0); got != 30*time.Second {
		t.Errorf("кэш: получили %v, ждали 30s", got)
	}
	if db.GetBool(ctx, KeyLogEnabled) {
		t.Error("журнал остался включённым после выключения")
	}
}

func TestOverridesLookupOrder(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if _, err := db.AddOverride(ctx, model.Override{ShortUUID: "user1", Reason: "весь пользователь"}); err != nil {
		t.Fatalf("блокировка пользователя: %v", err)
	}
	if _, err := db.AddOverride(ctx, model.Override{HWID: "dev-abc", Reason: "устройство везде"}); err != nil {
		t.Fatalf("блокировка устройства: %v", err)
	}
	if _, err := db.AddOverride(ctx, model.Override{ShortUUID: "user2", HWID: "dev-xyz", Reason: "устройство у пользователя"}); err != nil {
		t.Fatalf("блокировка пары: %v", err)
	}

	cases := []struct {
		name      string
		shortUUID string
		hwid      string
		want      bool
		reason    string
	}{
		{"пользователь целиком", "user1", "любое", true, "весь пользователь"},
		{"устройство везде", "userN", "dev-abc", true, "устройство везде"},
		{"пара пользователь и устройство", "user2", "dev-xyz", true, "устройство у пользователя"},
		{"та же пара, другое устройство", "user2", "dev-free", false, ""},
		{"никого нет", "user3", "dev-free", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, found := db.FindOverride(ctx, c.shortUUID, c.hwid)
			if found != c.want {
				t.Fatalf("нашли %v, ждали %v", found, c.want)
			}
			if found && o.Reason != c.reason {
				t.Errorf("причина %q, ждали %q", o.Reason, c.reason)
			}
		})
	}

	list, err := db.ListOverrides(ctx)
	if err != nil {
		t.Fatalf("список блокировок: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("в списке %d блокировок, ждали 3", len(list))
	}

	// Снятие блокировки обязано подействовать сразу, а не после истечения кэша:
	// администратор снимает её, когда клиент уже звонит в поддержку.
	if err := db.DeleteOverride(ctx, list[0].ID); err != nil {
		t.Fatalf("снятие блокировки: %v", err)
	}
	if _, found := db.FindOverride(ctx, "user2", "dev-xyz"); found {
		t.Error("блокировка осталась активной после снятия")
	}
}

func TestReqLoggerWritesAndFilters(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	lg := db.NewReqLogger(ctx)
	now := time.Now()
	for i := 0; i < 50; i++ {
		app := "Happ"
		decision := string(model.DecisionNormal)
		if i%5 == 0 {
			app = "v2rayNG"
			decision = string(model.DecisionBlocked)
		}
		lg.Add(model.RequestLog{
			At: now, ShortUUID: "abc123", Username: "user", IP: "10.0.0.1",
			UserAgent: app + "/1.0", App: app, Decision: decision, Status: 200,
		})
	}
	lg.Close() // дожидается сброса очереди

	all, total, err := db.ListRequestLog(ctx, ReqLogFilter{Limit: 100})
	if err != nil {
		t.Fatalf("чтение журнала: %v", err)
	}
	if total != 50 || len(all) != 50 {
		t.Fatalf("в журнале %d записей (total=%d), ждали 50", len(all), total)
	}

	blocked, totalBlocked, err := db.ListRequestLog(ctx, ReqLogFilter{Decision: string(model.DecisionBlocked)})
	if err != nil {
		t.Fatalf("фильтр по решению: %v", err)
	}
	if totalBlocked != 10 || len(blocked) != 10 {
		t.Errorf("заблокированных %d (total=%d), ждали 10", len(blocked), totalBlocked)
	}

	byApp, err := db.TopClients(ctx, now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatalf("разбивка по приложениям: %v", err)
	}
	if byApp["Happ"] != 40 || byApp["v2rayNG"] != 10 {
		t.Errorf("разбивка по приложениям неверная: %v", byApp)
	}
}

func TestReqLoggerDropsInsteadOfBlocking(t *testing.T) {
	db := newTestDB(t)
	lg := db.NewReqLogger(context.Background())
	defer lg.Close()

	// Журнал не имеет права задерживать выдачу подписки. Заваливаем его
	// заведомо больше буфера и проверяем, что вызовы не блокируются.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20000; i++ {
			lg.Add(model.RequestLog{ShortUUID: "flood", App: "Happ", Status: 200})
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("запись в журнал заблокировалась вместо того, чтобы выбрасывать записи")
	}
}

func TestPruneRequestLog(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	lg := db.NewReqLogger(ctx)
	lg.Add(model.RequestLog{At: time.Now().AddDate(0, 0, -30), ShortUUID: "старая"})
	lg.Add(model.RequestLog{At: time.Now(), ShortUUID: "свежая"})
	lg.Close()

	n, err := db.PruneRequestLog(ctx, 14)
	if err != nil {
		t.Fatalf("очистка журнала: %v", err)
	}
	if n != 1 {
		t.Errorf("удалили %d записей, ждали 1", n)
	}

	rest, _, err := db.ListRequestLog(ctx, ReqLogFilter{})
	if err != nil {
		t.Fatalf("чтение после очистки: %v", err)
	}
	if len(rest) != 1 || rest[0].ShortUUID != "свежая" {
		t.Errorf("после очистки осталось не то: %+v", rest)
	}
}

func TestSettingsConcurrentAccess(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Настройки читаются на каждом запросе подписки из множества горутин,
	// а пишутся из админки. Гонка здесь означала бы падение прода.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = db.Get(ctx, KeyMode)
				_ = db.GetBool(ctx, KeyDecoyEnabled)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = db.Set(ctx, KeyBrandTitle, "название")
			}
		}(i)
	}
	wg.Wait()
}

func TestStatsReportsTables(t *testing.T) {
	db := newTestDB(t)
	st, err := db.Stats(context.Background())
	if err != nil {
		t.Fatalf("статистика: %v", err)
	}
	if _, ok := st["request_log"]; !ok {
		t.Error("в статистике нет журнала запросов")
	}
	if _, ok := st["db_bytes"]; !ok {
		t.Error("в статистике нет размера базы")
	}
}
