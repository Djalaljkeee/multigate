package wgpool

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

const plainWGConfig = `[Interface]
PrivateKey = kL5UwZjfV6dEQeuJ+RaP8pOu9OFRDN6dhcDDsN0Iv1w=
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
`

const amneziaWGConfig = `[Interface]
PrivateKey = kL5UwZjfV6dEQeuJ+RaP8pOu9OFRDN6dhcDDsN0Iv1w=
Address = 10.0.0.3/32
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
`

func newTestDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "wgpool-test.db")
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestValidateConfig(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"обычный WireGuard", plainWGConfig, false},
		{"AmneziaWG", amneziaWGConfig, false},
		{"мусор", "просто какой-то текст без секций вообще", true},
		{"пусто", "", true},
		{"нет Peer", "[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n", true},
		{"нет Interface", "[Peer]\nPublicKey = x\nEndpoint = a:1\n", true},
		{"нет PrivateKey", "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = x\nEndpoint = a:1\n", true},
		{"нет Endpoint", "[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = x\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateConfig(c.content)
			if (err != nil) != c.wantErr {
				t.Fatalf("validateConfig() err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestImport_SkipsGarbageCountsValid(t *testing.T) {
	db := newTestDB(t)
	svc := New(db, testLogger())
	ctx := context.Background()

	n, err := svc.Import(ctx, "p1", map[string]string{
		"good1.conf": plainWGConfig,
		"good2.conf": amneziaWGConfig,
		"trash.txt":  "это не конфиг",
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if n != 2 {
		t.Fatalf("импортировано %d, хочу 2 (мусор должен быть пропущен)", n)
	}

	stats, err := svc.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats["p1"].Free != 2 {
		t.Fatalf("Stats[p1].Free=%d, хочу 2", stats["p1"].Free)
	}
}

func TestImport_EmptyMap(t *testing.T) {
	db := newTestDB(t)
	svc := New(db, testLogger())
	n, err := svc.Import(context.Background(), "p1", nil)
	if err != nil || n != 0 {
		t.Fatalf("Import(nil) = %d, %v", n, err)
	}
}

// TestImport_IdempotentDoesNotTouchActiveLease проверяет, что повторный
// импорт того же файла не создаёт вторую запись и не трогает уже выданный
// клиенту конфиг: перезапись содержимого сломала бы активное подключение.
func TestImport_IdempotentDoesNotTouchActiveLease(t *testing.T) {
	db := newTestDB(t)
	svc := New(db, testLogger())
	ctx := context.Background()

	configs := map[string]string{"a.conf": plainWGConfig}
	if n, err := svc.Import(ctx, "p1", configs); err != nil || n != 1 {
		t.Fatalf("первый импорт: n=%d err=%v", n, err)
	}

	lease, err := svc.Lease(ctx, "p1", "user-1", "hwid-1")
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}

	// Повторный импорт того же файла: ничего нового, существующая (уже
	// выданная) запись не должна измениться.
	n, err := svc.Import(ctx, "p1", configs)
	if err != nil {
		t.Fatalf("второй импорт: %v", err)
	}
	if n != 0 {
		t.Fatalf("повторный импорт не должен ничего добавлять, n=%d", n)
	}

	again, err := svc.Lease(ctx, "p1", "user-1", "hwid-1")
	if err != nil {
		t.Fatalf("Lease после переимпорта: %v", err)
	}
	if again.ID != lease.ID || again.Config != lease.Config {
		t.Fatalf("переимпорт не должен подменять активную выдачу: было %+v, стало %+v", lease, again)
	}
}

func TestLease_SameDeviceGetsSameConfig(t *testing.T) {
	db := newTestDB(t)
	svc := New(db, testLogger())
	ctx := context.Background()

	if _, err := svc.Import(ctx, "p1", map[string]string{
		"a.conf": plainWGConfig,
		"b.conf": amneziaWGConfig,
	}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	first, err := svc.Lease(ctx, "p1", "user-1", "hwid-1")
	if err != nil {
		t.Fatalf("Lease #1: %v", err)
	}
	second, err := svc.Lease(ctx, "p1", "user-1", "hwid-1")
	if err != nil {
		t.Fatalf("Lease #2: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("повторная выдача должна вернуть тот же конфиг: %d != %d", first.ID, second.ID)
	}
	if first.Config != second.Config {
		t.Fatal("содержимое конфига не должно меняться между обращениями")
	}

	stats, err := svc.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats["p1"].InUse != 1 || stats["p1"].Free != 1 {
		t.Fatalf("Stats[p1]=%+v, хочу InUse=1 Free=1 (повторная выдача не должна съедать второй слот)", stats["p1"])
	}
}

func TestLease_PoolEmpty(t *testing.T) {
	db := newTestDB(t)
	svc := New(db, testLogger())
	ctx := context.Background()

	if _, err := svc.Import(ctx, "p1", map[string]string{"a.conf": plainWGConfig}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if _, err := svc.Lease(ctx, "p1", "user-1", "hwid-1"); err != nil {
		t.Fatalf("Lease #1: %v", err)
	}

	_, err := svc.Lease(ctx, "p1", "user-2", "hwid-2")
	if err == nil {
		t.Fatal("ожидал ошибку: пул пуст")
	}
	if err != ErrPoolEmpty {
		t.Fatalf("err=%v, хочу ErrPoolEmpty", err)
	}
}

func TestLease_EmptyPoolNameUsesDefault(t *testing.T) {
	db := newTestDB(t)
	svc := New(db, testLogger())
	ctx := context.Background()

	if _, err := svc.Import(ctx, "", map[string]string{"a.conf": plainWGConfig}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	lease, err := svc.Lease(ctx, "", "user-1", "hwid-1")
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	if lease.Pool != defaultPool {
		t.Fatalf("pool = %q, хочу %q", lease.Pool, defaultPool)
	}
}

func TestRelease(t *testing.T) {
	db := newTestDB(t)
	svc := New(db, testLogger())
	ctx := context.Background()

	if _, err := svc.Import(ctx, "p1", map[string]string{"a.conf": plainWGConfig}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	lease, err := svc.Lease(ctx, "p1", "user-1", "hwid-1")
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}

	if err := svc.Release(ctx, lease.ID); err != nil {
		t.Fatalf("Release: %v", err)
	}
	stats, err := svc.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats["p1"].Free != 1 || stats["p1"].InUse != 0 {
		t.Fatalf("Stats[p1]=%+v, хочу Free=1 InUse=0 после освобождения", stats["p1"])
	}

	// Освобождение уже свободной (и несуществующей) записи не считается ошибкой.
	if err := svc.Release(ctx, lease.ID); err != nil {
		t.Fatalf("повторный Release: %v", err)
	}
	if err := svc.Release(ctx, 999999); err != nil {
		t.Fatalf("Release несуществующей записи: %v", err)
	}

	// После освобождения конфиг снова можно выдать (в том числе тому же
	// устройству, но уже как новую выдачу).
	again, err := svc.Lease(ctx, "p1", "user-2", "hwid-2")
	if err != nil {
		t.Fatalf("Lease после Release: %v", err)
	}
	if again.ID != lease.ID {
		t.Fatalf("освобождённый конфиг должен снова стать доступным для выдачи")
	}
}

func TestList(t *testing.T) {
	db := newTestDB(t)
	svc := New(db, testLogger())
	ctx := context.Background()

	if _, err := svc.Import(ctx, "p1", map[string]string{
		"a.conf": plainWGConfig,
		"b.conf": amneziaWGConfig,
	}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if _, err := svc.Lease(ctx, "p1", "user-1", "hwid-1"); err != nil {
		t.Fatalf("Lease: %v", err)
	}

	all, err := svc.List(ctx, "p1", false)
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("List(all)=%d, хочу 2", len(all))
	}

	inUse, err := svc.List(ctx, "p1", true)
	if err != nil {
		t.Fatalf("List inUse: %v", err)
	}
	if len(inUse) != 1 || !inUse[0].InUse {
		t.Fatalf("List(onlyInUse)=%v, хочу одну выданную запись", inUse)
	}
}

// TestLease_ConcurrentDifferentDevicesNoOverlap проверяет требование 2:
// параллельные обращения разных устройств не должны получить один и тот же
// конфиг.
func TestLease_ConcurrentDifferentDevicesNoOverlap(t *testing.T) {
	db := newTestDB(t)
	svc := New(db, testLogger())
	ctx := context.Background()

	const n = 25
	configs := make(map[string]string, n)
	for i := 0; i < n; i++ {
		configs[fmt.Sprintf("cfg-%02d.conf", i)] = plainWGConfig
	}
	imported, err := svc.Import(ctx, "p1", configs)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if imported != n {
		t.Fatalf("импортировано %d, хочу %d", imported, n)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[int64]int{}
	errs := 0

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lease, err := svc.Lease(ctx, "p1", fmt.Sprintf("user-%d", i), fmt.Sprintf("hwid-%d", i))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs++
				return
			}
			seen[lease.ID]++
		}(i)
	}
	wg.Wait()

	if errs != 0 {
		t.Fatalf("не ожидал ошибок при параллельной выдаче разным устройствам, errs=%d", errs)
	}
	if len(seen) != n {
		t.Fatalf("получено %d уникальных конфигов, хочу %d: %v", len(seen), n, seen)
	}
	for id, cnt := range seen {
		if cnt != 1 {
			t.Fatalf("конфиг %d выдан %d раз(а), хочу ровно 1", id, cnt)
		}
	}

	stats, err := svc.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats["p1"].InUse != n || stats["p1"].Free != 0 {
		t.Fatalf("Stats[p1]=%+v, хочу InUse=%d Free=0", stats["p1"], n)
	}
}

// TestLease_ConcurrentSameDeviceGetsOneConfig проверяет требование 1 под
// нагрузкой: параллельные обращения одного и того же устройства не должны
// расходовать больше одного слота пула.
func TestLease_ConcurrentSameDeviceGetsOneConfig(t *testing.T) {
	db := newTestDB(t)
	svc := New(db, testLogger())
	ctx := context.Background()

	configs := map[string]string{"a.conf": plainWGConfig, "b.conf": amneziaWGConfig}
	if _, err := svc.Import(ctx, "p1", configs); err != nil {
		t.Fatalf("Import: %v", err)
	}

	const workers = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[int64]int{}
	errs := 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lease, err := svc.Lease(ctx, "p1", "user-1", "hwid-1")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs++
				return
			}
			seen[lease.ID]++
		}()
	}
	wg.Wait()

	if errs != 0 {
		t.Fatalf("не ожидал ошибок, errs=%d", errs)
	}
	if len(seen) != 1 {
		t.Fatalf("одно устройство получило %d разных конфигов, хочу 1: %v", len(seen), seen)
	}

	stats, err := svc.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats["p1"].InUse != 1 {
		t.Fatalf("Stats[p1].InUse=%d, хочу 1 (одно устройство не должно съедать больше одного слота)", stats["p1"].InUse)
	}
}
