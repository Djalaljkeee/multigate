package grace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// newTestDB поднимает свежую SQLite-базу во временном каталоге с применённой схемой.
func newTestDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "grace-test.db")
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

// enableGrace включает грейс и прогревает кэш настроек, чтобы последующие
// db.Get*/GetBool читали значения из памяти, а не ходили в базу заново.
func enableGrace(t *testing.T, db *store.DB, squad string, hours string) {
	t.Helper()
	ctx := context.Background()
	kv := map[string]string{store.KeyGraceEnabled: "1"}
	if squad != "" {
		kv[store.KeyGraceSquad] = squad
	}
	if hours != "" {
		kv[store.KeyGraceHours] = hours
	}
	if err := db.SetMany(ctx, kv); err != nil {
		t.Fatalf("db.SetMany: %v", err)
	}
	if _, err := db.Settings(ctx); err != nil {
		t.Fatalf("db.Settings: %v", err)
	}
}

// fakePanel: подставная панель. Считает вызовы, запоминает патчи, умеет
// отказывать по требованию (имитация недоступности панели).
type fakePanel struct {
	mu         sync.Mutex
	calls      int
	patches    []capturedPatch
	failNext   bool // следующий вызов UpdateUser вернёт ошибку и сбросит флаг
	failAlways bool
}

type capturedPatch struct {
	ref   string
	patch map[string]any
}

func (f *fakePanel) UserByShortUUID(context.Context, string) (model.PanelUser, error) {
	return model.PanelUser{}, errors.New("fakePanel: UserByShortUUID не используется в этих тестах")
}

func (f *fakePanel) UpdateUser(_ context.Context, ref string, patch map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failAlways || f.failNext {
		f.failNext = false
		return errors.New("fakePanel: панель недоступна")
	}
	f.patches = append(f.patches, capturedPatch{ref: ref, patch: patch})
	return nil
}

func (f *fakePanel) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakePanel) lastPatch() capturedPatch {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.patches) == 0 {
		return capturedPatch{}
	}
	return f.patches[len(f.patches)-1]
}

func expiredUser() model.PanelUser {
	return model.PanelUser{
		Ref:               "user-ref-1",
		ShortUUID:         "short-1",
		Username:          "alice",
		Status:            "EXPIRED",
		ExpireAt:          time.Now().Add(-time.Hour),
		TrafficLimitBytes: 1 << 30,
		HWIDDeviceLimit:   3,
		Squads:            []string{"squad-orig-a", "squad-orig-b"},
	}
}

func TestIsExpired(t *testing.T) {
	cases := []struct {
		name string
		u    model.PanelUser
		want bool
	}{
		{"статус EXPIRED", model.PanelUser{Status: "EXPIRED"}, true},
		{"срок в прошлом", model.PanelUser{Status: "ACTIVE", ExpireAt: time.Now().Add(-time.Minute)}, true},
		{"срок в будущем", model.PanelUser{Status: "ACTIVE", ExpireAt: time.Now().Add(time.Hour)}, false},
		{"без срока и активен", model.PanelUser{Status: "ACTIVE"}, false},
		{"лимит трафика, не грейс", model.PanelUser{Status: "LIMITED", ExpireAt: time.Now().Add(time.Hour)}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isExpired(c.u); got != c.want {
				t.Errorf("isExpired() = %v, хочу %v", got, c.want)
			}
		})
	}
}

func TestMaybe_Disabled(t *testing.T) {
	db := newTestDB(t)
	panel := &fakePanel{}
	svc := New(db, panel, testLogger())

	applied, err := svc.Maybe(context.Background(), expiredUser())
	if err != nil {
		t.Fatalf("Maybe: %v", err)
	}
	if applied {
		t.Fatal("грейс выключен по умолчанию, applied должен быть false")
	}
	if panel.Calls() != 0 {
		t.Fatalf("панель не должна вызываться при выключенном грейсе, calls=%d", panel.Calls())
	}
	recs, err := svc.List(context.Background(), false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("не должно быть записей, получено %d", len(recs))
	}
}

func TestMaybe_NoSquad(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := db.SetMany(ctx, map[string]string{store.KeyGraceEnabled: "1"}); err != nil {
		t.Fatalf("db.SetMany: %v", err)
	}
	if _, err := db.Settings(ctx); err != nil {
		t.Fatalf("db.Settings: %v", err)
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	panel := &fakePanel{}
	svc := New(db, panel, log)

	applied, err := svc.Maybe(ctx, expiredUser())
	if err != nil {
		t.Fatalf("Maybe: %v", err)
	}
	if applied {
		t.Fatal("без сквада грейс не должен применяться")
	}
	if panel.Calls() != 0 {
		t.Fatalf("панель не должна вызываться без сквада, calls=%d", panel.Calls())
	}
	if !strings.Contains(buf.String(), "сквад") {
		t.Fatalf("ожидал предупреждение про отсутствующий сквад в журнале, получено: %s", buf.String())
	}
}

func TestMaybe_NotExpired(t *testing.T) {
	db := newTestDB(t)
	enableGrace(t, db, "grace-squad", "24")
	panel := &fakePanel{}
	svc := New(db, panel, testLogger())

	u := expiredUser()
	u.Status = "ACTIVE"
	u.ExpireAt = time.Now().Add(time.Hour)

	applied, err := svc.Maybe(context.Background(), u)
	if err != nil {
		t.Fatalf("Maybe: %v", err)
	}
	if applied {
		t.Fatal("подписка ещё действует, грейс не должен применяться")
	}
	if panel.Calls() != 0 {
		t.Fatalf("панель не должна вызываться для действующего пользователя, calls=%d", panel.Calls())
	}
}

func TestMaybe_AppliesOnceIdempotent(t *testing.T) {
	db := newTestDB(t)
	enableGrace(t, db, "grace-squad-uuid", "24")
	panel := &fakePanel{}
	svc := New(db, panel, testLogger())
	ctx := context.Background()
	u := expiredUser()

	applied, err := svc.Maybe(ctx, u)
	if err != nil {
		t.Fatalf("Maybe #1: %v", err)
	}
	if !applied {
		t.Fatal("первый вызов должен применить грейс")
	}
	if panel.Calls() != 1 {
		t.Fatalf("панель должна быть вызвана один раз, calls=%d", panel.Calls())
	}

	recs, err := svc.List(ctx, false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("хочу ровно одну запись грейса, получено %d", len(recs))
	}
	if recs[0].AppliedSquad != "grace-squad-uuid" {
		t.Fatalf("applied_squad = %q", recs[0].AppliedSquad)
	}
	if recs[0].Restored {
		t.Fatal("свежая запись не должна быть восстановленной")
	}
	if recs[0].Err != "" {
		t.Fatalf("свежая успешная запись не должна нести ошибку: %q", recs[0].Err)
	}
	var origSquads []string
	if err := json.Unmarshal([]byte(recs[0].OriginalSquads), &origSquads); err != nil {
		t.Fatalf("original_squads не json: %v", err)
	}
	if len(origSquads) != 2 || origSquads[0] != "squad-orig-a" {
		t.Fatalf("original_squads = %v, хочу исходные сквады пользователя", origSquads)
	}

	// Повторный вызов, пока грейс активен: не должен ни звать панель снова,
	// ни портить снимок, ни заводить вторую запись.
	applied2, err := svc.Maybe(ctx, u)
	if err != nil {
		t.Fatalf("Maybe #2: %v", err)
	}
	if applied2 {
		t.Fatal("повторный вызов не должен снова применять грейс")
	}
	if panel.Calls() != 1 {
		t.Fatalf("панель не должна вызываться повторно, calls=%d", panel.Calls())
	}
	recs2, err := svc.List(ctx, false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs2) != 1 {
		t.Fatalf("повторный вызов не должен плодить записи, получено %d", len(recs2))
	}
	if recs2[0].ID != recs[0].ID {
		t.Fatalf("это должна быть та же запись: было %d, стало %d", recs[0].ID, recs2[0].ID)
	}
}

// TestMaybe_SnapshotFailureBlocksPanelCall проверяет требование 1: если снимок
// не удалось записать в базу, в панель обращения не будет вовсе.
func TestMaybe_SnapshotFailureBlocksPanelCall(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	enableGrace(t, db, "grace-squad", "24")

	// База закрывается ПОСЛЕ прогрева кэша настроек: сами настройки читаются
	// из памяти, а вот запись снимка идёт в уже закрытое соединение и обязана
	// провалиться, это и имитирует "не удалось записать снимок".
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	panel := &fakePanel{}
	svc := New(db, panel, testLogger())

	applied, err := svc.Maybe(ctx, expiredUser())
	if err == nil {
		t.Fatal("ожидал ошибку записи снимка")
	}
	if applied {
		t.Fatal("без сохранённого снимка грейс не должен считаться применённым")
	}
	if panel.Calls() != 0 {
		t.Fatalf("панель не должна вызываться без сохранённого снимка, calls=%d", panel.Calls())
	}
}

// TestMaybe_RetriesFailedPushWithoutResnapshotting проверяет требования 2 и 5:
// после сбоя обращения к панели запись остаётся с ошибкой, а повторная попытка
// переиспользует уже сохранённый снимок, а не берёт новый из текущего (уже,
// возможно, "поплывшего") состояния пользователя.
func TestMaybe_RetriesFailedPushWithoutResnapshotting(t *testing.T) {
	db := newTestDB(t)
	enableGrace(t, db, "grace-squad-uuid", "24")
	ctx := context.Background()

	panel := &fakePanel{failNext: true}
	svc := New(db, panel, testLogger())

	u1 := expiredUser()
	applied1, err1 := svc.Maybe(ctx, u1)
	if err1 == nil {
		t.Fatal("ожидал ошибку: панель отказала на первой попытке")
	}
	if applied1 {
		t.Fatal("applied должен быть false при отказе панели")
	}
	if panel.Calls() != 1 {
		t.Fatalf("calls=%d, хочу 1", panel.Calls())
	}

	recs, err := svc.List(ctx, true)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("запись должна остаться в базе несмотря на отказ панели, получено %d", len(recs))
	}
	if recs[0].Err == "" {
		t.Fatal("ошибка панели должна быть записана в поле err")
	}

	// Состояние пользователя в панели "поплыло" между попытками: если бы grace
	// снимал новый снимок, вторая попытка запомнила бы эти сквады как исходные.
	u2 := u1
	u2.Squads = []string{"squad-drifted-during-outage"}

	applied2, err2 := svc.Maybe(ctx, u2)
	if err2 != nil {
		t.Fatalf("Maybe #2: %v", err2)
	}
	if !applied2 {
		t.Fatal("вторая попытка должна была успешно применить грейс")
	}
	if panel.Calls() != 2 {
		t.Fatalf("panel.Calls()=%d, хочу 2 (первая неудачная + повтор)", panel.Calls())
	}

	recs2, err := svc.List(ctx, false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs2) != 1 {
		t.Fatalf("повтор не должен создавать вторую запись, получено %d", len(recs2))
	}
	if recs2[0].Err != "" {
		t.Fatalf("успешный повтор должен снять ошибку, err=%q", recs2[0].Err)
	}
	var origSquads []string
	if err := json.Unmarshal([]byte(recs2[0].OriginalSquads), &origSquads); err != nil {
		t.Fatalf("original_squads не json: %v", err)
	}
	if len(origSquads) != 2 || origSquads[0] != "squad-orig-a" {
		t.Fatalf("original_squads = %v, снимок не должен был перезаписаться уже испорченными данными", origSquads)
	}
}

// TestMaybe_Concurrent прогоняет параллельные обращения одного и того же
// пользователя: подписка опрашивается клиентом по таймеру, и гонки реальны.
func TestMaybe_Concurrent(t *testing.T) {
	db := newTestDB(t)
	enableGrace(t, db, "grace-squad", "24")
	panel := &fakePanel{}
	svc := New(db, panel, testLogger())
	ctx := context.Background()
	u := expiredUser()

	const workers = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	appliedCount := 0
	errCount := 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applied, err := svc.Maybe(ctx, u)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errCount++
				return
			}
			if applied {
				appliedCount++
			}
		}()
	}
	wg.Wait()

	if errCount != 0 {
		t.Fatalf("не ожидал ошибок при параллельных вызовах, errCount=%d", errCount)
	}
	if appliedCount != 1 {
		t.Fatalf("ровно один вызов должен был реально применить грейс, applied=%d", appliedCount)
	}
	if panel.Calls() != 1 {
		t.Fatalf("панель должна быть вызвана ровно один раз, calls=%d", panel.Calls())
	}
	recs, err := svc.List(ctx, false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("должна остаться ровно одна запись, получено %d", len(recs))
	}
}

func TestRestore(t *testing.T) {
	db := newTestDB(t)
	enableGrace(t, db, "grace-squad-uuid", "1")
	panel := &fakePanel{}
	svc := New(db, panel, testLogger())
	ctx := context.Background()
	u := expiredUser()

	applied, err := svc.Maybe(ctx, u)
	if err != nil || !applied {
		t.Fatalf("Maybe: applied=%v err=%v", applied, err)
	}
	recs, err := svc.List(ctx, false)
	if err != nil || len(recs) != 1 {
		t.Fatalf("List: %v recs=%v", err, recs)
	}
	id := recs[0].ID

	if err := svc.Restore(ctx, id); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if panel.Calls() != 2 {
		t.Fatalf("panel.Calls()=%d, хочу 2 (заявка + восстановление)", panel.Calls())
	}

	last := panel.lastPatch()
	squads, _ := last.patch[PatchSquads].([]string)
	if len(squads) != 2 || squads[0] != "squad-orig-a" || squads[1] != "squad-orig-b" {
		t.Fatalf("восстановление должно вернуть исходные сквады, получено %v", squads)
	}
	expireAt, _ := last.patch[PatchExpireAt].(time.Time)
	if expireAt.Unix() != u.ExpireAt.Unix() {
		t.Fatalf("восстановление должно вернуть исходный срок: получено %v, хочу %v", expireAt, u.ExpireAt)
	}

	active, err := svc.List(ctx, true)
	if err != nil {
		t.Fatalf("List active: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("после восстановления активных записей быть не должно, получено %d", len(active))
	}
	all, err := svc.List(ctx, false)
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(all) != 1 || !all[0].Restored || all[0].RestoredAt.IsZero() {
		t.Fatalf("запись должна быть помечена восстановленной: %+v", all)
	}

	// Повторный вызов идемпотентен: панель второй раз не трогаем.
	if err := svc.Restore(ctx, id); err != nil {
		t.Fatalf("повторный Restore: %v", err)
	}
	if panel.Calls() != 2 {
		t.Fatalf("повторное восстановление не должно звать панель, calls=%d", panel.Calls())
	}
}

// TestMaybe_InvalidSnapshotBlocksGrace проверяет находку ревью 1: нулевой
// ExpireAt неотличим от ошибки разбора даты в клиенте панели, поэтому грейс
// с такой датой не применяется вовсе, иначе откатить будет нечем.
func TestMaybe_InvalidSnapshotBlocksGrace(t *testing.T) {
	db := newTestDB(t)
	enableGrace(t, db, "grace-squad", "24")
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	panel := &fakePanel{}
	svc := New(db, panel, log)
	ctx := context.Background()

	u := expiredUser()
	u.ExpireAt = time.Time{} // статус EXPIRED без даты: легитимно или баг разбора, неотличимо

	applied, err := svc.Maybe(ctx, u)
	if err != nil {
		t.Fatalf("Maybe: %v", err)
	}
	if applied {
		t.Fatal("без надёжного срока грейс не должен применяться")
	}
	if panel.Calls() != 0 {
		t.Fatalf("панель не должна вызываться без надёжного срока, calls=%d", panel.Calls())
	}
	recs, err := svc.List(ctx, false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("запись не должна была завестись, получено %d", len(recs))
	}
	if !strings.Contains(buf.String(), "срок") {
		t.Fatalf("ожидал предупреждение про отсутствующий срок в журнале, получено: %s", buf.String())
	}
}

// TestRestore_EmptyExpireAtNotSentToPanel проверяет находку ревью 1: если в
// снимке записи нет надёжной даты (запись заведена до этого исправления или
// данные повреждены), Restore не отправляет её панели, а не превращает
// нулевое время в "0001-01-01T00:00:00Z".
func TestRestore_EmptyExpireAtNotSentToPanel(t *testing.T) {
	db := newTestDB(t)
	enableGrace(t, db, "grace-squad-uuid", "24")
	panel := &fakePanel{}
	svc := New(db, panel, testLogger())
	ctx := context.Background()

	applied, err := svc.Maybe(ctx, expiredUser())
	if err != nil || !applied {
		t.Fatalf("Maybe: applied=%v err=%v", applied, err)
	}
	recs, _ := svc.List(ctx, false)
	id := recs[0].ID

	// Имитируем запись с ненадёжной датой в снимке (например заведённую до
	// этого исправления): напрямую портим колонку snapshot в базе.
	badSnap, err := json.Marshal(snapshot{Squads: expiredUser().Squads, ExpireAt: 0, Status: "EXPIRED"})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if _, err := db.RW().ExecContext(ctx, "UPDATE grace_users SET snapshot = ? WHERE id = ?", string(badSnap), id); err != nil {
		t.Fatalf("не смог подготовить тест: %v", err)
	}

	if err := svc.Restore(ctx, id); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	last := panel.lastPatch()
	if _, ok := last.patch[PatchExpireAt]; ok {
		t.Fatalf("PatchExpireAt не должен был попасть в патч при пустой дате снимка: %v", last.patch)
	}
	if _, ok := last.patch[PatchSquads]; !ok {
		t.Fatal("сквады были в снимке и должны были попасть в патч")
	}

	all, err := svc.List(ctx, false)
	if err != nil || len(all) != 1 || !all[0].Restored {
		t.Fatalf("запись должна быть восстановлена несмотря на пустую дату: %v recs=%v", err, all)
	}
}

// TestRestore_EmptySquadsNotSentToPanel проверяет находку ревью 1: пользователь
// без сквадов на момент грейса даёт original_squads = "null", и Restore не
// должен отправлять это панели как null (панель такое, скорее всего, отклонит).
func TestRestore_EmptySquadsNotSentToPanel(t *testing.T) {
	db := newTestDB(t)
	enableGrace(t, db, "grace-squad-uuid", "24")
	panel := &fakePanel{}
	svc := New(db, panel, testLogger())
	ctx := context.Background()

	u := expiredUser()
	u.Squads = nil // у пользователя не было сквадов на момент грейса

	applied, err := svc.Maybe(ctx, u)
	if err != nil || !applied {
		t.Fatalf("Maybe: applied=%v err=%v", applied, err)
	}
	recs, _ := svc.List(ctx, false)
	if recs[0].OriginalSquads != "null" {
		t.Fatalf(`ожидал original_squads = "null" для пользователя без сквадов, получено %q`, recs[0].OriginalSquads)
	}
	id := recs[0].ID

	if err := svc.Restore(ctx, id); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	last := panel.lastPatch()
	if _, ok := last.patch[PatchSquads]; ok {
		t.Fatalf("PatchSquads не должен был попасть в патч при пустом списке сквадов: %v", last.patch)
	}
	if _, ok := last.patch[PatchExpireAt]; !ok {
		t.Fatal("дата была в снимке и должна была попасть в патч")
	}

	all, err := svc.List(ctx, false)
	if err != nil || len(all) != 1 || !all[0].Restored {
		t.Fatalf("запись должна быть восстановлена несмотря на пустые сквады: %v recs=%v", err, all)
	}
}

// TestRestore_EmptySnapshotSkipsPanelCall проверяет пограничный случай: если
// в снимке ненадёжны и дата, и сквады, патч пуст целиком, и Restore не зовёт
// панель с пустым телом, а сразу отмечает запись восстановленной.
func TestRestore_EmptySnapshotSkipsPanelCall(t *testing.T) {
	db := newTestDB(t)
	enableGrace(t, db, "grace-squad-uuid", "24")
	panel := &fakePanel{}
	svc := New(db, panel, testLogger())
	ctx := context.Background()

	applied, err := svc.Maybe(ctx, expiredUser())
	if err != nil || !applied {
		t.Fatalf("Maybe: applied=%v err=%v", applied, err)
	}
	recs, _ := svc.List(ctx, false)
	id := recs[0].ID

	badSnap, err := json.Marshal(snapshot{ExpireAt: 0, Status: "EXPIRED"})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if _, err := db.RW().ExecContext(ctx,
		"UPDATE grace_users SET snapshot = ?, original_squads = 'null' WHERE id = ?", string(badSnap), id); err != nil {
		t.Fatalf("не смог подготовить тест: %v", err)
	}

	callsBefore := panel.Calls()
	if err := svc.Restore(ctx, id); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if panel.Calls() != callsBefore {
		t.Fatalf("панель не должна была вызываться при пустом патче, было %d вызовов, стало %d", callsBefore, panel.Calls())
	}

	all, err := svc.List(ctx, false)
	if err != nil || len(all) != 1 || !all[0].Restored {
		t.Fatalf("запись должна быть восстановлена: %v recs=%v", err, all)
	}
}

func TestRestore_NotFound(t *testing.T) {
	db := newTestDB(t)
	svc := New(db, &fakePanel{}, testLogger())
	err := svc.Restore(context.Background(), 12345)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ожидал store.ErrNotFound, получено %v", err)
	}
}

// TestRestoreExpired_PanelDownThenRecovers проверяет требование 4: недоступная
// панель оставляет запись невосстановленной с ошибкой, а следующий проход
// восстанавливает её, когда панель снова доступна.
func TestRestoreExpired_PanelDownThenRecovers(t *testing.T) {
	db := newTestDB(t)
	enableGrace(t, db, "grace-squad", "24")
	panel := &fakePanel{}
	svc := New(db, panel, testLogger())
	ctx := context.Background()

	applied, err := svc.Maybe(ctx, expiredUser())
	if err != nil || !applied {
		t.Fatalf("Maybe: applied=%v err=%v", applied, err)
	}
	recs, _ := svc.List(ctx, false)
	id := recs[0].ID

	// Переносим срок грейса в прошлое напрямую в базе: RestoreExpired должен
	// увидеть эту запись как готовую к восстановлению.
	if _, err := db.RW().ExecContext(ctx, "UPDATE grace_users SET expires_at = ? WHERE id = ?",
		time.Now().Add(-time.Minute).Unix(), id); err != nil {
		t.Fatalf("не смог подготовить тест: %v", err)
	}

	panel.mu.Lock()
	panel.failAlways = true
	panel.mu.Unlock()

	n, err := svc.RestoreExpired(ctx)
	if err == nil {
		t.Fatal("ожидал агрегированную ошибку: панель недоступна")
	}
	if n != 0 {
		t.Fatalf("при недоступной панели восстановленных быть не должно, n=%d", n)
	}
	recs, err = svc.List(ctx, false)
	if err != nil || len(recs) != 1 {
		t.Fatalf("List: %v recs=%v", err, recs)
	}
	if recs[0].Restored {
		t.Fatal("запись не должна считаться восстановленной при недоступной панели")
	}
	if recs[0].Err == "" {
		t.Fatal("ошибка недоступности панели должна быть видна в записи")
	}

	panel.mu.Lock()
	panel.failAlways = false
	panel.mu.Unlock()

	n, err = svc.RestoreExpired(ctx)
	if err != nil {
		t.Fatalf("RestoreExpired на следующем проходе: %v", err)
	}
	if n != 1 {
		t.Fatalf("ожидал одну восстановленную запись, n=%d", n)
	}
	recs, err = svc.List(ctx, false)
	if err != nil || len(recs) != 1 || !recs[0].Restored {
		t.Fatalf("запись должна была восстановиться: %v recs=%v", err, recs)
	}
	if recs[0].Err != "" {
		t.Fatalf("после успешного восстановления ошибка должна быть снята, err=%q", recs[0].Err)
	}
}

// TestRestoreExpired_NothingDue проверяет, что фоновая задача не трогает записи,
// срок которых ещё не наступил.
func TestRestoreExpired_NothingDue(t *testing.T) {
	db := newTestDB(t)
	enableGrace(t, db, "grace-squad", "24")
	panel := &fakePanel{}
	svc := New(db, panel, testLogger())
	ctx := context.Background()

	applied, err := svc.Maybe(ctx, expiredUser())
	if err != nil || !applied {
		t.Fatalf("Maybe: applied=%v err=%v", applied, err)
	}

	n, err := svc.RestoreExpired(ctx)
	if err != nil {
		t.Fatalf("RestoreExpired: %v", err)
	}
	if n != 0 {
		t.Fatalf("грейс ещё активен на сутки вперёд, восстанавливать нечего: n=%d", n)
	}
	if panel.Calls() != 1 {
		t.Fatalf("панель не должна вызываться повторно раньше срока, calls=%d", panel.Calls())
	}
}
