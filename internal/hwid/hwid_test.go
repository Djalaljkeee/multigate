package hwid

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// openTestDB поднимает временную SQLite-базу с применёнными миграциями.
// Общий помощник для всех тестов пакета.
func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "hwid_test.db")
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

// fakeDevices - управляемая тестом реализация Devices: список устройств
// панели по ref пользователя плюс возможность сымитировать недоступность панели.
type fakeDevices struct {
	byRef map[string][]model.Device
	err   error
}

func (f *fakeDevices) Devices(_ context.Context, userRef string) ([]model.Device, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byRef[userRef], nil
}

func (f *fakeDevices) DeleteDevice(context.Context, string, string) error {
	return errors.New("fakeDevices: DeleteDevice не используется в этих тестах")
}

func TestEnforce_DisabledByDefault(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// store.KeyHWIDEnforce по умолчанию "0" - Enforce обязан пропускать
	// любое устройство, даже с превышенным где-то лимитом.
	c := model.Client{HWID: "device-1"}
	u := model.PanelUser{ShortUUID: "user1", HWIDDeviceLimit: 1}

	allowed, reason := Enforce(ctx, db, nil, nil, c, u)
	if !allowed {
		t.Fatalf("ожидали allowed=true при выключенном enforce, получили reason=%q", reason)
	}
}

func TestEnforce_LocalOverrideBlock(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	if err := db.Set(ctx, store.KeyHWIDEnforce, "1"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}
	if _, err := db.AddOverride(ctx, model.Override{
		ShortUUID: "user1",
		HWID:      "bad-device",
		Action:    "block",
		Reason:    "жалоба клиента",
	}); err != nil {
		t.Fatalf("AddOverride: %v", err)
	}

	c := model.Client{HWID: "bad-device"}
	u := model.PanelUser{ShortUUID: "user1"}

	allowed, reason := Enforce(ctx, db, nil, nil, c, u)
	if allowed {
		t.Fatal("ожидали блокировку по локальному override")
	}
	if reason == "" {
		t.Fatal("ожидали непустую причину блокировки")
	}
}

func TestEnforce_NoHWIDPassesThrough(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyHWIDEnforce, "1"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}

	c := model.Client{HWID: ""}
	u := model.PanelUser{ShortUUID: "user1", HWIDDeviceLimit: 1}

	allowed, _ := Enforce(ctx, db, nil, nil, c, u)
	if !allowed {
		t.Fatal("без HWID лимит проверить не на чем, ожидали allowed=true")
	}
}

func TestEnforce_ZeroLimitMeansUnlimited(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyHWIDEnforce, "1"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}

	u := model.PanelUser{ShortUUID: "user1", HWIDDeviceLimit: 0}
	allowed, _ := Enforce(ctx, db, nil, nil, model.Client{HWID: "device-x"}, u)
	if !allowed {
		t.Fatal("нулевой лимит должен означать «без ограничений»")
	}
}

// TestEnforce_DeviceLimit проверяет лимит по данным реестра устройств
// панели (а не по локальному журналу запросов, как раньше): журнал
// наполняется HWID из заголовка клиента без всякой проверки, и его легко
// исчерпать чужими значениями, поэтому Enforce больше на него не смотрит.
func TestEnforce_DeviceLimit(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyHWIDEnforce, "1"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}

	// Два устройства уже зарегистрированы в панели за этим пользователем.
	devices := &fakeDevices{byRef: map[string][]model.Device{
		"ref-user1": {{HWID: "device-a"}, {HWID: "device-b"}},
	}}

	u := model.PanelUser{ShortUUID: "user1", Ref: "ref-user1", HWIDDeviceLimit: 2}

	// Уже известное устройство всегда проходит, даже на лимите.
	if allowed, reason := Enforce(ctx, db, devices, nil, model.Client{HWID: "device-a"}, u); !allowed {
		t.Fatalf("известное устройство должно проходить, reason=%q", reason)
	}

	// Третье, новое устройство при лимите 2 должно быть заблокировано.
	allowed, reason := Enforce(ctx, db, devices, nil, model.Client{HWID: "device-c"}, u)
	if allowed {
		t.Fatal("ожидали блокировку нового устройства сверх лимита")
	}
	if reason == "" {
		t.Fatal("ожидали непустую причину")
	}

	// У другого пользователя свой независимый счётчик (Enforce ходит за
	// устройствами по u.Ref, а не по u.ShortUUID).
	otherUser := model.PanelUser{ShortUUID: "user2", Ref: "ref-user2", HWIDDeviceLimit: 1}
	if allowed, reason := Enforce(ctx, db, devices, nil, model.Client{HWID: "device-c"}, otherUser); !allowed {
		t.Fatalf("устройство нового пользователя не должно блокироваться чужим лимитом, reason=%q", reason)
	}
}

// TestEnforce_PanelUnreachable_AllowsAndWarns проверяет требование ревью:
// если поход в панель за списком устройств не удался, клиента лучше
// пропустить, чем отключить из-за сбоя связи, но предупреждение об этом
// обязано попасть в журнал процесса - иначе потерянный лимит устройств
// никто не заметит.
func TestEnforce_PanelUnreachable_AllowsAndWarns(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyHWIDEnforce, "1"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}

	devices := &fakeDevices{err: errors.New("панель не отвечает")}
	u := model.PanelUser{ShortUUID: "user1", Ref: "ref-user1", HWIDDeviceLimit: 1}

	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))

	allowed, reason := Enforce(ctx, db, devices, log, model.Client{HWID: "device-a"}, u)
	if !allowed {
		t.Fatalf("сбой панели не должен блокировать клиента, reason=%q", reason)
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("hwid:")) {
		t.Fatalf("ожидали предупреждение в журнале процесса про недоступную панель, получили: %s", logBuf.String())
	}
}

// TestEnforce_SyntheticHWID_NotMatchedAgainstPanel проверяет, что
// синтетический HWID (собранный MultiGate из User-Agent) не сверяется с
// реестром устройств панели: там его быть не может в принципе, панель его
// никогда не видела. Клиент с таким HWID должен пройти даже вплотную к
// лимиту чужих (настоящих) устройств.
func TestEnforce_SyntheticHWID_NotMatchedAgainstPanel(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyHWIDEnforce, "1"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}

	// Лимит уже исчерпан настоящими устройствами панели.
	devices := &fakeDevices{byRef: map[string][]model.Device{
		"ref-user1": {{HWID: "device-a"}, {HWID: "device-b"}},
	}}
	u := model.PanelUser{ShortUUID: "user1", Ref: "ref-user1", HWIDDeviceLimit: 2}

	c := model.Client{HWID: "ua-deadbeef", HWIDSource: SyntheticSource}
	allowed, reason := Enforce(ctx, db, devices, nil, c, u)
	if !allowed {
		t.Fatalf("синтетический HWID не должен сверяться с лимитом панели, reason=%q", reason)
	}
}

func TestIsSyntheticHWID(t *testing.T) {
	cases := []struct {
		source string
		want   bool
	}{
		{source: "ua", want: true},
		{source: "header", want: false},
		{source: "", want: false},
	}
	for _, tc := range cases {
		got := IsSyntheticHWID(model.Client{HWIDSource: tc.source})
		if got != tc.want {
			t.Errorf("IsSyntheticHWID(source=%q) = %v, хотели %v", tc.source, got, tc.want)
		}
	}
}
