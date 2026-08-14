// Package grace: временная отсрочка для истёкшей подписки.
//
// Это единственное место во всей прослойке, которое ПИШЕТ в живую панель
// Remnawave: меняет сквады пользователя и срок действия, чтобы дать истёкшей
// подписке короткое окно на оплату вместо мгновенной блокировки. Ошибка
// здесь означает испорченные данные у реального клиента, поэтому у пакета
// три жёстких правила:
//
//  1. Снимок исходного состояния пользователя пишется в grace_users ДО
//     первого обращения к панели. Если снимок записать не удалось, грейс не
//     применяется вовсе: без снимка откат невозможен.
//  2. Снимок берётся ровно один раз за весь цикл грейса. Повторные попытки
//     достучаться до панели (после сетевого сбоя) переиспользуют уже
//     сохранённый снимок, а не читают из панели заново: иначе, если первая
//     попытка успела частично примениться, второй снимок зафиксирует уже
//     подменённое состояние как "исходное", и восстановить пользователя
//     станет нечем.
//  3. Восстановление идёт по расписанию и идемпотентно: недоступность
//     панели не роняет всю пачку, а откладывает ровно эту запись до
//     следующего прохода.
package grace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// Panel: то, что грейсу нужно от панели Remnawave. Реализацию поставляет
// пакет remnawave; здесь только интерфейс, чтобы не тянуть его зависимости.
type Panel interface {
	UserByShortUUID(ctx context.Context, shortUUID string) (model.PanelUser, error)
	UpdateUser(ctx context.Context, ref string, patch map[string]any) error
}

// Ключи патча, который Maybe и Restore передают в Panel.UpdateUser.
// Реализация Panel должна понимать оба.
const (
	// PatchSquads: []string, полная замена списка uuid сквадов пользователя.
	PatchSquads = "squads"
	// PatchExpireAt: time.Time, новый срок действия подписки.
	PatchExpireAt = "expireAt"
)

// Service: служба грейса.
type Service struct {
	db  *store.DB
	p   Panel
	log *slog.Logger

	locks keyLock // по shortUuid: не даём Maybe/Restore одного пользователя выполняться параллельно
}

// New собирает службу. db и p не должны быть nil в бою: грейс без панели
// работать не может, а без базы тем более. New не возвращает ошибку по
// сигнатуре, поэтому пустые значения проверяются уже в методах.
func New(db *store.DB, p Panel, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{db: db, p: p, log: log}
}

// snapshot описывает то, что сохраняется в колонку grace_users.snapshot:
// полное состояние пользователя на момент заявки, для админки и для
// возможного расширения восстановления в будущем. Поля, которые реально
// нужны Restore прямо сейчас (сквады и срок), дополнительно лежат в
// отдельных колонках записи.
type snapshot struct {
	Squads            []string `json:"squads"`
	ExpireAt          int64    `json:"expire_at"` // unix-секунды, 0 значит не задано
	TrafficLimitBytes int64    `json:"traffic_limit_bytes"`
	HWIDDeviceLimit   int      `json:"hwid_device_limit"`
	Status            string   `json:"status"`
}

// isExpired решает, истёк ли срок пользователя по данным панели.
// Грейс касается только истёкших: заблокированных или упёршихся в лимит
// трафика пользователей он не трогает, это отдельные состояния.
func isExpired(u model.PanelUser) bool {
	if u.Status == "EXPIRED" {
		return true
	}
	return !u.ExpireAt.IsZero() && !u.ExpireAt.After(time.Now())
}

// Maybe выдаёт грейс, если он положен: включён в настройках, для пользователя
// задан сквад грейса и у пользователя истёк срок. Повторный вызов, пока
// грейс уже активен и применён без ошибок, ничего не делает: это и есть
// идемпотентность, обязательная при опросе подписки клиентом по таймеру.
//
// Если предыдущая попытка применить грейс сорвалась на обращении к панели
// (запись в базе уже есть, но панель её не приняла), Maybe повторяет именно
// эту попытку тем же снимком, а не заводит новую заявку.
func (s *Service) Maybe(ctx context.Context, u model.PanelUser) (applied bool, err error) {
	shortUUID := strings.TrimSpace(u.ShortUUID)
	if shortUUID == "" {
		return false, errors.New("grace: у пользователя не задан shortUuid")
	}

	if !s.db.GetBool(ctx, store.KeyGraceEnabled) {
		return false, nil
	}
	if !isExpired(u) {
		return false, nil
	}
	squad := strings.TrimSpace(s.db.Get(ctx, store.KeyGraceSquad))
	if squad == "" {
		s.log.Warn("grace: сквад для грейса не задан, грейс не применяется", "short_uuid", shortUUID)
		return false, nil
	}
	// Находка ревью: нулевой ExpireAt в ответе панели неотличим от того, что
	// клиент панели не смог разобрать дату и молча вернул time.Time{}
	// (расхождение формата даты между версиями панели). Различить "у
	// пользователя правда нет срока" и "дата не распознана" на этом уровне
	// невозможно, а без надёжного исходного срока Restore будет нечем
	// откатывать. Поэтому, как и с отсутствующим снимком (см. требование 1
	// в шапке пакета), такой грейс просто не применяем: пользователь
	// останется истёкшим, зато его данные останутся целы.
	if u.ExpireAt.IsZero() {
		s.log.Warn("grace: у пользователя не задан срок действия (или он не распознан панелью), снимок ненадёжен, грейс не применяется",
			"short_uuid", shortUUID)
		return false, nil
	}
	if s.p == nil {
		return false, errors.New("grace: панель не подключена")
	}
	hours := s.db.GetInt(ctx, store.KeyGraceHours, 24)
	if hours <= 0 {
		hours = 24
	}

	unlock := s.locks.lock(shortUUID)
	defer unlock()

	now := time.Now()
	snap := snapshot{
		Squads:            u.Squads,
		ExpireAt:          timeUnix(u.ExpireAt),
		TrafficLimitBytes: u.TrafficLimitBytes,
		HWIDDeviceLimit:   u.HWIDDeviceLimit,
		Status:            u.Status,
	}
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		return false, fmt.Errorf("grace: не сериализовать снимок: %w", err)
	}
	origSquadsJSON, err := json.Marshal(u.Squads)
	if err != nil {
		return false, fmt.Errorf("grace: не сериализовать сквады: %w", err)
	}

	rec := model.GraceRecord{
		UserRef:        u.Ref,
		ShortUUID:      shortUUID,
		Username:       u.Username,
		StartedAt:      now,
		ExpiresAt:      now.Add(time.Duration(hours) * time.Hour),
		SnapshotJSON:   string(snapJSON),
		AppliedSquad:   squad,
		OriginalSquads: string(origSquadsJSON),
	}

	id, claimed, err := s.tryClaim(ctx, rec)
	if err != nil {
		// Требование 1: без сохранённого снимка в панель не идём вообще.
		return false, fmt.Errorf("grace: не сохранить снимок, грейс не применён: %w", err)
	}

	if !claimed {
		// Активная запись уже есть. Если она без ошибки, грейс уже применён,
		// повторно панель не трогаем. Если с ошибкой, прошлая попытка
		// сорвалась на сети, повторяем именно её, тем же снимком.
		existing, err := s.activeByShortUUID(ctx, shortUUID)
		if err != nil {
			return false, fmt.Errorf("grace: не прочитать текущий грейс: %w", err)
		}
		if existing == nil || existing.Err == "" {
			return false, nil
		}
		return s.pushToPanel(ctx, *existing)
	}

	rec.ID = id
	return s.pushToPanel(ctx, rec)
}

// pushToPanel переводит пользователя в сквад грейса с продлённым сроком
// и фиксирует результат в записи. Снимок к этому моменту уже сохранён.
func (s *Service) pushToPanel(ctx context.Context, rec model.GraceRecord) (bool, error) {
	patch := map[string]any{
		PatchSquads:   []string{rec.AppliedSquad},
		PatchExpireAt: rec.ExpiresAt,
	}
	if err := s.p.UpdateUser(ctx, rec.UserRef, patch); err != nil {
		// Требование 5: ошибка обращения к панели фиксируется в самой записи.
		_ = s.setErr(ctx, rec.ID, err.Error())
		return false, fmt.Errorf("grace: панель не приняла изменение (запись %d): %w", rec.ID, err)
	}
	if rec.Err != "" {
		_ = s.clearErr(ctx, rec.ID)
	}
	return true, nil
}

// Restore возвращает пользователя к состоянию из снимка: исходные сквады
// и исходный срок действия. Идемпотентен: повторный вызов на уже
// восстановленной записи ничего не делает.
func (s *Service) Restore(ctx context.Context, id int64) error {
	rec, err := s.getRecord(ctx, id)
	if err != nil {
		return err
	}
	if rec.Restored {
		return nil
	}

	unlock := s.locks.lock(rec.ShortUUID)
	defer unlock()

	// Перечитываем под блокировкой: пока её ждали, запись могла восстановиться.
	rec, err = s.getRecord(ctx, id)
	if err != nil {
		return err
	}
	if rec.Restored {
		return nil
	}

	var squads []string
	if err := json.Unmarshal([]byte(rec.OriginalSquads), &squads); err != nil {
		return fmt.Errorf("grace: повреждены исходные сквады записи %d: %w", id, err)
	}
	var snap snapshot
	if err := json.Unmarshal([]byte(rec.SnapshotJSON), &snap); err != nil {
		return fmt.Errorf("grace: повреждён снимок записи %d: %w", id, err)
	}
	if s.p == nil {
		return fmt.Errorf("grace: панель не подключена, запись %d останется в очереди", id)
	}

	// Находка ревью: поле идёт в патч, только если в снимке для него есть
	// надёжное значение. json.Unmarshal("null", &squads) без ошибки даёт nil
	// (у пользователя не было сквадов на момент грейса), а unixTime(0) даёт
	// нулевое время (в снимке нет даты, см. также проверку в Maybe выше).
	// Отправлять такие значения панели нельзя: null для activeInternalSquads
	// она, скорее всего, отклонит, а нулевая дата обнулит настоящий срок
	// подписки. Поле, для которого нечего восстанавливать, просто не
	// попадает в патч, тогда PATCH его не тронет.
	patch := make(map[string]any, 2)
	if len(squads) > 0 {
		patch[PatchSquads] = squads
	} else {
		s.log.Warn("grace: в снимке записи нет сквадов, восстановление их не тронет", "id", id, "short_uuid", rec.ShortUUID)
	}
	if snap.ExpireAt > 0 {
		patch[PatchExpireAt] = unixTime(snap.ExpireAt)
	} else {
		s.log.Warn("grace: в снимке записи нет срока действия, восстановление его не тронет", "id", id, "short_uuid", rec.ShortUUID)
	}

	if len(patch) == 0 {
		// Восстанавливать нечего: обе части снимка ненадёжны. Такое возможно
		// только у записей, заведённых до этого исправления (Maybe теперь не
		// даст создать новую запись с нулевым ExpireAt). Пустой PATCH панели
		// не нужен, отмечаем запись восстановленной сразу.
		if err := s.markRestored(ctx, id); err != nil {
			return fmt.Errorf("grace: снимок пуст, но отметить восстановленной не удалось (запись %d): %w", id, err)
		}
		return nil
	}

	if err := s.p.UpdateUser(ctx, rec.UserRef, patch); err != nil {
		// Требование 4: панель недоступна, запись остаётся невосстановленной
		// с ошибкой в поле err, следующий проход RestoreExpired повторит попытку.
		_ = s.setErr(ctx, id, err.Error())
		return fmt.Errorf("grace: панель не приняла восстановление записи %d: %w", id, err)
	}
	if err := s.markRestored(ctx, id); err != nil {
		return fmt.Errorf("grace: восстановлено в панели, но не отмечено в базе (запись %d): %w", id, err)
	}
	return nil
}

// RestoreExpired проходит по записям с истёкшим грейсом и восстанавливает
// каждую. Предназначен для вызова по расписанию (например, раз в несколько
// минут). Ошибка на одной записи не останавливает обработку остальных:
// проблемные записи просто попадут в следующий проход.
func (s *Service) RestoreExpired(ctx context.Context) (int, error) {
	ids, err := s.pendingExpiredIDs(ctx, time.Now())
	if err != nil {
		return 0, fmt.Errorf("grace: не выбрать записи для восстановления: %w", err)
	}

	var errs []error
	restored := 0
	for _, id := range ids {
		if err := s.Restore(ctx, id); err != nil {
			s.log.Warn("grace: не восстановить запись, повторю на следующем проходе", "id", id, "err", err)
			errs = append(errs, err)
			continue
		}
		restored++
	}
	return restored, errors.Join(errs...)
}

// List отдаёт записи грейса, свежие первыми. activeOnly оставляет только
// невосстановленные: то, что нужно видеть администратору как "сейчас в грейсе".
func (s *Service) List(ctx context.Context, activeOnly bool) ([]model.GraceRecord, error) {
	q := "SELECT " + graceColumns + " FROM grace_users"
	if activeOnly {
		q += " WHERE restored = 0"
	}
	q += " ORDER BY id DESC"

	rows, err := s.db.RO().QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("grace: не прочитать список: %w", err)
	}
	defer rows.Close()

	var out []model.GraceRecord
	for rows.Next() {
		rec, err := scanGraceRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
