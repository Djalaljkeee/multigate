package store

import (
	"context"
	"fmt"
	"strings"
)

// migration: один шаг схемы. Шаги применяются по порядку и только один раз,
// номер последнего применённого хранится в таблице schema_version.
type migration struct {
	id   int
	name string
	sql  []string
}

// schema возвращает миграции под конкретный диалект.
// Различий немного: автоинкремент, тип для больших чисел и синтаксис upsert.
func schema(d Dialect) []migration {
	var (
		pk   string // первичный ключ с автоинкрементом
		text string // длинный текст
		ts   string // отметка времени в unix-секундах
	)
	switch d {
	case DialectMySQL:
		pk = "BIGINT AUTO_INCREMENT PRIMARY KEY"
		text = "MEDIUMTEXT"
		ts = "BIGINT"
	default:
		pk = "INTEGER PRIMARY KEY AUTOINCREMENT"
		text = "TEXT"
		ts = "INTEGER"
	}

	return []migration{
		{
			id:   1,
			name: "базовые таблицы",
			sql: []string{
				// Настройки живут в базе, а не в файле: их правят из админки,
				// и перезапуск процесса для этого не нужен.
				`CREATE TABLE IF NOT EXISTS settings (
					k VARCHAR(190) PRIMARY KEY,
					v ` + text + `,
					updated_at ` + ts + ` NOT NULL DEFAULT 0
				)`,

				// Локальные блокировки: по пользователю целиком или по одному устройству.
				`CREATE TABLE IF NOT EXISTS overrides (
					id ` + pk + `,
					short_uuid VARCHAR(190) NOT NULL DEFAULT '',
					hwid VARCHAR(190) NOT NULL DEFAULT '',
					action VARCHAR(32) NOT NULL DEFAULT 'block',
					reason VARCHAR(500) NOT NULL DEFAULT '',
					created_at ` + ts + ` NOT NULL DEFAULT 0,
					created_by VARCHAR(190) NOT NULL DEFAULT ''
				)`,
				`CREATE INDEX IF NOT EXISTS idx_overrides_short ON overrides (short_uuid)`,
				`CREATE INDEX IF NOT EXISTS idx_overrides_hwid ON overrides (hwid)`,

				// Журнал запросов подписки. Пишется на каждый запрос, поэтому
				// колонок ровно столько, сколько нужно фильтрам в админке.
				`CREATE TABLE IF NOT EXISTS request_log (
					id ` + pk + `,
					at ` + ts + ` NOT NULL DEFAULT 0,
					short_uuid VARCHAR(190) NOT NULL DEFAULT '',
					username VARCHAR(190) NOT NULL DEFAULT '',
					ip VARCHAR(64) NOT NULL DEFAULT '',
					country VARCHAR(8) NOT NULL DEFAULT '',
					user_agent VARCHAR(500) NOT NULL DEFAULT '',
					app VARCHAR(64) NOT NULL DEFAULT '',
					app_version VARCHAR(64) NOT NULL DEFAULT '',
					platform VARCHAR(32) NOT NULL DEFAULT '',
					core VARCHAR(32) NOT NULL DEFAULT '',
					hwid VARCHAR(190) NOT NULL DEFAULT '',
					format VARCHAR(32) NOT NULL DEFAULT '',
					decision VARCHAR(32) NOT NULL DEFAULT '',
					status INTEGER NOT NULL DEFAULT 0,
					bytes INTEGER NOT NULL DEFAULT 0,
					duration_ms INTEGER NOT NULL DEFAULT 0,
					mode VARCHAR(16) NOT NULL DEFAULT '',
					err VARCHAR(500) NOT NULL DEFAULT ''
				)`,
				`CREATE INDEX IF NOT EXISTS idx_reqlog_at ON request_log (at)`,
				`CREATE INDEX IF NOT EXISTS idx_reqlog_short ON request_log (short_uuid, at)`,
				`CREATE INDEX IF NOT EXISTS idx_reqlog_hwid ON request_log (hwid, at)`,

				// Правила подмены заголовков ответа под конкретные приложения.
				`CREATE TABLE IF NOT EXISTS header_rules (
					id ` + pk + `,
					name VARCHAR(190) NOT NULL DEFAULT '',
					enabled INTEGER NOT NULL DEFAULT 1,
					priority INTEGER NOT NULL DEFAULT 100,
					match_app VARCHAR(64) NOT NULL DEFAULT '',
					match_os VARCHAR(32) NOT NULL DEFAULT '',
					match_ua VARCHAR(500) NOT NULL DEFAULT '',
					ua_regex INTEGER NOT NULL DEFAULT 0,
					set_headers ` + text + `,
					del_headers ` + text + `,
					created_at ` + ts + ` NOT NULL DEFAULT 0
				)`,
			},
		},
		{
			id:   2,
			name: "грейс, пул WireGuard, вебхуки, чат",
			sql: []string{
				// Снимок пользователя пишется ДО обращения к панели.
				// Без него откат грейса невозможен, а грейс является единственным местом,
				// где прослойка меняет данные в живой панели.
				`CREATE TABLE IF NOT EXISTS grace_users (
					id ` + pk + `,
					user_ref VARCHAR(190) NOT NULL DEFAULT '',
					short_uuid VARCHAR(190) NOT NULL DEFAULT '',
					username VARCHAR(190) NOT NULL DEFAULT '',
					started_at ` + ts + ` NOT NULL DEFAULT 0,
					expires_at ` + ts + ` NOT NULL DEFAULT 0,
					restored INTEGER NOT NULL DEFAULT 0,
					restored_at ` + ts + ` NOT NULL DEFAULT 0,
					snapshot ` + text + `,
					applied_squad VARCHAR(190) NOT NULL DEFAULT '',
					original_squads ` + text + `,
					err VARCHAR(500) NOT NULL DEFAULT ''
				)`,
				`CREATE INDEX IF NOT EXISTS idx_grace_short ON grace_users (short_uuid)`,
				`CREATE INDEX IF NOT EXISTS idx_grace_restored ON grace_users (restored, expires_at)`,

				`CREATE TABLE IF NOT EXISTS wg_leases (
					id ` + pk + `,
					pool VARCHAR(190) NOT NULL DEFAULT 'default',
					config_name VARCHAR(190) NOT NULL DEFAULT '',
					config ` + text + `,
					short_uuid VARCHAR(190) NOT NULL DEFAULT '',
					hwid VARCHAR(190) NOT NULL DEFAULT '',
					issued_at ` + ts + ` NOT NULL DEFAULT 0,
					released_at ` + ts + ` NOT NULL DEFAULT 0,
					in_use INTEGER NOT NULL DEFAULT 0
				)`,
				`CREATE INDEX IF NOT EXISTS idx_wg_pool ON wg_leases (pool, in_use)`,
				`CREATE INDEX IF NOT EXISTS idx_wg_short ON wg_leases (short_uuid, hwid)`,

				`CREATE TABLE IF NOT EXISTS webhook_log (
					id ` + pk + `,
					at ` + ts + ` NOT NULL DEFAULT 0,
					event VARCHAR(190) NOT NULL DEFAULT '',
					payload ` + text + `,
					sig_valid INTEGER NOT NULL DEFAULT 0,
					forwarded INTEGER NOT NULL DEFAULT 0,
					err VARCHAR(500) NOT NULL DEFAULT ''
				)`,
				`CREATE INDEX IF NOT EXISTS idx_whlog_at ON webhook_log (at)`,

				`CREATE TABLE IF NOT EXISTS forward_targets (
					id ` + pk + `,
					name VARCHAR(190) NOT NULL DEFAULT '',
					url VARCHAR(500) NOT NULL DEFAULT '',
					secret VARCHAR(500) NOT NULL DEFAULT '',
					enabled INTEGER NOT NULL DEFAULT 1,
					events ` + text + `,
					created_at ` + ts + ` NOT NULL DEFAULT 0
				)`,

				`CREATE TABLE IF NOT EXISTS forward_log (
					id ` + pk + `,
					at ` + ts + ` NOT NULL DEFAULT 0,
					target VARCHAR(190) NOT NULL DEFAULT '',
					event VARCHAR(190) NOT NULL DEFAULT '',
					status INTEGER NOT NULL DEFAULT 0,
					attempt INTEGER NOT NULL DEFAULT 1,
					err VARCHAR(500) NOT NULL DEFAULT ''
				)`,
				`CREATE INDEX IF NOT EXISTS idx_fwdlog_at ON forward_log (at)`,

				`CREATE TABLE IF NOT EXISTS chat_sessions (
					id ` + pk + `,
					session_id VARCHAR(190) NOT NULL DEFAULT '',
					short_uuid VARCHAR(190) NOT NULL DEFAULT '',
					created_at ` + ts + ` NOT NULL DEFAULT 0,
					last_at ` + ts + ` NOT NULL DEFAULT 0,
					tg_topic_id ` + ts + ` NOT NULL DEFAULT 0,
					closed INTEGER NOT NULL DEFAULT 0
				)`,
				`CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_session ON chat_sessions (session_id)`,

				`CREATE TABLE IF NOT EXISTS chat_messages (
					id ` + pk + `,
					session_id VARCHAR(190) NOT NULL DEFAULT '',
					at ` + ts + ` NOT NULL DEFAULT 0,
					from_user INTEGER NOT NULL DEFAULT 1,
					text ` + text + `,
					tg_msg_id ` + ts + ` NOT NULL DEFAULT 0,
					delivered INTEGER NOT NULL DEFAULT 0
				)`,
				`CREATE INDEX IF NOT EXISTS idx_chatmsg_session ON chat_messages (session_id, at)`,
			},
		},
		{
			id:   3,
			name: "кэш ответов подписки",
			sql: []string{
				// Короткий кэш ответа панели: спасает origin, когда клиент
				// дёргает подписку по таймеру, и держит сервис живым,
				// если панель на минуту стала недоступна.
				`CREATE TABLE IF NOT EXISTS sub_cache (
					id ` + pk + `,
					cache_key VARCHAR(190) NOT NULL DEFAULT '',
					body ` + text + `,
					headers ` + text + `,
					status INTEGER NOT NULL DEFAULT 200,
					stored_at ` + ts + ` NOT NULL DEFAULT 0,
					expires_at ` + ts + ` NOT NULL DEFAULT 0
				)`,
				`CREATE UNIQUE INDEX IF NOT EXISTS idx_subcache_key ON sub_cache (cache_key)`,
				`CREATE INDEX IF NOT EXISTS idx_subcache_exp ON sub_cache (expires_at)`,
			},
		},
	}
}

// Migrate приводит схему к актуальной версии. Вызывается на старте.
func (d *DB) Migrate(ctx context.Context) error {
	verTable := `CREATE TABLE IF NOT EXISTS schema_version (
		id INTEGER PRIMARY KEY,
		applied_at BIGINT NOT NULL DEFAULT 0,
		name VARCHAR(190) NOT NULL DEFAULT ''
	)`
	if _, err := d.rw.ExecContext(ctx, verTable); err != nil {
		return fmt.Errorf("store: не создать schema_version: %w", err)
	}

	var current int
	row := d.rw.QueryRowContext(ctx, "SELECT COALESCE(MAX(id), 0) FROM schema_version")
	if err := row.Scan(&current); err != nil {
		return fmt.Errorf("store: не прочитать версию схемы: %w", err)
	}

	for _, m := range schema(d.dialect) {
		if m.id <= current {
			continue
		}
		tx, err := d.rw.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: миграция %d: не начать транзакцию: %w", m.id, err)
		}
		for _, stmt := range m.sql {
			if _, err := tx.ExecContext(ctx, d.adaptDDL(stmt)); err != nil {
				if d.dialect == DialectMySQL && isDuplicateIndex(err) {
					// MySQL до 8.0.29 не знает CREATE INDEX IF NOT EXISTS, а DDL
					// у него вне транзакций: после сбоя посреди миграции индекс
					// может уже существовать. Это не ошибка, идём дальше.
					continue
				}
				_ = tx.Rollback()
				return fmt.Errorf("store: миграция %d (%s): %w", m.id, m.name, err)
			}
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_version (id, applied_at, name) VALUES (?, ?, ?)",
			m.id, nowUnix(), m.name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: миграция %d: не записать версию: %w", m.id, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: миграция %d: не зафиксировать: %w", m.id, err)
		}
	}
	return nil
}

// adaptDDL правит те места DDL, где MySQL расходится с SQLite.
// MySQL до 8.0.29 не понимает CREATE INDEX IF NOT EXISTS, поэтому такие
// индексы создаются отдельно с игнорированием ошибки «уже существует».
func (d *DB) adaptDDL(stmt string) string {
	if d.dialect != DialectMySQL {
		return stmt
	}
	s := strings.ReplaceAll(stmt, "CREATE INDEX IF NOT EXISTS", "CREATE INDEX")
	s = strings.ReplaceAll(s, "CREATE UNIQUE INDEX IF NOT EXISTS", "CREATE UNIQUE INDEX")
	return s
}
