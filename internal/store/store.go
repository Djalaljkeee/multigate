// Package store хранит состояние прослойки: настройки, журналы,
// локальные блокировки, грейс, пул WireGuard-конфигов.
//
// Поддерживаются SQLite (по умолчанию, чистый Go без cgo) и MySQL/MariaDB.
// Соединений два: rw и ro. Для SQLite это принципиально: писатель там один,
// и отдельный пул на чтение снимает блокировки на журнале запросов,
// который пишется на каждый запрос подписки.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// Dialect: вид базы под капотом.
type Dialect string

const (
	DialectSQLite Dialect = "sqlite"
	DialectMySQL  Dialect = "mysql"
)

// ErrNotFound возвращается, когда запись не найдена.
// Оборачивает общий сентинел, чтобы errors.Is работал одинаково
// с ошибками хранилища и с ошибками клиента панели.
var ErrNotFound = fmt.Errorf("store: запись не найдена: %w", model.ErrNotFound)

// DB: хранилище прослойки.
type DB struct {
	rw      *sql.DB
	ro      *sql.DB
	dialect Dialect
	dsn     string

	settings *settingsCache
	ov       *overrideCache
}

// Open открывает хранилище по DSN.
//
// Примеры DSN:
//
//	sqlite:///var/lib/multigate/multigate.db
//	sqlite://./data/multigate.db
//	mysql://user:pass@tcp(127.0.0.1:3306)/multigate
func Open(ctx context.Context, dsn string) (*DB, error) {
	switch {
	case strings.HasPrefix(dsn, "sqlite://"), strings.HasSuffix(dsn, ".db"), strings.HasSuffix(dsn, ".sqlite"):
		return openSQLite(ctx, dsn)
	case strings.HasPrefix(dsn, "mysql://"):
		return openMySQL(ctx, dsn)
	default:
		return nil, fmt.Errorf("store: не понял DSN %q: ожидается sqlite:// или mysql://", dsn)
	}
}

func openSQLite(ctx context.Context, dsn string) (*DB, error) {
	path := strings.TrimPrefix(dsn, "sqlite://")
	if path == "" {
		return nil, errors.New("store: в DSN SQLite не указан путь к файлу")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("store: не создать каталог базы %s: %w", dir, err)
		}
	}

	// WAL даёт одновременное чтение во время записи, busy_timeout убирает
	// мгновенные "database is locked" под параллельными запросами подписки.
	pragmas := "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	rw, err := sql.Open("sqlite", "file:"+path+"?"+pragmas)
	if err != nil {
		return nil, fmt.Errorf("store: не открыть базу на запись: %w", err)
	}
	// Писатель в SQLite ровно один, иначе драйвер будет ловить блокировки сам с собой.
	rw.SetMaxOpenConns(1)
	rw.SetMaxIdleConns(1)
	rw.SetConnMaxLifetime(0)

	ro, err := sql.Open("sqlite", "file:"+path+"?"+pragmas+"&mode=ro")
	if err != nil {
		_ = rw.Close()
		return nil, fmt.Errorf("store: не открыть базу на чтение: %w", err)
	}
	ro.SetMaxOpenConns(8)
	ro.SetMaxIdleConns(4)

	db := &DB{rw: rw, ro: ro, dialect: DialectSQLite, dsn: dsn}
	if err := db.ping(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	db.settings = newSettingsCache(db)
	db.ov = &overrideCache{}
	return db, nil
}

func openMySQL(ctx context.Context, dsn string) (*DB, error) {
	native, err := mysqlDSN(dsn)
	if err != nil {
		return nil, err
	}
	pool, err := sql.Open("mysql", native)
	if err != nil {
		return nil, fmt.Errorf("store: не открыть MySQL: %w", err)
	}
	pool.SetMaxOpenConns(16)
	pool.SetMaxIdleConns(8)
	pool.SetConnMaxLifetime(time.Hour)

	// У MySQL нет ограничения на одного писателя, поэтому пул общий.
	db := &DB{rw: pool, ro: pool, dialect: DialectMySQL, dsn: dsn}
	if err := db.ping(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	db.settings = newSettingsCache(db)
	db.ov = &overrideCache{}
	return db, nil
}

// mysqlDSN переводит URL-форму в форму драйвера go-sql-driver.
func mysqlDSN(dsn string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("store: не разобрать DSN MySQL: %w", err)
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	host := u.Host
	if !strings.Contains(host, "(") {
		if !strings.Contains(host, ":") {
			host += ":3306"
		}
		host = "tcp(" + host + ")"
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" {
		return "", errors.New("store: в DSN MySQL не указано имя базы")
	}
	q := u.Query()
	q.Set("parseTime", "true")
	q.Set("charset", "utf8mb4")
	if q.Get("loc") == "" {
		q.Set("loc", "UTC")
	}
	auth := user
	if pass != "" {
		auth += ":" + pass
	}
	if auth != "" {
		auth += "@"
	}
	return fmt.Sprintf("%s%s/%s?%s", auth, host, dbName, q.Encode()), nil
}

func (d *DB) ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := d.rw.PingContext(ctx); err != nil {
		return fmt.Errorf("store: база не отвечает: %w", err)
	}
	return nil
}

// Dialect сообщает, какая база под капотом.
func (d *DB) Dialect() Dialect { return d.dialect }

// RW возвращает пул на запись. Нужен пакетам, которым не хватает готовых методов.
func (d *DB) RW() *sql.DB { return d.rw }

// RO возвращает пул на чтение.
func (d *DB) RO() *sql.DB { return d.ro }

// Close закрывает соединения.
func (d *DB) Close() error {
	var errs []error
	if d.ro != nil && d.ro != d.rw {
		if err := d.ro.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if d.rw != nil {
		if err := d.rw.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Stats отдаёт размер базы и число строк в крупных таблицах: используется для вкладки «О системе».
func (d *DB) Stats(ctx context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	for _, t := range []string{"request_log", "webhook_log", "overrides", "grace_users", "wg_leases", "chat_messages"} {
		var n int64
		//nolint:gosec // имя таблицы из статического списка выше, подстановки извне нет
		if err := d.ro.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+t).Scan(&n); err != nil {
			continue
		}
		out[t] = n
	}
	if d.dialect == DialectSQLite {
		var pageCount, pageSize int64
		if err := d.ro.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err == nil {
			if err := d.ro.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err == nil {
				out["db_bytes"] = pageCount * pageSize
			}
		}
	}
	return out, nil
}
