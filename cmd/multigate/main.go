// Команда multigate: прослойка подписок для панели Remnawave.
//
// Процесс поднимает один HTTP-сервер. На нём живут: выдача подписки (всё,
// что не попало в служебные пути), админка, приём вебхуков, API чата
// поддержки и проверка живости. Разносить это по портам смысла нет:
// наружу прослойку всё равно выставляет обратный прокси.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/qwe8nxtroud/multigate/internal/admin"
	"github.com/qwe8nxtroud/multigate/internal/brand"
	"github.com/qwe8nxtroud/multigate/internal/chat"
	"github.com/qwe8nxtroud/multigate/internal/config"
	"github.com/qwe8nxtroud/multigate/internal/grace"
	"github.com/qwe8nxtroud/multigate/internal/landing"
	"github.com/qwe8nxtroud/multigate/internal/proxy"
	"github.com/qwe8nxtroud/multigate/internal/store"
	"github.com/qwe8nxtroud/multigate/internal/ua"
	"github.com/qwe8nxtroud/multigate/internal/version"
	"github.com/qwe8nxtroud/multigate/internal/webhooks"
	"github.com/qwe8nxtroud/multigate/internal/wgpool"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "multigate: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		return err
	}
	if cfg.ShowVersion {
		fmt.Println(version.Full())
		fmt.Println(brand.Line())
		return nil
	}

	log := newLogger(cfg)
	// Заставка автора первой строкой в журнале: её видит администратор при
	// каждом запуске сервиса, вырезать её из работающей установки нельзя,
	// не пересобрав бинарник самому.
	fmt.Fprint(os.Stderr, brand.Banner(version.Version))
	log.Info("запуск", "версия", version.Version, "коммит", version.Commit, "адрес", cfg.Listen)

	// Сигналы ловим до открытия базы: если пользователь передумал на первой же
	// секунде, процесс должен закрыться чисто, а не оставить базу в WAL-состоянии.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DSN)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.Migrate(ctx); err != nil {
		return err
	}
	if err := applyBootstrap(ctx, db, cfg, log); err != nil {
		return err
	}

	reqLog := db.NewReqLogger(ctx)
	defer reqLog.Close()

	// Держатель, а не клиент напрямую: адрес и токен панели меняются
	// в админке, и подхватываться это должно без перезапуска.
	panel := newPanelHolder(ctx, db, log)
	go panel.watch(ctx)

	graceSvc := grace.New(db, panel, log)
	whSvc := webhooks.New(db, log)
	defer whSvc.Close()
	chatSvc := chat.New(db, log)
	defer chatSvc.Close()

	adminH, err := admin.New(admin.Deps{
		Store:    db,
		Panel:    panel,
		ReqLog:   reqLog, // чтобы на обзоре было видно, теряет ли журнал записи
		Logger:   log,
		BasePath: adminPath(ctx, db),
		// Без этого флага админка считает заголовки прокси недостоверными
		// и ключует антибрутфорс по адресу соединения. Это безопасное
		// поведение по умолчанию, но за обратным прокси оно склеило бы
		// всех клиентов в один адрес.
		TrustProxy: cfg.TrustProxy,
	})
	if err != nil {
		return fmt.Errorf("админка: %w", err)
	}
	defer adminH.Close()

	decoy := landing.New(db)

	proxyH, err := proxy.New(proxy.Deps{
		Store:   db,
		Panel:   panel,
		ReqLog:  reqLog,
		ParseUA: ua.Parse,
		Landing: decoy,
		// Грейс и пул WireGuard включаются настройками и по умолчанию
		// выключены, но связать их надо здесь: иначе код есть, а
		// возможности в работающем сервисе нет.
		Grace:      graceSvc,
		WGPool:     wgpool.New(db, log),
		Logger:     log,
		TrustProxy: cfg.TrustProxy,
	})
	if err != nil {
		return fmt.Errorf("ядро прокси: %w", err)
	}

	mux := http.NewServeMux()
	base := adminPath(ctx, db)
	// Админка строит свои пути уже с префиксом, поэтому префикс не срезаем:
	// иначе она не узнаёт собственные маршруты и отвечает 404 на всё.
	mux.Handle(base+"/", adminH)
	mux.Handle(base, adminH)
	mux.Handle("/api/webhook", whSvc.Handler())
	mux.Handle("/api/chat/", chatSvc.Handler())
	mux.Handle("/api/chat/tg", chatSvc.WebhookHandler())
	mux.HandleFunc("/healthz", healthz)

	// robots.txt отдаёт маскировка. Без отдельного маршрута этот путь ушёл бы
	// в ядро подписки и был бы принят за идентификатор подписки.
	mux.Handle("/robots.txt", decoy)

	// Всё остальное это запросы за подпиской: конкретные пути разбирает само ядро.
	mux.Handle("/", proxyH)

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: mux,
		// Клиенты подписки бывают медленными на мобильной сети, но держать
		// соединение вечно незачем: заголовки читаются быстро, тело маленькое.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	go background(ctx, db, graceSvc, whSvc, chatSvc, log)

	errCh := make(chan error, 1)
	go func() {
		log.Info("слушаю", "адрес", cfg.Listen, "админка", base)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("останавливаюсь")
	}

	// Даём доработать текущим запросам: обрыв подписки на середине выглядит
	// у клиента как сбой сети, а не как перезапуск сервиса.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Warn("остановка с ошибкой", "ошибка", err)
	}
	return nil
}

func newLogger(cfg config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogJSON {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

// applyBootstrap переносит начальные значения из окружения в базу.
// Работает только на пустой установке: после первичной настройки значения
// живут в базе, и перезапуск контейнера не должен затирать то,
// что администратор поменял в админке.
func applyBootstrap(ctx context.Context, db *store.DB, cfg config.Config, log *slog.Logger) error {
	if !cfg.Bootstrap.Any() {
		return nil
	}
	if db.Get(ctx, store.KeyInstalled) == "1" {
		log.Debug("первичная настройка пропущена: установка уже настроена")
		return nil
	}

	kv := map[string]string{}
	put := func(key, val string) {
		if strings.TrimSpace(val) != "" {
			kv[key] = val
		}
	}
	b := cfg.Bootstrap
	put(store.KeyMode, b.Mode)
	put(store.KeyPanelURL, b.PanelURL)
	put(store.KeyPanelToken, b.PanelToken)
	put(store.KeyMirrorTarget, b.MirrorTarget)
	put(store.KeySubPageURL, b.SubPageURL)
	put(store.KeyOwnDomain, b.Domain)
	put(store.KeyAdminUser, b.AdminUser)
	put(store.KeyAdminPath, b.AdminPath)

	if b.AdminPassword != "" {
		// Пароль в базе только хешем. bcrypt здесь тот же, что проверяет
		// админка при входе, поэтому формат совпадает без общего кода.
		hash, err := bcrypt.GenerateFromPassword([]byte(b.AdminPassword), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("не сохранить пароль администратора: %w", err)
		}
		kv[store.KeyAdminHash] = string(hash)

		// Раз учётные данные заданы, установка считается настроенной, и мастер
		// закрывается. Без этого флага сервис после штатной установки из
		// compose или install.sh остаётся с открытым мастером: любой, кто
		// откроет его первым, назначит себя администратором и получит доступ
		// к списку пользователей панели и к настройкам апстрима.
		if strings.TrimSpace(b.AdminUser) != "" {
			kv[store.KeyInstalled] = "1"
		}
	}
	if len(kv) == 0 {
		return nil
	}
	if err := db.SetMany(ctx, kv); err != nil {
		return fmt.Errorf("первичная настройка: %w", err)
	}
	if kv[store.KeyInstalled] == "1" {
		log.Info("первичная настройка применена, мастер закрыт", "параметров", len(kv))
	} else {
		// Пароль без логина (или наоборот) войти не позволит, а мастер
		// останется открытым. Говорим об этом громко: молча оставленный
		// открытым мастер это дыра, а не мелкое неудобство.
		log.Warn("первичная настройка применена частично: мастер админки открыт, пройдите его сразу",
			"параметров", len(kv))
	}
	return nil
}

// adminPath возвращает префикс админки в виде "/admin": с ведущим слешем
// и без хвостового.
//
// Пустая строка здесь недопустима: она попала бы в mux.Handle("") и уронила
// бы процесс паникой при старте. Путь задаётся только переменной окружения,
// то есть получился бы неисправимый из админки цикл перезапусков. Поэтому
// негодное значение (в том числе одиночный слеш) заменяем на значение
// по умолчанию, а не пытаемся использовать как есть.
func adminPath(ctx context.Context, db *store.DB) string {
	p := strings.TrimSpace(db.Get(ctx, store.KeyAdminPath))
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "/admin"
	}
	return p
}

// healthz отвечает на проверку живости. Намеренно не ходит ни в базу,
// ни в панель: иначе оркестратор перезапускал бы рабочий процесс всякий раз,
// когда панель прилегла на минуту, и сделал бы недоступность полной.
//
// Название продукта и версия отсюда убраны намеренно. Адрес прослойки
// открыт интернету и прикрыт страницей-маскировкой, а эндпоинт живости,
// называющий продукт и версию, выдавал бы её первым же запросом сканера.
func healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// background крутит периодические задачи: чистку журналов и кэша, возврат
// пользователей из грейса.
//
// Все таблицы, в которые пишет интернет (журнал запросов, журнал вебхуков,
// кэш ответов, переписка чата), обязаны кем-то чиститься. Без этого место
// на диске кончается, и вместе с ним ложится выдача подписки: база общая.
func background(ctx context.Context, db *store.DB, g *grace.Service, wh *webhooks.Service, ch *chat.Service, log *slog.Logger) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			days := db.GetInt(ctx, store.KeyLogKeepDays, 14)
			if days > 0 {
				if n, err := db.PruneRequestLog(ctx, days); err != nil {
					log.Warn("чистка журнала запросов не удалась", "ошибка", err)
				} else if n > 0 {
					log.Debug("журнал запросов почищен", "удалено", n)
				}
				if n, err := wh.Prune(ctx, days); err != nil {
					log.Warn("чистка журнала вебхуков не удалась", "ошибка", err)
				} else if n > 0 {
					log.Debug("журнал вебхуков почищен", "удалено", n)
				}
			}

			// Переписку чата держим дольше журналов: к обращению возвращаются
			// через неделю и через две, а места она занимает немного.
			if n, err := ch.Prune(ctx, chatKeepDays(days)); err != nil {
				log.Warn("чистка чата не удалась", "ошибка", err)
			} else if n > 0 {
				log.Debug("чат почищен", "удалено", n)
			}

			if n, err := db.PruneSubCache(ctx); err != nil {
				log.Warn("чистка кэша подписок не удалась", "ошибка", err)
			} else if n > 0 {
				log.Debug("кэш подписок почищен", "удалено", n)
			}
			if n, err := db.TrimSubCache(ctx, maxSubCacheRows); err != nil {
				log.Warn("подрезка кэша подписок не удалась", "ошибка", err)
			} else if n > 0 {
				log.Info("кэш подписок подрезан по размеру", "удалено", n)
			}

			if db.GetBool(ctx, store.KeyGraceEnabled) {
				if n, err := g.RestoreExpired(ctx); err != nil {
					log.Warn("возврат из грейса не удался", "ошибка", err)
				} else if n > 0 {
					log.Info("пользователи возвращены из грейса", "количество", n)
				}
			}
		}
	}
}

// maxSubCacheRows: потолок числа записей в кэше ответов подписки.
// В режиме зеркала origin отвечает на любой путь, поэтому перебор случайных
// адресов иначе наполнял бы кэш без ограничений.
const maxSubCacheRows = 20000

// chatKeepDays переводит срок хранения журналов в срок хранения переписки.
func chatKeepDays(logDays int) int {
	if logDays <= 0 {
		return 0
	}
	if d := logDays * 3; d > 30 {
		return d
	}
	return 30
}
