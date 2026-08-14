package remnawave

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// rawUser: объединённые поля пользователя панели независимо от версии.
// 2.x кладёт идентификатор в uuid, а 3.x кладёт его числом в id; какого поля
// в ответе нет, то и остаётся нулевым, ошибкой это не считаем.
type rawUser struct {
	ID                json.Number     `json:"id"`
	UUID              string          `json:"uuid"`
	ShortUUID         string          `json:"shortUuid"`
	Username          string          `json:"username"`
	Status            string          `json:"status"`
	ExpireAt          json.RawMessage `json:"expireAt"`
	TrafficLimitBytes json.Number     `json:"trafficLimitBytes"`
	UsedTrafficBytes  json.Number     `json:"usedTrafficBytes"`
	HWIDDeviceLimit   json.Number     `json:"hwidDeviceLimit"`
	// Панель 2.8.0 отдаёт расход трафика не плоским полем, а вложенным
	// объектом userTraffic (проверено на живой панели). Держим оба варианта:
	// плоское поле встречается в других версиях и в ответах отдельных ручек.
	UserTraffic struct {
		UsedTrafficBytes         json.Number `json:"usedTrafficBytes"`
		LifetimeUsedTrafficBytes json.Number `json:"lifetimeUsedTrafficBytes"`
	} `json:"userTraffic"`
	TelegramID json.Number `json:"telegramId"`
	Email      string      `json:"email"`
	Tag        string      `json:"tag"`
	// Название поля со сквадами пользователя между версиями плавает:
	// поддерживаем оба варианта, использует тот, что панель заполнила.
	ActiveSquads []squadRef `json:"activeInternalSquads"`
	Squads       []squadRef `json:"internalSquads"`
}

type squadRef struct {
	UUID string `json:"uuid"`
}

// toPanelUser переводит сырой ответ панели в контракт model.PanelUser.
// major нужен только для одного решения: что положить в Ref.
func (r rawUser) toPanelUser(major int) model.PanelUser {
	u := model.PanelUser{
		UUID:              r.UUID,
		ShortUUID:         r.ShortUUID,
		Username:          r.Username,
		Status:            r.Status,
		ExpireAt:          parseTime(r.ExpireAt),
		TrafficLimitBytes: numOr(r.TrafficLimitBytes),
		UsedTrafficBytes:  r.usedTraffic(),
		HWIDDeviceLimit:   int(numOr(r.HWIDDeviceLimit)),
		TelegramID:        numOr(r.TelegramID),
		Email:             r.Email,
		Tag:               r.Tag,
	}

	squads := r.ActiveSquads
	if len(squads) == 0 {
		squads = r.Squads
	}
	for _, s := range squads {
		if s.UUID != "" {
			u.Squads = append(u.Squads, s.UUID)
		}
	}

	// В 3.x за обращение к пользователю отвечает числовой id. В 2.x поле id
	// в ответе тоже встречается (на 2.8.0 оно есть), но обращаться к панели
	// там нужно по uuid, поэтому смотрим на версию, а не на наличие поля.
	if major >= 3 && string(r.ID) != "" {
		u.Ref = string(r.ID)
	} else {
		u.Ref = r.UUID
	}
	return u
}

// usedTraffic отдаёт израсходованный трафик независимо от того, положила
// его панель плоским полем или вложенным объектом userTraffic.
func (r rawUser) usedTraffic() int64 {
	if v := numOr(r.UsedTrafficBytes); v > 0 {
		return v
	}
	return numOr(r.UserTraffic.UsedTrafficBytes)
}

// numOr читает json.Number, пустое значение (поле отсутствовало) даёт 0.
func numOr(n json.Number) int64 {
	if n == "" {
		return 0
	}
	v, err := n.Int64()
	if err != nil {
		return 0
	}
	return v
}

// parseTime разбирает время, которое панель отдаёт по-разному: строкой
// RFC3339 либо unix-временем числом (в секундах или миллисекундах).
// Нулевое значение (в т.ч. при ошибке разбора) означает "бессрочно",
// так же, как это принято в model.UserInfo.
func parseTime(raw json.RawMessage) time.Time {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" || s == `""` {
		return time.Time{}
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		if str == "" {
			return time.Time{}
		}
		if t, err := time.Parse(time.RFC3339, str); err == nil {
			return t
		}
		if t, err := time.Parse(time.RFC3339Nano, str); err == nil {
			return t
		}
		return time.Time{}
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil && n > 0 {
		if n > 1_000_000_000_000 { // похоже на миллисекунды, а не секунды
			return time.UnixMilli(n)
		}
		return time.Unix(n, 0)
	}
	return time.Time{}
}

// usersPage хранит типичную форму страницы списка в панели: массив плюс общее
// число. Если панель вернёт голый массив без обёртки, страница разбирается
// запасным путём в parseUsersPage.
type usersPage struct {
	Users []rawUser `json:"users"`
	Total int       `json:"total"`
}

// parseUsersPage разбирает ответ /api/users в формах, которые встречаются
// у разных версий панели: объект {users, total} и голый массив.
func parseUsersPage(raw json.RawMessage) (usersPage, error) {
	var page usersPage
	if err := json.Unmarshal(raw, &page); err == nil && len(page.Users) > 0 {
		return page, nil
	}
	var arr []rawUser
	if err := json.Unmarshal(raw, &arr); err == nil {
		return usersPage{Users: arr, Total: len(arr)}, nil
	}
	// Отдельно перепроверяем {users:[], total:0}: это валидная пустая страница,
	// просто на первой попытке она не прошла условие len(page.Users) > 0.
	if err := json.Unmarshal(raw, &page); err == nil {
		return page, nil
	}
	return usersPage{}, errors.New("неизвестная форма ответа")
}

// UserByShortUUID находит пользователя по короткому идентификатору из
// ссылки подписки: это основной путь при выдаче самой подписки.
func (c *Client) UserByShortUUID(ctx context.Context, shortUUID string) (model.PanelUser, error) {
	shortUUID = strings.TrimSpace(shortUUID)
	if shortUUID == "" {
		return model.PanelUser{}, errors.New("remnawave: пустой shortUuid")
	}
	major, err := c.ensureMajor(ctx)
	if err != nil {
		return model.PanelUser{}, err
	}
	var raw rawUser
	if _, err := c.getJSON(ctx, "/api/users/by-short-uuid/"+url.PathEscape(shortUUID), nil, true, &raw); err != nil {
		return model.PanelUser{}, err
	}
	return raw.toPanelUser(major), nil
}

// UserByUsername находит пользователя по имени.
func (c *Client) UserByUsername(ctx context.Context, username string) (model.PanelUser, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return model.PanelUser{}, errors.New("remnawave: пустой username")
	}
	major, err := c.ensureMajor(ctx)
	if err != nil {
		return model.PanelUser{}, err
	}
	var raw rawUser
	if _, err := c.getJSON(ctx, "/api/users/by-username/"+url.PathEscape(username), nil, true, &raw); err != nil {
		return model.PanelUser{}, err
	}
	return raw.toPanelUser(major), nil
}

// ListUsers возвращает страницу пользователей панели вместе с общим числом.
func (c *Client) ListUsers(ctx context.Context, offset, limit int, search string) ([]model.PanelUser, int, error) {
	major, err := c.ensureMajor(ctx)
	if err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	// Панель ждёт start и size (проверено на живой 2.8.0). Пара offset и limit
	// добавлена запасом: незнакомые параметры панель игнорирует, а если в какой-то
	// версии имена окажутся другими, список не окажется пустым.
	q := url.Values{}
	q.Set("start", strconv.Itoa(offset))
	q.Set("size", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	q.Set("limit", strconv.Itoa(limit))
	if search = strings.TrimSpace(search); search != "" {
		q.Set("search", search)
	}

	var raw json.RawMessage
	if _, err := c.getJSON(ctx, "/api/users", q, true, &raw); err != nil {
		return nil, 0, err
	}

	page, err := parseUsersPage(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("remnawave: разобрать список пользователей: %w", err)
	}

	out := make([]model.PanelUser, 0, len(page.Users))
	for _, u := range page.Users {
		out = append(out, u.toPanelUser(major))
	}
	total := page.Total
	if total == 0 && len(out) > 0 {
		total = len(out)
	}
	return out, total, nil
}

// patchFieldAliases: абстрактные имена полей, которыми пользуется остальная
// прослойка (в частности internal/grace: он не должен знать реальный формат
// DTO панели, только "squads" и "expireAt"), в реальные имена полей тела
// PATCH /api/users. "expireAt" совпадает с именем поля из GET-ответа и
// трансляции не требует, а "squads" не совпадает: панель отдаёт сквады
// пользователя как activeInternalSquads, симметрично ожидаем то же имя и на записи.
var patchFieldAliases = map[string]string{
	"squads": "activeInternalSquads",
}

// UpdateUser отправляет частичное обновление пользователя. patch: поля
// панели как есть (например "status", "trafficLimitBytes") плюс два
// признанных пакетом алиаса (см. patchFieldAliases); остальные ключи не
// трогает и не переименовывает. Пакет добавляет к патчу только идентификатор,
// причём в то поле, которого ждёт эта версия панели.
func (c *Client) UpdateUser(ctx context.Context, ref string, patch map[string]any) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return errors.New("remnawave: пустой ref пользователя")
	}
	major, err := c.ensureMajor(ctx)
	if err != nil {
		return err
	}

	body := make(map[string]any, len(patch)+1)
	for k, v := range patch {
		if alias, ok := patchFieldAliases[k]; ok {
			k = alias
		}
		body[k] = v
	}
	if major >= 3 {
		id, cerr := strconv.ParseInt(ref, 10, 64)
		if cerr != nil {
			return fmt.Errorf("remnawave: ref %q не похож на числовой id, ожидаемый панелью 3.x: %w", ref, cerr)
		}
		body["id"] = id
	} else {
		body["uuid"] = ref
	}

	return c.writeJSON(ctx, http.MethodPatch, "/api/users", body, nil)
}

// ResetTraffic обнуляет счётчик трафика пользователя.
func (c *Client) ResetTraffic(ctx context.Context, ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return errors.New("remnawave: пустой ref пользователя")
	}
	path := "/api/users/" + url.PathEscape(ref) + "/actions/reset-traffic"
	return c.writeJSON(ctx, http.MethodPost, path, nil, nil)
}

// detectMajorFromUsers: запасной способ понять версию, когда
// /api/system/metadata недоступен (так отвечают панели 2.7.4 и старше, либо
// временно легла сеть). Смотрим на форму первого пользователя в списке.
//
// Признак это именно uuid, а не числовой id: на живой панели 2.8.0 у
// пользователя есть ОБА поля, поэтому проверка по id принимала бы 2.8 за 3.x
// и обращалась бы к пользователям не тем идентификатором. В 3.x собственного
// uuid у пользователя нет, там он остался только у отдельных сущностей.
func (c *Client) detectMajorFromUsers(ctx context.Context) (int, error) {
	q := url.Values{"start": {"0"}, "size": {"1"}, "offset": {"0"}, "limit": {"1"}}
	var raw json.RawMessage
	if _, err := c.getJSON(ctx, "/api/users", q, true, &raw); err != nil {
		return 0, err
	}
	page, err := parseUsersPage(raw)
	if err != nil {
		return 0, fmt.Errorf("разобрать пользователя для определения версии: %w", err)
	}
	if len(page.Users) == 0 {
		return 0, errors.New("список пользователей пуст, версию панели определить нечем")
	}
	if strings.TrimSpace(page.Users[0].UUID) != "" {
		return 2, nil
	}
	return 3, nil
}
