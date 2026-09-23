package remnawave

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// rawSubInfo: ответ /api/sub/{shortUuid}/info. Объёмы трафика панель
// отдаёт строками (байты в виде числа-строки), поэтому и разбираем строками.
type rawSubInfo struct {
	IsFound bool `json:"isFound"`
	User    struct {
		ShortUUID         string `json:"shortUuid"`
		Username          string `json:"username"`
		DaysLeft          int    `json:"daysLeft"`
		ExpiresAt         string `json:"expiresAt"`
		IsActive          bool   `json:"isActive"`
		UserStatus        string `json:"userStatus"`
		TrafficUsedBytes  string `json:"trafficUsedBytes"`
		TrafficLimitBytes string `json:"trafficLimitBytes"`
	} `json:"user"`
	SubscriptionURL string `json:"subscriptionUrl"`
}

// SubscriptionInfo возвращает сведения о подписке для страницы в браузере.
// Ссылки подключения (links, ssConfLinks) из ответа сознательно не берутся:
// страница их не показывает, и им незачем задерживаться в памяти прослойки.
func (c *Client) SubscriptionInfo(ctx context.Context, shortUUID string) (model.SubInfo, error) {
	shortUUID = strings.TrimSpace(shortUUID)
	if shortUUID == "" {
		return model.SubInfo{}, errors.New("remnawave: пустой shortUuid")
	}
	var raw rawSubInfo
	if _, err := c.getJSON(ctx, "/api/sub/"+url.PathEscape(shortUUID)+"/info", nil, true, &raw); err != nil {
		return model.SubInfo{}, err
	}
	if !raw.IsFound {
		return model.SubInfo{}, ErrNotFound
	}
	u := raw.User
	return model.SubInfo{
		ShortUUID:         u.ShortUUID,
		Username:          u.Username,
		Status:            u.UserStatus,
		IsActive:          u.IsActive,
		ExpiresAt:         parseTime(json.RawMessage(strconv.Quote(u.ExpiresAt))),
		DaysLeft:          u.DaysLeft,
		TrafficUsedBytes:  parseInt64(u.TrafficUsedBytes),
		TrafficLimitBytes: parseInt64(u.TrafficLimitBytes),
		SubscriptionURL:   raw.SubscriptionURL,
	}, nil
}

func parseInt64(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// SubpageRef спрашивает у панели, какой конфиг страницы подписки положен
// пользователю и разрешена ли ему страница. Панель решает это по своим
// правилам (SRR), в том числе по заголовкам запроса, поэтому они уходят
// в теле как есть. Маршрут GET с телом: так его вызывает и страница
// подписки Remnawave.
func (c *Client) SubpageRef(ctx context.Context, shortUUID string, in http.Header) (model.SubpageRef, error) {
	headers := make(map[string]string, len(in))
	for k, vv := range in {
		if len(vv) > 0 {
			headers[strings.ToLower(k)] = vv[0]
		}
	}
	payload, err := json.Marshal(map[string]any{"requestHeaders": headers})
	if err != nil {
		return model.SubpageRef{}, fmt.Errorf("remnawave: собрать запрос конфига страницы: %w", err)
	}

	path := "/api/subscriptions/subpage-config/" + url.PathEscape(strings.TrimSpace(shortUUID))
	res, err := c.doRequest(ctx, http.MethodGet, path, nil, bytes.NewReader(payload), true, nil, defaultMaxBody)
	if err != nil {
		return model.SubpageRef{}, err
	}
	if res.status < 200 || res.status >= 300 {
		return model.SubpageRef{}, apiErr(http.MethodGet, path, res)
	}
	var out struct {
		SubpageConfigUUID *string `json:"subpageConfigUuid"`
		WebpageAllowed    bool    `json:"webpageAllowed"`
	}
	if err := decodeInto(res.body, &out); err != nil {
		return model.SubpageRef{}, fmt.Errorf("remnawave: разобрать ответ %s: %w", path, err)
	}
	ref := model.SubpageRef{WebpageAllowed: out.WebpageAllowed}
	if out.SubpageConfigUUID != nil {
		ref.ConfigUUID = *out.SubpageConfigUUID
	}
	return ref, nil
}

// SubpageConfig возвращает конфиг страницы подписки (платформы, приложения,
// шаги, тексты, оформление) как есть, сырым JSON: его разбирает пакет
// subpage, а клиенту панели незачем знать его схему.
func (c *Client) SubpageConfig(ctx context.Context, uuid string) (json.RawMessage, error) {
	var out struct {
		Config json.RawMessage `json:"config"`
	}
	path := "/api/subscription-page-configs/" + url.PathEscape(strings.TrimSpace(uuid))
	if _, err := c.getJSON(ctx, path, nil, true, &out); err != nil {
		return nil, err
	}
	if len(out.Config) == 0 || string(out.Config) == "null" {
		return nil, fmt.Errorf("remnawave: конфиг страницы %s пуст", uuid)
	}
	return out.Config, nil
}
