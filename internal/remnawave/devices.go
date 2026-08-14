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

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// rawDevice: запись устройства в реестре HWID. Имя пользователя-владельца
// плавает так же, как и у пользователя: uuid в 2.x, id в 3.x.
type rawDevice struct {
	HWID        string          `json:"hwid"`
	UserUUID    string          `json:"userUuid"`
	UserID      json.Number     `json:"userId"`
	Platform    string          `json:"platform"`
	OSVersion   string          `json:"osVersion"`
	DeviceModel string          `json:"deviceModel"`
	AppVersion  string          `json:"appVersion"`
	CreatedAt   json.RawMessage `json:"createdAt"`
	UpdatedAt   json.RawMessage `json:"updatedAt"`
}

func (r rawDevice) toDevice() model.Device {
	d := model.Device{
		HWID:       r.HWID,
		Platform:   r.Platform,
		OSVersion:  r.OSVersion,
		Device:     r.DeviceModel,
		AppVersion: r.AppVersion,
		CreatedAt:  parseTime(r.CreatedAt),
		UpdatedAt:  parseTime(r.UpdatedAt),
	}
	switch {
	case r.UserUUID != "":
		d.UserRef = r.UserUUID
	case string(r.UserID) != "":
		d.UserRef = string(r.UserID)
	}
	return d
}

// devicesPage: страница реестра устройств (массив плюс общее число).
type devicesPage struct {
	Devices []rawDevice `json:"devices"`
	Total   int         `json:"total"`
}

// parseDevicesPage поддерживает и обёртку {devices:[...], total}, и голый массив.
func parseDevicesPage(raw json.RawMessage) (devicesPage, error) {
	var page devicesPage
	if err := json.Unmarshal(raw, &page); err == nil && len(page.Devices) > 0 {
		return page, nil
	}
	var arr []rawDevice
	if err := json.Unmarshal(raw, &arr); err == nil {
		return devicesPage{Devices: arr, Total: len(arr)}, nil
	}
	if err := json.Unmarshal(raw, &page); err == nil {
		return page, nil
	}
	return devicesPage{}, errors.New("неизвестная форма ответа")
}

// Devices возвращает устройства одного пользователя.
func (c *Client) Devices(ctx context.Context, userRef string) ([]model.Device, error) {
	userRef = strings.TrimSpace(userRef)
	if userRef == "" {
		return nil, errors.New("remnawave: пустой ref пользователя")
	}
	var raw json.RawMessage
	if _, err := c.getJSON(ctx, "/api/hwid/devices/"+url.PathEscape(userRef), nil, true, &raw); err != nil {
		return nil, err
	}
	page, err := parseDevicesPage(raw)
	if err != nil {
		return nil, fmt.Errorf("remnawave: разобрать устройства пользователя: %w", err)
	}
	out := make([]model.Device, 0, len(page.Devices))
	for _, d := range page.Devices {
		dev := d.toDevice()
		if dev.UserRef == "" {
			dev.UserRef = userRef
		}
		out = append(out, dev)
	}
	return out, nil
}

// AllDevices возвращает страницу общего реестра устройств всех пользователей.
// Нужен админке: поштучный обход через Devices для каждого пользователя был
// бы N+1 запросов к панели.
func (c *Client) AllDevices(ctx context.Context, offset, limit int) ([]model.Device, int, error) {
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	q := url.Values{}
	q.Set("offset", strconv.Itoa(offset))
	q.Set("limit", strconv.Itoa(limit))

	var raw json.RawMessage
	if _, err := c.getJSON(ctx, "/api/hwid/devices", q, true, &raw); err != nil {
		return nil, 0, err
	}
	page, err := parseDevicesPage(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("remnawave: разобрать реестр устройств: %w", err)
	}
	out := make([]model.Device, 0, len(page.Devices))
	for _, d := range page.Devices {
		out = append(out, d.toDevice())
	}
	total := page.Total
	if total == 0 && len(out) > 0 {
		total = len(out)
	}
	return out, total, nil
}

// DeleteDevice убирает устройство из реестра HWID, и панель после этого
// разрешит тому же пользователю подключить новое взамен удалённого.
func (c *Client) DeleteDevice(ctx context.Context, userRef, hwid string) error {
	userRef = strings.TrimSpace(userRef)
	hwid = strings.TrimSpace(hwid)
	if userRef == "" || hwid == "" {
		return errors.New("remnawave: нужны и ref пользователя, и hwid")
	}
	major, err := c.ensureMajor(ctx)
	if err != nil {
		return err
	}

	body := map[string]any{"hwid": hwid}
	if major >= 3 {
		id, cerr := strconv.ParseInt(userRef, 10, 64)
		if cerr != nil {
			return fmt.Errorf("remnawave: userRef %q не похож на числовой id, ожидаемый панелью 3.x: %w", userRef, cerr)
		}
		body["userId"] = id
	} else {
		body["userUuid"] = userRef
	}

	return c.writeJSON(ctx, http.MethodPost, "/api/hwid/devices/delete", body, nil)
}
