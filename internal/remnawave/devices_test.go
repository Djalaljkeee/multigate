package remnawave

import (
	"context"
	"net/http"
	"testing"
)

func TestDevices_ParsesListAndFillsUserRef(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/hwid/devices/u-1": jsonOK(`{"devices":[{"hwid":"hw-1","platform":"ios"},{"hwid":"hw-2","userUuid":"other"}],"total":2}`),
	})
	c := newTestClient(t, ts.URL)

	devices, err := c.Devices(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("ожидал 2 устройства, got %d", len(devices))
	}
	// Панель не всегда дублирует владельца в каждой записи, подставляем ref,
	// которым спрашивали, если в самой записи его нет.
	if devices[0].UserRef != "u-1" {
		t.Errorf("ожидал подстановку userRef из запроса: %+v", devices[0])
	}
	if devices[1].UserRef != "other" {
		t.Errorf("явный userUuid в записи не должен перезаписываться: %+v", devices[1])
	}
}

func TestDevices_RejectsEmptyRef(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:0")
	if _, err := c.Devices(context.Background(), "  "); err == nil {
		t.Fatal("ожидал ошибку на пустой userRef")
	}
}

func TestAllDevices_PassesOffsetAndLimit(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/hwid/devices": func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if q.Get("offset") != "5" || q.Get("limit") != "50" {
				t.Errorf("неожиданные query: %v", q)
			}
			jsonOK(`{"devices":[{"hwid":"hw-1"}],"total":1}`)(w, r)
		},
	})
	c := newTestClient(t, ts.URL)

	devices, total, err := c.AllDevices(context.Background(), 5, 50)
	if err != nil {
		t.Fatalf("AllDevices: %v", err)
	}
	if total != 1 || len(devices) != 1 {
		t.Fatalf("неожиданный результат: devices=%+v total=%d", devices, total)
	}
}

func TestAllDevices_ArrayForm(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/hwid/devices": jsonOK(`[{"hwid":"hw-1"},{"hwid":"hw-2"}]`),
	})
	c := newTestClient(t, ts.URL)

	devices, total, err := c.AllDevices(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("AllDevices: %v", err)
	}
	if total != 2 || len(devices) != 2 {
		t.Fatalf("неожиданный результат: devices=%+v total=%d", devices, total)
	}
}

func TestDeleteDevice_V2SendsUserUUID(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata": jsonOK(`{"response":{"version":"2.7.4"}}`),
		"/api/hwid/devices/delete": func(w http.ResponseWriter, r *http.Request) {
			body := decodeBody(t, r)
			if body["userUuid"] != "u-1" || body["hwid"] != "hw-1" {
				t.Errorf("неожиданное тело: %v", body)
			}
			if _, hasUserID := body["userId"]; hasUserID {
				t.Errorf("на 2.x поле userId лишнее: %v", body)
			}
			jsonOK(`{"response":{}}`)(w, r)
		},
	})
	c := newTestClient(t, ts.URL)

	if err := c.DeleteDevice(context.Background(), "u-1", "hw-1"); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
}

func TestDeleteDevice_V3SendsUserID(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata":      jsonOK(`{"response":{"version":"3.2.2"}}`),
		"/api/system/configuration": jsonOK(`{"response":{}}`),
		"/api/hwid/devices/delete": func(w http.ResponseWriter, r *http.Request) {
			body := decodeBody(t, r)
			idVal, ok := body["userId"].(float64)
			if !ok || idVal != 9 {
				t.Errorf("ожидал числовой userId=9: %v", body)
			}
			if _, hasUUID := body["userUuid"]; hasUUID {
				t.Errorf("на 3.x поле userUuid лишнее: %v", body)
			}
			jsonOK(`{"response":{}}`)(w, r)
		},
	})
	c := newTestClient(t, ts.URL)

	if err := c.DeleteDevice(context.Background(), "9", "hw-1"); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
}
