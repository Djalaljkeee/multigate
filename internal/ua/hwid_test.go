package ua

import (
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

func TestSyntheticHWID_RequiresDeviceAndOSVersion(t *testing.T) {
	cases := []struct {
		name   string
		client model.Client
		wantOK bool
	}{
		{"есть и модель, и версия ос", model.Client{Platform: model.PlatformIOS, OSVersion: "17.4", Device: "iPhone14,2"}, true},
		{"нет модели устройства", model.Client{Platform: model.PlatformIOS, OSVersion: "17.4"}, false},
		{"нет версии ос", model.Client{Platform: model.PlatformIOS, Device: "iPhone14,2"}, false},
		{"нет ничего", model.Client{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := syntheticHWID(tc.client)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && id == "" {
				t.Error("ok=true, но идентификатор пуст")
			}
		})
	}
}

func TestSyntheticHWID_StableAndDistinct(t *testing.T) {
	a := model.Client{Platform: model.PlatformIOS, OSVersion: "17.4", Device: "iPhone14,2"}
	b := model.Client{Platform: model.PlatformIOS, OSVersion: "17.4", Device: "iPhone14,2"}
	c := model.Client{Platform: model.PlatformIOS, OSVersion: "17.5", Device: "iPhone14,2"}     // другая версия ОС
	d := model.Client{Platform: model.PlatformAndroid, OSVersion: "17.4", Device: "iPhone14,2"} // другая платформа
	e := model.Client{Platform: model.PlatformIOS, OSVersion: "17.4", Device: "iPhone15,3"}     // другая модель

	idA, _ := syntheticHWID(a)
	idB, _ := syntheticHWID(b)
	idC, _ := syntheticHWID(c)
	idD, _ := syntheticHWID(d)
	idE, _ := syntheticHWID(e)

	if idA != idB {
		t.Errorf("одинаковые устройства дали разные HWID: %q != %q", idA, idB)
	}
	for _, other := range []string{idC, idD, idE} {
		if other == idA {
			t.Errorf("разные устройства дали одинаковый HWID: %q", idA)
		}
	}
}

func TestSyntheticHWID_IgnoresAppName(t *testing.T) {
	// Одно физическое устройство с двумя разными клиентами подписки должно
	// давать один и тот же синтетический HWID: иначе оно посчиталось бы
	// как два разных устройства в лимите панели.
	base := model.Client{Platform: model.PlatformAndroid, OSVersion: "14", Device: "Pixel 7"}
	withApp1 := base
	withApp1.App, withApp1.Core = "v2rayNG", model.CoreXray
	withApp2 := base
	withApp2.App, withApp2.Core = "Clash", model.CoreMihomo

	id1, _ := syntheticHWID(withApp1)
	id2, _ := syntheticHWID(withApp2)
	if id1 != id2 {
		t.Errorf("HWID зависит от имени приложения: %q != %q", id1, id2)
	}
}

func TestSyntheticHWID_CaseInsensitive(t *testing.T) {
	lower := model.Client{Platform: model.PlatformIOS, OSVersion: "17.4", Device: "iPhone14,2"}
	upper := model.Client{Platform: model.PlatformIOS, OSVersion: "17.4", Device: "IPHONE14,2"}
	id1, _ := syntheticHWID(lower)
	id2, _ := syntheticHWID(upper)
	if id1 != id2 {
		t.Errorf("HWID регистрозависим: %q != %q", id1, id2)
	}
}
