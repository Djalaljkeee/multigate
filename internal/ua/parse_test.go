package ua

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

func newReq(uaStr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/sub/abc", nil)
	if uaStr != "" {
		r.Header.Set("User-Agent", uaStr)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestParse_HWIDFromHeader(t *testing.T) {
	r := newReq("v2rayNG/1.8.23", map[string]string{"x-hwid": "real-hwid-123"})
	c := Parse(r)
	if c.HWID != "real-hwid-123" {
		t.Errorf("HWID = %q, want %q", c.HWID, "real-hwid-123")
	}
	if c.HWIDSource != "header" {
		t.Errorf("HWIDSource = %q, want header", c.HWIDSource)
	}
}

func TestParse_HWIDFallsBackToDeviceID(t *testing.T) {
	r := newReq("v2rayNG/1.8.23", map[string]string{"x-device-id": "dev-id-456"})
	c := Parse(r)
	if c.HWID != "dev-id-456" {
		t.Errorf("HWID = %q, want %q", c.HWID, "dev-id-456")
	}
	if c.HWIDSource != "header" {
		t.Errorf("HWIDSource = %q, want header", c.HWIDSource)
	}
}

func TestParse_HWIDPrefersXHWIDOverDeviceID(t *testing.T) {
	r := newReq("v2rayNG/1.8.23", map[string]string{
		"x-hwid":      "primary",
		"x-device-id": "secondary",
	})
	c := Parse(r)
	if c.HWID != "primary" {
		t.Errorf("HWID = %q, want primary (x-hwid важнее x-device-id)", c.HWID)
	}
}

func TestParse_NoHeaders_FallsBackToSyntheticFromUA(t *testing.T) {
	// v2rayNG сам заголовков не шлёт: типичный случай, под который
	// синтетический HWID и придуман.
	r := newReq("v2rayNG/1.8.29 (Linux; Android 14; Pixel 7 Build/UQ1A.240205.004)", nil)
	c := Parse(r)
	if c.HWIDSource != "ua" {
		t.Fatalf("HWIDSource = %q, want ua", c.HWIDSource)
	}
	if c.HWID == "" {
		t.Fatal("HWID пуст, а должен был собраться синтетически")
	}
	// Тот же UA должен давать тот же HWID при повторном запросе.
	c2 := Parse(newReq("v2rayNG/1.8.29 (Linux; Android 14; Pixel 7 Build/UQ1A.240205.004)", nil))
	if c2.HWID != c.HWID {
		t.Errorf("синтетический HWID нестабилен: %q != %q", c2.HWID, c.HWID)
	}
}

func TestParse_DeviceHeadersOverrideUA(t *testing.T) {
	r := newReq("Happ/2.15.0 (iOS 17.4; iPhone14,2)", map[string]string{
		"x-device-os":    "android",
		"x-ver-os":       "15",
		"x-device-model": "Pixel 9",
		"x-app-version":  "2.16.0",
	})
	c := Parse(r)
	if c.Platform != model.PlatformAndroid {
		t.Errorf("Platform = %q, want android (переопределено заголовком)", c.Platform)
	}
	if c.OSVersion != "15" {
		t.Errorf("OSVersion = %q, want 15", c.OSVersion)
	}
	if c.Device != "Pixel 9" {
		t.Errorf("Device = %q, want Pixel 9", c.Device)
	}
	if c.AppVersion != "2.16.0" {
		t.Errorf("AppVersion = %q, want 2.16.0", c.AppVersion)
	}
	// Имя и ядро при этом остаются из UA: заголовков с именем приложения нет.
	if c.App != "Happ" || c.Core != model.CoreXray {
		t.Errorf("App/Core = %q/%q, want Happ/xray", c.App, c.Core)
	}
}

func TestParse_EmptyHeadersIgnored(t *testing.T) {
	r := newReq("Happ/2.15.0 (iOS 17.4; iPhone14,2)", map[string]string{
		"x-hwid":         "",
		"x-device-id":    "",
		"x-device-os":    "",
		"x-device-model": "",
	})
	c := Parse(r)
	// Пустые заголовки не должны перекрывать то, что видно по UA.
	if c.Platform != model.PlatformIOS {
		t.Errorf("Platform = %q, want ios (пустой заголовок не должен был сработать)", c.Platform)
	}
	if c.Device != "iPhone14,2" {
		t.Errorf("Device = %q, want iPhone14,2", c.Device)
	}
	if c.HWIDSource != "ua" {
		t.Errorf("HWIDSource = %q, want ua (пустой x-hwid не в счёт)", c.HWIDSource)
	}
}

func TestParse_DeviceOSHeaderNormalization(t *testing.T) {
	cases := []struct {
		header string
		want   model.Platform
	}{
		{"ios", model.PlatformIOS},
		{"iOS", model.PlatformIOS},
		{"iPhone OS", model.PlatformIOS},
		{"android", model.PlatformAndroid},
		{"Android", model.PlatformAndroid},
		{"windows", model.PlatformWindows},
		{"macos", model.PlatformMacOS},
		{"darwin", model.PlatformMacOS},
		{"linux", model.PlatformLinux},
		{"toaster-os", model.PlatformUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.header, func(t *testing.T) {
			r := newReq("SomeClient/1.0", map[string]string{"x-device-os": tc.header})
			c := Parse(r)
			if c.Platform != tc.want {
				t.Errorf("x-device-os=%q -> Platform = %q, want %q", tc.header, c.Platform, tc.want)
			}
		})
	}
}
