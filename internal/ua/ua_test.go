package ua

import (
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// want: ожидаемый разбор UA. Поле HWID здесь не сравниваем побайтово
// (это хеш), только источник: пуст он или нет, видно из HWIDSource.
type want struct {
	app        string
	core       model.Core
	appVersion string
	platform   model.Platform
	osVersion  string
	device     string
	isBrowser  bool
	hwidSource string // "", "ua": источник ожидаемого HWID (заголовков тут нет)
}

func TestParseUA(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want want
	}{
		{
			name: "happ ios с моделью устройства",
			ua:   "Happ/2.15.0 (iOS 17.4; iPhone14,2)",
			want: want{app: "Happ", core: model.CoreXray, appVersion: "2.15.0",
				platform: model.PlatformIOS, osVersion: "17.4", device: "iPhone14,2", hwidSource: "ua"},
		},
		{
			name: "v2rayng android с моделью и build-хвостом",
			ua:   "v2rayNG/1.8.29 (Linux; Android 14; Pixel 7 Build/UQ1A.240205.004)",
			want: want{app: "v2rayNG", core: model.CoreXray, appVersion: "1.8.29",
				platform: model.PlatformAndroid, osVersion: "14", device: "Pixel 7", hwidSource: "ua"},
		},
		{
			name: "shadowrocket без явной ОС в UA",
			ua:   "Shadowrocket/2680 CFNetwork/1481.2 Darwin/23.1.0",
			want: want{app: "Shadowrocket", core: model.CoreXray, appVersion: "2680",
				platform: model.PlatformUnknown},
		},
		{
			name: "v2box ios без цифровой модели",
			ua:   "V2Box/1.4.2 (iPhone; iOS 17.5)",
			want: want{app: "V2Box", core: model.CoreXray, appVersion: "1.4.2",
				platform: model.PlatformIOS, osVersion: "17.5"},
		},
		{
			name: "v2rayn windows",
			ua:   "v2rayN/6.23 (Windows NT 10.0; Win64; x64)",
			want: want{app: "v2rayN", core: model.CoreXray, appVersion: "6.23",
				platform: model.PlatformWindows, osVersion: "10.0"},
		},
		{
			name: "v2raytun ios без цифровой модели",
			ua:   "V2rayTun/1.3.2 (iPhone; iOS 17.4)",
			want: want{app: "V2rayTun", core: model.CoreXray, appVersion: "1.3.2",
				platform: model.PlatformIOS, osVersion: "17.4"},
		},
		{
			name: "clash без версии ос",
			ua:   "Clash/1.9.0",
			want: want{app: "Clash", core: model.CoreMihomo, appVersion: "1.9.0",
				platform: model.PlatformUnknown},
		},
		{
			name: "clash meta слипшийся с for android",
			ua:   "ClashMetaForAndroid/2.10.0",
			want: want{app: "Clash Meta", core: model.CoreMihomo, appVersion: "2.10.0",
				platform: model.PlatformUnknown},
		},
		{
			name: "clash for windows слипшийся без пробела",
			ua:   "ClashforWindows/0.20.39",
			want: want{app: "Clash", core: model.CoreMihomo, appVersion: "0.20.39",
				platform: model.PlatformUnknown},
		},
		{
			name: "clash verge с v в версии и словом windows отдельно",
			ua:   "clash-verge/v1.6.6 (Windows 11)",
			want: want{app: "Clash Verge", core: model.CoreMihomo, appVersion: "1.6.6",
				platform: model.PlatformWindows},
		},
		{
			name: "flclash android",
			ua:   "FlClash/0.8.6 (Android 14)",
			want: want{app: "FlClash", core: model.CoreMihomo, appVersion: "0.8.6",
				platform: model.PlatformAndroid, osVersion: "14"},
		},
		{
			name: "flclashx не путается с flclash",
			ua:   "FlClashX/1.2.0",
			want: want{app: "FlClashX", core: model.CoreMihomo, appVersion: "1.2.0",
				platform: model.PlatformUnknown},
		},
		{
			name: "koala clash слипшееся имя, windows",
			ua:   "KoalaClash/1.0.0 (Windows NT 10.0; Win64; x64)",
			want: want{app: "Koala Clash", core: model.CoreMihomo, appVersion: "1.0.0",
				platform: model.PlatformWindows, osVersion: "10.0"},
		},
		{
			name: "mihomo напрямую, linux",
			ua:   "mihomo/1.18.0 (linux amd64)",
			want: want{app: "mihomo", core: model.CoreMihomo, appVersion: "1.18.0",
				platform: model.PlatformLinux},
		},
		{
			name: "sing-box напрямую",
			ua:   "sing-box/1.9.0",
			want: want{app: "sing-box", core: model.CoreSingBox, appVersion: "1.9.0",
				platform: model.PlatformUnknown},
		},
		{
			name: "nekobox for android слипшееся имя",
			ua:   "NekoBoxForAndroid/1.3.7",
			want: want{app: "NekoBox", core: model.CoreSingBox, appVersion: "1.3.7",
				platform: model.PlatformUnknown},
		},
		{
			name: "nekoray windows",
			ua:   "NekoRay/3.26 (Windows NT 10.0; Win64; x64)",
			want: want{app: "NekoRay", core: model.CoreSingBox, appVersion: "3.26",
				platform: model.PlatformWindows, osVersion: "10.0"},
		},
		{
			name: "hiddify next ios с моделью",
			ua:   "HiddifyNext/2.5.7 (iOS 17.5; iPhone15,3)",
			want: want{app: "Hiddify", core: model.CoreSingBox, appVersion: "2.5.7",
				platform: model.PlatformIOS, osVersion: "17.5", device: "iPhone15,3", hwidSource: "ua"},
		},
		{
			name: "streisand ios без цифровой модели",
			ua:   "Streisand/1.0 (iPhone; iOS 17.4)",
			want: want{app: "Streisand", core: model.CoreSingBox, appVersion: "1.0",
				platform: model.PlatformIOS, osVersion: "17.4"},
		},
		{
			name: "karing ios с моделью",
			ua:   "Karing/1.4.0 (iOS 17.4; iPhone14,2)",
			want: want{app: "Karing", core: model.CoreSingBox, appVersion: "1.4.0",
				platform: model.PlatformIOS, osVersion: "17.4", device: "iPhone14,2", hwidSource: "ua"},
		},
		{
			name: "throne без версии ос",
			ua:   "Throne/1.0.3",
			want: want{app: "Throne", core: model.CoreSingBox, appVersion: "1.0.3",
				platform: model.PlatformUnknown},
		},
		{
			name: "sfi официальный клиент sing-box, ios, пример из задания",
			ua:   "SFI/1.9.0 (iOS 17.4; iPhone14,2)",
			want: want{app: "SFI", core: model.CoreSingBox, appVersion: "1.9.0",
				platform: model.PlatformIOS, osVersion: "17.4", device: "iPhone14,2", hwidSource: "ua"},
		},
		{
			name: "sfa android с моделью",
			ua:   "SFA/1.9.0 (Android 14; Pixel 8)",
			want: want{app: "SFA", core: model.CoreSingBox, appVersion: "1.9.0",
				platform: model.PlatformAndroid, osVersion: "14", device: "Pixel 8", hwidSource: "ua"},
		},
		{
			name: "sfm macos новая форма версии без x",
			ua:   "SFM/1.9.0 (macOS 14.4)",
			want: want{app: "SFM", core: model.CoreSingBox, appVersion: "1.9.0",
				platform: model.PlatformMacOS, osVersion: "14.4"},
		},
		{
			name: "клиент маскируется под браузер под mozilla: ловушка",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Karing/1.4.0",
			want: want{app: "Karing", core: model.CoreSingBox, appVersion: "1.4.0",
				platform: model.PlatformIOS, osVersion: "17.4", isBrowser: false},
		},
		{
			name: "обычный chrome на windows: настоящий браузер",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			want: want{core: model.CoreUnknown, platform: model.PlatformWindows, osVersion: "10.0", isBrowser: true},
		},
		{
			name: "safari macos: настоящий браузер",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
			want: want{core: model.CoreUnknown, platform: model.PlatformMacOS, osVersion: "10.15.7", isBrowser: true},
		},
		{
			name: "firefox linux: настоящий браузер",
			ua:   "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
			want: want{core: model.CoreUnknown, platform: model.PlatformLinux, isBrowser: true},
		},
		{
			name: "yabrowser windows: настоящий браузер",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) YaBrowser/24.4.0.0 Safari/537.36",
			want: want{core: model.CoreUnknown, platform: model.PlatformWindows, osVersion: "10.0", isBrowser: true},
		},
		{
			name: "curl: не браузер и не клиент подписки",
			ua:   "curl/8.4.0",
			want: want{core: model.CoreUnknown, platform: model.PlatformUnknown, isBrowser: false},
		},
		{
			name: "googlebot маскируется под mozilla",
			ua:   "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			want: want{core: model.CoreUnknown, platform: model.PlatformUnknown, isBrowser: false},
		},
		{
			name: "неизвестное приложение с опознаваемой ос: не браузер и не клиент",
			ua:   "MyCustomApp/1.0 (Windows NT 10.0; Win64; x64)",
			want: want{core: model.CoreUnknown, platform: model.PlatformWindows, osVersion: "10.0", isBrowser: false},
		},
		{
			name: "мусорный ua без паники",
			ua:   "asdkjaslkdj 12903-12 !!! ??? ///",
			want: want{core: model.CoreUnknown, platform: model.PlatformUnknown, isBrowser: false},
		},
		{
			name: "пустой user-agent",
			ua:   "",
			want: want{core: model.CoreUnknown, platform: model.PlatformUnknown, isBrowser: false},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseUA(tc.ua)

			if got.UserAgent != tc.ua {
				t.Errorf("UserAgent = %q, want %q", got.UserAgent, tc.ua)
			}
			if got.App != tc.want.app {
				t.Errorf("App = %q, want %q", got.App, tc.want.app)
			}
			if got.Core != tc.want.core {
				t.Errorf("Core = %q, want %q", got.Core, tc.want.core)
			}
			if got.AppVersion != tc.want.appVersion {
				t.Errorf("AppVersion = %q, want %q", got.AppVersion, tc.want.appVersion)
			}
			if got.Platform != tc.want.platform {
				t.Errorf("Platform = %q, want %q", got.Platform, tc.want.platform)
			}
			if got.OSVersion != tc.want.osVersion {
				t.Errorf("OSVersion = %q, want %q", got.OSVersion, tc.want.osVersion)
			}
			if got.Device != tc.want.device {
				t.Errorf("Device = %q, want %q", got.Device, tc.want.device)
			}
			if got.IsBrowser != tc.want.isBrowser {
				t.Errorf("IsBrowser = %v, want %v", got.IsBrowser, tc.want.isBrowser)
			}
			if got.HWIDSource != tc.want.hwidSource {
				t.Errorf("HWIDSource = %q, want %q", got.HWIDSource, tc.want.hwidSource)
			}
			if tc.want.hwidSource != "" && got.HWID == "" {
				t.Errorf("HWID пуст, а источник %q: ожидался непустой синтетический идентификатор", tc.want.hwidSource)
			}
			if tc.want.hwidSource == "" && got.HWID != "" {
				t.Errorf("HWID = %q, а источника нет: ожидался пустой", got.HWID)
			}
		})
	}
}

// TestIsBrowser проверяет функцию отдельно от ParseUA: с прицелом на
// ловушку из задания: клиент подписки, замаскированный под Mozilla,
// не должен считаться браузером.
func TestIsBrowser(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want bool
	}{
		{"пусто", "", false},
		{"v2rayNG: клиент, не браузер", "v2rayNG/1.8.23", false},
		{"клиент под маской mozilla: не браузер", "Mozilla/5.0 (Linux; Android 13) Happ/2.0.0", false},
		{"chrome: браузер", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36", true},
		{"edge chromium: браузер", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", true},
		{"wget: не браузер", "Wget/1.21.3", false},
		{"postman: не браузер", "PostmanRuntime/7.36.0", false},
		{"go http client: не браузер", "Go-http-client/1.1", false},
		{"мусор: не браузер", "????", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsBrowser(tc.ua); got != tc.want {
				t.Errorf("IsBrowser(%q) = %v, want %v", tc.ua, got, tc.want)
			}
		})
	}
}
