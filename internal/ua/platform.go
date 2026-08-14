package ua

import (
	"regexp"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// Признаки платформы в UA. Проверяем через границы слов (\b), а не простым
// вхождением подстроки: иначе, например, "bios" даст ложный iOS, а имя
// приложения "NekoBoxForAndroid" (слипшееся с "For") даст ложную Android:
// у "Android" внутри "ForAndroid" нет границы слова слева, у "For" и
// "Android" одна буква на стыке, поэтому \b там не сработает, и это
// правильно, ведь сама по себе строка ничего не говорит про реальную ОС.
var (
	reIOSHint     = regexp.MustCompile(`(?i)\b(?:iphone|ipad|ipod)|\bios\b`)
	reAndroidHint = regexp.MustCompile(`(?i)\bandroid\b`)
	reWindowsHint = regexp.MustCompile(`(?i)\bwindows\b`)
	// "darwin" в этот список специально не входит: CFNetwork/Darwin в UA
	// пишут и iOS-, и macOS-приложения (общее ядро), поэтому по одному
	// этому слову платформу не отличить, лучше остаться в unknown,
	// чем угадать неверно (так и бывает у Shadowrocket на iOS).
	reMacHint   = regexp.MustCompile(`(?i)\b(?:mac ?os ?x|macintosh|macos)\b`)
	reLinuxHint = regexp.MustCompile(`(?i)\blinux\b`)

	// "CPU iPhone OS 17_4 like Mac OS X": типичная форма из WebKit-based UA.
	// "iOS 17.4" / "iOS/17.4": форма, которую чаще пишут сами клиенты.
	reIOSVersion = regexp.MustCompile(`(?i)(?:CPU (?:iPhone )?OS|iPhone OS|iOS)[ /]([0-9_]+(?:\.[0-9_]+)*)`)
	// Аппаратный идентификатор вида iPhone14,2: модель устройства Apple.
	reIOSDevice = regexp.MustCompile(`(?i)\b(iPhone\d{1,3},\d{1,2}|iPad\d{1,3},\d{1,2}|iPod\d{1,3},\d{1,2})\b`)

	reAndroidVersion = regexp.MustCompile(`(?i)\bAndroid[ /]([0-9][0-9.]*)`)
	// Модель устройства обычно идёт следом за версией Android до ";" или ")".
	reAndroidDevice = regexp.MustCompile(`(?i)\bAndroid\s+[0-9][0-9.]*\s*;\s*([^;)]+)`)

	reWindowsVersion = regexp.MustCompile(`(?i)\bWindows NT[ /]([0-9.]+)`)
	// И старая форма "Mac OS X 10_15_7", и новая "macOS 14.4".
	reMacVersion = regexp.MustCompile(`(?i)\b(?:Mac ?OS ?X|macOS)[ /]?([0-9_]+(?:\.[0-9_]+)*)`)
)

// detectPlatform достаёт из UA операционную систему, её версию и модель
// устройства, если они там есть. Порядок проверки: от самых характерных
// признаков к самым общим. iOS проверяем раньше macOS специально: строка
// "like Mac OS X" входит и в UA iOS-приложений (так исторически устроен
// WebKit), и без этой проверки iPhone определился бы как Mac.
func detectPlatform(ua string) (model.Platform, string, string) {
	switch {
	case reIOSHint.MatchString(ua):
		version := ""
		if m := reIOSVersion.FindStringSubmatch(ua); m != nil {
			version = strings.ReplaceAll(m[1], "_", ".")
		}
		return model.PlatformIOS, version, reIOSDevice.FindString(ua)

	case reAndroidHint.MatchString(ua):
		version := ""
		if m := reAndroidVersion.FindStringSubmatch(ua); m != nil {
			version = m[1]
		}
		device := ""
		if m := reAndroidDevice.FindStringSubmatch(ua); m != nil {
			device = cleanDevice(m[1])
		}
		return model.PlatformAndroid, version, device

	case reWindowsHint.MatchString(ua):
		version := ""
		if m := reWindowsVersion.FindStringSubmatch(ua); m != nil {
			version = m[1]
		}
		return model.PlatformWindows, version, ""

	case reMacHint.MatchString(ua):
		version := ""
		if m := reMacVersion.FindStringSubmatch(ua); m != nil {
			version = strings.ReplaceAll(m[1], "_", ".")
		}
		return model.PlatformMacOS, version, ""

	case reLinuxHint.MatchString(ua):
		return model.PlatformLinux, "", ""

	default:
		return model.PlatformUnknown, "", ""
	}
}

// cleanDevice обрезает служебный хвост вида "Build/TP1A..." у модели Android,
// который обычно идёт следом за именем модели в UA.
func cleanDevice(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(strings.ToLower(s), "build/"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// normalizePlatform приводит значение заголовка x-device-os к одной из
// известных платформ: клиенты присылают то "ios", то "iOS", то "iPhone OS".
func normalizePlatform(v string) model.Platform {
	low := strings.ToLower(strings.TrimSpace(v))
	switch {
	case strings.Contains(low, "ios") || strings.Contains(low, "iphone") || strings.Contains(low, "ipad"):
		return model.PlatformIOS
	case strings.Contains(low, "android"):
		return model.PlatformAndroid
	case strings.Contains(low, "windows"):
		return model.PlatformWindows
	case strings.Contains(low, "mac") || strings.Contains(low, "darwin"):
		return model.PlatformMacOS
	case strings.Contains(low, "linux"):
		return model.PlatformLinux
	default:
		return model.PlatformUnknown
	}
}
