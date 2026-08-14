package ua

import (
	"regexp"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// appRule: один узнаваемый клиент подписки, как его найти в UA и на каком
// ядре он работает. Ядро решает, какой формат конфигов ему отдавать
// (см. model.Client.SupportsWireGuard и пакет subfmt).
type appRule struct {
	app  string
	core model.Core
	re   *regexp.Regexp
}

// appRules: таблица известных клиентов подписки.
//
// Внутри группы одного ядра правила идут от самых конкретных имён к самым
// общим: например, "Clash Meta" и "ClashX" проверяются раньше голого
// "Clash". Границы слов (\b) в самих регулярках уже не дают "ClashX"
// случайно совпасть с правилом "Clash" (после "Clash" в "ClashX" нет
// границы слова, там же буква), так что порядок здесь скорее для
// читаемости и однозначности при отладке, чем критичен для корректности.
//
// UA живого клиента не переговорённый формат, а то, что разработчик решил
// туда вписать, поэтому у части правил есть терпимость к слипшимся без
// пробела словам вида "ClashforWindows" или "ClashMetaForAndroid".
var appRules = []appRule{
	// ядро xray
	{"Happ", model.CoreXray, regexp.MustCompile(`(?i)\bHapp\b`)},
	{"v2rayNG", model.CoreXray, regexp.MustCompile(`(?i)\bv2rayNG\b`)},
	{"Shadowrocket", model.CoreXray, regexp.MustCompile(`(?i)\bShadowrocket\b`)},
	{"V2Box", model.CoreXray, regexp.MustCompile(`(?i)\bV2Box\b`)},
	{"v2rayN", model.CoreXray, regexp.MustCompile(`(?i)\bv2rayN\b`)},
	{"V2rayTun", model.CoreXray, regexp.MustCompile(`(?i)\bV2rayTun\b`)},

	// ядро mihomo (Clash и его форки)
	{"ClashX", model.CoreMihomo, regexp.MustCompile(`(?i)\bClashX\b`)},
	{"Clash Verge", model.CoreMihomo, regexp.MustCompile(`(?i)\bclash[-_ ]?verge\b`)},
	{"Clash Meta", model.CoreMihomo, regexp.MustCompile(`(?i)\bclash[-_. ]?meta(?:for[a-z]+)?\b`)},
	{"FlClashX", model.CoreMihomo, regexp.MustCompile(`(?i)\bFlClashX\b`)},
	{"FlClash", model.CoreMihomo, regexp.MustCompile(`(?i)\bFlClash\b`)},
	{"Koala Clash", model.CoreMihomo, regexp.MustCompile(`(?i)\bkoala[-_ ]?clash\b`)},
	{"mihomo", model.CoreMihomo, regexp.MustCompile(`(?i)\bmihomo\b`)},
	// Общий "Clash" последним в группе: если это не более конкретный
	// форк, то хотя бы ядро определим верно. Терпим слипшееся "for<ОС>"
	// вида "ClashforWindows/0.20.39": это тоже реальный формат UA.
	{"Clash", model.CoreMihomo, regexp.MustCompile(`(?i)\bclash(?:for[a-z]+)?\b`)},

	// ядро sing-box
	{"NekoBox", model.CoreSingBox, regexp.MustCompile(`(?i)\bnekobox(?:forandroid)?\b`)},
	{"NekoRay", model.CoreSingBox, regexp.MustCompile(`(?i)\bnekoray\b`)},
	{"Hiddify", model.CoreSingBox, regexp.MustCompile(`(?i)\bhiddify(?:[ ]?next)?\b`)},
	{"Streisand", model.CoreSingBox, regexp.MustCompile(`(?i)\bstreisand\b`)},
	{"Karing", model.CoreSingBox, regexp.MustCompile(`(?i)\bkaring\b`)},
	{"Throne", model.CoreSingBox, regexp.MustCompile(`(?i)\bthrone\b`)},
	// SFA/SFI/SFM: официальные консольные клиенты sing-box для
	// Android/iOS/macOS. Три буквы легко случайно найти в произвольном
	// мусоре, поэтому без учёта регистра не проверяем: настоящие релизы
	// шлют их ровно заглавными.
	{"SFA", model.CoreSingBox, regexp.MustCompile(`\bSFA\b`)},
	{"SFI", model.CoreSingBox, regexp.MustCompile(`\bSFI\b`)},
	{"SFM", model.CoreSingBox, regexp.MustCompile(`\bSFM\b`)},
	{"sing-box", model.CoreSingBox, regexp.MustCompile(`(?i)\bsing-?box\b`)},
}

// versionAfter: версия сразу после найденного имени приложения,
// "/1.2.3", " 1.2.3", "/v1.2.3" и подобные варианты разделителя.
// Версия ищется именно сразу после имени, а не где-то ещё в строке:
// иначе можно случайно подхватить постороннее число из скобок с ОС.
var versionAfter = regexp.MustCompile(`^[\s/_:=-]{0,3}v?([0-9]+(?:\.[0-9]+){0,4})`)

// matchApp ищет в UA первое известное имя клиента и, если получится,
// версию сразу после него.
func matchApp(ua string) (appRule, string, bool) {
	for _, rule := range appRules {
		loc := rule.re.FindStringIndex(ua)
		if loc == nil {
			continue
		}
		version := ""
		if m := versionAfter.FindStringSubmatch(ua[loc[1]:]); m != nil {
			version = m[1]
		}
		return rule, version, true
	}
	return appRule{}, "", false
}
