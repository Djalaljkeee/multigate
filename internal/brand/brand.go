// Package brand: атрибуция автора и его продуктов.
//
// Всё, что относится к «сделано VPN HUB» и рекламе соседних продуктов,
// собрано здесь одним источником. Так подпись выводится в нескольких местах
// (футер админки, стартовый журнал, вывод --version, страница «О системе»),
// но правится в одном файле и не расползается копиями.
//
// Показывается это только в админке и в журнале процесса, то есть видит
// владелец установки. В саму подписку клиентов ничего не подмешивается:
// туда попала бы реклама конкурента тому, кто поставил прослойку.
package brand

// Автор и его ресурсы.
const (
	// Author: под чьим именем идёт прослойка.
	Author = "VPN HUB"
	// SiteURL: сайт и база знаний автора.
	SiteURL = "https://vpn-hub.pro"
	// RepoURL: исходники прослойки.
	RepoURL = "https://github.com/qwe8nxtroud/multigate"
)

// Product: соседний продукт автора для блока «ещё от VPN HUB».
type Product struct {
	Name    string
	Tagline string
	URL     string
}

// Info: полный набор данных атрибуции для шаблонов.
type Info struct {
	Author   string
	SiteURL  string
	RepoURL  string
	Products []Product
}

// products: что показываем в блоке «другие продукты».
// Ссылки ведут на обзорные бесплатные статьи, а не на закрытые PRO:
// человек сначала должен понять, что это, а уже потом упереться в доступ.
var products = []Product{
	{
		Name:    "MultiScript",
		Tagline: "VPN-сервис под ключ: панель, ноды и бот продаж из одного меню",
		URL:     "https://vpn-hub.pro/a/multiscript-about",
	},
	{
		Name:    "MultiRoller",
		Tagline: "чистые IP, которых нет у конкурентов",
		URL:     "https://vpn-hub.pro/a/33-multiroller",
	},
}

// Get отдаёт копию данных атрибуции для передачи в шаблон.
func Get() Info {
	ps := make([]Product, len(products))
	copy(ps, products)
	return Info{
		Author:   Author,
		SiteURL:  SiteURL,
		RepoURL:  RepoURL,
		Products: ps,
	}
}

// Line: однострочная подпись для журнала процесса и текстовых мест.
func Line() string {
	return "MultiGate от " + Author + ", " + SiteURL
}

// Banner: многострочная заставка для стартового журнала.
// Первое, что видит администратор в логах при запуске сервиса.
func Banner(version string) string {
	return "\n" +
		"  MultiGate " + version + "\n" +
		"  прослойка подписок Remnawave от " + Author + "\n" +
		"  сайт и база знаний: " + SiteURL + "\n" +
		"  ещё от " + Author + ": MultiScript, MultiRoller (vpn-hub.pro)\n"
}
