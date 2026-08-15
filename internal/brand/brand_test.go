package brand

import (
	"strings"
	"testing"
)

// Атрибуция это причина существования пакета, поэтому тест сторожит,
// что ключевые данные на месте и не опустели при рефакторинге.
func TestAttributionPresent(t *testing.T) {
	if Author == "" || SiteURL == "" || RepoURL == "" {
		t.Fatal("атрибуция автора не должна быть пустой")
	}
	info := Get()
	if info.Author != Author || info.SiteURL != SiteURL || info.RepoURL != RepoURL {
		t.Error("Get вернул не те данные, что в константах")
	}
	if len(info.Products) == 0 {
		t.Fatal("список продуктов пуст")
	}
	for _, p := range info.Products {
		if p.Name == "" || p.URL == "" {
			t.Errorf("у продукта не заполнены имя или ссылка: %+v", p)
		}
		if !strings.HasPrefix(p.URL, "https://") {
			t.Errorf("ссылка продукта %s должна быть https: %s", p.Name, p.URL)
		}
	}
}

// Get обязан отдавать копию: если вызывающий код изменит свой срез продуктов,
// это не должно менять то, что увидят следующие страницы админки.
func TestGetReturnsCopy(t *testing.T) {
	a := Get()
	if len(a.Products) == 0 {
		t.Skip("нет продуктов для проверки")
	}
	a.Products[0].Name = "подменено"
	b := Get()
	if b.Products[0].Name == "подменено" {
		t.Error("Get отдаёт общий срез: правка у одного вызывающего протекла к другому")
	}
}

func TestBannerAndLineMentionAuthor(t *testing.T) {
	if !strings.Contains(Line(), Author) {
		t.Error("однострочная подпись не называет автора")
	}
	b := Banner("v1.0.0")
	if !strings.Contains(b, Author) || !strings.Contains(b, "v1.0.0") {
		t.Error("баннер должен называть автора и версию")
	}
	if !strings.Contains(b, "MultiScript") || !strings.Contains(b, "MultiRoller") {
		t.Error("баннер должен упоминать соседние продукты")
	}
}
