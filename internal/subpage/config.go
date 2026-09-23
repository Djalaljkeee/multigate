package subpage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Config: конфиг страницы подписки из панели Remnawave (раздел
// «Страница подписки»). Разбирается только то, что рисует страница;
// остальные поля схемы молча пропускаются.
type Config struct {
	Locales          []string             `json:"locales"`
	Platforms        []Platform           `json:"-"` // в порядке из панели, см. ParseConfig
	SVG              map[string]string    `json:"svgLibrary"`
	Branding         Branding             `json:"brandingSettings"`
	Base             BaseSettings         `json:"baseSettings"`
	BaseTranslations map[string]Localized `json:"baseTranslations"`
}

// Branding: название, логотип и ссылка поддержки.
type Branding struct {
	Title      string `json:"title"`
	LogoURL    string `json:"logoUrl"`
	SupportURL string `json:"supportUrl"`
}

// BaseSettings: общие переключатели страницы.
type BaseSettings struct {
	MetaTitle         string `json:"metaTitle"`
	MetaDescription   string `json:"metaDescription"`
	HideGetLinkButton bool   `json:"hideGetLinkButton"`
}

// Platform: одна вкладка платформы (iOS, Android...).
type Platform struct {
	Key         string    `json:"-"`
	DisplayName Localized `json:"displayName"`
	SVGIconKey  string    `json:"svgIconKey"`
	Apps        []App     `json:"apps"`
}

// App: приложение с пошаговой инструкцией.
type App struct {
	Name     string  `json:"name"`
	Featured bool    `json:"featured"`
	Blocks   []Block `json:"blocks"`
}

// Block: шаг инструкции.
type Block struct {
	Title        Localized `json:"title"`
	Description  Localized `json:"description"`
	SVGIconKey   string    `json:"svgIconKey"`
	SVGIconColor string    `json:"svgIconColor"`
	Buttons      []Button  `json:"buttons"`
}

// Button: кнопка шага. Type "external" ведёт на сайт или в магазин,
// "subscriptionLink" открывает приложение с подпиской.
type Button struct {
	Link       string    `json:"link"`
	Text       Localized `json:"text"`
	Type       string    `json:"type"`
	SVGIconKey string    `json:"svgIconKey"`
}

// Localized: текст на нескольких языках, ключ: код языка.
type Localized map[string]string

// In отдаёт текст на языке lang, а если его нет, то на русском, английском
// или первом попавшемся (в порядке ключей не гарантирован, поэтому только
// как последняя мера).
func (l Localized) In(lang string) string {
	for _, k := range []string{lang, "ru", "en"} {
		if v := strings.TrimSpace(l[k]); v != "" {
			return v
		}
	}
	for _, v := range l {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// ParseConfig разбирает конфиг страницы. Платформы в JSON лежат объектом,
// и их порядок в панели (он же порядок вкладок) важен, поэтому объект
// читается потоково, а не через map.
func ParseConfig(raw []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("subpage: разобрать конфиг: %w", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("subpage: разобрать конфиг: %w", err)
	}
	if p, ok := top["platforms"]; ok {
		keys, values, err := orderedObject(p)
		if err != nil {
			return nil, fmt.Errorf("subpage: разобрать платформы: %w", err)
		}
		for i, k := range keys {
			var pl Platform
			if err := json.Unmarshal(values[i], &pl); err != nil {
				return nil, fmt.Errorf("subpage: разобрать платформу %s: %w", k, err)
			}
			pl.Key = k
			if len(pl.Apps) > 0 {
				c.Platforms = append(c.Platforms, pl)
			}
		}
	}
	if len(c.Platforms) == 0 {
		return nil, fmt.Errorf("subpage: в конфиге нет ни одной платформы с приложениями")
	}
	return &c, nil
}

// orderedObject читает JSON-объект, сохраняя порядок ключей.
func orderedObject(raw json.RawMessage) ([]string, []json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, nil, fmt.Errorf("ожидался объект")
	}
	var keys []string
	var values []json.RawMessage
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, nil, fmt.Errorf("ожидался ключ объекта")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, err
		}
		keys = append(keys, key)
		values = append(values, v)
	}
	return keys, values, nil
}
