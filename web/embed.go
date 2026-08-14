// Package web встраивает HTML-шаблоны и статику админки в бинарник.
//
// Директива go:embed не умеет подниматься выше каталога, где она написана,
// поэтому обёртка живёт здесь, рядом с templates и static, а не в
// internal/admin: тот лежит в соседней ветке дерева и дотянуться до этих
// файлов напрямую не может. Продукт должен собираться в один файл без
// внешних ассетов, так что оба каталога встраиваются целиком.
package web

import "embed"

// StaticFS: CSS и JS админки, отдаются как есть через http.FileServer.
//
//go:embed static
var StaticFS embed.FS

// TemplatesFS: HTML-шаблоны страниц админки.
//
//go:embed templates
var TemplatesFS embed.FS
