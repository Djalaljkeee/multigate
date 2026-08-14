package proxy

import (
	"net/http"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// upstream - единый результат похода за подпиской, что в mirror-режиме, что
// в panel-режиме. Дальше по коду оба варианта обрабатываются одинаково.
type upstream struct {
	status int
	header http.Header
	body   []byte
	// format известен только когда подписку отдала панель напрямую
	// (model.SubResponse.Format); в mirror-режиме прослойка получает
	// голые байты и формата не знает, там всегда model.FormatUnknown.
	format model.Format
}
