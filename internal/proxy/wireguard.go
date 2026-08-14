package proxy

import (
	"context"
	"errors"

	"github.com/qwe8nxtroud/multigate/internal/hwid"
	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
	"github.com/qwe8nxtroud/multigate/internal/subfmt"
	"github.com/qwe8nxtroud/multigate/internal/wgpool"
)

// appendWireGuard дописывает в тело подписки конфиг WireGuard/AmneziaWG из
// пула, если это включено в настройках и клиент умеет такие конфиги
// принимать. Вызывается только на нормальной (не заблокированной, не
// истёкшей) выдаче: заблокированный или истёкший клиент не должен получать
// рабочий тоннель в обход собственно блокировки/истечения срока.
//
// Лиза закреплена за парой (shortUuid, hwid) - устройство без HWID (пустой
// или синтетический, собранный MultiGate из User-Agent) пропускается: у
// wgpool нет реального идентификатора, чтобы закрепить конфиг именно за
// этим устройством, а синтетический HWID совпадёт у любых двух устройств
// одной модели и версии ОС (см. internal/ua/hwid.go) - два разных
// физических устройства получили бы один и тот же приватный ключ
// WireGuard и конфликтовали бы друг с другом на сервере.
//
// Любая ошибка (пул пуст, тело не разобрать под нужный формат) только
// пишется в журнал процесса - клиент в любом случае должен получить свою
// обычную подписку, довесок WireGuard это бонус, а не обязательная часть ответа.
func (h *Handler) appendWireGuard(ctx context.Context, client model.Client, shortUUID string, format model.Format, body []byte) []byte {
	if h.deps.WGPool == nil || !h.deps.Store.GetBool(ctx, store.KeyWGPoolEnabled) {
		return body
	}
	if !client.SupportsWireGuard() {
		return body
	}
	if client.HWID == "" || hwid.IsSyntheticHWID(client) {
		return body
	}

	lease, err := h.deps.WGPool.Lease(ctx, "", shortUUID, client.HWID)
	if err != nil {
		if errors.Is(err, wgpool.ErrPoolEmpty) {
			h.deps.Logger.Debug("proxy: пул WireGuard пуст, конфиг не выдан", "short_uuid", shortUUID)
		} else {
			h.deps.Logger.Warn("proxy: не выдать конфиг WireGuard из пула", "short_uuid", shortUUID, "err", err)
		}
		return body
	}

	extra := []subfmt.Entry{{Name: lease.ConfigName, WG: lease.Config}}
	appended, err := subfmt.Append(body, format, extra)
	if err != nil {
		// Контракт subfmt.Append: при ошибке возвращает body без изменений,
		// так что здесь просто теряем довесок, а не подписку целиком.
		h.deps.Logger.Warn("proxy: не дописать конфиг WireGuard в тело подписки",
			"short_uuid", shortUUID, "format", format, "err", err)
		return body
	}
	return appended
}
