package admin

import (
	"context"
	"sort"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/rules"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// Работа с таблицей header_rules идёт через пакет rules (Load/Save/Delete),
// а не собственным SQL по той же таблице. Раньше здесь был независимый
// CRUD: он писал в базу мимо кэша, которым пользуется прокси на каждом
// ответе подписки (см. internal/rules/rules.go), и сохранённое или
// удалённое правило применялось только после того, как кэш сам протухал:
// до 30 секунд задержки, необъяснимой для администратора. Два набора
// функций над одной таблицей вдобавок надо было бы поддерживать синхронно,
// что не имеет смысла: rules.Save/rules.Delete уже сбрасывают кэш сами.

// listHeaderRules отдаёт все правила, по приоритету и затем по id: так
// порядок совпадает с тем, в каком их будет применять прокси (rules.Apply
// сортирует так же перед применением, здесь та же сортировка нужна для
// стабильного отображения списка в админке).
func (h *Handler) listHeaderRules(ctx context.Context) ([]model.HeaderRule, error) {
	all, err := rules.Load(ctx, h.store)
	if err != nil {
		return nil, err
	}
	out := make([]model.HeaderRule, len(all))
	copy(out, all)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// getHeaderRule отдаёт одно правило по id.
func (h *Handler) getHeaderRule(ctx context.Context, id int64) (model.HeaderRule, error) {
	all, err := rules.Load(ctx, h.store)
	if err != nil {
		return model.HeaderRule{}, err
	}
	for _, r := range all {
		if r.ID == id {
			return r, nil
		}
	}
	return model.HeaderRule{}, store.ErrNotFound
}

// createHeaderRule сохраняет новое правило и возвращает его id. r.ID у
// новых правил всегда 0 (см. parseHeaderRuleForm), поэтому rules.Save сам
// выбирает INSERT, а не UPDATE.
func (h *Handler) createHeaderRule(ctx context.Context, r model.HeaderRule) (int64, error) {
	return rules.Save(ctx, h.store, r)
}

// updateHeaderRule переписывает существующее правило целиком: вызывающий
// код обязан выставить r.ID (см. handleHeaderRuleUpdate), иначе rules.Save
// создаст новую запись вместо правки существующей.
func (h *Handler) updateHeaderRule(ctx context.Context, r model.HeaderRule) error {
	_, err := rules.Save(ctx, h.store, r)
	return err
}

// deleteHeaderRule удаляет правило по id.
func (h *Handler) deleteHeaderRule(ctx context.Context, id int64) error {
	return rules.Delete(ctx, h.store, id)
}
