// Пакет внешний (model_test), чтобы можно было импортировать пакеты,
// которые сами зависят от model, и проверить их стык.
package model_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/remnawave"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// Ядро прокси отличает «пользователя нет» от «панель не отвечает» одной
// проверкой errors.Is по общему сентинелу. Пока каждый пакет объявлял свой
// признак, проверка молча не срабатывала, и клиент получал 502 вместо 404.
// Тест держит цепочку обёрток на месте.
func TestNotFoundSentinelIsShared(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"ошибка хранилища", store.ErrNotFound},
		{"ошибка клиента панели", remnawave.ErrNotFound},
		{"обёрнутая ошибка хранилища", fmt.Errorf("искали пользователя: %w", store.ErrNotFound)},
		{"обёрнутая ошибка панели", fmt.Errorf("запрос подписки: %w", remnawave.ErrNotFound)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !errors.Is(c.err, model.ErrNotFound) {
				t.Errorf("errors.Is не увидел общий сентинел в %v", c.err)
			}
		})
	}

	// Обратное тоже важно: посторонняя ошибка не должна выдавать себя
	// за отсутствие записи, иначе сбой сети превратится в 404,
	// и клиент решит, что подписки больше нет.
	if errors.Is(errors.New("сеть недоступна"), model.ErrNotFound) {
		t.Error("посторонняя ошибка распознана как отсутствие записи")
	}
	if errors.Is(remnawave.ErrUnauthorized, model.ErrNotFound) {
		t.Error("отказ по токену распознан как отсутствие записи")
	}
}
