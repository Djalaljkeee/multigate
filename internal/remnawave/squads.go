package remnawave

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// rawSquad: внутренний сквад панели в сыром виде.
type rawSquad struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Members int    `json:"membersCount"`
}

// squadsEnvelope: типичная форма ответа /api/internal-squads.
type squadsEnvelope struct {
	InternalSquads []rawSquad `json:"internalSquads"`
}

// parseSquadsList поддерживает и обёртку {internalSquads:[...]}, и голый массив.
func parseSquadsList(raw json.RawMessage) ([]rawSquad, error) {
	var env squadsEnvelope
	if err := json.Unmarshal(raw, &env); err == nil && len(env.InternalSquads) > 0 {
		return env.InternalSquads, nil
	}
	var arr []rawSquad
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	if err := json.Unmarshal(raw, &env); err == nil {
		return env.InternalSquads, nil
	}
	return nil, errors.New("неизвестная форма ответа")
}

// Squads возвращает список внутренних сквадов панели.
func (c *Client) Squads(ctx context.Context) ([]model.Squad, error) {
	var raw json.RawMessage
	if _, err := c.getJSON(ctx, "/api/internal-squads", nil, true, &raw); err != nil {
		return nil, err
	}

	list, err := parseSquadsList(raw)
	if err != nil {
		return nil, fmt.Errorf("remnawave: разобрать список сквадов: %w", err)
	}

	out := make([]model.Squad, 0, len(list))
	for _, s := range list {
		out = append(out, model.Squad{UUID: s.UUID, Name: s.Name, Members: s.Members})
	}
	return out, nil
}
