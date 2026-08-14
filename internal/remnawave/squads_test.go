package remnawave

import (
	"context"
	"net/http"
	"testing"
)

func TestSquads_EnvelopeForm(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/internal-squads": jsonOK(`{"response":{"internalSquads":[{"uuid":"sq-1","name":"DE","membersCount":10}]}}`),
	})
	c := newTestClient(t, ts.URL)

	squads, err := c.Squads(context.Background())
	if err != nil {
		t.Fatalf("Squads: %v", err)
	}
	if len(squads) != 1 || squads[0].UUID != "sq-1" || squads[0].Name != "DE" || squads[0].Members != 10 {
		t.Fatalf("неожиданный результат: %+v", squads)
	}
}

func TestSquads_ArrayForm(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/internal-squads": jsonOK(`[{"uuid":"sq-1","name":"DE"},{"uuid":"sq-2","name":"NL"}]`),
	})
	c := newTestClient(t, ts.URL)

	squads, err := c.Squads(context.Background())
	if err != nil {
		t.Fatalf("Squads: %v", err)
	}
	if len(squads) != 2 {
		t.Fatalf("неожиданный результат: %+v", squads)
	}
}

func TestSystemStats_ReturnsRawMap(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/stats": jsonOK(`{"response":{"cpuCount":4,"usersOnline":12}}`),
	})
	c := newTestClient(t, ts.URL)

	stats, err := c.SystemStats(context.Background())
	if err != nil {
		t.Fatalf("SystemStats: %v", err)
	}
	if stats["usersOnline"] != float64(12) {
		t.Fatalf("неожиданный результат: %+v", stats)
	}
}
