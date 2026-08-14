package remnawave

import "context"

// SystemStats отдаёт статистику панели как есть: набор полей у разных версий
// разный, и заворачивать их в свою структуру смысла нет: этим пользуется
// только вкладка "О системе" в админке.
func (c *Client) SystemStats(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if _, err := c.getJSON(ctx, "/api/system/stats", nil, true, &out); err != nil {
		return nil, err
	}
	return out, nil
}
