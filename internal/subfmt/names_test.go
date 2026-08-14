package subfmt

import "testing"

func TestDedupeName(t *testing.T) {
	used := map[string]bool{}
	first := dedupeName("node", used)
	if first != "node" {
		t.Errorf("первое имя не должно меняться: %q", first)
	}
	second := dedupeName("node", used)
	if second != "node (2)" {
		t.Errorf("второе имя = %q, want %q", second, "node (2)")
	}
	third := dedupeName("node", used)
	if third != "node (3)" {
		t.Errorf("третье имя = %q, want %q", third, "node (3)")
	}
	// Регистр не должен позволять обойти проверку дубликата.
	fourth := dedupeName("NODE", used)
	if fourth == "NODE" {
		t.Errorf("дубликат по регистру не пойман: %q", fourth)
	}
}

func TestDedupeEntries_AgainstExistingAndWithinBatch(t *testing.T) {
	existing := []string{"alpha", "beta"}
	extra := []Entry{
		{Name: "alpha"}, // конфликт с existing
		{Name: "alpha"}, // конфликт и с existing, и с предыдущей строкой этой же пачки
		{Name: "gamma"}, // без конфликтов
	}
	out := dedupeEntries(existing, extra)
	if len(out) != 3 {
		t.Fatalf("len(out) = %d, want 3", len(out))
	}
	if out[0].Name == "alpha" || out[1].Name == "alpha" {
		t.Errorf("оба конфликтующих alpha должны были переименоваться: %q, %q", out[0].Name, out[1].Name)
	}
	if out[0].Name == out[1].Name {
		t.Errorf("переименованные имена не должны совпадать друг с другом: %q", out[0].Name)
	}
	if out[2].Name != "gamma" {
		t.Errorf("gamma не должна была измениться: %q", out[2].Name)
	}
}
