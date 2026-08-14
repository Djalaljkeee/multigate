package subfmt

import (
	"fmt"
	"strings"
)

// normalizeName приводит имя узла к виду для сравнения: без регистра и
// краевых пробелов. Panel и клиенты не гарантируют одинаковый регистр
// одного и того же имени.
func normalizeName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// usedNames строит множество уже занятых имён для поиска дубликатов.
func usedNames(names []string) map[string]bool {
	used := make(map[string]bool, len(names))
	for _, n := range names {
		if k := normalizeName(n); k != "" {
			used[k] = true
		}
	}
	return used
}

// namesOf собирает имена узлов, обычно для usedNames.
func namesOf(entries []Entry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names
}

// dedupeName подбирает имени первый не занятый в used вариант: само имя,
// если оно свободно, иначе "имя (2)", "имя (3)" и так далее. used
// пополняется найденным именем, так следующий вызов в той же пачке не
// наступит на него же.
//
// Перезаписывать одноимённый узел молча нельзя: так легко случайно
// подменить чужую рабочую ноду, дописывая в существующую подписку.
func dedupeName(name string, used map[string]bool) string {
	key := normalizeName(name)
	if key == "" || !used[key] {
		used[key] = true
		return name
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s (%d)", name, i)
		ck := normalizeName(candidate)
		if !used[ck] {
			used[ck] = true
			return candidate
		}
	}
}

// dedupeEntries переименовывает в extra узлы, чьи имена конфликтуют с
// existingNames или друг с другом, и возвращает копию extra с уже
// уникальными именами.
func dedupeEntries(existingNames []string, extra []Entry) []Entry {
	used := usedNames(existingNames)
	out := make([]Entry, 0, len(extra))
	for _, e := range extra {
		e.Name = dedupeName(e.Name, used)
		out = append(out, e)
	}
	return out
}
