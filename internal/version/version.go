// Package version хранит сведения о сборке.
// Значения подставляются линковщиком: -ldflags "-X ...version.Version=v1.0.0".
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

var (
	// Version: версия сборки.
	Version = "dev"
	// Commit: короткий хеш коммита.
	Commit = ""
	// BuildDate: дата сборки в формате RFC3339.
	BuildDate = ""
)

// Name: имя продукта, используется в User-Agent и заголовках.
const Name = "MultiGate"

func init() {
	// Если версию не передали через ldflags, берём то, что записал сам Go
	// при сборке из репозитория: это спасает `go install`.
	if Commit != "" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 7 {
				Commit = s.Value[:7]
			} else {
				Commit = s.Value
			}
		case "vcs.time":
			if BuildDate == "" {
				BuildDate = s.Value
			}
		}
	}
}

// String отдаёт человекочитаемую версию.
func String() string {
	s := Name + " " + Version
	if Commit != "" {
		s += " (" + Commit + ")"
	}
	return s
}

// Full отдаёт развёрнутые сведения для вкладки «О системе».
func Full() string {
	return fmt.Sprintf("%s %s, сборка %s от %s, %s %s/%s",
		Name, Version, orDash(Commit), orDash(BuildDate),
		runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// UserAgent: как прослойка представляется панели.
func UserAgent() string { return Name + "/" + Version }

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
