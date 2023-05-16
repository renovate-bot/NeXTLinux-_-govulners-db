package ui

import (
	"github.com/nextlinux/govulners-db/internal/ui/loggerui"
)

func Select(cfg Config) (uis []UI) {
	// TODO: in the future we may support a TUI, this is the spot to select it

	return []UI{loggerui.New(cfg.Debug, cfg.Quiet)}
}
