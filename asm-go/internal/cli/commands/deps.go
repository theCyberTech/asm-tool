package commands

import (
	"github.com/theCyberTech/asm-tool/asm-go/internal/config"
	"github.com/theCyberTech/asm-tool/asm-go/internal/database"
)

// Deps holds shared dependencies for CLI commands.
// Using a struct avoids the double-pointer anti-pattern while allowing
// deferred initialization (database and config are set in PersistentPreRunE).
type Deps struct {
	DB  *database.Database
	Cfg *config.Config
}

// NewDeps creates a new empty Deps struct.
// The DB and Cfg fields should be set before commands execute.
func NewDeps() *Deps {
	return &Deps{}
}
