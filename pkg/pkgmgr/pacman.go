package pkgmgr

import (
	pacmanVer "github.com/parthivsaikia/go-pacman-version"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
)

type pacmanManager struct {
	config        *buildkit.Config
	workingFolder string
}

func isValidPacmanVersion(v string) bool {
	return pacmanVer.IsValid(v)
}

func isLessThanPacmanVersion(v1, v2 string) bool {
	return pacmanVer.LessThan(v1, v2)
}
