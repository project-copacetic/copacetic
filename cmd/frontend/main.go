package main

import (
	"os"

	"github.com/project-copacetic/copacetic/pkg/frontend"
)

func main() {
	frontend.RunFrontend(os.Args[1:])
}
