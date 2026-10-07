package main

import (
	"os"

	"github.com/brerabineth/hellhound/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
