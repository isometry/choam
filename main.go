package main

import (
	"os"

	"github.com/isometry/choam/cmd"
)

func main() {
	if err := cmd.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
