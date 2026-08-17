package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/isometry/choam/cmd"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := cmd.NewRootCmd().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
