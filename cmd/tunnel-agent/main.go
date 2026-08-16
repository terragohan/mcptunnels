// Command tunnel-agent runs next to a local (MCP) server, dials outbound to
// tunneld, and forwards proxied requests to the local upstream.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/generalpiston/openai-tunnel-oauth/internal/agent"
	"github.com/generalpiston/openai-tunnel-oauth/internal/config"
)

func main() {
	configPath := flag.String("config", "./agent.yaml", "path to the tunnel-agent YAML config")
	flag.Parse()

	cfg, err := config.LoadAgent(*configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	client, err := agent.New(cfg)
	if err != nil {
		slog.Error("build agent", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("tunnel-agent: starting", "server", cfg.Server, "service", cfg.Service, "upstream", cfg.Upstream)
	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		slog.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}
