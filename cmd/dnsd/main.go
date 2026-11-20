package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/GoreeCloud/DNS/internal/server"
)

func env(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" { return fallback }
	return value
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg := server.Config{
		DNSListen: env("DNS_LISTEN_ADDR", "127.0.0.1:1053"),
		APIListen: env("DNS_API_ADDR", "127.0.0.1:8080"),
		Upstream: env("DNS_UPSTREAM_ADDR", "127.0.0.1:5335"),
		APIToken: os.Getenv("DNS_API_TOKEN"),
		RulesFile: env("DNS_RULES_FILE", "config/rules.txt"),
	}
	s, err := server.New(cfg)
	if err != nil { log.Fatalf("invalid configuration: %v", err) }
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("dns listener %s, admin API %s", cfg.DNSListen, cfg.APIListen)
	if err := s.Run(ctx); err != nil { log.Fatalf("server stopped: %v", err) }
}
