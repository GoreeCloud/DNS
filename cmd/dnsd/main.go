package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/GoreeCloud/DNS/internal/server"
)

func env(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	maxConcurrent, err := strconv.Atoi(env("DNS_MAX_CONCURRENT", "128"))
	if err != nil {
		log.Fatalf("DNS_MAX_CONCURRENT must be an integer")
	}
	cfg := server.Config{
		DNSListen:         env("DNS_LISTEN_ADDR", "127.0.0.1:1053"),
		APIListen:         env("DNS_API_ADDR", "127.0.0.1:8080"),
		Upstream:          env("DNS_UPSTREAM_ADDR", "127.0.0.1:5335"),
		UpstreamMode:      env("DNS_UPSTREAM_MODE", "auto"),
		UpstreamTLSName:   os.Getenv("DNS_UPSTREAM_TLS_NAME"),
		UpstreamTLSCAFile: os.Getenv("DNS_UPSTREAM_TLS_CA_FILE"),
		APIToken:          os.Getenv("DNS_API_TOKEN"),
		RulesFile:         env("DNS_RULES_FILE", "config/rules.txt"),
		LocalRecordsFile:  env("DNS_LOCAL_RECORDS_FILE", "config/local-records.txt"),
		MaxConcurrent:     maxConcurrent,
		AllowedCIDRs:      env("DNS_ALLOWED_CIDRS", "127.0.0.0/8,::1/128"),
	}
	s, err := server.New(cfg)
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("DNS listener %s, admin API %s, upstream transport %s", cfg.DNSListen, cfg.APIListen, cfg.UpstreamMode)
	if err := s.Run(ctx); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
