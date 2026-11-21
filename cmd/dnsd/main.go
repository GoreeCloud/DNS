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
	rateQPS, err := strconv.Atoi(env("DNS_RATE_QPS", "500"))
	if err != nil {
		log.Fatal("DNS_RATE_QPS must be an integer")
	}
	rateBurst, err := strconv.Atoi(env("DNS_RATE_BURST", "1000"))
	if err != nil {
		log.Fatal("DNS_RATE_BURST must be an integer")
	}
	allowInsecureAPI, err := strconv.ParseBool(env("DNS_API_ALLOW_INSECURE_REMOTE", "false"))
	if err != nil {
		log.Fatal("DNS_API_ALLOW_INSECURE_REMOTE must be true or false")
	}
	allowRemoteDoT, err := strconv.ParseBool(env("DNS_DOT_ALLOW_REMOTE", "false"))
	if err != nil {
		log.Fatal("DNS_DOT_ALLOW_REMOTE must be true or false")
	}
	cfg := server.Config{
		DNSListen:              env("DNS_LISTEN_ADDR", "127.0.0.1:1053"),
		DoTListen:              os.Getenv("DNS_DOT_LISTEN_ADDR"),
		DoTAllowRemote:         allowRemoteDoT,
		DoTTLSCertFile:         os.Getenv("DNS_DOT_TLS_CERT_FILE"),
		DoTTLSKeyFile:          os.Getenv("DNS_DOT_TLS_KEY_FILE"),
		APIListen:              env("DNS_API_ADDR", "127.0.0.1:8080"),
		APITLSCertFile:         os.Getenv("DNS_API_TLS_CERT_FILE"),
		APITLSKeyFile:          os.Getenv("DNS_API_TLS_KEY_FILE"),
		APIAllowInsecureRemote: allowInsecureAPI,
		Upstream:               env("DNS_UPSTREAM_ADDR", "127.0.0.1:5335"),
		UpstreamMode:           env("DNS_UPSTREAM_MODE", "auto"),
		UpstreamTLSName:        os.Getenv("DNS_UPSTREAM_TLS_NAME"),
		UpstreamTLSCAFile:      os.Getenv("DNS_UPSTREAM_TLS_CA_FILE"),
		APIToken:               os.Getenv("DNS_API_TOKEN"),
		RulesFile:              env("DNS_RULES_FILE", "config/rules.txt"),
		LocalRecordsFile:       env("DNS_LOCAL_RECORDS_FILE", "config/local-records.txt"),
		MaxConcurrent:          maxConcurrent,
		RateQPS:                rateQPS,
		RateBurst:              rateBurst,
		AllowedCIDRs:           env("DNS_ALLOWED_CIDRS", "127.0.0.0/8,::1/128"),
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
