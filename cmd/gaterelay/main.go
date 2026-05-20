package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gaterelay/internal/config"
	"gaterelay/internal/server"
)

const shutdownTimeout = 10 * time.Second

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	if err := run(os.Args[1:], logger); err != nil {
		logger.Fatalf("%v", err)
	}
}

func run(args []string, logger *log.Logger) error {
	if logger == nil {
		logger = log.Default()
	}

	flags := flag.NewFlagSet("gaterelay", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "config.yaml", "path to GateRelay YAML config")
	checkConfig := flags.Bool("check-config", false, "validate config and exit without serving")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if *checkConfig {
		logger.Printf("configuration OK: %s", *configPath)
		return nil
	}

	app, err := server.New(cfg, logger)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return serve(ctx, newHTTPServer(cfg, app.Handler()), cfg.TLS, logger)
}

func newHTTPServer(cfg *config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: cfg.Timeouts.ReadHeader,
		ReadTimeout:       cfg.Timeouts.Read,
		WriteTimeout:      cfg.Timeouts.Write,
		IdleTimeout:       cfg.Timeouts.Idle,
	}
}

func serve(ctx context.Context, httpServer *http.Server, tlsConfig config.TLSConfig, logger *log.Logger) error {
	serverErr := make(chan error, 1)
	go func() {
		if tlsConfig.Enabled() {
			logger.Printf("GateRelay listening on %s with TLS", httpServer.Addr)
			serverErr <- httpServer.ListenAndServeTLS(tlsConfig.CertFile, tlsConfig.KeyFile)
			return
		}

		logger.Printf("GateRelay listening on %s without TLS", httpServer.Addr)
		serverErr <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		return normalizeServeError(err)
	case <-ctx.Done():
		logger.Printf("shutdown requested")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return normalizeServeError(<-serverErr)
	}
}

func normalizeServeError(err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("serve: %w", err)
}
