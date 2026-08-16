// Command tunneld is the quick-tunnel server: it creates anonymous ephemeral
// tenants (POST /api/v1/quick), accepts outbound agent connections on
// /tunnel/connect, and reverse-proxies public HTTP traffic under
// /t/{tenant}/s/{service}/... over them to the agents' local MCP servers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/terragohan/mcptunnels/internal/config"
	"github.com/terragohan/mcptunnels/internal/controlplane"
	"github.com/terragohan/mcptunnels/internal/gateway"
	"github.com/terragohan/mcptunnels/internal/oauth"
	"github.com/terragohan/mcptunnels/internal/proxy"
	"github.com/terragohan/mcptunnels/internal/store"
	"github.com/terragohan/mcptunnels/internal/tunnelproto"
)

func main() {
	configPath := flag.String("config", "./tunneld.yaml", "path to the tunneld YAML config")
	killTenant := flag.String("kill-tenant", "", "delete the tenant with this slug (and its services/keys) and exit — operator kill switch")
	flag.Parse()

	cfg, err := config.LoadDaemon(*configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	// Operator kill switch: delete an abusive tenant directly in the
	// database and exit. Its public endpoints 404 and its agent key stops
	// validating immediately (a connected agent's session lingers in the
	// running daemon until it disconnects, but serves no traffic).
	if *killTenant != "" {
		ok, err := st.DeleteTenant(*killTenant)
		if err != nil {
			slog.Error("kill tenant", "tenant", *killTenant, "err", err)
			os.Exit(1)
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "tunneld: tenant %q not found\n", *killTenant)
			os.Exit(1)
		}
		fmt.Printf("tunneld: deleted tenant %q and its services\n", *killTenant)
		return
	}

	// Agents authenticate with the agent key returned by POST /api/v1/quick
	// plus X-Tenant / X-Service-Name headers.
	gw := gateway.New(st)
	cp := controlplane.New(st)
	resolver := oauth.NewResolver(st, cfg.PublicBaseURL)

	mux := http.NewServeMux()
	mux.Handle(tunnelproto.ConnectPath, gw)
	mux.Handle("/api/v1/", cp.Handler())
	mux.Handle("/t/{tenant}/s/", proxy.New(gw, st, resolver))
	mux.Handle("/.well-known/", resolver.WellKnownHandler())
	mux.Handle("/t/", resolver.Handler(http.NotFoundHandler()))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok\n"))
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Janitor: delete expired quick-tunnel tenants every minute; their public
	// endpoints start returning 404 and their agent keys stop validating.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				slugs, err := st.DeleteExpiredTenants(time.Now())
				if err != nil {
					slog.Warn("tunneld: expired-tenant sweep failed", "err", err)
					continue
				}
				for _, slug := range slugs {
					slog.Info("tunneld: deleted expired quick-tunnel tenant", "tenant", slug)
				}
			}
		}
	}()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if cfg.TLS.Mode == config.TLSModeACME {
		host, err := publicHost(cfg.PublicBaseURL)
		if err != nil {
			slog.Error("invalid public_base_url", "err", err)
			os.Exit(1)
		}
		m := &autocert.Manager{
			Cache:      autocert.DirCache(cfg.TLS.ACME.CacheDir),
			Prompt:     autocert.AcceptTOS,
			Email:      cfg.TLS.ACME.Email,
			HostPolicy: autocert.HostWhitelist(host),
		}
		srv.TLSConfig = m.TLSConfig()
		slog.Info("tunneld: ACME enabled (TLS-ALPN-01)", "host", host, "cache", cfg.TLS.ACME.CacheDir)
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("tunneld: listening", "addr", cfg.Listen, "tls", cfg.TLS.Mode)
		var err error
		switch cfg.TLS.Mode {
		case config.TLSModeACME:
			err = srv.ListenAndServeTLS("", "")
		case config.TLSModeManual:
			err = srv.ListenAndServeTLS(cfg.TLS.Manual.CertFile, cfg.TLS.Manual.KeyFile)
		default:
			err = srv.ListenAndServe()
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("serve", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		slog.Info("tunneld: shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("graceful shutdown failed, forcing close", "err", err)
			srv.Close()
		}
	}
}

func publicHost(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if u.Hostname() == "" {
		return "", errors.New("public_base_url must include a host")
	}
	return u.Hostname(), nil
}
