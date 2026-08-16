// Command tunneld is the tunnel server: it accepts outbound agent connections
// and reverse-proxies public HTTP traffic over them to local services.
//
// M2 surface: per-tenant OAuth 2.1 AS under /t/{tenant}/..., the MCP proxy
// under /t/{tenant}/s/{service}/..., the /api/v1 control plane, the
// /tunnel/connect agent gateway and /healthz.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/generalpiston/openai-tunnel-oauth/internal/config"
	"github.com/generalpiston/openai-tunnel-oauth/internal/controlplane"
	"github.com/generalpiston/openai-tunnel-oauth/internal/gateway"
	"github.com/generalpiston/openai-tunnel-oauth/internal/oauth"
	"github.com/generalpiston/openai-tunnel-oauth/internal/proxy"
	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
	"github.com/generalpiston/openai-tunnel-oauth/internal/tunnelproto"
)

func main() {
	configPath := flag.String("config", "./tunneld.yaml", "path to the tunneld YAML config")
	flag.Parse()

	cfg, err := config.LoadDaemon(*configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	issuer := strings.TrimRight(cfg.PublicBaseURL, "/")

	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	// Agents authenticate with store-issued agent keys (mcptunnel service
	// create / agent-key issue) plus X-Tenant / X-Service-Name headers.
	gw := gateway.New(st)
	gw.SetAuditFunc(func(tenant, event, service, remoteAddr string) {
		if err := st.LogAudit(tenant, store.AuditEntry{
			Event:   event,
			Service: service,
			IP:      remoteAddr,
		}); err != nil {
			slog.Debug("audit write failed", "event", event, "err", err)
		}
	})

	// Control-plane bootstrap: while no operator tokens exist, create a
	// one-time setup token and print it prominently on startup.
	hasOps, err := st.HasOperatorTokens()
	if err != nil {
		slog.Error("check operator tokens", "err", err)
		os.Exit(1)
	}
	setupTokenPath := filepath.Join(filepath.Dir(cfg.DatabasePath), "setup_token")
	if !hasOps {
		setupToken, err := st.CreateSetupToken()
		if err != nil {
			slog.Error("create setup token", "err", err)
			os.Exit(1)
		}
		// Also write it next to the database (0600) so co-located users don't
		// have to grep logs; deleted by the control plane once bootstrap
		// succeeds.
		if err := os.WriteFile(setupTokenPath, []byte(setupToken+"\n"), 0o600); err != nil {
			slog.Warn("could not write setup token file", "path", setupTokenPath, "err", err)
		}
		slog.Warn("tunneld: no operator tokens exist — control-plane bootstrap is ENABLED",
			"setup_token", setupToken,
			"setup_token_file", setupTokenPath,
			"hint", "mcptunnel bootstrap --server <url> --setup-token "+setupToken)
	}

	resolver := oauth.NewResolver(oauth.ResolverConfig{
		BaseURL:              issuer,
		Store:                st,
		DevUsername:          cfg.DevAuth.Username,
		DevPassword:          cfg.DevAuth.Password,
		AllowedRedirectHosts: cfg.OAuth.AllowedRedirectHosts,
		AccessTokenTTL:       cfg.Tokens.AccessTTL.D(),
		RefreshTokenTTL:      cfg.Tokens.RefreshTTL.D(),
		Scopes:               cfg.Scopes,
	})

	cp := controlplane.New(st, resolver)
	cp.OnBootstrap = func() {
		if err := os.Remove(setupTokenPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("could not remove setup token file", "path", setupTokenPath, "err", err)
		}
	}

	mux := http.NewServeMux()
	mux.Handle(tunnelproto.ConnectPath, gw)
	mux.Handle("/api/v1/", cp.Handler())
	mux.Handle("/t/{tenant}/s/", proxy.New(gw, &proxy.Auth{
		BaseURL: issuer,
		ValidatorFor: func(tenant string) (proxy.Validator, bool) {
			return resolver.Validator(tenant)
		},
		Store: st,
	}))
	mux.Handle("/", resolver.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok\n"))
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
