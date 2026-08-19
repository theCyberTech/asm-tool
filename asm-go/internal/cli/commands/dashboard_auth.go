package commands

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func withDashboardAuth(token string, next http.Handler) http.Handler {
	token = strings.TrimSpace(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || token == "" {
			next.ServeHTTP(w, r)
			return
		}
		if dashboardRequestHasValidToken(r, token) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="ASM Dashboard"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func dashboardRequestHasValidToken(r *http.Request, token string) bool {
	if tokenMatches(dashboardRequestToken(r), token) {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	if user != "asm" && user != "" {
		return false
	}
	return tokenMatches(pass, token)
}

func dashboardRequestToken(r *http.Request) string {
	if h := strings.TrimSpace(r.Header.Get("X-ASM-Token")); h != "" {
		return h
	}
	const bearer = "bearer "
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); len(auth) > len(bearer) && strings.EqualFold(auth[:len(bearer)], bearer) {
		return strings.TrimSpace(auth[len(bearer):])
	}
	return ""
}

func tokenMatches(got, want string) bool {
	if want == "" || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func isLoopbackHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

type dashboardOptions struct {
	host  string
	port  int
	token string
}

func resolveDashboardOptions(cmd *cobra.Command, deps *Deps) (dashboardOptions, error) {
	opts := dashboardOptions{
		host:  dashboardHost,
		port:  dashboardPort,
		token: dashboardAuthToken,
	}
	if deps != nil && deps.Cfg != nil {
		if !cmd.Flags().Changed("host") && deps.Cfg.Dashboard.Host != "" {
			opts.host = deps.Cfg.Dashboard.Host
		}
		if !cmd.Flags().Changed("port") && deps.Cfg.Dashboard.Port > 0 {
			opts.port = deps.Cfg.Dashboard.Port
		}
		if !cmd.Flags().Changed("auth-token") && strings.TrimSpace(opts.token) == "" {
			opts.token = deps.Cfg.Dashboard.Token
		}
	}
	opts.token = strings.TrimSpace(opts.token)
	if !isLoopbackHost(opts.host) && opts.token == "" {
		return opts, fmt.Errorf("dashboard requires a token when binding to %s; set ASM_DASHBOARD_TOKEN or --auth-token", opts.host)
	}
	return opts, nil
}
