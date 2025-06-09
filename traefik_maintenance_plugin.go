package traefik_maintenance_plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
)

type Config struct {
	RedirectURL string   `json:"redirectUrl,omitempty"`
	AllowedIPs  []string `json:"allowedIPs,omitempty"`
	Debug       bool     `json:"debug,omitempty"`
}

type IPWhitelistRedirect struct {
	next        http.Handler
	name        string
	redirectURL string
	allowedIPs  []net.IPNet
	debug       bool
	logger      *slog.Logger
}

func CreateConfig() *Config {
	return &Config{
		RedirectURL: "",
		AllowedIPs:  []string{},
		Debug:       false,
	}
}

var ErrMissingRedirectURL = errors.New("redirectUrl is required")

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedirectURL == "" {
		return nil, ErrMissingRedirectURL
	}

	allowedIPs := make([]net.IPNet, 0, len(config.AllowedIPs))
	for _, ipStr := range config.AllowedIPs {
		if !strings.Contains(ipStr, "/") {
			if strings.Contains(ipStr, ":") {
				ipStr += "/128"
			} else {
				ipStr += "/32"
			}
		}

		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return nil, fmt.Errorf("invalid IP or CIDR notation '%s': %w", ipStr, err)
		}
		allowedIPs = append(allowedIPs, *ipNet)
	}

	loglevel := slog.LevelError
	if config.Debug {
		loglevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: loglevel,
	}))

	plugin := &IPWhitelistRedirect{
		next:        next,
		name:        name,
		redirectURL: config.RedirectURL,
		allowedIPs:  allowedIPs,
		debug:       config.Debug,
		logger:      logger,
	}

	if plugin.debug {
		plugin.logger.Info("Plugin initialized with debug mode enabled",
			"plugin", name,
			"redirectURL", config.RedirectURL,
			"allowedIPsCount", len(allowedIPs))
		for i, ip := range allowedIPs {
			plugin.logger.Debug("Allowed IP configured",
				"plugin", name,
				"index", i+1,
				"network", ip.String())
		}
	}

	return plugin, nil
}

func (i *IPWhitelistRedirect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := i.getClientIP(req)

	if i.isIPAllowed(clientIP) {
		i.logger.Debug("IP allowed, passing request through",
			"plugin", i.name, "clientIP", clientIP.String())

		i.next.ServeHTTP(rw, req)
		return
	}

	i.logger.Debug("IP not allowed, redirecting",
		"plugin", i.name,
		"clientIP", clientIP.String(),
		"redirectURL", i.redirectURL)
	http.Redirect(rw, req, i.redirectURL, http.StatusFound)
}

func (i *IPWhitelistRedirect) getClientIP(req *http.Request) net.IP {
	// Try X-Forwarded-For
	if ip := i.extractIPFromHeader(req, "X-Forwarded-For", true); ip != nil {
		i.logger.Debug("Extracted IP from X-Forwarded-For header",
			"plugin", i.name,
			"ip", ip.String())
		return ip
	}

	// Try X-Real-IP
	if ip := i.extractIPFromHeader(req, "X-Real-IP", false); ip != nil {
		i.logger.Debug("Extracted IP from X-Real-IP header",
			"plugin", i.name,
			"ip", ip.String())
		return ip
	}

	// Fallback to RemoteAddr
	ip := i.extractIPFromRemoteAddr(req.RemoteAddr)
	i.logger.Debug("Extracted IP from RemoteAddr",
		"plugin", i.name,
		"ip", ip.String())
	return ip
}

func (i *IPWhitelistRedirect) extractIPFromHeader(req *http.Request, header string, isList bool) net.IP {
	value := req.Header.Get(header)
	if value == "" {
		return nil
	}

	var ipStr string
	if isList {
		parts := strings.Split(value, ",")
		if len(parts) > 0 {
			ipStr = strings.TrimSpace(parts[0])
		}
	} else {
		ipStr = value
	}

	return net.ParseIP(ipStr)
}

func (i *IPWhitelistRedirect) extractIPFromRemoteAddr(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return net.ParseIP(remoteAddr)
	}

	return net.ParseIP(host)
}

func (i *IPWhitelistRedirect) isIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}

	for _, allowedNet := range i.allowedIPs {
		if allowedNet.Contains(ip) {
			i.logger.Debug("IP matches is allowed",
				"plugin", i.name,
				"ip", ip.String(),
				"network", allowedNet.String())
			return true
		}
	}

	i.logger.Debug("IP does not match any allowed networks",
		"plugin", i.name,
		"ip", ip.String())
	return false
}
