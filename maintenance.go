package maintenance

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type Config struct {
	RedirectURL string   `json:"redirectUrl,omitempty"`
	AllowedIPs  []string `json:"allowedIPs,omitempty"`
}

type IPWhitelistRedirect struct {
	next        http.Handler
	name        string
	redirectURL string
	allowedIPs  []net.IPNet
}

func CreateConfig() *Config {
	return &Config{
		RedirectURL: "",
		AllowedIPs:  []string{},
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedirectURL == "" {
		return nil, fmt.Errorf("redirectUrl is required")
	}

	var allowedIPs []net.IPNet
	for _, ipStr := range config.AllowedIPs {
		// Handle both single IPs and CIDR notation
		if !strings.Contains(ipStr, "/") {
			// Single IP - add appropriate subnet mask
			if strings.Contains(ipStr, ":") {
				// IPv6
				ipStr += "/128"
			} else {
				// IPv4
				ipStr += "/32"
			}
		}

		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return nil, fmt.Errorf("invalid IP or CIDR notation '%s': %w", ipStr, err)
		}
		allowedIPs = append(allowedIPs, *ipNet)
	}

	return &IPWhitelistRedirect{
		next:        next,
		name:        name,
		redirectURL: config.RedirectURL,
		allowedIPs:  allowedIPs,
	}, nil
}

func (i *IPWhitelistRedirect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := i.getClientIP(req)

	// Check if client IP is in the allowed list
	if i.isIPAllowed(clientIP) {
		// IP is allowed, pass through to next handler
		i.next.ServeHTTP(rw, req)
		return
	}

	// IP not allowed, redirect to configured URL
	http.Redirect(rw, req, i.redirectURL, http.StatusFound)
}

func (i *IPWhitelistRedirect) getClientIP(req *http.Request) net.IP {
	// Check X-Forwarded-For header first (most common with reverse proxies)
	xff := req.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return parsedIP
			}
		}
	}

	// Check X-Real-IP header
	xri := req.Header.Get("X-Real-IP")
	if xri != "" {
		if parsedIP := net.ParseIP(xri); parsedIP != nil {
			return parsedIP
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, try parsing the whole string as IP
		return net.ParseIP(req.RemoteAddr)
	}

	return net.ParseIP(host)
}

func (i *IPWhitelistRedirect) isIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}

	for _, allowedNet := range i.allowedIPs {
		if allowedNet.Contains(ip) {
			return true
		}
	}

	return false
}
