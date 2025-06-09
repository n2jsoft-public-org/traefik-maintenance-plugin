package traefik_maintenance_plugin

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsIPAllowed(t *testing.T) {
	config := &Config{
		RedirectURL: "https://example.com/redirect",
		AllowedIPs:  []string{"192.168.0.0/24", "10.0.0.1"},
	}
	handler, err := New(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), config, "test")
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}
	plugin := handler.(*IPWhitelistRedirect)

	tests := []struct {
		ip      string
		allowed bool
	}{
		{"192.168.0.42", true},
		{"192.168.1.1", false},
		{"10.0.0.1", true},
		{"10.0.0.2", false},
		{"::1", false},
	}

	for _, test := range tests {
		ip := net.ParseIP(test.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP: %s", test.ip)
		}
		got := plugin.isIPAllowed(ip)
		if got != test.allowed {
			t.Errorf("isIPAllowed(%q) = %v; want %v", test.ip, got, test.allowed)
		}
	}
}

func TestGetClientIP(t *testing.T) {
	config := &Config{
		RedirectURL: "https://example.com",
	}
	handler, err := New(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), config, "test")
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}
	plugin := handler.(*IPWhitelistRedirect)

	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		wantIP     string
	}{
		{
			name:       "X-Forwarded-For with multiple IPs",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1, 198.51.100.2"},
			remoteAddr: "192.0.2.1:1234",
			wantIP:     "203.0.113.1",
		},
		{
			name:       "X-Real-IP",
			headers:    map[string]string{"X-Real-IP": "198.51.100.42"},
			remoteAddr: "192.0.2.1:1234",
			wantIP:     "198.51.100.42",
		},
		{
			name:       "Fallback to RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "192.0.2.33:5678",
			wantIP:     "192.0.2.33",
		},
		{
			name:       "Invalid RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "invalid-addr",
			wantIP:     "", // expect nil IP
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header:     make(http.Header),
				RemoteAddr: tt.remoteAddr,
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := plugin.getClientIP(req)
			if ip == nil && tt.wantIP != "" {
				t.Errorf("expected IP %q but got nil", tt.wantIP)
			} else if ip != nil && ip.String() != tt.wantIP {
				t.Errorf("got IP %q; want %q", ip.String(), tt.wantIP)
			}
		})
	}
}

func TestServeHTTP(t *testing.T) {
	redirectURL := "https://example.com/redirect"

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler"))
	})

	config := &Config{
		RedirectURL: redirectURL,
		AllowedIPs:  []string{"192.168.1.0/24"},
	}

	pluginHandler, err := New(nil, nextHandler, config, "test")
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}
	plugin := pluginHandler.(*IPWhitelistRedirect)

	// Allowed IP test
	t.Run("allowed IP passes to next handler", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.RemoteAddr = "192.168.1.42:1234"

		rec := httptest.NewRecorder()
		nextCalled = false
		plugin.ServeHTTP(rec, req)

		if !nextCalled {
			t.Error("expected next handler to be called for allowed IP")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "next handler") {
			t.Errorf("unexpected response body: %s", rec.Body.String())
		}
	})

	// Disallowed IP test (should proxy redirectURL response)
	t.Run("disallowed IP proxies redirectURL", func(t *testing.T) {
		// Start test server to simulate redirectURL
		redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
			w.Write([]byte("redirected content"))
		}))
		defer redirectServer.Close()

		plugin.redirectURL = redirectServer.URL

		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.RemoteAddr = "10.0.0.42:5678"

		rec := httptest.NewRecorder()
		plugin.ServeHTTP(rec, req)

		if rec.Code != http.StatusTeapot {
			t.Errorf("expected status %d, got %d", http.StatusTeapot, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "redirected content") {
			t.Errorf("unexpected response body: %s", rec.Body.String())
		}
	})
}
