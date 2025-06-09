package traefik_maintenance_plugin

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()

	if config == nil {
		t.Fatal("CreateConfig() returned nil")
	}

	if config.RedirectURL != "" {
		t.Errorf("Expected empty RedirectURL, got %s", config.RedirectURL)
	}

	if len(config.AllowedIPs) != 0 {
		t.Errorf("Expected empty AllowedIPs slice, got %v", config.AllowedIPs)
	}
}

func TestNew(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	t.Run("valid config", func(t *testing.T) {
		config := &Config{
			RedirectURL: "https://maintenance.example.com",
			AllowedIPs:  []string{"192.168.1.1", "10.0.0.0/24"},
		}

		handler, err := New(ctx, next, config, "test")
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		if handler == nil {
			t.Fatal("New() returned nil handler")
		}

		ipwr, ok := handler.(*IPWhitelistRedirect)
		if !ok {
			t.Fatal("Handler is not of type *IPWhitelistRedirect")
		}

		if ipwr.redirectURL != config.RedirectURL {
			t.Errorf("Expected redirectURL %s, got %s", config.RedirectURL, ipwr.redirectURL)
		}

		if len(ipwr.allowedIPs) != 2 {
			t.Errorf("Expected 2 allowed IPs, got %d", len(ipwr.allowedIPs))
		}
	})

	t.Run("missing redirect URL", func(t *testing.T) {
		config := &Config{
			RedirectURL: "",
			AllowedIPs:  []string{"192.168.1.1"},
		}

		_, err := New(ctx, next, config, "test")
		if err == nil {
			t.Fatal("Expected error for missing redirectUrl")
		}

		expectedError := "redirectUrl is required"
		if err.Error() != expectedError {
			t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
		}
	})

	t.Run("invalid IP address", func(t *testing.T) {
		config := &Config{
			RedirectURL: "https://maintenance.example.com",
			AllowedIPs:  []string{"invalid-ip"},
		}

		_, err := New(ctx, next, config, "test")
		if err == nil {
			t.Fatal("Expected error for invalid IP")
		}
	})

	t.Run("IPv6 handling", func(t *testing.T) {
		config := &Config{
			RedirectURL: "https://maintenance.example.com",
			AllowedIPs:  []string{"2001:db8::1", "2001:db8::/32"},
		}

		handler, err := New(ctx, next, config, "test")
		if err != nil {
			t.Fatalf("New() failed with IPv6: %v", err)
		}

		ipwr := handler.(*IPWhitelistRedirect)
		if len(ipwr.allowedIPs) != 2 {
			t.Errorf("Expected 2 allowed IPv6 networks, got %d", len(ipwr.allowedIPs))
		}
	})

	t.Run("single IP gets correct subnet mask", func(t *testing.T) {
		config := &Config{
			RedirectURL: "https://maintenance.example.com",
			AllowedIPs:  []string{"192.168.1.1", "2001:db8::1"},
		}

		handler, err := New(ctx, next, config, "test")
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		ipwr := handler.(*IPWhitelistRedirect)

		// Check IPv4 got /32
		ipv4Net := ipwr.allowedIPs[0]
		ones, bits := ipv4Net.Mask.Size()
		if ones != 32 || bits != 32 {
			t.Errorf("Expected IPv4 single IP to get /32 mask, got /%d", ones)
		}

		// Check IPv6 got /128
		ipv6Net := ipwr.allowedIPs[1]
		ones, bits = ipv6Net.Mask.Size()
		if ones != 128 || bits != 128 {
			t.Errorf("Expected IPv6 single IP to get /128 mask, got /%d", ones)
		}
	})
}

func TestServeHTTP(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, err := rw.Write([]byte("allowed"))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	})

	config := &Config{
		RedirectURL: "https://maintenance.example.com",
		AllowedIPs:  []string{"192.168.1.1", "10.0.0.0/24", "2001:db8::1"},
	}

	handler, err := New(ctx, next, config, "test")
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	t.Run("allowed IP passes through", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status OK, got %d", rr.Code)
		}

		if rr.Body.String() != "allowed" {
			t.Errorf("Expected 'allowed', got '%s'", rr.Body.String())
		}
	})

	t.Run("IP in subnet passes through", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.50:12345"

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status OK, got %d", rr.Code)
		}
	})

	t.Run("disallowed IP redirects", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "203.0.113.1:12345"

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("Expected status Found (302), got %d", rr.Code)
		}

		location := rr.Header().Get("Location")
		if location != config.RedirectURL {
			t.Errorf("Expected redirect to %s, got %s", config.RedirectURL, location)
		}
	})

	t.Run("X-Forwarded-For header takes precedence", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "203.0.113.1:12345"             // This would be blocked
		req.Header.Set("X-Forwarded-For", "192.168.1.1") // This should be allowed

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status OK (X-Forwarded-For should take precedence), got %d", rr.Code)
		}
	})

	t.Run("X-Real-IP header used when X-Forwarded-For absent", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "203.0.113.1:12345"     // This would be blocked
		req.Header.Set("X-Real-IP", "10.0.0.25") // This should be allowed (in subnet)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status OK (X-Real-IP should be used), got %d", rr.Code)
		}
	})

	t.Run("IPv6 address works", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "[2001:db8::1]:12345"

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status OK for IPv6, got %d", rr.Code)
		}
	})
}

func TestGetClientIP(t *testing.T) {
	handler := &IPWhitelistRedirect{
		logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
	}

	t.Run("X-Forwarded-For single IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.100")
		req.RemoteAddr = "10.0.0.1:12345"

		ip := handler.getClientIP(req)
		expected := net.ParseIP("192.168.1.100")

		if !ip.Equal(expected) {
			t.Errorf("Expected IP %s, got %s", expected, ip)
		}
	})

	t.Run("X-Forwarded-For multiple IPs", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.100, 10.0.0.1, 172.16.0.1")
		req.RemoteAddr = "203.0.113.1:12345"

		ip := handler.getClientIP(req)
		expected := net.ParseIP("192.168.1.100")

		if !ip.Equal(expected) {
			t.Errorf("Expected first IP %s, got %s", expected, ip)
		}
	})

	t.Run("X-Real-IP when no X-Forwarded-For", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "192.168.1.200")
		req.RemoteAddr = "10.0.0.1:12345"

		ip := handler.getClientIP(req)
		expected := net.ParseIP("192.168.1.200")

		if !ip.Equal(expected) {
			t.Errorf("Expected IP %s, got %s", expected, ip)
		}
	})

	t.Run("RemoteAddr fallback", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"

		ip := handler.getClientIP(req)
		expected := net.ParseIP("10.0.0.1")

		if !ip.Equal(expected) {
			t.Errorf("Expected IP %s, got %s", expected, ip)
		}
	})

	t.Run("IPv6 RemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "[2001:db8::1]:8080"

		ip := handler.getClientIP(req)
		expected := net.ParseIP("2001:db8::1")

		if !ip.Equal(expected) {
			t.Errorf("Expected IPv6 %s, got %s", expected, ip)
		}
	})

	t.Run("invalid X-Forwarded-For falls back", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "invalid-ip")
		req.Header.Set("X-Real-IP", "192.168.1.50")
		req.RemoteAddr = "10.0.0.1:12345"

		ip := handler.getClientIP(req)
		expected := net.ParseIP("192.168.1.50")

		if !ip.Equal(expected) {
			t.Errorf("Expected fallback to X-Real-IP %s, got %s", expected, ip)
		}
	})

	t.Run("malformed RemoteAddr without port", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1"

		ip := handler.getClientIP(req)
		expected := net.ParseIP("192.168.1.1")

		if !ip.Equal(expected) {
			t.Errorf("Expected IP %s, got %s", expected, ip)
		}
	})
}

func TestIsIPAllowed(t *testing.T) {
	// Create handler with test IPs
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	config := &Config{
		RedirectURL: "https://maintenance.example.com",
		AllowedIPs:  []string{"192.168.1.1", "10.0.0.0/24", "2001:db8::/32"},
	}

	handler, err := New(ctx, next, config, "test")
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	ipwr := handler.(*IPWhitelistRedirect)

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"exact IPv4 match", "192.168.1.1", true},
		{"IPv4 in subnet", "10.0.0.50", true},
		{"IPv4 not in subnet", "10.0.1.1", false},
		{"IPv4 not allowed", "203.0.113.1", false},
		{"IPv6 in subnet", "2001:db8::1234", true},
		{"IPv6 not in subnet", "2001:db9::1", false},
		{"nil IP", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip net.IP
			if tt.ip != "" {
				ip = net.ParseIP(tt.ip)
			}

			result := ipwr.isIPAllowed(ip)
			if result != tt.expected {
				t.Errorf("isIPAllowed(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func BenchmarkServeHTTP(b *testing.B) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	config := &Config{
		RedirectURL: "https://maintenance.example.com",
		AllowedIPs:  []string{"192.168.1.0/24", "10.0.0.0/8"},
	}

	handler, err := New(ctx, next, config, "test")
	if err != nil {
		b.Fatalf("Failed to create handler: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}
