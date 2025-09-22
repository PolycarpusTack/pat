package ratelimit

import (
    "net/http"
    "net/http/httptest"
    "sync"
    "testing"
)

func TestNewSimpleRateLimiter(t *testing.T) {
    limiter := NewSimpleRateLimiter(100)
    if limiter == nil {
        t.Fatal("Expected rate limiter to be created, got nil")
    }
}

func TestSimpleRateLimiter_Allow(t *testing.T) {
    limiter := NewSimpleRateLimiter(3) // Allow 3 requests per minute

    client := "192.168.1.1:1000"

    // First 3 requests should be allowed
    for i := 0; i < 3; i++ {
        if !limiter.Allow(client) {
            t.Errorf("Request %d should be allowed", i+1)
        }
    }

    // 4th request should be blocked
    if limiter.Allow(client) {
        t.Error("4th request should be blocked")
    }

    // Different IP should be allowed
    if !limiter.Allow("192.168.1.2:2000") {
        t.Error("Request from different IP should be allowed")
    }
}

func TestSimpleRateLimiter_HTTPMiddleware(t *testing.T) {
    limiter := NewSimpleRateLimiter(2) // Allow 2 requests per minute

    // Create a test handler
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte("OK"))
    })

    middleware := limiter.HTTPMiddleware()
    wrapped := middleware(handler)

    // 1st request
    req1 := httptest.NewRequest("GET", "/test", nil)
    req1.RemoteAddr = "192.168.1.1:12345"
    w1 := httptest.NewRecorder()
    wrapped.ServeHTTP(w1, req1)
    if w1.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", w1.Code)
    }

    // 2nd request
    req2 := httptest.NewRequest("GET", "/test", nil)
    req2.RemoteAddr = "192.168.1.1:12346"
    w2 := httptest.NewRecorder()
    wrapped.ServeHTTP(w2, req2)
    if w2.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", w2.Code)
    }

    // 3rd request should be rate limited
    req3 := httptest.NewRequest("GET", "/test", nil)
    req3.RemoteAddr = "192.168.1.1:12347"
    w3 := httptest.NewRecorder()
    wrapped.ServeHTTP(w3, req3)
    if w3.Code != http.StatusTooManyRequests {
        t.Errorf("Expected status 429, got %d", w3.Code)
    }
}

func TestSimpleRateLimiter_ConcurrentAccess(t *testing.T) {
    limiter := NewSimpleRateLimiter(1000)

    var wg sync.WaitGroup
    numGoroutines := 50
    requestsPerGoroutine := 10
    wg.Add(numGoroutines)

    for i := 0; i < numGoroutines; i++ {
        go func(id int) {
            defer wg.Done()
            for j := 0; j < requestsPerGoroutine; j++ {
                limiter.Allow("192.168.1.1:" + string(rune('0'+j)))
            }
        }(i)
    }
    wg.Wait()
}

func TestSimpleRateLimiter_Close(t *testing.T) {
    limiter := NewSimpleRateLimiter(10)
    // Close should not panic
    limiter.Close()
}

func TestSimpleRateLimiter_ExtractIP(t *testing.T) {
	limiter := NewSimpleRateLimiter(10)

	tests := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{
			name:       "IPv4 with port",
			remoteAddr: "192.168.1.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "IPv4 without port",
			remoteAddr: "192.168.1.1",
			expected:   "192.168.1.1",
		},
		{
			name:       "IPv6 with port",
			remoteAddr: "[::1]:12345",
			expected:   "::1",
		},
		{
			name:       "IPv6 without port",
			remoteAddr: "::1",
			expected:   "::1",
		},
		{
			name:       "Localhost with port",
			remoteAddr: "127.0.0.1:54321",
			expected:   "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := limiter.extractIP(tt.remoteAddr)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}
