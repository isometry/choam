package httpclient

import (
	"net/http"
	"time"
)

const (
	// DefaultTimeout is the default timeout for individual HTTP requests
	DefaultTimeout = 15 * time.Second
	// DefaultMaxIdleConns is the default maximum number of idle connections
	DefaultMaxIdleConns = 100
	// DefaultMaxIdleConnsPerHost is the default maximum number of idle connections per host
	DefaultMaxIdleConnsPerHost = 10
	// DefaultIdleConnTimeout is the default timeout for idle connections
	DefaultIdleConnTimeout = 90 * time.Second
	// DefaultTLSHandshakeTimeout is the default timeout for TLS handshakes
	DefaultTLSHandshakeTimeout = 10 * time.Second
)

// NewHTTPClient creates a new HTTP client with sensible defaults for choam
// This client includes:
// - 15 second timeout for individual HTTP requests
// - Connection pooling for better performance
// - Reasonable timeouts for TLS handshakes and idle connections
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: DefaultTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        DefaultMaxIdleConns,
			MaxIdleConnsPerHost: DefaultMaxIdleConnsPerHost,
			IdleConnTimeout:     DefaultIdleConnTimeout,
			TLSHandshakeTimeout: DefaultTLSHandshakeTimeout,
		},
	}
}

// NewHTTPClientWithTimeout creates an HTTP client with a custom timeout
func NewHTTPClientWithTimeout(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        DefaultMaxIdleConns,
			MaxIdleConnsPerHost: DefaultMaxIdleConnsPerHost,
			IdleConnTimeout:     DefaultIdleConnTimeout,
			TLSHandshakeTimeout: DefaultTLSHandshakeTimeout,
		},
	}
}
