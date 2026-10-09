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
// (see NewHTTPClientWithTimeout) and the default request timeout.
func NewHTTPClient() *http.Client {
	return NewHTTPClientWithTimeout(DefaultTimeout)
}

// NewHTTPClientWithTimeout creates an HTTP client with a custom per-request
// timeout, connection pooling, bounded TLS handshakes, and the standard
// HTTPS_PROXY/HTTP_PROXY/NO_PROXY environment honoured.
func NewHTTPClientWithTimeout(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConns:        DefaultMaxIdleConns,
			MaxIdleConnsPerHost: DefaultMaxIdleConnsPerHost,
			IdleConnTimeout:     DefaultIdleConnTimeout,
			TLSHandshakeTimeout: DefaultTLSHandshakeTimeout,
		},
	}
}
