package httpclient

import (
	"net/http"
	"testing"
	"time"
)

func TestNewHTTPClient_HonoursProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
	t.Setenv("NO_PROXY", "")

	for name, client := range map[string]*http.Client{
		"default":      NewHTTPClient(),
		"with timeout": NewHTTPClientWithTimeout(time.Second),
	} {
		transport, ok := client.Transport.(*http.Transport)
		if !ok || transport.Proxy == nil {
			t.Fatalf("%s: transport has no Proxy func", name)
		}
		req, _ := http.NewRequest(http.MethodGet, "https://api.osv.dev/v1/vulns/X", nil)
		proxyURL, err := transport.Proxy(req)
		if err != nil || proxyURL == nil || proxyURL.Host != "proxy.invalid:3128" {
			t.Errorf("%s: Proxy(%s) = %v, %v; want proxy.invalid:3128", name, req.URL, proxyURL, err)
		}
	}
}
