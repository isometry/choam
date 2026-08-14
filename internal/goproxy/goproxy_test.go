package goproxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFirstURL(t *testing.T) {
	tests := []struct {
		name    string
		goproxy string
		wantURL string
		wantOK  bool
	}{
		{name: "empty - Go default", goproxy: "", wantURL: DefaultProxyURL, wantOK: true},
		{name: "whitespace only - Go default", goproxy: "   ", wantURL: DefaultProxyURL, wantOK: true},
		{name: "single https URL", goproxy: "https://proxy.example.com", wantURL: "https://proxy.example.com", wantOK: true},
		{name: "single http URL", goproxy: "http://proxy.example.com", wantURL: "http://proxy.example.com", wantOK: true},
		{name: "comma list - first entry wins", goproxy: "https://a.example.com,https://b.example.com", wantURL: "https://a.example.com", wantOK: true},
		{name: "pipe list - first entry wins", goproxy: "https://a.example.com|https://b.example.com", wantURL: "https://a.example.com", wantOK: true},
		{name: "mixed comma/pipe - first entry wins", goproxy: "https://a.example.com|https://b.example.com,https://c.example.com", wantURL: "https://a.example.com", wantOK: true},
		{name: "whitespace around entries trimmed", goproxy: "  https://a.example.com , https://b.example.com ", wantURL: "https://a.example.com", wantOK: true},
		{name: "direct alone - not ok", goproxy: "direct", wantOK: false},
		{name: "off alone - not ok", goproxy: "off", wantOK: false},
		{name: "direct first - not ok, no fallback walking", goproxy: "direct,https://a.example.com", wantOK: false},
		{name: "off first - not ok, no fallback walking", goproxy: "off,https://a.example.com", wantOK: false},
		{name: "garbage first - not ok, no fallback walking", goproxy: "not-a-url,https://a.example.com", wantOK: false},
		{name: "garbage alone - not ok", goproxy: "banana", wantOK: false},
		{name: "unsupported scheme - not ok", goproxy: "ftp://proxy.example.com", wantOK: false},
		{name: "scheme with no host - not ok", goproxy: "https://", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotOK := FirstURL(tt.goproxy)
			assert.Equal(t, tt.wantOK, gotOK, "ok mismatch")
			if tt.wantOK {
				assert.Equal(t, tt.wantURL, gotURL)
			}
		})
	}
}

func TestIndexBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		goproxy string
		want    string
	}{
		{name: "empty falls back to default", goproxy: "", want: DefaultProxyURL},
		{name: "usable URL passed through", goproxy: "https://proxy.example.com", want: "https://proxy.example.com"},
		{name: "direct falls back to default", goproxy: "direct", want: DefaultProxyURL},
		{name: "off falls back to default", goproxy: "off", want: DefaultProxyURL},
		{name: "garbage falls back to default", goproxy: "banana", want: DefaultProxyURL},
		{name: "list - first entry used", goproxy: "https://a.example.com,direct", want: "https://a.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IndexBaseURL(tt.goproxy))
		})
	}
}

func TestDisabled(t *testing.T) {
	tests := []struct {
		name    string
		goproxy string
		want    bool
	}{
		{name: "off", goproxy: "off", want: true},
		{name: "off with whitespace", goproxy: "  off  ", want: true},
		{name: "empty", goproxy: "", want: false},
		{name: "direct", goproxy: "direct", want: false},
		{name: "usable URL", goproxy: "https://proxy.example.com", want: false},
		{name: "off not first - still not ok as a URL, but Disabled only looks at first entry", goproxy: "https://a.example.com,off", want: false},
		{name: "off first with fallback list", goproxy: "off,https://a.example.com", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Disabled(tt.goproxy))
		})
	}
}

func TestIsPrivate(t *testing.T) {
	tests := []struct {
		name       string
		modulePath string
		goprivate  string
		gonoproxy  string
		want       bool
	}{
		{name: "no patterns at all - not private", modulePath: "github.com/example/foo", want: false},
		{name: "goprivate match", modulePath: "github.com/example/foo", goprivate: "github.com/example/*", want: true},
		{name: "goprivate no match", modulePath: "github.com/other/foo", goprivate: "github.com/example/*", want: false},
		{name: "goprivate glob multi-segment", modulePath: "github.com/example/foo/bar", goprivate: "github.com/example/*", want: true},
		{name: "gonoproxy match, no goprivate", modulePath: "github.com/example/foo", gonoproxy: "github.com/example/*", want: true},
		{
			name:       "gonoproxy takes precedence over goprivate - gonoproxy doesn't match so module is NOT private, even though goprivate would match",
			modulePath: "github.com/example/foo",
			goprivate:  "github.com/example/*",
			gonoproxy:  "github.com/other/*",
			want:       false,
		},
		{
			name:       "gonoproxy takes precedence over goprivate - both set, gonoproxy matches",
			modulePath: "github.com/example/foo",
			goprivate:  "github.com/other/*",
			gonoproxy:  "github.com/example/*",
			want:       true,
		},
		{name: "empty gonoproxy falls back to goprivate", modulePath: "github.com/example/foo", goprivate: "github.com/example/*", gonoproxy: "", want: true},
		{name: "comma separated patterns", modulePath: "github.com/example/foo", goprivate: "gitlab.com/other/*,github.com/example/*", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsPrivate(tt.modulePath, tt.goprivate, tt.gonoproxy))
		})
	}
}
