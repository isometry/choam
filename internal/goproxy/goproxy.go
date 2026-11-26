// Package goproxy provides pure helpers for interpreting the GOPROXY,
// GOPRIVATE and GONOPROXY environment variables the way the go command
// itself does. The parsing helpers are pure string -> value transforms; the
// per-spec module variables (GOPRIVATE and friends) ride on ctx, see
// WithSpecEnv.
package goproxy

import (
	"context"
	"net/url"
	"os"
	"strings"

	"golang.org/x/mod/module"
)

// DefaultProxyURL is the module proxy the go command falls back to when
// GOPROXY is unset - https://proxy.golang.org.
const DefaultProxyURL = "https://proxy.golang.org"

// firstEntry returns the first entry of a GOPROXY-style value - a list of
// entries separated by "," (fallback on any error) and/or "|" (fallback
// only on 404/410) - trimmed of surrounding whitespace. It reports false
// when goproxy is empty or whitespace-only, i.e. has no entries at all.
func firstEntry(goproxy string) (string, bool) {
	trimmed := strings.TrimSpace(goproxy)
	if trimmed == "" {
		return "", false
	}
	entry := trimmed
	if idx := strings.IndexAny(entry, ",|"); idx >= 0 {
		entry = entry[:idx]
	}
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", false
	}
	return entry, true
}

// FirstURL returns the first usable http(s) proxy URL named by a
// GOPROXY-style value. Only the first entry (before any "," or "|") is
// considered - there is no fallback-entry walking. An empty (or
// whitespace-only) goproxy reports Go's default proxy. A first entry of
// "direct", "off", or anything that doesn't parse as an http(s) URL with a
// host is reported as not-ok; it is up to the caller to decide what to do
// (fall back to a default, skip a probe, etc).
func FirstURL(goproxy string) (string, bool) {
	entry, ok := firstEntry(goproxy)
	if !ok {
		return DefaultProxyURL, true
	}
	switch entry {
	case "direct", "off":
		return "", false
	}
	u, err := url.Parse(entry)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	return entry, true
}

// IndexBaseURL returns the base URL to query for the golang.org/toolchain
// release index: the first usable GOPROXY entry, falling back to Go's
// default public proxy when GOPROXY's first entry isn't directly usable
// (e.g. "direct", "off", or a private proxy this process can't reach
// unauthenticated). The toolchain index is public release metadata, so this
// fallback carries no privacy concern.
func IndexBaseURL(goproxy string) string {
	if base, ok := FirstURL(goproxy); ok {
		return base
	}
	return DefaultProxyURL
}

// Disabled reports whether goproxy's first entry is "off" - module
// downloading disabled entirely, per the go command's own convention.
func Disabled(goproxy string) bool {
	entry, ok := firstEntry(goproxy)
	return ok && entry == "off"
}

// IsPrivate reports whether modulePath should be treated as private,
// mirroring the go command's own precedence rule: when GONOPROXY is
// non-empty it governs exclusively; GOPRIVATE is only consulted as its
// default when GONOPROXY is empty. Patterns are matched with
// module.MatchPrefixPatterns, the same comma-separated glob matcher the go
// command itself uses for GOPRIVATE/GONOPROXY/GONOSUMCHECK.
func IsPrivate(modulePath, goprivate, gonoproxy string) bool {
	patterns := gonoproxy
	if patterns == "" {
		patterns = goprivate
	}
	if patterns == "" {
		return false
	}
	return module.MatchPrefixPatterns(patterns, modulePath)
}

// moduleVars are the go command's private-module variables a melange spec's
// build environment may set.
var moduleVars = []string{"GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOINSECURE"}

type specEnvKey struct{}

// WithSpecEnv returns ctx carrying each module variable as the union of the
// process environment and spec (a melange spec's environment), comma-joined
// with empty values skipped, so a spec's private modules are treated as
// private by every go subprocess and module-name check run for it.
func WithSpecEnv(ctx context.Context, spec map[string]string) context.Context {
	env := make(map[string]string, len(moduleVars))
	for _, key := range moduleVars {
		var parts []string
		for _, v := range []string{os.Getenv(key), spec[key]} {
			if v != "" {
				parts = append(parts, v)
			}
		}
		env[key] = strings.Join(parts, ",")
	}
	return context.WithValue(ctx, specEnvKey{}, env)
}

// Getenv returns key's value from ctx's spec environment when ctx carries
// one (see WithSpecEnv), else the process environment.
func Getenv(ctx context.Context, key string) string {
	if env, ok := ctx.Value(specEnvKey{}).(map[string]string); ok {
		if v, ok := env[key]; ok {
			return v
		}
	}
	return os.Getenv(key)
}

// Environ returns KEY=value for every module variable, always all of them
// (empty when unset), so a go subprocess sees exactly ctx's values.
func Environ(ctx context.Context) []string {
	out := make([]string, 0, len(moduleVars))
	for _, key := range moduleVars {
		out = append(out, key+"="+Getenv(ctx, key))
	}
	return out
}
