/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon_test

import (
	"testing"

	"github.com/edoardottt/csprecon/pkg/csprecon"

	"github.com/stretchr/testify/require"
)

func TestCSPMatching(t *testing.T) {
	t.Parallel()

	const (
		httpsPage = "https://victim.example"
		httpPage  = "http://victim.example"
	)

	tests := []struct {
		name   string
		policy string
		gadget string
		page   string
		want   bool
	}{
		{
			name:   "exact host match",
			policy: "script-src https://accounts.google.com",
			gadget: "https://accounts.google.com/o/oauth2/revoke?callback=alert(1)",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "exact host mismatch",
			policy: "script-src https://accounts.google.com",
			gadget: "https://evil.example/x",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "wildcard matches subdomain",
			policy: "script-src https://*.google.com",
			gadget: "https://accounts.google.com/x?cb=alert",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "wildcard does not match apex",
			policy: "script-src https://*.google.com",
			gadget: "https://google.com/x?cb=alert",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "wildcard does not match different suffix",
			policy: "script-src https://*.google.com",
			gadget: "https://accounts.google.com.evil.example/x",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "star matches any host",
			policy: "script-src *",
			gadget: "https://anything.example/x",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "scheme-source https matches https gadget",
			policy: "script-src https:",
			gadget: "https://whatever.example/x",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "scheme-source https does not match http gadget",
			policy: "script-src https:",
			gadget: "http://whatever.example/x",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "scheme-less source inherits https page scheme",
			policy: "script-src accounts.google.com",
			gadget: "https://accounts.google.com/x",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "http page allows https gadget (upgrade relaxation)",
			policy: "script-src accounts.google.com",
			gadget: "https://accounts.google.com/x",
			page:   httpPage,
			want:   true,
		},
		{
			name:   "explicit http source allows https gadget",
			policy: "script-src http://accounts.google.com",
			gadget: "https://accounts.google.com/x",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "https source does not allow http gadget",
			policy: "script-src https://accounts.google.com",
			gadget: "http://accounts.google.com/x",
			page:   httpsPage,
			want:   false,
		},
		{
			// A source path without a trailing "/" names a single file.
			name:   "file path does not allow sub path",
			policy: "script-src https://host.example/gtag/js",
			gadget: "https://host.example/gtag/js/file.js",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "file path allows exact path",
			policy: "script-src https://host.example/gtag/js",
			gadget: "https://host.example/gtag/js",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "file path rejects longer file name",
			policy: "script-src https://host.example/gtag/js",
			gadget: "https://host.example/gtag/jsloader",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "path prefix rejects different path",
			policy: "script-src https://host.example/safe/",
			gadget: "https://host.example/other",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "trailing slash directory prefix",
			policy: "script-src https://host.example/safe/",
			gadget: "https://host.example/safe/app.js",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "none blocks everything",
			policy: "script-src 'none'",
			gadget: "https://accounts.google.com/x",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "strict-dynamic ignores host allowlist",
			policy: "script-src 'strict-dynamic' https://accounts.google.com 'nonce-abc'",
			gadget: "https://accounts.google.com/x",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "default-src used when script-src absent",
			policy: "default-src https://accounts.google.com",
			gadget: "https://accounts.google.com/x",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "script-src overrides default-src (blocked)",
			policy: "default-src https://accounts.google.com; script-src https://other.example",
			gadget: "https://accounts.google.com/x",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "script-src overrides default-src (allowed)",
			policy: "default-src https://accounts.google.com; script-src https://other.example",
			gadget: "https://other.example/x",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "empty script-src blocks (does not fall back)",
			policy: "script-src; default-src *",
			gadget: "https://anything.example/x",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "no script directive is unrestricted",
			policy: "img-src https://img.example",
			gadget: "https://anything.example/x",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "self matches same-origin gadget",
			policy: "script-src 'self'",
			gadget: "https://victim.example/jsonp?cb=alert",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "self does not match cross-origin gadget",
			policy: "script-src 'self'",
			gadget: "https://accounts.google.com/x",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "duplicate directive first wins",
			policy: "script-src https://a.example; script-src https://b.example",
			gadget: "https://b.example/x",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "explicit port enforced",
			policy: "script-src https://host.example:8443",
			gadget: "https://host.example/x",
			page:   httpsPage,
			want:   false,
		},
		{
			name:   "matching explicit port",
			policy: "script-src https://host.example:443",
			gadget: "https://host.example/x",
			page:   httpsPage,
			want:   true,
		},
		{
			name:   "case-insensitive host and directive",
			policy: "SCRIPT-SRC https://Accounts.Google.COM",
			gadget: "https://accounts.google.com/x",
			page:   httpsPage,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := csprecon.EvalAllows(tt.policy, tt.gadget, tt.page)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCSPMatchingMultiplePolicies(t *testing.T) {
	t.Parallel()

	const page = "https://victim.example"

	t.Run("must pass all policies - blocked by second", func(t *testing.T) {
		t.Parallel()

		got := csprecon.EvalAllowsMulti(
			[]string{"script-src https://a.example", "script-src https://b.example"},
			"https://a.example/x",
			page,
		)
		require.False(t, got)
	})

	t.Run("must pass all policies - allowed by both", func(t *testing.T) {
		t.Parallel()

		got := csprecon.EvalAllowsMulti(
			[]string{"script-src https://a.example https://b.example", "script-src https://a.example"},
			"https://a.example/x",
			page,
		)
		require.True(t, got)
	})

	t.Run("comma separated policies in one header", func(t *testing.T) {
		t.Parallel()

		// A single header value carrying two policies: the gadget is only in
		// the first, so it must be blocked by the second.
		got := csprecon.EvalAllows(
			"script-src https://a.example, script-src https://b.example",
			"https://a.example/x",
			page,
		)
		require.False(t, got)
	})
}

// matchCase is one compact matcher expectation: does policy allow a <script
// src=gadget> on page? Expectations follow Chrome, whose behaviour the matcher
// mirrors. Every expectation in this file was checked in Chrome 157: a page
// carrying the policy was loaded in headless Chrome, and the script counted as
// allowed when Chrome requested it (or, for a wss: URL, which Chrome never
// fetches as a script, reported no violation) and blocked when Chrome reported
// a violation (or, for a URL with an invalid port, never requested it).
type matchCase struct {
	name, policy, gadget, page string
	want                       bool
}

func runMatchCases(t *testing.T, cases []matchCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := csprecon.EvalAllows(tc.policy, tc.gadget, tc.page)
			require.Equal(t, tc.want, got, "policy=%q gadget=%q page=%q", tc.policy, tc.gadget, tc.page)
		})
	}
}

// TestCSPScriptSrcElem covers the <script src> fallback list:
// script-src-elem, then script-src, then default-src.
func TestCSPScriptSrcElem(t *testing.T) {
	t.Parallel()

	const (
		page   = "https://victim.example"
		gadget = "https://g.example/jsonp?cb=alert(1)"
	)

	runMatchCases(t, []matchCase{
		{"overrides script-src (blocked)", "script-src-elem 'self'; script-src https://g.example", gadget, page, false},
		{"overrides script-src (allowed)", "script-src-elem https://g.example; script-src 'self'", gadget, page, true},
		{"overrides default-src (blocked)", "default-src https://g.example; script-src-elem 'self'", gadget, page, false},
		{"overrides default-src (allowed)", "default-src 'none'; script-src-elem https://g.example", gadget, page, true},
		{"order of directives is irrelevant", "script-src https://g.example; script-src-elem 'self'", gadget, page, false},
		{"empty script-src-elem blocks (no fallback)", "script-src-elem; script-src https://g.example", gadget, page, false},
		{"none blocks", "script-src-elem 'none'; script-src *", gadget, page, false},
		{"strict-dynamic ignores host allowlist", "script-src-elem 'strict-dynamic' https://g.example; script-src https://g.example", gadget, page, false},
		{"directive name is case-insensitive", "SCRIPT-SRC-ELEM 'self'; script-src https://g.example", gadget, page, false},
		{"duplicate directive first wins", "script-src-elem 'self'; script-src-elem https://g.example", gadget, page, false},
		{"self allows same-origin gadget", "script-src-elem 'self'; script-src 'none'", "https://victim.example/jsonp?cb=x", page, true},
		{"script-src-attr does not govern elements", "script-src-attr 'none'; script-src https://g.example", gadget, page, true},
		{"script-src-attr alone leaves elements unrestricted", "script-src-attr 'none'", gadget, page, true},
		{"script-src still used without script-src-elem", "default-src 'none'; script-src https://g.example", gadget, page, true},
	})
}

// TestCSPPathMatching covers path-part matching: a trailing "/" is a directory
// (prefix), anything else names a single file (exact), after percent-decoding.
func TestCSPPathMatching(t *testing.T) {
	t.Parallel()

	const page = "https://victim.example"

	runMatchCases(t, []matchCase{
		{"file path ignores query string", "script-src https://h.example/gtag/js", "https://h.example/gtag/js?id=G-1&callback=alert", page, true},
		{"file path ignores fragment", "script-src https://h.example/gtag/js", "https://h.example/gtag/js#x", page, true},
		{"file path is case-sensitive", "script-src https://h.example/gtag/JS", "https://h.example/gtag/js", page, false},
		{"file path rejects trailing-slash variant", "script-src https://h.example/gtag/js", "https://h.example/gtag/js/", page, false},
		{"file path rejects parent directory", "script-src https://h.example/a/b.js", "https://h.example/a/", page, false},
		{"directory rejects itself without slash", "script-src https://h.example/safe/", "https://h.example/safe", page, false},
		{"directory allows itself", "script-src https://h.example/safe/", "https://h.example/safe/", page, true},
		{"directory allows deep sub path", "script-src https://h.example/safe/", "https://h.example/safe/a/b/c.js", page, true},
		{"directory rejects sibling with same prefix", "script-src https://h.example/safe/", "https://h.example/safeguard/x.js", page, false},
		{"root path allows everything", "script-src https://h.example/", "https://h.example/any/thing.js", page, true},
		{"file path rejects url without path", "script-src https://h.example/a", "https://h.example?cb=alert", page, false},
		{"root path allows url without path", "script-src https://h.example/", "https://h.example?cb=alert", page, true},
		{"encoded gadget path matches decoded source", "script-src https://h.example/a-b", "https://h.example/a%2Db", page, true},
		{"encoded source path matches decoded gadget", "script-src https://h.example/a%2Db", "https://h.example/a-b", page, true},
		{"encoded slash decoded before directory check", "script-src https://h.example/dir/", "https://h.example/dir%2Fx.js", page, true},
		{"malformed escape compared verbatim (equal)", "script-src https://h.example/a%zz", "https://h.example/a%zz", page, true},
		{"malformed escape compared verbatim (different)", "script-src https://h.example/a%zz", "https://h.example/a", page, false},
		{"valid escape decoded next to a malformed one", "script-src https://h.example/a%2Db%zz", "https://h.example/a-b%zz", page, true},
		{"non-ascii path matches its encoding", "script-src https://h.example/caf%C3%A9.js", "https://h.example/café.js", page, true},
		{"wildcard host with directory (allowed)", "script-src https://*.h.example/api/", "https://x.h.example/api/jsonp?cb=1", page, true},
		{"wildcard host with directory (blocked)", "script-src https://*.h.example/api/", "https://x.h.example/other.js", page, false},
		{"scheme-less source with directory", "script-src h.example/api/", "https://h.example/api/x.js", page, true},
		{"path does not loosen host check", "script-src https://h.example/api/", "https://evil.example/api/x.js", page, false},
	})
}

// TestCSPPortMatching covers port-part matching: no port means the scheme's
// default port only, while "*" and scheme-sources allow any port.
func TestCSPPortMatching(t *testing.T) {
	t.Parallel()

	const (
		httpsPage = "https://victim.example"
		httpPage  = "http://victim.example"
	)

	runMatchCases(t, []matchCase{
		{"no port rejects non-default port", "script-src https://g.example", "https://g.example:8443/x", httpsPage, false},
		{"no port allows explicit default port", "script-src https://g.example", "https://g.example:443/x", httpsPage, true},
		{"no port allows implicit default port", "script-src https://g.example", "https://g.example/x", httpsPage, true},
		{"http source without port allows upgraded https", "script-src http://g.example", "https://g.example/x", httpsPage, true},
		{"scheme-less source allows https on http page", "script-src g.example", "https://g.example/x", httpPage, true},
		{"scheme-less source rejects non-default port", "script-src g.example", "https://g.example:8443/x", httpsPage, false},
		{"explicit port matches same port", "script-src https://g.example:8443", "https://g.example:8443/x", httpsPage, true},
		{"explicit port rejects other port", "script-src https://g.example:8443", "https://g.example:9443/x", httpsPage, false},
		{"explicit default port matches implicit", "script-src https://g.example:443", "https://g.example/x", httpsPage, true},
		{"wildcard port allows any port", "script-src https://g.example:*", "https://g.example:8443/x", httpsPage, true},
		{"bare star allows any port", "script-src *", "https://g.example:8443/x", httpsPage, true},
		{"scheme-source allows any port", "script-src https:", "https://g.example:8443/x", httpsPage, true},
		{"star host without port rejects non-default", "script-src https://*", "https://g.example:8443/x", httpsPage, false},
		{"star host without port allows default", "script-src https://*", "https://g.example/x", httpsPage, true},
		{"star host with wildcard port", "script-src https://*:*", "https://g.example:8443/x", httpsPage, true},
		{"wildcard subdomain with explicit port", "script-src https://*.g.example:8443", "https://a.g.example:8443/x", httpsPage, true},
		{"wildcard subdomain without port rejects non-default", "script-src https://*.g.example", "https://a.g.example:8443/x", httpsPage, false},
		{"wss source without port allows 443", "script-src wss://g.example", "wss://g.example:443/x", httpsPage, true},
		{"port with leading zeros", "script-src https://g.example:08443", "https://g.example:8443/x", httpsPage, true},
		{"gadget url with an invalid port never loads", "script-src *", "https://g.example:99999/x", httpsPage, false},
	})
}

// TestCSPNoneKeyword covers 'none': it blocks everything when alone, and Chrome
// ignores it next to other sources.
func TestCSPNoneKeyword(t *testing.T) {
	t.Parallel()

	const (
		page   = "https://victim.example"
		gadget = "https://g.example/x.js"
	)

	runMatchCases(t, []matchCase{
		{"alone blocks", "script-src 'none'", gadget, page, false},
		{"ignored next to a host", "script-src 'none' https://g.example", gadget, page, true},
		{"ignored next to self", "script-src 'self' 'none'", "https://victim.example/x.js", page, true},
		{"keyword is case-insensitive", "script-src 'NONE' g.example", gadget, page, true},
		{"next to a nonce still blocks hosts", "script-src 'none' 'nonce-abc'", gadget, page, false},
		{"in script-src-elem not rescued by script-src", "script-src-elem 'none'; script-src https://g.example", gadget, page, false},
	})
}

// TestCSPSelfKeyword covers 'self': the page's origin, plus the same host over
// https (or http from an http page) when both ports are the same or default.
func TestCSPSelfKeyword(t *testing.T) {
	t.Parallel()

	const (
		httpsPage = "https://victim.example"
		httpPage  = "http://victim.example"
		page8080  = "http://victim.example:8080"
		policy    = "script-src 'self'"
	)

	runMatchCases(t, []matchCase{
		{"http page allows same host over https", policy, "https://victim.example/x.js", httpPage, true},
		{"http page allows same host over http", policy, "http://victim.example/x.js", httpPage, true},
		{"https page blocks same host over http", policy, "http://victim.example/x.js", httpsPage, false},
		{"http page blocks https on another port", policy, "https://victim.example:8443/x.js", httpPage, false},
		{"page on 8080 allows https on 8080", policy, "https://victim.example:8080/x.js", page8080, true},
		{"page on 8080 blocks https on default port", policy, "https://victim.example/x.js", page8080, false},
		{"page on 8080 blocks http on default port", policy, "http://victim.example/x.js", page8080, false},
		{"https page on 8080 allows itself", policy, "https://victim.example:8080/x.js", "https://victim.example:8080", true},
		{"page url with explicit default port", policy, "https://victim.example/x.js", "https://victim.example:443", true},
		{"subdomain is another origin", policy, "https://sub.victim.example/x.js", httpsPage, false},
	})
}

// TestCSPUpgrades covers Chrome's upgrade rule: http->https (and port 80->443)
// only count when the scheme and the port can both upgrade.
func TestCSPUpgrades(t *testing.T) {
	t.Parallel()

	const (
		httpsPage = "https://victim.example"
		httpPage  = "http://victim.example"
		gadget    = "https://g.example/x.js"
	)

	runMatchCases(t, []matchCase{
		{"http source on 80 allows https", "script-src http://g.example:80", gadget, httpsPage, true},
		{"http source on 80 allows http", "script-src http://g.example:80", "http://g.example/x.js", httpsPage, true},
		{"http source on 443 allows https", "script-src http://g.example:443", gadget, httpsPage, true},
		{"http source on 8080 blocks https on 8080", "script-src http://g.example:8080", "https://g.example:8080/x.js", httpsPage, false},
		{"http source on 8080 allows http on 8080", "script-src http://g.example:8080", "http://g.example:8080/x.js", httpsPage, true},
		{"https source on 80 blocks https", "script-src https://g.example:80", gadget, httpsPage, false},
		{"https source on 80 allows https on 80", "script-src https://g.example:80", "https://g.example:80/x.js", httpsPage, true},
		{"http source blocks http on 443", "script-src http://g.example", "http://g.example:443/x.js", httpsPage, false},
		{"http source with any port allows https on any port", "script-src http://g.example:*", "https://g.example:8080/x.js", httpsPage, true},
		{"scheme-less source on 80 upgrades from an http page", "script-src g.example:80", gadget, httpPage, true},
		{"scheme-less source on 80 blocks https on an https page", "script-src g.example:80", gadget, httpsPage, false},
		{"scheme-less source on 8080 blocks https on 8080 from an http page", "script-src g.example:8080", "https://g.example:8080/x.js", httpPage, false},
		{"http scheme-source allows https", "script-src http:", gadget, httpsPage, true},
		{"https source blocks http", "script-src https://g.example", "http://g.example/x.js", httpPage, false},
		{"wildcard subdomain on 80 upgrades", "script-src http://*.g.example:80", "https://a.g.example/x.js", httpsPage, true},
	})
}

// TestCSPStar covers the bare "*", which allows any http(s) URL, and the
// "*" host in a host-source, which follows the usual scheme and port rules.
func TestCSPStar(t *testing.T) {
	t.Parallel()

	const (
		httpsPage = "https://victim.example"
		httpPage  = "http://victim.example"
		gadget    = "https://g.example/x.js"
	)

	runMatchCases(t, []matchCase{
		{"bare star allows https", "script-src *", gadget, httpsPage, true},
		{"bare star allows http on an https page", "script-src *", "http://g.example/x.js", httpsPage, true},
		{"bare star allows any port", "script-src *", "https://g.example:8080/x.js", httpsPage, true},
		{"star with any port", "script-src *:*", "https://g.example:8080/x.js", httpsPage, true},
		{"star with any port upgrades from an http page", "script-src *:*", "https://g.example:8080/x.js", httpPage, true},
		{"star with explicit port blocks an upgrade", "script-src *:8080", "https://g.example:8080/x.js", httpPage, false},
		{"https star allows the default port only", "script-src https://*", "https://g.example:8080/x.js", httpsPage, false},
		{"star label allows subdomains", "script-src *.example", gadget, httpsPage, true},
	})
}

// TestCSPInvalidSources covers source expressions Chrome's parser rejects:
// they are ignored, so they allow nothing.
func TestCSPInvalidSources(t *testing.T) {
	t.Parallel()

	const (
		page   = "https://victim.example"
		gadget = "https://g.example/x.js"
	)

	runMatchCases(t, []matchCase{
		{"empty port", "script-src https://g.example:", gadget, page, false},
		{"non-numeric port", "script-src https://g.example:abc", gadget, page, false},
		{"single slash after scheme", "script-src https:/g.example", gadget, page, false},
		{"underscore in host", "script-src https://g_x.example", "https://g_x.example/x.js", page, false},
		{"ipv6 host", "script-src https://[2001:db8::1]", "https://[2001:db8::1]/x.js", page, false},
		{"star inside a label", "script-src https://*g.example", gadget, page, false},
		{"invalid source does not hide valid ones", "script-src https://g.example: https://g.example", gadget, page, true},
		{"query in source path ignored", "script-src https://g.example/x.js?v=1", gadget, page, true},
		{"fragment in source path ignored", "script-src https://g.example/x.js#f", gadget, page, true},
		{"uppercase host", "script-src https://G.EXAMPLE", gadget, page, true},
	})
}
