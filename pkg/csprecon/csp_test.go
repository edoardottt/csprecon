/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/edoardottt/csprecon/pkg/csprecon"

	"github.com/stretchr/testify/require"
)

func TestParseCSP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty CSP",
			input: "",
			want:  []string{},
		},
		{
			name: "Instagram (https://www.instagram.com/) 2022-12-15",
			input: `report-uri https://www.instagram.com/security/csp_report/; 
				default-src 'self' https://www.instagram.com; 
				img-src data: blob: https://*.fbcdn.net https://*.instagram.com https://*.cdninstagram.com https://*.facebook.com https://*.fbsbx.com https://*.giphy.com;
				font-src data: https://*.fbcdn.net https://*.instagram.com https://*.cdninstagram.com; 
				media-src 'self' blob: https://www.instagram.com https://*.cdninstagram.com https://*.fbcdn.net; 
				manifest-src 'self' https://www.instagram.com; 
				script-src 'self' https://instagram.com https://www.instagram.com https://*.www.instagram.com https://*.cdninstagram.com wss://www.instagram.com https://*.facebook.com https://*.fbcdn.net https://*.facebook.net 'unsafe-inline' 'unsafe-eval' blob:;
				style-src 'self' https://*.www.instagram.com https://www.instagram.com 'unsafe-inline'; 
				connect-src 'self' https://instagram.com https://www.instagram.com https://*.www.instagram.com https://graph.instagram.com https://*.graph.instagram.com https://i.instagram.com/graphql_www https://graphql.instagram.com https://*.cdninstagram.com https://api.instagram.com https://i.instagram.com https://*.i.instagram.com https://*.od.instagram.com wss://www.instagram.com wss://edge-chat.instagram.com https://*.facebook.com https://*.fbcdn.net https://*.facebook.net chrome-extension://boadgeojelhgndaghljhdicfkmllpafd blob:; 
				worker-src 'self' blob: https://www.instagram.com; 
				frame-src 'self' https://instagram.com https://www.instagram.com https://*.instagram.com https://staticxx.facebook.com https://www.facebook.com https://web.facebook.com https://connect.facebook.net https://m.facebook.com https://*.fbsbx.com; 
				object-src 'none'; 
				upgrade-insecure-requests`,
			want: []string{
				"api.instagram.com",
				"*.cdninstagram.com",
				"connect.facebook.net",
				"edge-chat.instagram.com",
				"*.facebook.com",
				"*.facebook.net",
				"*.fbcdn.net",
				"*.fbsbx.com",
				"*.giphy.com",
				"*.graph.instagram.com",
				"graph.instagram.com",
				"graphql.instagram.com",
				"*.i.instagram.com",
				"i.instagram.com",
				"*.instagram.com",
				"instagram.com",
				"m.facebook.com",
				"*.od.instagram.com",
				"staticxx.facebook.com",
				"web.facebook.com",
				"www.facebook.com",
				"*.www.instagram.com",
				"www.instagram.com",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := csprecon.ParseCSP(tt.input, csprecon.CompileRegex(csprecon.DomainRegex))
			require.ElementsMatch(t, tt.want, got)
		})
	}
}

// TestParseCSPHosts checks that only the host of each source and report URL is
// reported, never a file name or another part of the policy.
func TestParseCSPHosts(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "file names in paths",
			input: "script-src https://cdn.example.com/js/app.min.js; report-uri /csp/report.php; " +
				"style-src https://s.example.org/main.css",
			want: []string{"cdn.example.com", "s.example.org"},
		},
		{
			name:  "source without a scheme",
			input: "script-src cdn.example.com/lib/jquery.min.js",
			want:  []string{"cdn.example.com"},
		},
		{
			name:  "query and fragment",
			input: "connect-src https://a.example.com?u=b.example.net https://c.example.com#d.example.net",
			want:  []string{"a.example.com", "c.example.com"},
		},
		{
			name: "domain in a path",
			input: "img-src https://i0.wp.com/s3.example.com/ https://cdn.example.com/npm/@scope/pkg.js@1/ " +
				"img.example.com/a//b.example.net/",
			want: []string{"i0.wp.com", "cdn.example.com", "img.example.com"},
		},
		{
			name:  "report URLs",
			input: "report-uri https://csp.example.com/r //report.example.org/csp /csp/report.php; report-to csp-endpoint",
			want:  []string{"csp.example.com", "report.example.org"},
		},
		{
			name: "schemes",
			input: "frame-src data: blob: https: wss: com.example.app: ms-appx-web: " +
				"x-apple.systempreferences:com.apple.preference.security mailto:a@example.com",
			want: []string{},
		},
		{
			name:  "keywords, nonces and hashes",
			input: "script-src 'self' 'nonce-a.b.example' 'sha256-abc+/=' 'strict-dynamic' 'https://quoted.example.com/'",
			want:  []string{},
		},
		{
			name:  "ports",
			input: "connect-src https://a.example.com:8443 b.example.com:* https://c.example.com:443/x wss://d.example.com:*/ e.example.com:x",
			want:  []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"},
		},
		{
			name:  "wildcards",
			input: "img-src * https://* https://*.example.com *.example.org:* *:*",
			want:  []string{"*.example.com", "*.example.org"},
		},
		{
			name:  "case and trailing dot",
			input: "SCRIPT-SRC HTTPS://CDN.Example.COM https://cdn.example.com https://dot.example.com.",
			want:  []string{"cdn.example.com", "dot.example.com"},
		},
		{
			name:  "IP addresses and local names",
			input: "connect-src http://127.0.0.1:8080 http://localhost:3000 https://[::1]:443 ws://[2001:db8::1] intranet",
			want:  []string{},
		},
		{
			name:  "separators",
			input: "script-src\ta.example.com\n b.example.com,c.example.com;d.example.com , e.example.com",
			want:  []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"},
		},
		{
			name:  "duplicates",
			input: "script-src https://a.example.com; img-src https://a.example.com/x.png a.example.com",
			want:  []string{"a.example.com"},
		},
		{
			name:  "other directives",
			input: "sandbox allow-scripts; trusted-types default goog#html lit-html; require-trusted-types-for 'script'",
			want:  []string{},
		},
		{
			name:  "underscore",
			input: "script-src https://my_host.example.com",
			want:  []string{"my_host.example.com"},
		},
		{
			name:  "label too long",
			input: "script-src https://a." + strings.Repeat("b", 64) + " https://" + strings.Repeat("c", 64) + ".example.com",
			want:  []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := csprecon.ParseCSP(tt.input, csprecon.CompileRegex(csprecon.DomainRegex))
			require.Equal(t, tt.want, got)
		})
	}
}

// TestParseCSPRegex checks that a host is kept only when the regex matches all
// of it, not just a part.
func TestParseCSPRegex(t *testing.T) {
	r := csprecon.CompileRegex(`[a-z]+\.example\.com`)
	got := csprecon.ParseCSP("script-src https://cdn.example.com https://a.b.example.com https://cdn.example.com.evil", r)
	require.Equal(t, []string{"cdn.example.com"}, got)
}

// FuzzParseCSP checks that every reported domain is a whole, lowercase match of
// the domain regex, and that none is reported twice.
func FuzzParseCSP(f *testing.F) {
	f.Add("script-src 'self' https://cdn.example.com/js/app.min.js; report-uri /csp/report.php")
	f.Add("img-src *.Example.org:* //a.example.com/x com.example.app: a.example.com:x")

	r := csprecon.CompileRegex(csprecon.DomainRegex)

	f.Fuzz(func(t *testing.T, policy string) {
		got := csprecon.ParseCSP(policy, r)
		seen := map[string]bool{}

		for _, d := range got {
			require.Equal(t, d, r.FindString(d))
			require.Equal(t, strings.ToLower(d), d)
			require.False(t, seen[d], "%q reported twice", d)

			seen[d] = true
		}
	})
}

// TestCheckCSPDuplicates checks that a domain found in several headers and in
// a meta tag is reported once.
func TestCheckCSPDuplicates(t *testing.T) {
	const policy = "script-src https://cdn.example.com/app.js; img-src https://img.example.org"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", policy)
		w.Header().Set("Content-Security-Policy-Report-Only", policy)
		w.Header().Set("X-WebKit-CSP", "script-src https://CDN.Example.com")
		_, _ = io.WriteString(w, `<html><head><meta http-equiv="Content-Security-Policy" content="`+policy+`"></head></html>`)
	}))
	defer srv.Close()

	got, _, err := csprecon.CheckCSPFull(srv.URL, "test-agent", srv.Client())
	require.NoError(t, err)
	require.Equal(t, []string{"cdn.example.com", "img.example.org"}, got)
}

func TestCheckCSPMultipleHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Same header name sent twice. Each one declares a different domain.
		w.Header().Add("Content-Security-Policy", "default-src 'self' https://first.example.com")
		w.Header().Add("Content-Security-Policy", "img-src https://second.example.com")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	got, _, err := csprecon.CheckCSPFull(srv.URL, "test-agent", srv.Client())
	require.NoError(t, err)
	require.Contains(t, got, "first.example.com")
	require.Contains(t, got, "second.example.com")
}

func TestParseBodyCSP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty HTML",
			input: "",
			want:  []string{},
		},
		{
			name: "Instagram (https://www.instagram.com/) 2022-12-15 adapted for HTML meta tag CSP",
			input: `<html>
			<head>
			<meta http-equiv="Content-Security-Policy" content="report-uri https://www.instagram.com/security/csp_report/; 
				default-src 'self' https://www.instagram.com; 
				img-src data: blob: https://*.fbcdn.net https://*.instagram.com https://*.cdninstagram.com https://*.facebook.com https://*.fbsbx.com https://*.giphy.com;
				font-src data: https://*.fbcdn.net https://*.instagram.com https://*.cdninstagram.com; 
				media-src 'self' blob: https://www.instagram.com https://*.cdninstagram.com https://*.fbcdn.net; 
				manifest-src 'self' https://www.instagram.com; 
				script-src 'self' https://instagram.com https://www.instagram.com https://*.www.instagram.com https://*.cdninstagram.com wss://www.instagram.com https://*.facebook.com https://*.fbcdn.net https://*.facebook.net 'unsafe-inline' 'unsafe-eval' blob:;
				style-src 'self' https://*.www.instagram.com https://www.instagram.com 'unsafe-inline'; 
				connect-src 'self' https://instagram.com https://www.instagram.com https://*.www.instagram.com https://graph.instagram.com https://*.graph.instagram.com https://i.instagram.com/graphql_www https://graphql.instagram.com https://*.cdninstagram.com https://api.instagram.com https://i.instagram.com https://*.i.instagram.com https://*.od.instagram.com wss://www.instagram.com wss://edge-chat.instagram.com https://*.facebook.com https://*.fbcdn.net https://*.facebook.net chrome-extension://boadgeojelhgndaghljhdicfkmllpafd blob:; 
				worker-src 'self' blob: https://www.instagram.com; 
				frame-src 'self' https://instagram.com https://www.instagram.com https://*.instagram.com https://staticxx.facebook.com https://www.facebook.com https://web.facebook.com https://connect.facebook.net https://m.facebook.com https://*.fbsbx.com; 
				object-src 'none'; 
				upgrade-insecure-requests"/>
			</head>
			<body>
			</body>
			</html>`,
			want: []string{
				"api.instagram.com",
				"*.cdninstagram.com",
				"connect.facebook.net",
				"edge-chat.instagram.com",
				"*.facebook.com",
				"*.facebook.net",
				"*.fbcdn.net",
				"*.fbsbx.com",
				"*.giphy.com",
				"*.graph.instagram.com",
				"graph.instagram.com",
				"graphql.instagram.com",
				"*.i.instagram.com",
				"i.instagram.com",
				"*.instagram.com",
				"instagram.com",
				"m.facebook.com",
				"*.od.instagram.com",
				"staticxx.facebook.com",
				"web.facebook.com",
				"www.facebook.com",
				"*.www.instagram.com",
				"www.instagram.com",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.NewReader(tt.input)
			got := csprecon.ParseBodyCSP(body)
			require.ElementsMatch(t, tt.want, got)
		})
	}
}
