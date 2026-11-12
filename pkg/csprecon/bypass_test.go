/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edoardottt/csprecon/pkg/csprecon"
	"github.com/edoardottt/csprecon/pkg/input"
	"github.com/edoardottt/csprecon/pkg/output"

	"github.com/stretchr/testify/require"
)

const testFilePerm = 0o600

func TestParseGadgets(t *testing.T) {
	t.Parallel()

	data := "Domain\tCode\n" +
		"a.example\t<script src=\"https://a.example/x?cb=alert(1)\"></script>\n" +
		"b.example  <script src=\"https://b.example/y?cb=alert\"></script>\r\n" + // space separated + CRLF
		"a.example\t<script src=\"https://a.example/z?cb=alert\"></script>\n" + // duplicate domain, second gadget
		"\n" + // blank line
		"C.EXAMPLE\t<script src=\"https://c.example/w\"></script>\n" // uppercase domain

	db := csprecon.ParseGadgets(strings.NewReader(data))
	entries := csprecon.GadgetEntries(db)

	require.Len(t, entries, 4) // header and blank line skipped

	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Domain]++
	}

	require.Equal(t, 2, counts["a.example"])
	require.Equal(t, 1, counts["b.example"])
	require.Equal(t, 1, counts["c.example"]) // lowercased
}

func TestExtractGadgetURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		code   string
		domain string
		want   string
	}{
		{
			name:   "absolute src",
			code:   `<script src="https://a.example/x?cb=alert(1)"></script>`,
			domain: "a.example",
			want:   "https://a.example/x?cb=alert(1)",
		},
		{
			name:   "scheme-relative normalized to https",
			code:   `<script src="//a.example/x"></script>`,
			domain: "a.example",
			want:   "https://a.example/x",
		},
		{
			name:   "leading relative skipped for following absolute",
			code:   `<iframe src="/rel"></iframe><script src="https://a.example/y"></script>`,
			domain: "a.example",
			want:   "https://a.example/y",
		},
		{
			name:   "unquoted src",
			code:   `<script src=https://a.example/z></script>`,
			domain: "a.example",
			want:   "https://a.example/z",
		},
		{
			name:   "single-quoted src",
			code:   `<script src='https://a.example/q'></script>`,
			domain: "a.example",
			want:   "https://a.example/q",
		},
		{
			name:   "href attribute",
			code:   `<link href="https://a.example/style">`,
			domain: "a.example",
			want:   "https://a.example/style",
		},
		{
			name:   "fallback to domain when no usable url",
			code:   `<div ng-app></div>`,
			domain: "a.example",
			want:   "https://a.example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, csprecon.ExtractGadgetURL(tt.code, tt.domain))
		})
	}
}

func TestBypasses(t *testing.T) {
	t.Parallel()

	const page = "https://victim.example"

	data := "Domain\tCode\n" +
		"accounts.google.com\t<script src=\"https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)\"></script>\n" +
		"other.example\t<script src=\"https://other.example/jsonp?cb=alert\"></script>\n"

	db := csprecon.ParseGadgets(strings.NewReader(data))

	t.Run("whitelisted gadget is reported", func(t *testing.T) {
		t.Parallel()

		views := csprecon.BypassFindings(db, page, []string{"script-src https://accounts.google.com"})
		require.Len(t, views, 1)
		require.Equal(t, "accounts.google.com", views[0].Domain)
		require.Equal(t, "script-src", views[0].Directive)
		require.Equal(t, page, views[0].URL)
	})

	t.Run("strict-dynamic yields no bypass", func(t *testing.T) {
		t.Parallel()

		views := csprecon.BypassFindings(db, page, []string{"script-src 'strict-dynamic' https://accounts.google.com"})
		require.Empty(t, views)
	})

	t.Run("no enforced policy yields no bypass", func(t *testing.T) {
		t.Parallel()

		views := csprecon.BypassFindings(db, page, nil)
		require.Empty(t, views)
	})

	t.Run("non-script directive yields no bypass", func(t *testing.T) {
		t.Parallel()

		views := csprecon.BypassFindings(db, page, []string{"img-src https://accounts.google.com"})
		require.Empty(t, views)
	})

	t.Run("unsafe-inline surfaced as flag", func(t *testing.T) {
		t.Parallel()

		views := csprecon.BypassFindings(db, page, []string{"script-src https://accounts.google.com 'unsafe-inline'"})
		require.Len(t, views, 1)
		require.Contains(t, views[0].Flags, "unsafe-inline")
	})

	t.Run("gadget not fetched over http(s) is never reported", func(t *testing.T) {
		t.Parallel()

		other := csprecon.ParseGadgets(strings.NewReader(
			"ws.example\t<script src=\"wss://ws.example/x\"></script>\n" +
				"custom.example\t<script src=\"custom://custom.example/x\"></script>\n" +
				"h.example\t<script src=\"http://h.example/x\"></script>\n"))

		views := csprecon.BypassFindings(other, "http://victim.example", []string{"script-src * wss: custom:"})
		require.Len(t, views, 1)
		require.Equal(t, "h.example", views[0].Domain)
	})
}

// TestBypassesAfterRedirect checks that a redirected target is evaluated
// against the page it landed on (whose CSP was read), while the finding still
// names the input URL.
func TestBypassesAfterRedirect(t *testing.T) {
	t.Parallel()

	const (
		target = "http://victim.example"
		final  = "https://www.victim.example/home"
	)

	db := csprecon.ParseGadgets(strings.NewReader("Domain\tCode\n" +
		"victim.example\t<script src=\"https://victim.example/jsonp?cb=alert\"></script>\n" +
		"www.victim.example\t<script src=\"https://www.victim.example/jsonp?cb=alert\"></script>\n" +
		"g.example\t<script src=\"http://g.example/jsonp?cb=alert\"></script>\n"))

	t.Run("self is the final origin", func(t *testing.T) {
		t.Parallel()

		views := csprecon.BypassFindingsRedirected(db, target, final, []string{"script-src 'self'"})
		require.Len(t, views, 1)
		require.Equal(t, "www.victim.example", views[0].Domain)
		require.Equal(t, target, views[0].URL)
	})

	t.Run("scheme-less source takes the final scheme", func(t *testing.T) {
		t.Parallel()

		// On the http input page "g.example" would allow the http gadget, but
		// the policy came from an https page, where it means https only.
		require.Len(t, csprecon.BypassFindings(db, target, []string{"script-src g.example"}), 1)
		require.Empty(t, csprecon.BypassFindingsRedirected(db, target, final, []string{"script-src g.example"}))
	})
}

// TestBypassDirectiveAndFlags checks which directive a finding reports and that
// the flags come from the right directives: <script src> is governed by
// script-src-elem (then script-src, then default-src), while eval() is governed
// by script-src (then default-src) and never by script-src-elem.
func TestBypassDirectiveAndFlags(t *testing.T) {
	t.Parallel()

	const page = "https://victim.example"

	db := csprecon.ParseGadgets(strings.NewReader(
		"g.example\t<script src=\"https://g.example/jsonp?cb=alert\"></script>\n"))

	tests := []struct {
		name      string
		policy    string
		directive string // "" means no finding expected
		flags     []string
	}{
		{"script-src-elem governs", "script-src-elem https://g.example; script-src 'none'", "script-src-elem", nil},
		{"script-src-elem blocks", "script-src-elem 'self'; script-src https://g.example", "", nil},
		{"empty script-src-elem blocks", "script-src-elem; default-src *", "", nil},
		{"script-src governs", "script-src https://g.example; default-src 'none'", "script-src", nil},
		{"default-src governs", "default-src https://g.example", "default-src", nil},
		{
			"eval read from script-src with script-src-elem",
			"script-src-elem https://g.example 'unsafe-inline'; script-src 'unsafe-eval'",
			"script-src-elem", []string{"unsafe-eval", "unsafe-inline"},
		},
		{
			"eval in script-src-elem ignored",
			"script-src-elem https://g.example 'unsafe-eval'; script-src 'self'",
			"script-src-elem", nil,
		},
		{"eval read from default-src", "default-src https://g.example 'unsafe-eval'", "default-src", []string{"unsafe-eval"}},
		{"eval in default-src overridden by script-src", "default-src 'unsafe-eval'; script-src https://g.example", "script-src", nil},
		{"eval and inline from script-src", "script-src https://g.example 'UNSAFE-EVAL' 'unsafe-inline'", "script-src", []string{"unsafe-eval", "unsafe-inline"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			views := csprecon.BypassFindings(db, page, []string{tt.policy})
			if tt.directive == "" {
				require.Empty(t, views)

				return
			}

			require.Len(t, views, 1)
			require.Equal(t, tt.directive, views[0].Directive)
			require.Equal(t, tt.flags, views[0].Flags)
		})
	}
}

func TestFormatBypassLine(t *testing.T) {
	t.Parallel()

	v := csprecon.BypassView{
		URL:       "https://victim.example",
		Domain:    "accounts.google.com",
		Directive: "script-src",
		Code:      `<script src="x"></script>`,
	}

	line := csprecon.PlainLine(v)

	require.True(t, strings.HasPrefix(line, csprecon.BypassPrefix+" "))
	require.Equal(t,
		csprecon.BypassPrefix+` https://victim.example accounts.google.com script-src <script src="x"></script>`,
		line,
	)
}

func TestBypassJSON(t *testing.T) {
	t.Parallel()

	views := []csprecon.BypassView{{
		Domain:    "a.example",
		Directive: "script-src",
		Code:      "<script></script>",
		Flags:     []string{"unsafe-inline"},
	}}

	data := output.JSONData{
		URL:       "https://victim.example",
		CSPResult: []string{"a.example"},
		Bypasses:  csprecon.JSONResults(views),
	}

	out, err := output.FormatJSON(data)
	require.NoError(t, err)
	require.Contains(t, string(out), `"Bypasses"`)
	require.Contains(t, string(out), `"Domain":"a.example"`)

	// Backward compatibility: with no bypasses the field is omitted.
	plain, err := output.FormatJSON(output.JSONData{URL: "x", CSPResult: []string{"a"}})
	require.NoError(t, err)
	require.NotContains(t, string(plain), "Bypasses")
}

func TestLoadGadgetsFromFile(t *testing.T) {
	t.Parallel()

	file := filepath.Join(t.TempDir(), "my.tsv")
	content := "Domain\tCode\nx.example\t<script src=\"https://x.example/a\"></script>\n"
	require.NoError(t, os.WriteFile(file, []byte(content), testFilePerm))

	db, src, err := csprecon.LoadGadgetsForTest(&input.Options{BypassFile: file})
	require.NoError(t, err)
	require.Equal(t, "file", src)
	require.Len(t, csprecon.GadgetEntries(db), 1)
}

func TestLoadGadgetsRejectsDirectory(t *testing.T) {
	t.Parallel()

	_, _, err := csprecon.LoadGadgetsForTest(&input.Options{BypassFile: t.TempDir()})
	require.ErrorIs(t, err, input.ErrIsDirectory)
}

func TestLoadGadgetsMissingFile(t *testing.T) {
	t.Parallel()

	_, _, err := csprecon.LoadGadgetsForTest(&input.Options{BypassFile: filepath.Join(t.TempDir(), "nope.tsv")})
	require.ErrorIs(t, err, os.ErrNotExist)
}

// TestLoadGadgetsFetchCacheFallback mutates package-level seams and therefore
// does not run in parallel.
func TestLoadGadgetsFetchCacheFallback(t *testing.T) {
	origURL := csprecon.BypassDataURL()
	origCache := csprecon.CachePathFunc()

	t.Cleanup(func() {
		csprecon.SetBypassDataURL(origURL)
		csprecon.SetCachePathFunc(origCache)
	})

	cachePath := filepath.Join(t.TempDir(), "cspbypass.tsv")

	csprecon.SetCachePathFunc(func() (string, error) { return cachePath, nil })

	tsv := "Domain\tCode\nexample.com\t<script src=\"https://example.com/x?cb=alert(1)\"></script>\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, tsv)
	}))
	csprecon.SetBypassDataURL(srv.URL)

	// 1. Live fetch succeeds and writes the cache.
	db, src, err := csprecon.LoadGadgetsForTest(&input.Options{Bypass: true})
	require.NoError(t, err)
	require.Equal(t, "live", src)
	require.Len(t, csprecon.GadgetEntries(db), 1)

	_, statErr := os.Stat(cachePath)
	require.NoError(t, statErr)

	// 2. Server down: fall back to the cached copy.
	srv.Close()

	db2, src2, err2 := csprecon.LoadGadgetsForTest(&input.Options{Bypass: true})
	require.NoError(t, err2)
	require.Equal(t, "cache", src2)
	require.Len(t, csprecon.GadgetEntries(db2), 1)

	// 3. Server down and no cache: error.
	require.NoError(t, os.Remove(cachePath))

	_, _, err3 := csprecon.LoadGadgetsForTest(&input.Options{Bypass: true})
	require.Error(t, err3)
}

func TestCheckCSPFullCategorization(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Content-Security-Policy", "script-src https://a.example")
		w.Header().Add("Content-Security-Policy-Report-Only", "script-src https://b.example")
		_, _ = io.WriteString(w,
			`<html><head><meta http-equiv="Content-Security-Policy" content="script-src https://c.example"></head></html>`)
	}))
	defer srv.Close()

	domains, enforced, err := csprecon.CheckCSPFull(srv.URL, "test-agent", srv.Client())
	require.NoError(t, err)

	// Enforced: the CSP header plus the meta tag, not the Report-Only header.
	require.Equal(t, 2, enforced)

	// Discovery output still includes domains from every directive/header.
	require.Contains(t, domains, "a.example")
	require.Contains(t, domains, "b.example")
	require.Contains(t, domains, "c.example")
}

func TestCheckCSPFullMetaInHead(t *testing.T) {
	t.Parallel()

	meta := func(policy string) string {
		return `<meta http-equiv="Content-Security-Policy" content="` + policy + `">`
	}
	four := func(host string) string {
		return "script-src https://" + host + ".example, img-src 'none', style-src 'none', font-src 'none'"
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `<html><head>`+
			meta("script-src https://head.example")+
			`<template>`+meta(four("template"))+`</template>`+
			`</head>`+
			// The parser moves a meta written right after </head> into <head>.
			meta("script-src https://after.example, img-src 'none'")+
			`<body>`+meta(four("body"))+`</body></html>`)
	}))
	defer srv.Close()

	domains, enforced, err := csprecon.CheckCSPFull(srv.URL, "test-agent", srv.Client())
	require.NoError(t, err)

	// Like Chrome: only a meta in <head> is enforced, and its content is split
	// on commas. The tags hold 1, 2, 4 and 4 policies, so any other pick gives
	// another total.
	require.Equal(t, 3, enforced)

	// Every meta still feeds domain discovery.
	for _, d := range []string{"head.example", "after.example", "template.example", "body.example"} {
		require.Contains(t, domains, d)
	}
}
