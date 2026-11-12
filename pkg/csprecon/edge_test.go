/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon_test

import (
	"strings"
	"testing"
	"unicode"

	"github.com/edoardottt/csprecon/pkg/csprecon"
	"github.com/edoardottt/csprecon/pkg/input"

	"github.com/stretchr/testify/require"
)

func TestSplitURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                     string
		raw                      string
		scheme, host, port, path string
		ok                       bool
	}{
		{"simple", "https://a.example/x", "https", "a.example", "", "/x", true},
		{"no path defaults to slash", "http://a.example", "http", "a.example", "", "/", true},
		{"query and fragment stripped", "https://a.example:8443/p?q=1#f", "https", "a.example", "8443", "/p", true},
		{"userinfo stripped", "https://user:pass@a.example/x", "https", "a.example", "", "/x", true},
		{"ipv6 host with port", "https://[2001:db8::1]:8443/x", "https", "[2001:db8::1]", "8443", "/x", true},
		{"scheme and host lowercased path preserved", "HTTPS://A.Example/PaTh", "https", "a.example", "", "/PaTh", true},
		{"non-http scheme", "ftp://host.example/f", "ftp", "host.example", "", "/f", true},
		{"empty port", "https://a.example:/x", "https", "a.example", "", "/x", true},
		{"default port dropped", "https://a.example:443/x", "https", "a.example", "", "/x", true},
		{"port with leading zeros", "https://a.example:08443/x", "https", "a.example", "8443", "/x", true},
		{"non-numeric port", "https://a.example:abc/x", "", "", "", "", false},
		{"port out of range", "https://a.example:65536/x", "", "", "", "", false},
		{"colon in host", "https://a:b:443/x", "", "", "", "", false},
		{"not a url", "not-a-url", "", "", "", "", false},
		{"empty", "", "", "", "", "", false},
		{"scheme relative not absolute", "//a.example/x", "", "", "", "", false},
		{"pseudo scheme without authority", "javascript:alert(1)", "", "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scheme, host, port, path, ok := csprecon.SplitURL(tt.raw)
			require.Equal(t, tt.ok, ok)

			if !tt.ok {
				return
			}

			require.Equal(t, tt.scheme, scheme)
			require.Equal(t, tt.host, host)
			require.Equal(t, tt.port, port)
			require.Equal(t, tt.path, path)
		})
	}
}

func TestCIDR(t *testing.T) {
	t.Parallel()

	t.Run("valid cidr expands", func(t *testing.T) {
		t.Parallel()

		ips, err := csprecon.HandleCIDRInput("192.168.1.0/30")
		require.NoError(t, err)
		require.NotEmpty(t, ips)
		require.Contains(t, ips, "192.168.1.1")
	})

	t.Run("bare ip is not a cidr", func(t *testing.T) {
		t.Parallel()

		_, err := csprecon.HandleCIDRInput("10.0.0.5")
		require.ErrorIs(t, err, input.ErrCidrBadFormat)
	})

	t.Run("garbage is not a cidr", func(t *testing.T) {
		t.Parallel()

		_, err := csprecon.HandleCIDRInput("garbage")
		require.ErrorIs(t, err, input.ErrCidrBadFormat)
	})

	t.Run("isCIDR", func(t *testing.T) {
		t.Parallel()

		require.True(t, csprecon.IsCIDR("192.168.1.0/24"))
		require.False(t, csprecon.IsCIDR("192.168.1.1"))
		require.False(t, csprecon.IsCIDR(""))
	})
}

func TestCompileRegex(t *testing.T) {
	t.Parallel()

	require.NotNil(t, csprecon.CompileRegex(csprecon.DomainRegex))
	require.Panics(t, func() { csprecon.CompileRegex("[") })
}

func TestParseGadgetsEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty input", func(t *testing.T) {
		t.Parallel()

		db := csprecon.ParseGadgets(strings.NewReader(""))
		require.Empty(t, csprecon.GadgetEntries(db))
	})

	t.Run("domain-only line skipped", func(t *testing.T) {
		t.Parallel()

		db := csprecon.ParseGadgets(strings.NewReader("Domain\tCode\njust-a-domain.example\n"))
		require.Empty(t, csprecon.GadgetEntries(db))
	})

	t.Run("header is case-insensitive", func(t *testing.T) {
		t.Parallel()

		db := csprecon.ParseGadgets(strings.NewReader("DOMAIN\tCODE\na.example\t<script src=\"https://a.example/x\"></script>\n"))
		require.Len(t, csprecon.GadgetEntries(db), 1)
	})

	t.Run("file without header keeps first data line", func(t *testing.T) {
		t.Parallel()

		db := csprecon.ParseGadgets(strings.NewReader("a.example\t<script src=\"https://a.example/x\"></script>\n"))
		entries := csprecon.GadgetEntries(db)
		require.Len(t, entries, 1)
		require.Equal(t, "a.example", entries[0].Domain)
	})

	t.Run("whitespace-only lines skipped", func(t *testing.T) {
		t.Parallel()

		db := csprecon.ParseGadgets(strings.NewReader("Domain\tCode\n   \t  \n\t\na.example\t<script src=\"https://a.example/x\"></script>\n"))
		require.Len(t, csprecon.GadgetEntries(db), 1)
	})
}

func TestBypassesMultiPolicyAndDedup(t *testing.T) {
	t.Parallel()

	const page = "https://victim.example"

	data := "Domain\tCode\n" +
		"a.example\t<script src=\"https://a.example/jsonp?cb=alert\"></script>\n" +
		"a.example\t<script src=\"https://a.example/jsonp?cb=alert\"></script>\n" + // exact duplicate
		"b.example\t<script src=\"https://b.example/jsonp?cb=alert\"></script>\n"

	db := csprecon.ParseGadgets(strings.NewReader(data))

	t.Run("duplicate gadget reported once", func(t *testing.T) {
		t.Parallel()

		views := csprecon.BypassFindings(db, page, []string{"script-src https://a.example"})
		require.Len(t, views, 1)
		require.Equal(t, "a.example", views[0].Domain)
	})

	t.Run("must satisfy all enforced policies", func(t *testing.T) {
		t.Parallel()

		// a.example is allowed by the first policy but not the second.
		views := csprecon.BypassFindings(db, page, []string{
			"script-src https://a.example",
			"script-src https://b.example",
		})
		require.Empty(t, views)
	})

	t.Run("gadget allowed by all policies is reported", func(t *testing.T) {
		t.Parallel()

		views := csprecon.BypassFindings(db, page, []string{
			"script-src https://a.example https://b.example",
			"script-src https://a.example",
		})
		require.Len(t, views, 1)
		require.Equal(t, "a.example", views[0].Domain)
	})
}

// Fuzz targets: the parsers must never panic on arbitrary input.

func FuzzSplitURL(f *testing.F) {
	seeds := []string{
		"", "https://a.example/x", "://", "http://", "https://[::1", "%", "a:b:c://///",
		"HTTPS://EXAMPLE.COM:99999999999999999999/path", "\x00\x01",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(_ *testing.T, raw string) {
		_, _, _, _, _ = csprecon.SplitURL(raw)
	})
}

func FuzzExtractGadgetURL(f *testing.F) {
	seeds := []string{
		"", `<script src="https://a.example/x">`, `<script src=//a.example/x>`,
		`<script src="/rel">`, `src='`, `href=`, "\x00",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, code string) {
		if got := csprecon.ExtractGadgetURL(code, "d.example"); got == "" {
			t.Errorf("ExtractGadgetURL returned empty for code %q", code)
		}
	})
}

func FuzzEvalAllows(f *testing.F) {
	seeds := []string{
		"", "script-src 'none'", "default-src *", "script-src https://a.example",
		"script-src 'strict-dynamic'", ";;;", "script-src ,,, https://",
		"script-src *.*.* https://*.:*/", "'", "script-src 'nonce-", "SCRIPT-SRC HTTP://A",
		"script-src-elem https://a.example", "script-src-elem; script-src *",
		"script-src-elem 'none'; script-src https://a.example", "script-src https://a.example/x/",
		"script-src https://a.example/%78", "script-src https://a.example/%zz",
		"script-src https://a.example:443/x", "script-src https://a.example:*", "script-src https://a.example:",
		"script-src https://[::1]:8443/", "default-src https: 'unsafe-eval'",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(_ *testing.T, policy string) {
		_ = csprecon.EvalAllows(policy, "https://a.example/x", "https://p.example")
	})
}

// FuzzSourceMatchesItself checks matcher invariants on arbitrary URLs: a source
// expression built from a URL's own parts must allow that URL, while turning its
// file path into a directory or dropping its non-default port must not.
func FuzzSourceMatchesItself(f *testing.F) {
	seeds := []string{
		"https://a.example/x", "https://a.example/x/y.js?cb=1#f", "http://a.example:8080/",
		"https://a.example:443/x", "https://A.Example/%7Euser/a%20b.js", "https://[::1]:8443/x",
		"https://a.example/%zz", "wss://a.example:9000/s", "custom-s+1.x://h/p", "A://::", "a://a::5/x", "A://0:0:",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	const page = "https://p.example/"

	f.Fuzz(func(t *testing.T, raw string) {
		scheme, host, port, path, ok := csprecon.SplitURL(raw)
		if !ok || host == "" || strings.Contains(host, "*") {
			return
		}

		hostport := host
		if port != "" {
			hostport += ":" + port
		}

		src := scheme + "://" + hostport + path
		// Characters that would split the token or the policy cannot be
		// expressed in a single source expression.
		if strings.ContainsAny(src, ";,") || strings.IndexFunc(src, unicode.IsSpace) != -1 {
			return
		}

		// Only a source Chrome keeps can match: an IPv6 host or the "a:" in
		// "a://a::", for example, is rejected.
		if !csprecon.ParseSourceOK(src) {
			return
		}

		if !csprecon.EvalAllows("script-src "+src, raw, page) {
			t.Fatalf("source %q does not allow its own URL %q", src, raw)
		}

		if !csprecon.EvalAllows("script-src "+scheme+"://"+hostport, raw, page) {
			t.Fatalf("host-only source %q does not allow %q", scheme+"://"+hostport, raw)
		}

		// script-src-elem takes precedence over script-src and default-src.
		if !csprecon.EvalAllows("default-src 'none'; script-src 'none'; script-src-elem "+src, raw, page) {
			t.Fatalf("script-src-elem %q ignored for %q", src, raw)
		}

		if csprecon.EvalAllows("script-src "+src+"; script-src-elem 'none'", raw, page) {
			t.Fatalf("script-src-elem 'none' not enforced for %q", raw)
		}

		if path != "/" && !strings.HasSuffix(path, "/") {
			if dir := src + "/"; csprecon.EvalAllows("script-src "+dir, raw, page) {
				t.Fatalf("directory source %q allows file URL %q", dir, raw)
			}
		}

		if (scheme == "http" || scheme == "https") && port != "" && port != "*" &&
			port != map[string]string{"http": "80", "https": "443"}[scheme] {
			noPort := scheme + "://" + host + path
			if csprecon.EvalAllows("script-src "+noPort, raw, page) {
				t.Fatalf("port-less source %q allows non-default port URL %q", noPort, raw)
			}
		}
	})
}
