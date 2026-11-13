/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/PuerkitoBio/goquery"
	"github.com/edoardottt/csprecon/pkg/input"
	"github.com/edoardottt/golazy"
	"github.com/projectdiscovery/gologger"
)

const (
	TLSHandshakeTimeout = 10
	KeepAlive           = 30
	DomainRegex         = `(?i)(?:[_a-z0-9\*](?:[_a-z0-9-\*]{0,61}[a-z0-9])?\.)+(?:[a-z](?:[a-z0-9-]{0,61}[a-z0-9]))+`
	MinURLLength        = 4
	MaxKBBodyReader     = 500 * 1024 // Limit reading to the first 500KB of the HTML body
	MaxIdleConns        = 100
	MaxIdleConnsPerHost = 10
	IdleConnTimeout     = 90
)

// cspData holds everything parsed from a response's CSP: the domains (as used by
// the normal discovery output) plus, when the bypass feature is enabled, the
// enforced policies.
type cspData struct {
	Domains  []string
	Enforced []cspPolicy
	// FinalURL is the URL of the page the CSP was read from, set only when the
	// request was redirected there.
	FinalURL string
}

// cspHeader pairs a CSP header name with whether it is report-only (not enforced).
type cspHeader struct {
	name       string
	reportOnly bool
}

//nolint:gochecknoglobals // read-only header table.
var cspHeaders = []cspHeader{
	{"Content-Security-Policy", false},
	{"Content-Security-Policy-Report-Only", true},
	{"X-Content-Security-Policy", false},
	{"X-WebKit-CSP", false},
}

// checkCSPFull fetches the URL once and extracts both the discovered domains and,
// when bypass is true, the structured CSP policies needed for bypass detection.
func checkCSPFull(rawurl, ua string, rCSP *regexp.Regexp, client *http.Client, bypass bool) (cspData, error) {
	data := cspData{Domains: []string{}}

	gologger.Debug().Msgf("Checking CSP for %s", rawurl)

	req, err := http.NewRequest(http.MethodGet, rawurl, nil)
	if err != nil {
		return data, err
	}

	req.Header.Add("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return data, err
	}

	defer resp.Body.Close()

	// The client follows redirects, so the CSP belongs to the last page.
	if final := resp.Request.URL.String(); final != req.URL.String() {
		data.FinalURL = final
	}

	// A response may carry the same CSP header more than once. Header.Get only
	// returns the first value, so iterate over every value to avoid missing
	// domains (or policies) declared in the later headers.
	for _, h := range cspHeaders {
		for _, val := range resp.Header.Values(h.name) {
			if val == "" {
				continue
			}

			data.Domains = append(data.Domains, ParseCSP(val, rCSP)...)

			// A Report-Only policy blocks nothing, so there is nothing to bypass.
			if bypass && !h.reportOnly {
				data.Enforced = append(data.Enforced, parsePolicies(val)...)
			}
		}
	}

	bodyDomains, metaPolicies := parseBodyCSPRaw(resp.Body, rCSP)
	data.Domains = append(data.Domains, bodyDomains...)
	// Sites often send the same policy in several headers and a meta tag.
	data.Domains = golazy.RemoveDuplicateValues(data.Domains)

	if bypass {
		// A CSP delivered via a <meta> tag is always enforced (report-only is
		// not valid in meta and is ignored by browsers). Chrome splits it on
		// commas, like a header.
		for _, mp := range metaPolicies {
			data.Enforced = append(data.Enforced, parsePolicies(mp)...)
		}
	}

	return data, nil
}

// ParseCSP returns the domains named in a raw CSP: the host of each source and
// report URL, lowercased. Paths are skipped, so a file name such as app.min.js
// is not mistaken for a domain. A host is kept only when r matches all of it.
func ParseCSP(input string, r *regexp.Regexp) []string {
	result := []string{}

	tokens := strings.FieldsFunc(input, func(c rune) bool {
		return c == ';' || c == ',' || unicode.IsSpace(c)
	})

	for _, token := range tokens {
		if host := tokenHost(token); host != "" && r.FindString(host) == host {
			result = append(result, host)
		}
	}

	return golazy.RemoveDuplicateValues(result)
}

// tokenHost returns the host of one CSP token, or "" when it has none: a
// keyword, nonce or hash ('self'), a scheme ("https:", "com.example.app:") or
// a path ("/csp/report.php").
func tokenHost(token string) string {
	if strings.HasPrefix(token, "'") {
		return ""
	}

	// "https://host" and "//host" (a report URL relative to the page's scheme).
	if scheme, rest, ok := strings.Cut(token, "//"); ok && (scheme == "" || strings.HasSuffix(scheme, ":")) {
		token = rest
	}

	if i := strings.IndexAny(token, "/?#"); i != -1 {
		token = token[:i]
	}

	// A port is a number or "*". Anything else after the colon means the token
	// is a scheme, e.g. "x-apple.systempreferences:" or "data:".
	host, port, hasPort := strings.Cut(token, ":")
	if hasPort && port != "*" && (port == "" || strings.Trim(port, "0123456789") != "") {
		return ""
	}

	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// parseBodyCSPRaw returns the domains found in the CSP meta tags of the input
// HTML body, and the raw CSP strings of the ones a browser enforces.
func parseBodyCSPRaw(body io.Reader, rCSP *regexp.Regexp) (domains, rawPolicies []string) {
	domains = []string{}

	limitedReader := io.LimitReader(body, MaxKBBodyReader)

	doc, err := goquery.NewDocumentFromReader(limitedReader)
	if err != nil {
		// HARD FIX
		// https://github.com/edoardottt/csprecon/issues/482
		// with a simple print instead of fatal/panic
		// we get a SIGSEGV in doc.Find
		return []string{}, nil
	}

	// Add the 'i' modifier to make http-equiv case-insensitive
	doc.Find("meta[http-equiv='Content-Security-Policy' i]").Each(func(_ int, s *goquery.Selection) {
		contentCSP := s.AttrOr("content", "")
		if contentCSP == "" {
			return
		}

		domains = append(domains, ParseCSP(contentCSP, rCSP)...)

		// Chrome enforces a meta CSP only as a child of <head>: one in <body>
		// or inside a <template> is ignored. Its domains are still reported.
		if s.Parent().Is("head") {
			rawPolicies = append(rawPolicies, contentCSP)
		}
	})

	return domains, rawPolicies
}

func customClient(options *input.Options) (*http.Client, error) {
	transport := http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(options.Timeout) * time.Second,
			KeepAlive: KeepAlive * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: TLSHandshakeTimeout * time.Second,
		MaxIdleConns:        MaxIdleConns,
		MaxIdleConnsPerHost: MaxIdleConnsPerHost,
		IdleConnTimeout:     IdleConnTimeout * time.Second,
	}

	if options.Proxy != "" {
		u, err := url.Parse(options.Proxy)
		if err != nil {
			return nil, err
		}

		transport.Proxy = http.ProxyURL(u)

		gologger.Debug().Msgf("Using Proxy %s", options.Proxy)
	}

	client := http.Client{
		Transport: &transport,
		Timeout:   time.Duration(options.Timeout) * time.Second,
	}

	return &client, nil
}
