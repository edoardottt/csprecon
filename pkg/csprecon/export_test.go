/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon

import (
	"io"
	"net/http"
	"strconv"

	"github.com/edoardottt/csprecon/pkg/input"
	"github.com/edoardottt/csprecon/pkg/output"
)

// This file exposes unexported internals to the external test package. It is
// named export_test.go so it is compiled only for tests and skipped by the
// testpackage linter.

// GadgetDB is the test alias for the gadget database.
type GadgetDB = gadgetDB

// GadgetView is a read-only view of a parsed gadget for assertions.
type GadgetView struct {
	Domain string
	URL    string
	Code   string
}

// BypassView is a read-only view of a bypass finding for assertions.
type BypassView struct {
	URL       string
	Domain    string
	Directive string
	Code      string
	Flags     []string
}

// ParseGadgets parses a data.tsv stream (test wrapper).
func ParseGadgets(r io.Reader) *GadgetDB { return parseGadgets(r) }

// ExtractGadgetURL extracts a gadget URL from its PoC (test wrapper).
func ExtractGadgetURL(code, domain string) string { return extractGadgetURL(code, domain) }

// GadgetEntries returns the parsed gadgets as views.
func GadgetEntries(db *GadgetDB) []GadgetView {
	views := make([]GadgetView, 0, len(db.all))
	for _, g := range db.all {
		views = append(views, GadgetView{Domain: g.domain, URL: g.url, Code: g.code})
	}

	return views
}

// LoadGadgetsForTest exercises the full load path (test wrapper).
func LoadGadgetsForTest(o *input.Options) (*GadgetDB, string, error) { return loadGadgets(o) }

// EvalAllows reports whether the gadget URL is allowed by policyStr (treated as
// a single enforced CSP header value) for a page at pageURL.
func EvalAllows(policyStr, gadgetURL, pageURL string) bool {
	return EvalAllowsMulti([]string{policyStr}, gadgetURL, pageURL)
}

// EvalAllowsMulti treats each entry of policyStrs as a separate enforced policy,
// all of which must allow the gadget URL.
func EvalAllowsMulti(policyStrs []string, gadgetURL, pageURL string) bool {
	enforced := make([]cspPolicy, 0, len(policyStrs))

	for _, s := range policyStrs {
		enforced = append(enforced, parsePolicies(s)...)
	}

	// Like the real evaluation, a gadget URL that does not parse never loads.
	g, ok := parseURLParts(gadgetURL)
	if !ok {
		return false
	}

	p, _ := parseURLParts(pageURL)

	return allowedByAllEnforced(g, p, enforced)
}

// BypassFindings runs the full bypass evaluation for a page against the given
// enforced policy strings and returns the findings as views.
func BypassFindings(db *GadgetDB, pageRaw string, policyStrs []string) []BypassView {
	return BypassFindingsRedirected(db, pageRaw, pageRaw, policyStrs)
}

// BypassFindingsRedirected is BypassFindings for a target that redirected to
// finalURL, the page the policies were read from.
func BypassFindingsRedirected(db *GadgetDB, targetURL, finalURL string, policyStrs []string) []BypassView {
	enforced := make([]cspPolicy, 0, len(policyStrs))

	for _, s := range policyStrs {
		enforced = append(enforced, parsePolicies(s)...)
	}

	findings := db.bypasses(targetURL, finalURL, enforced)

	views := make([]BypassView, 0, len(findings))
	for _, f := range findings {
		views = append(views, BypassView{
			URL:       f.url,
			Domain:    f.domain,
			Directive: f.directive,
			Code:      f.code,
			Flags:     f.flags,
		})
	}

	return views
}

// PlainLine renders a finding as its plain-output line (test wrapper).
func PlainLine(v BypassView) string {
	return formatBypassLine(bypassFinding{
		url:       v.URL,
		domain:    v.Domain,
		directive: v.Directive,
		code:      v.Code,
		flags:     v.Flags,
	})
}

// JSONResults converts findings to the JSON output shape (test wrapper).
func JSONResults(vs []BypassView) []output.BypassResult {
	findings := make([]bypassFinding, 0, len(vs))
	for _, v := range vs {
		findings = append(findings, bypassFinding{
			url:       v.URL,
			domain:    v.Domain,
			directive: v.Directive,
			code:      v.Code,
			flags:     v.Flags,
		})
	}

	return toBypassResults(findings)
}

// CheckCSPFull exposes the structured CSP parse for integration tests. It
// returns the discovered domains and the number of enforced policies found.
func CheckCSPFull(rawurl, ua string, client *http.Client) (domains []string, enforced int, err error) {
	data, err := checkCSPFull(rawurl, ua, CompileRegex(DomainRegex), client, true)
	return data.Domains, len(data.Enforced), err
}

// ParseBodyCSP returns the domains found in the CSP meta tags of an HTML body
// (test wrapper).
func ParseBodyCSP(body io.Reader) []string {
	domains, _ := parseBodyCSPRaw(body, CompileRegex(DomainRegex))
	return domains
}

// Seams for the fetch/cache path.

// BypassDataURL returns the current dataset URL seam.
func BypassDataURL() string { return bypassDataURL }

// SetBypassDataURL overrides the dataset URL seam.
func SetBypassDataURL(u string) { bypassDataURL = u }

// CachePathFunc returns the current cache-path seam.
func CachePathFunc() func() (string, error) { return cachePathFunc }

// SetCachePathFunc overrides the cache-path seam.
func SetCachePathFunc(f func() (string, error)) { cachePathFunc = f }

// SplitURL exposes parseURLParts for testing. The port is "" when absent or
// the scheme's default.
func SplitURL(raw string) (scheme, host, port, path string, ok bool) {
	p, ok := parseURLParts(raw)
	if p.port != portNone {
		port = strconv.Itoa(p.port)
	}

	return p.scheme, p.host, port, p.path, ok
}

// ParseSourceOK reports whether a source expression is valid, i.e. kept by
// Chrome's parser rather than ignored.
func ParseSourceOK(token string) bool {
	_, ok := parseSource(token)
	return ok
}

// HandleCIDRInput exposes handleCIDRInput for testing, collecting its stream.
func HandleCIDRInput(cidr string) ([]string, error) {
	stream, err := handleCIDRInput(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := range stream {
		ips = append(ips, ip)
	}

	return ips, nil
}

// IsCIDR exposes isCIDR for testing.
func IsCIDR(cidr string) bool { return isCIDR(cidr) }
