/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon

import (
	"cmp"
	"encoding/hex"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// This file implements a focused Content Security Policy matcher. It is used
// only by the bypass feature, to decide whether a known gadget URL would
// actually be allowed to execute as a script by a target's enforced CSP. The
// goal is to reflect what a browser does and so avoid reporting false bypasses.
//
// The matcher follows Chrome: it mirrors the code Chromium uses, so wherever
// browsers and the W3C CSP3 text disagree, Chrome's behaviour wins.
//   - Parsing sources: ParseSource, ParseHost, ParsePort and ParsePath in
//     services/network/public/cpp/content_security_policy/content_security_policy.cc.
//     A token Chrome rejects (an IPv6 host, an empty or non-numeric port,
//     "scheme:/host", ...) is ignored, as Chrome ignores it.
//   - Matching a <script src>: CSPSourceListAllows in
//     third_party/blink/renderer/core/frame/csp/source_list_directive.cc, and
//     CSPSourceMatches and CSPSourceMatchesAsSelf in
//     third_party/blink/renderer/core/frame/csp/csp_source.cc. Script loads
//     are checked there, in the renderer. The network-service copy
//     (services/network/.../csp_source.cc) only checks navigations and
//     differs on 'self'.
//
// Where Chrome differs from the W3C text:
//   - An http->https (or ws->wss) scheme upgrade is accepted only when the
//     port is unspecified or upgrades too. "http://a.com:8080" does not allow
//     "https://a.com:8080"; the W3C text and Firefox allow it.
//   - An explicit port 80 (or, for http, 443) upgrades to 443 only together
//     with a scheme upgrade. "http://a.com:80" allows "https://a.com", which
//     the W3C text does not; "https://a.com:80" does not, which Firefox allows.
//
// Only script execution is modelled. A gadget is loaded with <script src>, so
// the effective directive is script-src-elem, falling back to script-src and
// then default-src (the CSP3 fallback list). Report-Only policies are never
// evaluated here (they are not enforced, so there is nothing to bypass).

var (
	schemeRe    = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.\-]*$`)
	hostLabelRe = regexp.MustCompile(`(?i)^[a-z0-9\-]*$`)
	urlPartsRe  = regexp.MustCompile(`(?i)^([a-z][a-z0-9+.\-]*)://([^/?#]+)(/[^?#]*)?`)
)

const (
	// portNone marks an absent port (Chromium's url::PORT_UNSPECIFIED).
	portNone = -1

	portHTTP  = 80
	portHTTPS = 443
	portFTP   = 21
)

// urlParts holds the pieces of a URL needed for CSP matching.
type urlParts struct {
	scheme string
	host   string // lowercased, no port
	port   int    // portNone when absent or the scheme's default (dropped, as the URL parser does)
	path   string // always starts with "/", defaults to "/"
}

// parseURLParts splits a raw absolute URL into the pieces used for matching.
// It is deliberately lenient (regex based) so it copes with the messy, often
// non-RFC-compliant URLs found in gadget PoCs, where net/url.Parse would error.
// A URL with an invalid port or host is rejected: a browser never loads it.
func parseURLParts(raw string) (urlParts, bool) {
	m := urlPartsRe.FindStringSubmatch(raw)
	if m == nil {
		return urlParts{}, false
	}

	hostport := m[2]

	// Drop any userinfo component.
	if at := strings.LastIndex(hostport, "@"); at != -1 {
		hostport = hostport[at+1:]
	}

	host, port := splitHostPort(hostport)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return urlParts{}, false // "a:b:c": a ":" outside an IPv6 literal
	}

	u := urlParts{
		scheme: strings.ToLower(m[1]),
		host:   strings.ToLower(host),
		port:   portNone,
		path:   cmp.Or(m[3], "/"),
	}

	if port != "" {
		n, ok := parsePort(port)
		if !ok {
			return urlParts{}, false
		}

		if n != defaultPort(u.scheme) {
			u.port = n
		}
	}

	return u, true
}

// splitHostPort separates host and (optional) port, with basic IPv6 support.
func splitHostPort(hostport string) (host, port string) {
	if strings.HasPrefix(hostport, "[") { // IPv6 literal
		if end := strings.Index(hostport, "]"); end != -1 {
			host = hostport[:end+1]
			if len(hostport) > end+1 && hostport[end+1] == ':' {
				port = hostport[end+2:]
			}

			return host, port
		}
	}

	if c := strings.LastIndexByte(hostport, ':'); c != -1 {
		return hostport[:c], hostport[c+1:]
	}

	return hostport, ""
}

// parsePort parses a decimal port number (leading zeros allowed).
func parsePort(s string) (int, bool) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}

	n, err := strconv.Atoi(s)

	return n, err == nil && n <= 65535
}

// defaultPort returns the default port of a scheme, or portNone when it has
// none (Blink's DefaultPortForProtocol).
func defaultPort(scheme string) int {
	switch scheme {
	case "http", "ws":
		return portHTTP
	case "https", "wss":
		return portHTTPS
	case "ftp":
		return portFTP
	default:
		return portNone
	}
}

// isDefaultPort reports whether port is the default port of scheme.
func isDefaultPort(port int, scheme string) bool {
	return port != portNone && port == defaultPort(scheme)
}

// effectivePort returns the URL's port, or the default port of its scheme.
func effectivePort(u urlParts) int {
	if u.port != portNone {
		return u.port
	}

	return defaultPort(u.scheme)
}

// cspSource is a single parsed host-source or scheme-source expression.
type cspSource struct {
	scheme       string // "" when the token had no scheme (the page's scheme is used)
	host         string // lowercased, without a leading "*."; "" for "*" and scheme-sources
	wildcardHost bool   // "*" or "*.example.com"
	port         int    // portNone when absent
	wildcardPort bool   // ":*"
	path         string // percent-decoded; "" when absent
}

// isSchemeOnly reports whether the source is a scheme-source such as "https:".
func (s cspSource) isSchemeOnly() bool {
	return s.host == "" && !s.wildcardHost
}

// cspPolicy is one parsed policy, reduced to the information needed to decide
// whether a script URL is allowed.
type cspPolicy struct {
	directive     string // directive governing <script src>: "script-src-elem", "script-src" or "default-src"; "" when none present
	sources       []cspSource
	allowStar     bool // the bare "*" source
	hasSelf       bool
	strictDynamic bool
	unsafeInline  bool
	unsafeEval    bool
}

// restrictsScripts reports whether this policy actually constrains script
// loading (i.e. a script-src-elem, script-src or default-src directive is
// present).
func (p cspPolicy) restrictsScripts() bool {
	return p.directive != ""
}

// parsePolicies parses one CSP header value, which may contain several policies
// separated by commas (as browsers treat combined header fields), into the list
// of policies it declares.
func parsePolicies(headerValue string) []cspPolicy {
	var policies []cspPolicy

	for part := range strings.SplitSeq(headerValue, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		policies = append(policies, parsePolicy(part))
	}

	return policies
}

// parsePolicy parses a single policy string (no commas) into a cspPolicy.
func parsePolicy(policyStr string) cspPolicy {
	// Build a directive -> tokens map. Per spec, the first occurrence of a
	// directive wins and later duplicates are ignored.
	directives := map[string][]string{}

	for raw := range strings.SplitSeq(policyStr, ";") {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}

		name := strings.ToLower(fields[0])
		if _, seen := directives[name]; !seen {
			directives[name] = fields[1:]
		}
	}

	policy := cspPolicy{}

	// A gadget is loaded with <script src>, which is governed by the first
	// present of script-src-elem, script-src and default-src.
	var tokens []string

	policy.directive, tokens = firstDirective(directives, "script-src-elem", "script-src", "default-src")

	for _, tok := range tokens {
		classifyToken(&policy, tok)
	}

	// eval() is governed by script-src (falling back to default-src), never by
	// script-src-elem, so 'unsafe-eval' is read from there.
	_, evalTokens := firstDirective(directives, "script-src", "default-src")
	policy.unsafeEval = slices.ContainsFunc(evalTokens, func(tok string) bool {
		return strings.EqualFold(tok, "'unsafe-eval'")
	})

	return policy
}

// firstDirective returns the name and source list of the first directive in
// names that the policy declares, or "" and nil when it declares none of them.
// A declared directive with an empty source list still counts (it blocks all).
func firstDirective(directives map[string][]string, names ...string) (string, []string) {
	for _, name := range names {
		if tokens, ok := directives[name]; ok {
			return name, tokens
		}
	}

	return "", nil
}

// classifyToken sorts a single source-list token into a keyword flag or a
// parsed source expression.
func classifyToken(policy *cspPolicy, tok string) {
	switch strings.ToLower(tok) {
	case "'none'":
		// Nothing to record: alone it leaves the list empty, which blocks
		// everything, and next to other sources Chrome ignores it.
	case "'self'":
		policy.hasSelf = true
	case "*":
		policy.allowStar = true
	case "'strict-dynamic'":
		policy.strictDynamic = true
	case "'unsafe-inline'":
		policy.unsafeInline = true
	default:
		// Other keyword-sources ('nonce-...', 'sha256-...', 'report-sample',
		// ...) do not affect whether a host-based script may load, and
		// parseSource rejects them. 'unsafe-eval' is read in parsePolicy.
		if s, ok := parseSource(tok); ok {
			policy.sources = append(policy.sources, s)
		}
	}
}

// parseSource parses a host-source or scheme-source token the way Chromium's
// ParseSource does, and reports false for a token Chrome rejects.
func parseSource(expr string) (cspSource, bool) {
	s := cspSource{port: portNone}

	pos := strings.IndexAny(expr, ":/")
	if pos != -1 && expr[pos] == ':' {
		if pos+1 == len(expr) { // "scheme:"
			return s, parseScheme(expr[:pos], &s)
		}

		if expr[pos+1] == '/' { // "scheme://", anything else is invalid
			if !strings.HasPrefix(expr[pos:], "://") || !parseScheme(expr[:pos], &s) {
				return s, false
			}

			expr = expr[pos+3:]
			pos = strings.IndexAny(expr, ":/")
		}
	}

	host, rest := expr, ""
	if pos != -1 {
		host, rest = expr[:pos], expr[pos:]
	}

	if !parseHost(host, &s) {
		return s, false
	}

	if port, ok := strings.CutPrefix(rest, ":"); ok {
		rest = ""
		if i := strings.IndexByte(port, '/'); i != -1 {
			port, rest = port[:i], port[i:]
		}

		if port == "*" {
			s.wildcardPort = true
		} else if s.port, ok = parsePort(port); !ok {
			return s, false
		}
	}

	// rest is now empty or a path. Chrome ignores a query or fragment in it.
	if i := strings.IndexAny(rest, "?#"); i != -1 {
		rest = rest[:i]
	}

	s.path = percentDecode(rest)

	return s, true
}

// parseScheme validates and stores a source's scheme (Chromium's ParseScheme).
func parseScheme(scheme string, s *cspSource) bool {
	s.scheme = strings.ToLower(scheme)

	return schemeRe.MatchString(scheme)
}

// parseHost validates and stores a source's host (Chromium's ParseHost):
// "*", or an optional "*." followed by dot-separated labels of letters,
// digits and "-", where only a trailing dot may leave a label empty.
func parseHost(host string, s *cspSource) bool {
	if host == "*" {
		s.wildcardHost = true

		return true
	}

	if rest, ok := strings.CutPrefix(host, "*."); ok {
		s.wildcardHost = true
		host = rest
	}

	if host == "" {
		return false
	}

	labels := strings.Split(host, ".")
	for i, label := range labels {
		if (label == "" && i+1 < len(labels)) || !hostLabelRe.MatchString(label) {
			return false
		}
	}

	s.host = strings.ToLower(host)

	return true
}

// percentDecode decodes %XX escapes and leaves malformed ones as they are, like
// Chromium's DecodeUrlEscapeSequences.
func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}

	var b strings.Builder

	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				b.Write(v)

				i += 2

				continue
			}
		}

		b.WriteByte(s[i])
	}

	return b.String()
}

// matchResult is how a scheme or a port matched (Blink's SchemeMatchingResult
// and PortMatchingResult). Only ports produce matchWildcard.
type matchResult int

const (
	noMatch matchResult = iota
	matchWildcard
	matchUpgrade
	matchExact
)

// canUpgrade reports whether a scheme or port result allows an upgrade.
func canUpgrade(r matchResult) bool {
	return r == matchUpgrade || r == matchWildcard
}

// matchScheme compares the URL scheme with a source's scheme, or with the
// page's scheme when the source has none (Blink's SchemeMatches).
func matchScheme(srcScheme, selfScheme, urlScheme string) matchResult {
	scheme := cmp.Or(srcScheme, selfScheme)

	switch {
	case scheme == urlScheme:
		return matchExact
	case scheme == "http" && urlScheme == "https", scheme == "ws" && urlScheme == "wss":
		return matchUpgrade
	default:
		return noMatch
	}
}

// matchPort compares the URL port with the source's port (Blink's
// PortMatches). A missing source port means the default port, and an explicit
// 80, or 443 on an http source, can upgrade to 443.
func (s cspSource) matchPort(selfScheme string, g urlParts) matchResult {
	switch {
	case s.wildcardPort:
		return matchWildcard
	case g.port == portNone && s.port == portNone:
		return matchWildcard
	case g.port == s.port:
		return matchExact
	}

	isHTTP := cmp.Or(s.scheme, selfScheme) == "http"
	if (s.port == portHTTP || (isHTTP && (s.port == portNone || s.port == portHTTPS))) &&
		(g.port == portHTTPS || (g.port == portNone && defaultPort(g.scheme) == portHTTPS)) {
		return matchUpgrade
	}

	if (g.port == portNone && isDefaultPort(s.port, g.scheme)) ||
		(s.port == portNone && isDefaultPort(g.port, g.scheme)) {
		return matchExact
	}

	return noMatch
}

// matchHost compares the URL host with the source's host (Blink's
// HostMatches). "*.a.com" matches subdomains of a.com but not a.com itself.
func (s cspSource) matchHost(g urlParts) bool {
	if s.wildcardHost {
		return s.host == "" || strings.HasSuffix(g.host, "."+s.host)
	}

	return g.host == s.host
}

// matchPath compares the URL path with the source's path (Blink's
// PathMatches), after percent-decoding. A source path ending in "/" is a
// directory that allows every path under it, while any other source path names
// a single file and must match exactly: "/a/" allows "/a/b", "/a" only "/a".
func (s cspSource) matchPath(urlPath string) bool {
	if s.path == "" {
		return true
	}

	path := percentDecode(urlPath)

	if strings.HasSuffix(s.path, "/") {
		return strings.HasPrefix(path, s.path)
	}

	return path == s.path
}

// matches reports whether the gadget URL g is allowed by this source on a page
// whose scheme is selfScheme (Blink's CSPSourceMatches).
func (s cspSource) matches(g urlParts, selfScheme string) bool {
	scheme := matchScheme(s.scheme, selfScheme, g.scheme)
	if scheme == noMatch {
		return false
	}

	if s.isSchemeOnly() {
		return true
	}

	port := s.matchPort(selfScheme, g)

	// An upgrade (http->https, ws->wss, port 80->443) only counts when both
	// the scheme and the port can upgrade, so neither upgrades alone.
	if (scheme == matchUpgrade || port == matchUpgrade) && (!canUpgrade(scheme) || !canUpgrade(port)) {
		return false
	}

	return port != noMatch && s.matchHost(g) && s.matchPath(g.path)
}

// matchesSelf reports whether the gadget URL g is allowed by 'self' on page
// (Blink's CSPSourceMatchesAsSelf, the CSP3 'self' rules). The page's own
// origin matches, and so does the same host over https or wss (or http or ws
// from an http page) when both ports are the same or both are default.
func matchesSelf(g, page urlParts) bool {
	if page.host == "" {
		return false
	}

	self := cspSource{scheme: page.scheme, host: page.host, port: effectivePort(page)}
	if !self.matchHost(g) {
		return false
	}

	scheme := matchScheme(self.scheme, self.scheme, g.scheme)
	port := self.matchPort(self.scheme, g)

	if scheme == matchExact && (port == matchExact || port == matchWildcard) {
		return true
	}

	// g.port is portNone exactly when the URL has no port or its default one.
	portsMatch := port == matchExact ||
		((self.port == portNone || isDefaultPort(self.port, self.scheme)) && g.port == portNone)

	return portsMatch && (g.scheme == "https" || g.scheme == "wss" || self.scheme == "http")
}

// allows reports whether the gadget URL g would be permitted to load as a
// script under this policy (Blink's CSPSourceListAllows and CheckSource).
func (p cspPolicy) allows(g, page urlParts) bool {
	if !p.restrictsScripts() {
		// No script-src and no default-src: scripts are unrestricted.
		return true
	}

	// With 'strict-dynamic', host-source and scheme-source expressions are
	// ignored for parser-inserted scripts, so an allowlisted gadget cannot load.
	if p.strictDynamic {
		return false
	}

	// "*" allows any http(s) URL and any URL on the page's own scheme.
	if p.allowStar && (g.scheme == "http" || g.scheme == "https" || g.scheme == page.scheme) {
		return true
	}

	if p.hasSelf && matchesSelf(g, page) {
		return true
	}

	return slices.ContainsFunc(p.sources, func(s cspSource) bool {
		return s.matches(g, page.scheme)
	})
}

// allowedByAllEnforced reports whether the gadget URL is allowed by every
// enforced policy. A script must satisfy all policies simultaneously, so a
// gadget is only a real bypass when it passes all of them.
func allowedByAllEnforced(g, page urlParts, enforced []cspPolicy) bool {
	for _, p := range enforced {
		if !p.allows(g, page) {
			return false
		}
	}

	return true
}
