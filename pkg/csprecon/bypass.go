/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/edoardottt/csprecon/pkg/input"
	"github.com/edoardottt/csprecon/pkg/output"
)

// errBypassStatus is returned when the dataset endpoint answers with a non-200 status.
var errBypassStatus = errors.New("unexpected status fetching bypass data")

// The gadget dataset is sourced from the CSPBypass project
// (https://github.com/renniepak/CSPBypass, GPL-3.0). csprecon does not bundle
// or redistribute it: when -b/--bypass is used it is fetched at runtime from the
// upstream repository and cached locally for the user, or supplied directly by
// the user via -bf/--bypass-file.

const (
	// bypassFetchTimeout bounds the one-time dataset download.
	bypassFetchTimeout = 15 * time.Second
	// maxBypassDataSize caps how much of the dataset we read (safety net).
	maxBypassDataSize = 8 * 1024 * 1024
	// bypassUserAgent is a generic, identity-free User-Agent for the fetch.
	bypassUserAgent = "csprecon/" + output.Version
	// bypassLabel is the label of bypass findings, highlighted on a terminal.
	bypassLabel = "BYPASS"
	// BypassPrefix marks bypass findings in plain/silent output so they can be
	// filtered apart from discovered domains.
	BypassPrefix = "[" + bypassLabel + "]"
	// cacheDirPerm is the permission for the cache directory.
	cacheDirPerm = 0o755
	// scannerInitBufSize and scannerMaxBufSize size the line scanner; gadget
	// PoCs can be long, so the limit is well above the default 64KB.
	scannerInitBufSize = 64 * 1024
	scannerMaxBufSize  = 1024 * 1024
)

// Seams overridable in tests.
//
//nolint:gochecknoglobals // package-level seams, set once / in tests.
var (
	bypassDataURL = "https://raw.githubusercontent.com/renniepak/CSPBypass/main/data.tsv"
	cachePathFunc = defaultCachePath
)

var (
	srcAttrRe   = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']?([^"'` + "`" + ` >]+)`)
	hasSchemeRe = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.\-]*://`)
)

// gadget is a single known CSP bypass gadget.
type gadget struct {
	domain  string   // host the gadget lives on (lowercased)
	code    string   // PoC HTML snippet
	url     string   // extracted, normalized gadget URL
	parts   urlParts // parsed url (for matching)
	partsOK bool
}

// gadgetDB indexes the loaded gadgets.
type gadgetDB struct {
	all []gadget
}

func (db *gadgetDB) count() int {
	if db == nil {
		return 0
	}

	return len(db.all)
}

// bypassFinding is one matched gadget tied to the input URL whose CSP it bypasses.
type bypassFinding struct {
	url       string // input/target URL
	domain    string // gadget domain
	directive string // directives that would have restricted the script, comma-separated
	code      string // PoC
	flags     []string
}

// loadGadgets loads the gadget dataset according to the options.
//
// Behaviour:
//   - BypassFile set: read that file (bring-your-own data.tsv), no network.
//   - otherwise: fetch live from upstream, caching the result; on failure fall
//     back to the previously cached copy.
//
// It returns the database and a short description of where the data came from
// ("file", "live" or "cache").
func loadGadgets(o *input.Options) (*gadgetDB, string, error) {
	if o.BypassFile != "" {
		f, err := os.Open(o.BypassFile)
		if err != nil {
			return nil, "", err
		}
		defer f.Close()

		// Opening a directory succeeds but reading it fails, which would
		// silently yield an empty dataset.
		info, err := f.Stat()
		if err != nil {
			return nil, "", err
		}

		if info.IsDir() {
			return nil, "", fmt.Errorf("%w: %s", input.ErrIsDirectory, o.BypassFile)
		}

		return parseGadgets(f), "file", nil
	}

	data, ferr := fetchBypassData(bypassDataURL, o)
	if ferr == nil {
		// Best effort: a failed cache write must not break the feature.
		_ = writeCache(data)

		return parseGadgets(bytes.NewReader(data)), "live", nil
	}

	if cached, cerr := readCache(); cerr == nil {
		return parseGadgets(bytes.NewReader(cached)), "cache", nil
	}

	return nil, "", fmt.Errorf("could not load bypass data: %w", ferr)
}

// fetchBypassData downloads the dataset over a client that verifies TLS (unlike
// the recon client used for targets), honouring the configured proxy and using
// a generic User-Agent.
func fetchBypassData(dataURL string, o *input.Options) ([]byte, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		// Default TLS config: certificates are verified, so a MITM cannot
		// inject gadgets into the results.
	}

	if o.Proxy != "" {
		if u, err := url.Parse(o.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}

	client := &http.Client{
		Timeout:   bypassFetchTimeout,
		Transport: transport,
	}

	req, err := http.NewRequest(http.MethodGet, dataURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", bypassUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d (%s)", errBypassStatus, resp.StatusCode, dataURL)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxBypassDataSize))
}

// defaultCachePath returns the per-user cache location, working across
// Windows, macOS and Linux via os.UserCacheDir.
func defaultCachePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "csprecon", "cspbypass.tsv"), nil
}

func readCache() ([]byte, error) {
	path, err := cachePathFunc()
	if err != nil {
		return nil, err
	}

	return os.ReadFile(path)
}

// writeCache atomically writes the dataset to the cache (temp file + rename), so
// concurrent runs cannot observe a half-written file.
func writeCache(data []byte) error {
	path, err := cachePathFunc()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, cacheDirPerm); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "cspbypass-*.tmp")
	if err != nil {
		return err
	}

	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)

		return err
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)

		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)

		return err
	}

	return nil
}

// parseGadgets parses a data.tsv stream into a gadgetDB. The format is
// "domain <whitespace> code" per line. Parsing is defensive: it tolerates both
// tab- and space-separated rows, CRLF line endings, a header row and blank
// lines, so it works with upstream data and user-supplied files alike.
func parseGadgets(r io.Reader) *gadgetDB {
	db := &gadgetDB{}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, scannerInitBufSize), scannerMaxBufSize)

	first := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		domain, code, ok := splitGadgetLine(line)
		if !ok {
			continue
		}

		if first {
			first = false
			// Skip the "Domain\tCode" header if present.
			if strings.EqualFold(domain, "domain") && strings.EqualFold(code, "code") {
				continue
			}
		}

		domain = strings.ToLower(domain)
		g := gadget{domain: domain, code: code, url: extractGadgetURL(code, domain)}
		g.parts, g.partsOK = parseURLParts(g.url)
		// A browser runs a <script src> only when it is fetched over http(s),
		// so a gadget on any other scheme can never be a bypass.
		g.partsOK = g.partsOK && (g.parts.scheme == "http" || g.parts.scheme == "https")
		db.all = append(db.all, g)
	}

	return db
}

// splitGadgetLine splits a line on its first run of whitespace into domain and code.
func splitGadgetLine(line string) (domain, code string, ok bool) {
	idx := strings.IndexFunc(line, unicode.IsSpace)
	if idx == -1 {
		return "", "", false
	}

	domain = line[:idx]
	code = strings.TrimSpace(line[idx:])

	if domain == "" || code == "" {
		return "", "", false
	}

	return domain, code, true
}

// extractGadgetURL pulls the gadget's script URL out of its PoC snippet,
// mirroring CSPBypass PR #53: collect every src/href, pick the first absolute
// or scheme-relative one, normalize "//host" to "https://host", skip leading
// relative values, and fall back to "https://<domain>" when none is usable.
func extractGadgetURL(code, domain string) string {
	for _, m := range srcAttrRe.FindAllStringSubmatch(code, -1) {
		candidate := m[1]

		if hasSchemeRe.MatchString(candidate) {
			return candidate
		}

		if strings.HasPrefix(candidate, "//") {
			return "https:" + candidate
		}
		// Relative value: skip, it must not mask the real URL that follows.
	}

	return "https://" + domain
}

// bypasses returns the gadgets whose URL is allowed by every enforced policy of
// the target identified by pageRaw. A finding is only produced when at least one
// enforced policy actually restricts scripts (otherwise there is nothing to
// bypass). A finding names the directive of every policy that restricts
// scripts, since the gadget gets past each of them.
func (db *gadgetDB) bypasses(targetURL, pageURL string, enforced []cspPolicy) []bypassFinding {
	if db == nil || len(enforced) == 0 {
		return nil
	}

	// Identify the restrictive directives and any relevant flags once.
	var (
		directives []string
		flagSet    = map[string]bool{}
	)

	for _, p := range enforced {
		if !p.restrictsScripts() {
			continue
		}

		if !slices.Contains(directives, p.directive) {
			directives = append(directives, p.directive)
		}

		if p.unsafeInline {
			flagSet["unsafe-inline"] = true
		}

		if p.unsafeEval {
			flagSet["unsafe-eval"] = true
		}
	}

	if len(directives) == 0 {
		return nil
	}

	page, _ := parseURLParts(pageURL)
	flags := sortedKeys(flagSet)
	directive := strings.Join(directives, ",")

	var findings []bypassFinding

	seen := map[string]struct{}{}

	for i := range db.all {
		g := &db.all[i]
		if !g.partsOK {
			continue
		}

		if !allowedByAllEnforced(g.parts, page, enforced) {
			continue
		}

		key := g.domain + "\x00" + g.code
		if _, dup := seen[key]; dup {
			continue
		}

		seen[key] = struct{}{}

		findings = append(findings, bypassFinding{
			url:       targetURL,
			domain:    g.domain,
			directive: directive,
			code:      g.code,
			flags:     flags,
		})
	}

	return findings
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

// formatBypassLine renders a finding as a single, prefixed, space-separated line
// for plain/silent output.
func formatBypassLine(f bypassFinding) string {
	return strings.Join([]string{BypassPrefix, f.url, f.domain, f.directive, f.code}, " ")
}

// toBypassResults converts findings into the JSON output shape.
func toBypassResults(findings []bypassFinding) []output.BypassResult {
	if len(findings) == 0 {
		return nil
	}

	results := make([]output.BypassResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, output.BypassResult{
			Domain:    f.domain,
			Directive: f.directive,
			Code:      f.code,
			Flags:     f.flags,
		})
	}

	return results
}
