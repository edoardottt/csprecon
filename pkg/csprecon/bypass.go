/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CSPBypassDataURL is the dataset of known CSP bypass gadgets maintained by
// renniepak/CSPBypass (the data behind https://cspbypass.com/). Each row maps a
// whitelisted domain to a payload that achieves script execution through it.
const CSPBypassDataURL = "https://raw.githubusercontent.com/renniepak/CSPBypass/main/data.tsv"

const (
	// MaxBypassBodyReader limits how much of the dataset is read into memory.
	MaxBypassBodyReader = 10 * 1024 * 1024
	// bypassInitBufSize and bypassMaxBufSize size the line scanner, since a
	// single gadget can be longer than the default scanner limit.
	bypassInitBufSize = 64 * 1024
	bypassMaxBufSize  = 1024 * 1024
	// bypassTSVFields is the number of tab separated fields per row.
	bypassTSVFields = 2
)

// ErrBypassFetch is returned when the bypass dataset cannot be downloaded.
var ErrBypassFetch = errors.New("could not fetch CSP bypass data")

// ParseBypassData reads the CSPBypass TSV dataset and returns a map from domain
// to its known bypass gadget. The first line is the "Domain\tCode" header and is
// skipped.
func ParseBypassData(r io.Reader) map[string]string {
	gadgets := map[string]string{}

	scanner := bufio.NewScanner(io.LimitReader(r, MaxBypassBodyReader))
	// Gadgets can be long, so allow a generous line size.
	scanner.Buffer(make([]byte, 0, bypassInitBufSize), bypassMaxBufSize)

	for scanner.Scan() {
		line := scanner.Text()

		parts := strings.SplitN(line, "\t", bypassTSVFields)
		if len(parts) != bypassTSVFields {
			continue
		}

		domain := strings.TrimSpace(parts[0])
		code := strings.TrimSpace(parts[1])

		if domain == "" || domain == "Domain" {
			continue
		}

		gadgets[domain] = code
	}

	return gadgets
}

// FetchBypassData downloads and parses the CSPBypass dataset.
func FetchBypassData(client *http.Client, ua string) (map[string]string, error) {
	req, err := http.NewRequest(http.MethodGet, CSPBypassDataURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status %d", ErrBypassFetch, resp.StatusCode)
	}

	return ParseBypassData(resp.Body), nil
}

// LookupBypass returns the known bypass gadget for a domain found in a CSP, if
// any. CSP entries are matched directly, and wildcard entries such as
// *.example.com match any gadget host that falls under them.
func LookupBypass(domain string, gadgets map[string]string) (string, bool) {
	if len(gadgets) == 0 || domain == "" {
		return "", false
	}

	if code, ok := gadgets[domain]; ok {
		return code, true
	}

	if strings.HasPrefix(domain, "*.") {
		suffix := domain[1:] // ".example.com"
		base := domain[2:]   // "example.com"

		for host, code := range gadgets {
			if host == base || strings.HasSuffix(host, suffix) {
				return code, true
			}
		}
	}

	return "", false
}
