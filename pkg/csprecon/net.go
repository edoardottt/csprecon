/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/edoardottt/csprecon/pkg/input"
	"github.com/projectdiscovery/mapcidr"
)

// CompileRegex compiles regex, and panics if it is not a valid regular
// expression.
func CompileRegex(regex string) *regexp.Regexp {
	return regexp.MustCompile(regex)
}

// DomainOk checks domains filtering based on input.
func DomainOk(input string, domains []string) bool {
	if len(input) == 0 || len(domains) == 0 {
		return false
	}

	// Domain names are case-insensitive.
	input = strings.ToLower(input)

	for _, domain := range domains {
		domain = strings.ToLower(domain)

		if input == domain {
			return true
		}

		if len(input)-len(domain) >= 2 && input[len(input)-len(domain)-1:] == "."+domain {
			return true
		}
	}

	return false
}

// PrepareURL returns the URL to request for an input value: the value without
// surrounding whitespace, with "http://" added when it has no scheme. The rest
// is kept as given (query, encoded characters such as %2F), except for the
// fragment, which is never sent to the server.
func PrepareURL(inputURL string) (string, error) {
	inputURL = strings.TrimSpace(inputURL)

	if len(inputURL) < MinURLLength {
		return "", input.ErrMalformedURL
	}

	if !strings.Contains(inputURL, "://") {
		inputURL = "http://" + inputURL
	}

	u, err := url.Parse(inputURL)
	if err != nil {
		return "", err
	}

	u.Fragment = ""
	// Go sends the query as it is, and a space would split the request line:
	// servers answer 400. Browsers send it as %20.
	u.RawQuery = strings.ReplaceAll(u.RawQuery, " ", "%20")

	return u.String(), nil
}

// handleCIDRInput returns the addresses of a CIDR range as a stream. They are
// generated one at a time as the stream is read, never all held in memory, so
// even a huge range can be scanned. The stream must be read to the end, or its
// generating goroutine is never released.
func handleCIDRInput(inputCidr string) (<-chan string, error) {
	if !isCIDR(inputCidr) {
		return nil, input.ErrCidrBadFormat
	}

	return mapcidr.IPAddressesAsStream(inputCidr)
}

// isCIDR determines if the given ip is a cidr range.
func isCIDR(inputCidr string) bool {
	_, _, err := net.ParseCIDR(inputCidr)
	return err == nil
}
