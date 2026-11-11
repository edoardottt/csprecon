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
	"time"

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

// CheckCSP returns the list of domains parsed from a URL found in CSP.
func CheckCSP(url, ua string, rCSP *regexp.Regexp, client *http.Client) ([]string, error) {
	result := []string{}

	gologger.Debug().Msgf("Checking CSP for %s", url)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return result, err
	}

	req.Header.Add("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}

	defer resp.Body.Close()

	cspHeaders := []string{
		"Content-Security-Policy",
		"Content-Security-Policy-Report-Only",
		"X-Content-Security-Policy",
		"X-WebKit-CSP",
	}

	// A response may carry the same CSP header more than once. Header.Get only
	// returns the first value, so iterate over every value to avoid missing
	// domains declared in the later headers.
	for _, h := range cspHeaders {
		for _, val := range resp.Header.Values(h) {
			if val != "" {
				result = append(result, ParseCSP(val, rCSP)...)
			}
		}
	}

	bodyCSP := ParseBodyCSP(resp.Body, rCSP)
	result = append(result, bodyCSP...)

	return result, nil
}

// ParseCSP returns the list of domains parsed from a raw CSP (string).
func ParseCSP(input string, r *regexp.Regexp) []string {
	result := r.FindAllString(input, -1)
	return golazy.RemoveDuplicateValues(result)
}

// ParseBodyCSP returns the list of domains parsed from the CSP found in the meta tag
// of the input HTML body.
func ParseBodyCSP(body io.Reader, rCSP *regexp.Regexp) []string {
	result := []string{}

	limitedReader := io.LimitReader(body, MaxKBBodyReader)

	doc, err := goquery.NewDocumentFromReader(limitedReader)
	if err != nil {
		// HARD FIX
		// https://github.com/edoardottt/csprecon/issues/482
		// with a simple print instead of fatal/panic
		// we get a SIGSEGV in doc.Find
		return []string{}
	}

	// Add the 'i' modifier to make http-equiv case-insensitive
	doc.Find("meta[http-equiv='Content-Security-Policy' i]").Each(func(i int, s *goquery.Selection) {
		contentCSP := s.AttrOr("content", "")
		if contentCSP != "" {
			result = append(result, ParseCSP(contentCSP, rCSP)...)
		}
	})

	return result
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

		if options.Verbose {
			gologger.Debug().Msgf("Using Proxy %s", options.Proxy)
		}
	}

	client := http.Client{
		Transport: &transport,
		Timeout:   time.Duration(options.Timeout) * time.Second,
	}

	return &client, nil
}
