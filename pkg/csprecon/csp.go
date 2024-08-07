package csprecon

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
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
)

// CheckCSP returns the list of domains parsed from a URL found in CSP.
func CheckCSP(url, ua string, rCSP *regexp.Regexp, client *http.Client) ([]string, error) {
    result := []string{}
    gologger.Debug().Msgf("Checking CSP for %s", url)
    
    req, err := http.NewRequest(http.MethodGet, url, nil)
    if err != nil {
        return result, fmt.Errorf("error creating request: %v", err)
    }
    req.Header.Add("User-Agent", ua)
    
    resp, err := client.Do(req)
    if err != nil {
        return result, fmt.Errorf("error making request: %v", err)
    }
    defer resp.Body.Close()
    
    gologger.Debug().Msgf("Response status: %s", resp.Status)
    
    // Check Content-Security-Policy header
    cspHeader := resp.Header.Get("Content-Security-Policy")
    if cspHeader != "" {
        headerCSP := ParseCSP(cspHeader, rCSP)
        gologger.Debug().Msgf("CSP Header domains: %v", headerCSP)
        result = append(result, headerCSP...)
    } else {
        gologger.Debug().Msg("No Content-Security-Policy header found")
    }

    // Check Content-Security-Portal header
    portalHeader := resp.Header.Get("Content-Security-Portal")
    if portalHeader != "" {
        portalCSP := ParseCSP(portalHeader, rCSP)
        gologger.Debug().Msgf("Content-Security-Portal Header domains: %v", portalCSP)
        result = append(result, portalCSP...)
    } else {
        gologger.Debug().Msg("No Content-Security-Portal header found")
    }

    bodyCSP, err := ParseBodyCSP(resp.Body, rCSP)
    if err != nil {
        gologger.Warning().Msgf("Error parsing body: %v", err)
    } else {
        gologger.Debug().Msgf("Body CSP domains: %v", bodyCSP)
        result = append(result, bodyCSP...)
    }
    
    gologger.Debug().Msgf("Total domains found: %d", len(result))
    return result, nil
}

// ParseCSP returns the list of domains parsed from a raw CSP (string).
func ParseCSP(input string, r *regexp.Regexp) []string {
    result := []string{}
    matches := r.FindAllStringSubmatch(input, -1)
    for _, match := range matches {
        if len(match) > 0 {
            domain := match[0]
            // Strip "*." from the beginning of the domain
            domain = strings.TrimPrefix(domain, "*.")
            result = append(result, domain)
        }
    }
    return golazy.RemoveDuplicateValues(result)
}

// ParseBodyCSP returns the list of domains parsed from the CSP found in the meta tag
// of the input HTML body.
func ParseBodyCSP(body io.Reader, rCSP *regexp.Regexp) ([]string, error) {
    result := []string{}

    bodyBytes, err := ioutil.ReadAll(body)
    if err != nil {
        return nil, fmt.Errorf("error reading body: %v", err)
    }

    doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bodyBytes))
    if err != nil {
        return nil, fmt.Errorf("error parsing HTML: %v", err)
    }

    doc.Find("meta[http-equiv]").Each(func(i int, s *goquery.Selection) {
        httpEquiv := s.AttrOr("http-equiv", "")
        content := s.AttrOr("content", "")

        if httpEquiv == "Content-Security-Policy" || httpEquiv == "Content-Security-Portal" {
            if content != "" {
                parsed := ParseCSP(content, rCSP)
                gologger.Debug().Msgf("Found %s in meta tag: %v", httpEquiv, parsed)
                result = append(result, parsed...)
            }
        }
    })

    return result, nil
}

func customClient(options *input.Options) (*http.Client, error) {
	transport := http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   time.Duration(options.Timeout) * time.Second,
			KeepAlive: KeepAlive * time.Second,
		}).Dial,
		TLSHandshakeTimeout: TLSHandshakeTimeout * time.Second,
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
